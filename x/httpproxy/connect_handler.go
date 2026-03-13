// Copyright 2023 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package httpproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"golang.getoutline.org/sdk/transport"
)

type sanitizeErrorDialer struct {
	transport.StreamDialer
}

func isCancelledError(err error) bool {
	if err == nil {
		return false
	}
	// Works around the fact that DNS doesn't return typed errors.
	return errors.Is(err, context.Canceled) || strings.HasSuffix(err.Error(), "operation was canceled")
}

func (d *sanitizeErrorDialer) DialStream(ctx context.Context, addr string) (transport.StreamConn, error) {
	conn, err := d.StreamDialer.DialStream(ctx, addr)
	if isCancelledError(err) {
		return nil, context.Canceled
	}
	if err != nil {
		return nil, errors.New("base dial failed")
	}
	return conn, nil
}

// StreamDialerParser creates a [transport.StreamDialer] from a config string.
// It is used by [NewConnectHandler] to support the Transport request header.
type StreamDialerParser func(ctx context.Context, config string) (transport.StreamDialer, error)

// HandlerOption configures a connect handler.
type HandlerOption func(*connectHandler)

// WithStreamDialerParser sets a factory that creates a dialer from the Transport request header value.
// When set, clients can override the transport per-request by sending a Transport header.
func WithStreamDialerParser(f StreamDialerParser) HandlerOption {
	return func(h *connectHandler) {
		h.dialerFactory = f
	}
}

type connectHandler struct {
	dialer        *sanitizeErrorDialer
	dialerFactory StreamDialerParser
}

var _ http.Handler = (*connectHandler)(nil)

func (h *connectHandler) ServeHTTP(proxyResp http.ResponseWriter, proxyReq *http.Request) {
	if proxyReq.Method != http.MethodConnect {
		proxyResp.Header().Add("Allow", "CONNECT")
		http.Error(proxyResp, fmt.Sprintf("Method %v is not supported", proxyReq.Method), http.StatusMethodNotAllowed)
		return
	}
	// Validate the target address.
	_, portStr, err := net.SplitHostPort(proxyReq.Host)
	if err != nil {
		http.Error(proxyResp, fmt.Sprintf("Authority \"%v\" is not a valid host:port", proxyReq.Host), http.StatusBadRequest)
		return
	}
	if portStr == "" {
		// As per https://httpwg.org/specs/rfc9110.html#CONNECT.
		http.Error(proxyResp, "Port number must be specified", http.StatusBadRequest)
		return
	}

	// Dial the target, optionally using a per-request transport from the Transport header.
	var dialer transport.StreamDialer = h.dialer
	if transportConfig := proxyReq.Header.Get("Transport"); transportConfig != "" {
		if h.dialerFactory == nil {
			http.Error(proxyResp, "Transport header is not supported", http.StatusNotImplemented)
			return
		}
		var err error
		dialer, err = h.dialerFactory(proxyReq.Context(), transportConfig)
		if err != nil {
			// Because we sanitize the base dialer error, it's safe to return error details here.
			http.Error(proxyResp, fmt.Sprintf("Invalid config in Transport header: %v", err), http.StatusBadRequest)
			return
		}
	}
	targetConn, err2 := dialer.DialStream(proxyReq.Context(), proxyReq.Host)
	if err2 != nil {
		http.Error(proxyResp, fmt.Sprintf("Failed to connect to %v: %v", proxyReq.Host, err2), http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	// Set up protocol-specific client I/O. H1 hijacks the raw connection; H2/H3 stream
	// through the ResponseWriter with explicit flushing after each write.
	var clientReader io.Reader
	var clientWriter io.ReaderFrom
	var afterCopy func()
	if hijacker, ok := proxyResp.(http.Hijacker); ok {
		// H1: hijack the raw connection and relay using the underlying bufio.ReadWriter.
		httpConn, clientRW, err := hijacker.Hijack()
		if err != nil {
			http.Error(proxyResp, "Failed to hijack connection", http.StatusInternalServerError)
			return
		}
		// TODO(fortuna): Use context.AfterFunc after we migrate to Go 1.21.
		go func() {
			// We close the hijacked connection when the context is done. This way
			// we allow the HTTP server to control the request lifetime.
			// The request context will be cancelled right after ServeHTTP returns,
			// but it can be cancelled before, if the server uses a custom BaseContext.
			<-proxyReq.Context().Done()
			httpConn.Close()
		}()
		clientRW.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		clientRW.Flush()
		// clientRW (bufio.ReadWriter) implements io.ReaderFrom via its embedded bufio.Writer.
		clientReader = clientRW
		clientWriter = clientRW
		// afterCopy flushes the bufio buffer to push any remaining bytes to the client.
		afterCopy = func() { clientRW.Flush() }
	} else {
		// H2/H3: hijacking is not available on multiplexed connections.
		flusher, ok := proxyResp.(http.Flusher)
		if !ok {
			http.Error(proxyResp, "Webserver doesn't support flushing", http.StatusInternalServerError)
			return
		}
		proxyResp.WriteHeader(http.StatusOK)
		flusher.Flush()
		// flushingWriter flushes after every write, so no afterCopy flush is needed.
		clientReader = proxyReq.Body
		clientWriter = &flushingWriter{w: proxyResp, f: flusher}
		afterCopy = func() {}
	}

	// Relay data between client and target in both directions.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// io.Copy prefers WriteTo, which clientRW implements. However,
		// bufio.ReadWriter.WriteTo issues an empty Write() call, which flushes
		// the Shadowsocks IV and connect request, breaking the coalescing with
		// the initial data. By preferring ReaderFrom, the coalescing of IV,
		// request and initial data is preserved.
		if rf, ok := targetConn.(io.ReaderFrom); ok {
			rf.ReadFrom(clientReader)
		} else {
			io.Copy(targetConn, clientReader)
		}
		targetConn.CloseWrite()
	}()
	// We can't use io.Copy here because it doesn't call Flush on writes, so the first
	// write is never sent and the entire relay gets stuck. bufio.Writer.ReadFrom (H1)
	// and flushingWriter.ReadFrom (H2/H3) take care of that.
	clientWriter.ReadFrom(targetConn)
	afterCopy()
	wg.Wait()
}

// flushingWriter wraps an http.ResponseWriter and flushes after every write,
// ensuring bytes are sent to the client immediately over H2/H3 streams.
type flushingWriter struct {
	w http.ResponseWriter
	f http.Flusher
}

func (fw *flushingWriter) Write(b []byte) (int, error) {
	n, err := fw.w.Write(b)
	fw.f.Flush()
	return n, err
}

// ReadFrom shadows http.ResponseWriter's own ReadFrom (present in net/http's *response),
// which does not flush. This implementation flushes after every write so bytes reach
// the client immediately, and prefers r.WriteTo to avoid an intermediate buffer.
func (fw *flushingWriter) ReadFrom(r io.Reader) (int64, error) {
	if wt, ok := r.(io.WriterTo); ok {
		return wt.WriteTo(fw)
	}
	buf := make([]byte, 32*1024)
	var n int64
	for {
		nr, er := r.Read(buf)
		if nr > 0 {
			nw, ew := fw.Write(buf[:nr])
			n += int64(nw)
			if ew != nil {
				return n, ew
			}
		}
		if er == io.EOF {
			return n, nil
		}
		if er != nil {
			return n, er
		}
	}
}

// NewConnectHandler creates a [http.Handler] that handles CONNECT requests and forwards
// the requests using the given [transport.StreamDialer].
//
// Use [WithStreamDialerParser] to support the Transport request header, which allows clients
// to specify a per-request transport config.
//
// The resulting handler is currently vulnerable to probing attacks. It's ok as a localhost proxy
// but it may be vulnerable if used as a public proxy.
func NewConnectHandler(dialer transport.StreamDialer, opts ...HandlerOption) http.Handler {
	// We sanitize the errors from the input Dialer because we don't want to leak sensitive details
	// of the base dialer (e.g. access key credentials) to the user.
	sd := &sanitizeErrorDialer{dialer}
	h := &connectHandler{dialer: sd}
	for _, opt := range opts {
		opt(h)
	}
	return h
}
