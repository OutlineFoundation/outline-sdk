// Copyright 2025 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package websocket provides the Websocket transport.
package websocket

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.getoutline.org/sdk/transport"
)

// NewStreamEndpoint creates a new Websocket Stream Endpoint. Streams are sent over
// Websockets, with each Write becoming a separate message. Half-close is supported:
// CloseRead will not close the Websocket connection, while CloseWrite sends a Websocket
// close but continues reading until a close is received from the server.
func NewStreamEndpoint(urlStr string, se transport.StreamEndpoint, opts ...Option) (func(context.Context) (transport.StreamConn, error), error) {
	return newEndpoint(urlStr, se, func(gc *gorillaConn) transport.StreamConn { return gc }, opts...)
}

// NewPacketEndpoint creates a new Websocket Packet Endpoint. Each packet is exchanged as a Websocket message.
func NewPacketEndpoint(urlStr string, se transport.StreamEndpoint, opts ...Option) (func(context.Context) (net.Conn, error), error) {
	return newEndpoint(urlStr, se, func(gc *gorillaConn) net.Conn { return gc }, opts...)
}

type options struct {
	tlsConfig *tls.Config
	headers   http.Header
}

// Option for building the Websocket endpoint.
type Option func(c *options)

// WithTLSConfig specifies the TLS configuration to use.
// TODO(fortuna): Use Outline TLS instead.
func WithTLSConfig(tlsConfig *tls.Config) Option {
	return func(c *options) {
		c.tlsConfig = tlsConfig
	}
}

// WithHTTPHeaders specifies the HTTP headers to use.
func WithHTTPHeaders(headers http.Header) Option {
	return func(c *options) {
		c.headers = headers
	}
}

func newEndpoint[ConnType net.Conn](urlStr string, se transport.StreamEndpoint, wsToConn func(*gorillaConn) ConnType, opts ...Option) (func(context.Context) (ConnType, error), error) {
	_, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("url is invalid: %w", err)
	}

	resolvedOpts := options{
		// By default, we use this User-Agent.
		headers: http.Header(map[string][]string{"User-Agent": {fmt.Sprintf("Outline (%s; %s; %s)", runtime.GOOS, runtime.GOARCH, runtime.Version())}}),
	}
	for _, opt := range opts {
		opt(&resolvedOpts)
	}

	wsDialer := &websocket.Dialer{
		TLSClientConfig: resolvedOpts.tlsConfig,
		NetDialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			if !strings.HasPrefix(network, "tcp") {
				return nil, fmt.Errorf("websocket dialer does not support network type %v", network)
			}
			return se.ConnectStream(ctx)
		},
	}
	return func(ctx context.Context) (ConnType, error) {
		var zero ConnType
		wsConn, _, err := wsDialer.DialContext(ctx, urlStr, resolvedOpts.headers)
		if err != nil {
			return zero, err
		}
		return wsToConn(newGorillaConn(wsConn)), nil
	}, nil
}

func newGorillaConn(wsConn *websocket.Conn) *gorillaConn {
	gConn := &gorillaConn{wsConn: wsConn}
	wsConn.SetCloseHandler(func(code int, text string) error {
		gConn.readErr = io.EOF
		return nil
	})
	return gConn
}

type gorillaConn struct {
	wsConn *websocket.Conn

	// websocket.Conn is not safe for concurrent use
	// https://github.com/OutlineFoundation/outline-apps/issues/2573
	readMu, writeMu sync.Mutex

	writeErr      error
	readErr       error
	pendingReader io.Reader
}

var _ transport.StreamConn = (*gorillaConn)(nil)

func (c *gorillaConn) LocalAddr() net.Addr {
	return c.wsConn.LocalAddr()
}

func (c *gorillaConn) RemoteAddr() net.Addr {
	return c.wsConn.RemoteAddr()
}

func (c *gorillaConn) SetDeadline(deadline time.Time) error {
	return errors.Join(c.wsConn.SetReadDeadline(deadline), c.wsConn.SetWriteDeadline(deadline))
}

func (c *gorillaConn) SetReadDeadline(deadline time.Time) error {
	return c.wsConn.SetReadDeadline(deadline)
}

func (c *gorillaConn) SetWriteDeadline(deadline time.Time) error {
	return c.wsConn.SetWriteDeadline(deadline)
}

func (c *gorillaConn) Read(buf []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if c.readErr != nil {
		return 0, c.readErr
	}
	if c.pendingReader != nil {
		n, err := c.pendingReader.Read(buf)
		if c.readErr != nil {
			return n, c.readErr
		}
		if !errors.Is(err, io.EOF) {
			return n, err
		}
		c.pendingReader = nil
	}

	msgType, reader, err := c.wsConn.NextReader()
	if c.readErr != nil {
		return 0, c.readErr
	}
	if err != nil {
		var closeError *websocket.CloseError
		if errors.As(err, &closeError) {
			if closeError.Code == websocket.CloseNormalClosure {
				return 0, io.EOF
			}
			return 0, fmt.Errorf("%w %w", net.ErrClosed, closeError)
		}
		return 0, err
	}
	if msgType != websocket.BinaryMessage {
		return 0, errors.New("read message is not binary")
	}

	c.pendingReader = reader
	return reader.Read(buf)
}

func (c *gorillaConn) Write(buf []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	err := c.wsConn.WriteMessage(websocket.BinaryMessage, buf)
	if err != nil {
		if c.writeErr != nil {
			return 0, c.writeErr
		}
		return 0, err
	}
	return len(buf), nil
}

func (c *gorillaConn) CloseRead() error {
	c.readErr = net.ErrClosed
	c.wsConn.SetReadDeadline(time.Now())
	return nil
}

func (c *gorillaConn) CloseWrite() error {
	// Send close message.
	message := websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")
	c.wsConn.WriteControl(websocket.CloseMessage, message, time.Now().Add(time.Second))
	c.writeErr = net.ErrClosed
	c.wsConn.SetWriteDeadline(time.Now())
	return nil
}

func (c *gorillaConn) Close() error {
	c.CloseRead()
	c.CloseWrite()
	return c.wsConn.Close()
}

// Upgrade upgrades an HTTP connection to a WebSocket connection. It returns a
// [transport.StreamConn] representing the WebSocket connection, or an error if
// the upgrade fails.
func Upgrade(w http.ResponseWriter, r *http.Request, responseHeader http.Header) (transport.StreamConn, error) {
	upgrader := websocket.Upgrader{}
	wsConn, err := upgrader.Upgrade(w, r, responseHeader)
	if err != nil {
		return nil, err
	}
	return newGorillaConn(wsConn), nil
}
