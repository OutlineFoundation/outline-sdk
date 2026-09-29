// Copyright 2025 The Outline Authors
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

package httpconnect

import (
	"context"
	stdTLS "crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/require"
	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/transport/tls"
	"golang.org/x/net/http2"

	"golang.getoutline.org/sdk/x/httpproxy"
)

// Compile-time check: net.Conn satisfies io.ReadWriteCloser.
var _ io.ReadWriteCloser = (net.Conn)(nil)

// tlsCertPool returns the built-in httptest TLS certificate and a cert pool trusting it.
// Reusing httptest's certificate avoids generating a custom CA in each test.
func tlsCertPool(t *testing.T) (stdTLS.Certificate, *x509.CertPool) {
	t.Helper()
	// Create a throwaway server solely to borrow its built-in TLS cert material.
	srv := httptest.NewTLSServer(nil)
	srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return srv.TLS.Certificates[0], pool
}

// verifyTunnel sends an HTTP GET through the given dialer to a local target server
// and asserts the response is received correctly end-to-end.
func verifyTunnel(t *testing.T, dialer transport.StreamDialer) {
	t.Helper()

	type Response struct {
		Message string `json:"message"`
	}
	want := Response{Message: "hello"}

	targetSrv := newTargetSrv(t, want)
	t.Cleanup(targetSrv.Close)

	hc := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				conn, err := dialer.DialStream(ctx, addr)
				if err != nil {
					return nil, err
				}
				require.Equal(t, addr, conn.RemoteAddr().String())
				return conn, nil
			},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetSrv.URL, nil)
	require.NoError(t, err)
	req.Close = true // close the tunnel right after the request

	resp, err := hc.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { resp.Body.Close() })

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var got Response
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	require.Equal(t, want, got)
}

// Test_ConnectClient_H1_Plain verifies that custom headers (e.g. Proxy-Authorization)
// are forwarded on every CONNECT request when using a plain HTTP/1.1 proxy.
func Test_ConnectClient_H1_Plain(t *testing.T) {
	t.Parallel()

	tcpDialer := &transport.TCPDialer{}
	creds := base64.StdEncoding.EncodeToString([]byte("username:password"))

	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Basic "+creds, r.Header.Get("Proxy-Authorization"))
		httpproxy.NewConnectHandler(tcpDialer).ServeHTTP(w, r)
	}))
	t.Cleanup(proxySrv.Close)

	proxyURL, err := url.Parse(proxySrv.URL)
	require.NoError(t, err, "Parse")

	tr, err := NewHTTPProxyTransport(tcpDialer, proxyURL.Host, WithPlainHTTP())
	require.NoError(t, err, "NewHTTPProxyTransport")

	connClient, err := NewConnectClient(tr, WithHeaders(http.Header{
		"Proxy-Authorization": []string{"Basic " + creds},
	}))
	require.NoError(t, err, "NewConnectClient")

	verifyTunnel(t, connClient)
}

// Test_ConnectClient_H1_TLS verifies end-to-end tunneling over a TLS-wrapped HTTP/1.1 proxy.
func Test_ConnectClient_H1_TLS(t *testing.T) {
	t.Parallel()

	tcpDialer := &transport.TCPDialer{}

	proxySrv := httptest.NewUnstartedServer(httpproxy.NewConnectHandler(tcpDialer))
	proxySrv.StartTLS()
	t.Cleanup(proxySrv.Close)

	certPool := x509.NewCertPool()
	certPool.AddCert(proxySrv.Certificate())

	proxyURL, err := url.Parse(proxySrv.URL)
	require.NoError(t, err, "Parse")

	tr, err := NewHTTPProxyTransport(tcpDialer, proxyURL.Host,
		WithTLSOptions(tls.WithCertVerifier(&tls.StandardCertVerifier{Roots: certPool})),
	)
	require.NoError(t, err, "NewHTTPProxyTransport")

	connClient, err := NewConnectClient(tr)
	require.NoError(t, err, "NewConnectClient")

	verifyTunnel(t, connClient)
}

// Test_ConnectClient_H2_TLS verifies tunneling over HTTP/2 using NewH2ProxyTransport directly with TLS.
func Test_ConnectClient_H2_TLS(t *testing.T) {
	t.Parallel()

	tcpDialer := &transport.TCPDialer{}

	// Use httpproxy.NewConnectHandler directly to verify it handles H2 (not just H1).
	// Previously this would fail because the handler required http.Hijacker, which H2 doesn't support.
	proxySrv := httptest.NewUnstartedServer(httpproxy.NewConnectHandler(tcpDialer))
	proxySrv.EnableHTTP2 = true
	proxySrv.StartTLS()
	t.Cleanup(proxySrv.Close)

	certPool := x509.NewCertPool()
	certPool.AddCert(proxySrv.Certificate())

	proxyURL, err := url.Parse(proxySrv.URL)
	require.NoError(t, err, "Parse")

	tr, err := NewH2ProxyTransport(tcpDialer, proxyURL.Host,
		WithTLSOptions(tls.WithCertVerifier(&tls.StandardCertVerifier{Roots: certPool})),
	)
	require.NoError(t, err, "NewH2ProxyTransport")

	connClient, err := NewConnectClient(tr)
	require.NoError(t, err, "NewConnectClient")

	verifyTunnel(t, connClient)
}

// Test_ConnectClient_H2_TLS_HTTPTransport verifies tunneling over HTTP/2 when ALPN negotiation selects h2.
// Uses NewHTTPProxyTransport, which adds H2 support on top of net/http.Transport via ALPN.
func Test_ConnectClient_H2_TLS_HTTPTransport(t *testing.T) {
	t.Parallel()

	tcpDialer := &transport.TCPDialer{}

	proxySrv := httptest.NewUnstartedServer(httpproxy.NewConnectHandler(tcpDialer))
	proxySrv.EnableHTTP2 = true
	proxySrv.StartTLS()
	t.Cleanup(proxySrv.Close)

	certPool := x509.NewCertPool()
	certPool.AddCert(proxySrv.Certificate())

	proxyURL, err := url.Parse(proxySrv.URL)
	require.NoError(t, err, "Parse")

	tr, err := NewHTTPProxyTransport(tcpDialer, proxyURL.Host,
		WithTLSOptions(
			tls.WithCertVerifier(&tls.StandardCertVerifier{Roots: certPool}),
			tls.WithALPN([]string{"h2"}),
		),
	)
	require.NoError(t, err, "NewHTTPProxyTransport")

	connClient, err := NewConnectClient(tr)
	require.NoError(t, err, "NewConnectClient")

	verifyTunnel(t, connClient)
}

// Test_ConnectClient_H2_TLS_AlpnFails verifies that when the client enforces H2 via ALPN
// but the server only supports H1, the TLS handshake fails with a clear protocol error.
func Test_ConnectClient_H2_TLS_AlpnFails(t *testing.T) {
	t.Parallel()

	tcpDialer := &transport.TCPDialer{}

	// H1-only server: no EnableHTTP2.
	proxySrv := httptest.NewUnstartedServer(httpproxy.NewConnectHandler(tcpDialer))
	proxySrv.StartTLS()
	t.Cleanup(proxySrv.Close)

	certPool := x509.NewCertPool()
	certPool.AddCert(proxySrv.Certificate())

	proxyURL, err := url.Parse(proxySrv.URL)
	require.NoError(t, err, "Parse")

	tr, err := NewHTTPProxyTransport(tcpDialer, proxyURL.Host,
		WithTLSOptions(
			tls.WithCertVerifier(&tls.StandardCertVerifier{Roots: certPool}),
			tls.WithALPN([]string{"h2"}),
		),
	)
	require.NoError(t, err, "NewHTTPProxyTransport")

	connClient, err := NewConnectClient(tr)
	require.NoError(t, err, "NewConnectClient")

	_, err = connClient.DialStream(context.Background(), "127.0.0.1:1")
	require.ErrorContains(t, err, "tls: no application protocol")
}

// Test_ConnectClient_H2C verifies tunneling over cleartext HTTP/2 (h2c) via prior knowledge.
// Uses NewH2ProxyTransport with WithPlainHTTP(): no TLS, no HTTP upgrade — H2 from the first byte.
func Test_ConnectClient_H2C(t *testing.T) {
	t.Parallel()

	tcpDialer := &transport.TCPDialer{}

	// Serve H2 prior knowledge (no TLS, no upgrade) on a raw TCP listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "Listen")
	t.Cleanup(func() { ln.Close() })

	h2srv := &http2.Server{}
	handler := httpproxy.NewConnectHandler(tcpDialer)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go h2srv.ServeConn(conn, &http2.ServeConnOpts{Handler: handler})
		}
	}()

	tr, err := NewH2ProxyTransport(tcpDialer, ln.Addr().String(), WithPlainHTTP())
	require.NoError(t, err, "NewH2ProxyTransport")

	connClient, err := NewConnectClient(tr)
	require.NoError(t, err, "NewConnectClient")

	verifyTunnel(t, connClient)
}

// Test_ConnectClient_H2_TLS_Multiplexed verifies that NewH2ProxyTransport uses a single
// underlying TCP connection to the proxy for multiple concurrent CONNECT streams.
func Test_ConnectClient_H2_TLS_Multiplexed(t *testing.T) {
	t.Parallel()

	tcpDialer := &transport.TCPDialer{}

	proxySrv := httptest.NewUnstartedServer(httpproxy.NewConnectHandler(tcpDialer))
	proxySrv.EnableHTTP2 = true
	proxySrv.StartTLS()
	t.Cleanup(proxySrv.Close)

	certPool := x509.NewCertPool()
	certPool.AddCert(proxySrv.Certificate())

	proxyURL, err := url.Parse(proxySrv.URL)
	require.NoError(t, err, "Parse")

	// Wrap the dialer to count how many TCP connections are opened to the proxy.
	var mu sync.Mutex
	var dialCount int
	countingDialer := transport.FuncStreamDialer(func(ctx context.Context, addr string) (transport.StreamConn, error) {
		mu.Lock()
		dialCount++
		mu.Unlock()
		return tcpDialer.DialStream(ctx, addr)
	})

	tr, err := NewH2ProxyTransport(countingDialer, proxyURL.Host,
		WithTLSOptions(tls.WithCertVerifier(&tls.StandardCertVerifier{Roots: certPool})),
	)
	require.NoError(t, err, "NewH2ProxyTransport")

	connClient, err := NewConnectClient(tr)
	require.NoError(t, err, "NewConnectClient")

	// Open 3 concurrent tunnels and assert they all share 1 TCP connection to the proxy.
	targetSrv := newTargetSrv(t, "ignored")
	t.Cleanup(targetSrv.Close)
	targetURL, err := url.Parse(targetSrv.URL)
	require.NoError(t, err, "Parse")

	var wg sync.WaitGroup
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := connClient.DialStream(context.Background(), targetURL.Host)
			require.NoError(t, err, "DialStream")
			conn.Close()
		}()
	}
	wg.Wait()

	mu.Lock()
	require.Equal(t, 1, dialCount, "expected all streams to share 1 TCP connection to proxy")
	mu.Unlock()

	verifyTunnel(t, connClient)
}

// newH3ProxyServer starts an HTTP/3 CONNECT proxy on a loopback UDP port. It listens on
// "localhost", so the address it returns is whichever loopback IP the machine maps that name to.
// It also returns a cert pool that trusts the proxy's certificate, which is valid for both
// loopback IPs. Uses http3.HTTPStreamer to access the raw H3 stream.
func newH3ProxyServer(t *testing.T) (*net.UDPAddr, *x509.CertPool) {
	t.Helper()

	// http3.Server requires its own TLS config; borrow httptest's built-in cert.
	tlsCert, certPool := tlsCertPool(t)

	srvConn, err := net.ListenPacket("udp", "localhost:0")
	require.NoError(t, err, "ListenPacket")

	proxySrv := &http3.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, "HTTP/3.0", r.Proto, "Proto")
			require.Equal(t, http.MethodConnect, r.Method, "Method")

			conn, err := net.Dial("tcp", r.URL.Host)
			require.NoError(t, err, "Dial")
			defer conn.Close()

			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()

			streamer, ok := w.(http3.HTTPStreamer)
			require.True(t, ok, "expected http3.HTTPStreamer")
			stream := streamer.HTTPStream()
			defer stream.Close()

			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				io.Copy(stream, conn)
			}()
			wg.Add(1)
			go func() {
				defer wg.Done()
				io.Copy(conn, stream)
			}()
			wg.Wait()
		}),
		TLSConfig: &stdTLS.Config{Certificates: []stdTLS.Certificate{tlsCert}},
	}
	go func() { _ = proxySrv.Serve(srvConn) }()
	t.Cleanup(func() {
		_ = proxySrv.Close()
		_ = srvConn.Close()
	})

	return srvConn.LocalAddr().(*net.UDPAddr), certPool
}

// newLoopbackPacketConn returns a UDP connection bound to an ephemeral port on ip, so it is in
// the same IP family as a server listening on that IP.
func newLoopbackPacketConn(t *testing.T, ip net.IP) net.PacketConn {
	t.Helper()
	conn, err := net.ListenPacket("udp", net.JoinHostPort(ip.String(), "0"))
	require.NoError(t, err, "ListenPacket")
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// Test_ConnectClient_H3_QUIC verifies tunneling over HTTP/3, where CONNECT streams
// run over QUIC rather than TCP.
func Test_ConnectClient_H3_QUIC(t *testing.T) {
	t.Parallel()

	proxyAddr, certPool := newH3ProxyServer(t)
	cliConn := newLoopbackPacketConn(t, proxyAddr.IP)

	tr, err := NewH3ProxyTransport(cliConn, proxyAddr.String(),
		WithTLSOptions(tls.WithCertVerifier(&tls.StandardCertVerifier{Roots: certPool})),
	)
	require.NoError(t, err, "NewH3ProxyTransport")

	connClient, err := NewConnectClient(tr)
	require.NoError(t, err, "NewConnectClient")

	verifyTunnel(t, connClient)
}

// Test_ConnectClient_H3_QUIC_HostnameProxy verifies that the proxy can be addressed by hostname.
// QUIC needs a resolved UDP address for every datagram, so the transport must resolve the
// hostname itself; before that, a hostname made quic-go panic on a *net.UDPConn.
//
// The proxy listens on whichever loopback IP "localhost" maps to, and the client connection is
// bound to the same IP, so the transport resolves "localhost" to the family it can reach.
func Test_ConnectClient_H3_QUIC_HostnameProxy(t *testing.T) {
	t.Parallel()

	proxyIPAddr, certPool := newH3ProxyServer(t)
	proxyAddr := net.JoinHostPort("localhost", fmt.Sprint(proxyIPAddr.Port))
	cliConn := newLoopbackPacketConn(t, proxyIPAddr.IP)

	// The test certificate is not valid for "localhost", so validate it against the IP it covers.
	tr, err := NewH3ProxyTransport(cliConn, proxyAddr,
		WithTLSOptions(tls.WithCertVerifier(&tls.StandardCertVerifier{Roots: certPool, CertificateName: proxyIPAddr.IP.String()})),
	)
	require.NoError(t, err, "NewH3ProxyTransport")

	connClient, err := NewConnectClient(tr)
	require.NoError(t, err, "NewConnectClient")

	verifyTunnel(t, connClient)
}

// Test_chooseIPAddr verifies that the resolved proxy address matches the IP family the client
// connection can send from.
func Test_chooseIPAddr(t *testing.T) {
	t.Parallel()

	v4 := net.IPAddr{IP: net.IPv4(192, 0, 2, 1)}
	v6 := net.IPAddr{IP: net.ParseIP("2001:db8::1")}
	both := []net.IPAddr{v6, v4} // IPv6 first, as many resolvers order it.

	tests := []struct {
		name  string
		local net.Addr
		ips   []net.IPAddr
		want  net.IPAddr
	}{
		{"IPv4 local prefers IPv4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, both, v4},
		{"IPv4 unspecified local prefers IPv4", &net.UDPAddr{IP: net.IPv4zero}, both, v4},
		{"IPv6 unspecified local is dual-stack, prefers IPv4", &net.UDPAddr{IP: net.IPv6unspecified}, both, v4},
		{"nil IP local prefers IPv4", &net.UDPAddr{}, both, v4},
		{"non-UDP local prefers IPv4", &net.TCPAddr{IP: net.ParseIP("::1")}, both, v4},
		{"nil local prefers IPv4", nil, both, v4},
		{"specific IPv6 local prefers IPv6", &net.UDPAddr{IP: net.ParseIP("::1")}, both, v6},
		{"IPv4 local falls back to IPv6 only", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, []net.IPAddr{v6}, v6},
		{"specific IPv6 local falls back to IPv4 only", &net.UDPAddr{IP: net.ParseIP("::1")}, []net.IPAddr{v4}, v4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, chooseIPAddr(tt.local, tt.ips))
		})
	}
}

// Test_ConnectClient_H3_QUIC_UnresolvableProxy verifies that a proxy hostname that cannot be
// resolved produces an error from DialStream rather than a panic.
func Test_ConnectClient_H3_QUIC_UnresolvableProxy(t *testing.T) {
	t.Parallel()

	cliConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err, "ListenPacket")
	t.Cleanup(func() { _ = cliConn.Close() })

	// ".invalid" is reserved by RFC 2606 and never resolves.
	tr, err := NewH3ProxyTransport(cliConn, "proxy.invalid:443")
	require.NoError(t, err, "NewH3ProxyTransport")

	connClient, err := NewConnectClient(tr)
	require.NoError(t, err, "NewConnectClient")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = connClient.DialStream(ctx, "example.com:443")
	require.ErrorContains(t, err, "failed to resolve proxy address proxy.invalid:443")
}

// newTargetSrv starts a local HTTP server that responds to any request with resp serialized as JSON.
// It represents the tunnel destination — the server the client reaches through the proxy.
func newTargetSrv(t *testing.T, resp interface{}) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		jsonResp, err := json.Marshal(resp)
		require.NoError(t, err)

		_, err = w.Write(jsonResp)
		require.NoError(t, err)
	}))
}
