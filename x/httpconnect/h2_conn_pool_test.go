// Copyright 2026 The Outline Authors
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
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/transport/tls"

	"golang.getoutline.org/sdk/x/httpproxy"
)

// newH2TLSProxy starts an HTTP/2 over TLS CONNECT proxy and returns it with its address
// and the options to trust its certificate.
func newH2TLSProxy(t *testing.T) (*httptest.Server, string, TransportOption) {
	t.Helper()
	proxySrv := httptest.NewUnstartedServer(httpproxy.NewConnectHandler(&transport.TCPDialer{}))
	proxySrv.EnableHTTP2 = true
	proxySrv.StartTLS()
	t.Cleanup(proxySrv.Close)

	certPool := x509.NewCertPool()
	certPool.AddCert(proxySrv.Certificate())
	proxyURL, err := url.Parse(proxySrv.URL)
	require.NoError(t, err, "Parse")
	return proxySrv, proxyURL.Host, WithTLSOptions(tls.WithCertVerifier(&tls.StandardCertVerifier{Roots: certPool}))
}

// Test_H2ProxyTransport_Redial verifies that a new connection to the proxy is dialed
// once the existing one is closed.
func Test_H2ProxyTransport_Redial(t *testing.T) {
	t.Parallel()

	proxySrv, proxyAddr, tlsOpt := newH2TLSProxy(t)

	var dialCount atomic.Int32
	countingDialer := transport.FuncStreamDialer(func(ctx context.Context, addr string) (transport.StreamConn, error) {
		dialCount.Add(1)
		return (&transport.TCPDialer{}).DialStream(ctx, addr)
	})

	tr, err := NewH2ProxyTransport(countingDialer, proxyAddr, tlsOpt)
	require.NoError(t, err, "NewH2ProxyTransport")
	connClient, err := NewConnectClient(tr)
	require.NoError(t, err, "NewConnectClient")

	verifyTunnel(t, connClient)
	verifyTunnel(t, connClient)
	require.Equal(t, int32(1), dialCount.Load(), "sequential tunnels should reuse the connection")

	targetSrv := newTargetSrv(t, "ignored")
	t.Cleanup(targetSrv.Close)
	proxySrv.CloseClientConnections()
	require.Eventually(t, func() bool {
		conn, err := connClient.DialStream(context.Background(), targetSrv.Listener.Addr().String())
		if err != nil {
			return false
		}
		conn.Close()
		return true
	}, time.Second, 10*time.Millisecond, "tunnel after the proxy closed the connection")
	require.Equal(t, int32(2), dialCount.Load(), "expected a new connection after the old one was closed")

	verifyTunnel(t, connClient)
}

// Test_H2ProxyTransport_TLS_RequiresH2 verifies that NewH2ProxyTransport fails instead of
// falling back to HTTP/1 when the proxy doesn't negotiate HTTP/2.
func Test_H2ProxyTransport_TLS_RequiresH2(t *testing.T) {
	t.Parallel()

	// A TLS proxy without ALPN, so the handshake succeeds without negotiating a protocol.
	tlsCert, certPool := tlsCertPool(t)
	ln, err := stdTLS.Listen("tcp", "127.0.0.1:0", &stdTLS.Config{Certificates: []stdTLS.Certificate{tlsCert}})
	require.NoError(t, err, "Listen")
	proxySrv := &http.Server{Handler: httpproxy.NewConnectHandler(&transport.TCPDialer{})}
	go func() { _ = proxySrv.Serve(ln) }()
	t.Cleanup(func() { proxySrv.Close() })

	tr, err := NewH2ProxyTransport(&transport.TCPDialer{}, ln.Addr().String(),
		WithTLSOptions(tls.WithCertVerifier(&tls.StandardCertVerifier{Roots: certPool})))
	require.NoError(t, err, "NewH2ProxyTransport")
	connClient, err := NewConnectClient(tr)
	require.NoError(t, err, "NewConnectClient")

	_, err = connClient.DialStream(context.Background(), "127.0.0.1:1")
	require.ErrorContains(t, err, "proxy did not negotiate HTTP/2")
}

// Test_H2ProxyTransport_CloseIdleConnections verifies that idle connections are closed.
func Test_H2ProxyTransport_CloseIdleConnections(t *testing.T) {
	t.Parallel()

	_, proxyAddr, tlsOpt := newH2TLSProxy(t)

	var dialCount atomic.Int32
	countingDialer := transport.FuncStreamDialer(func(ctx context.Context, addr string) (transport.StreamConn, error) {
		dialCount.Add(1)
		return (&transport.TCPDialer{}).DialStream(ctx, addr)
	})
	tr, err := NewH2ProxyTransport(countingDialer, proxyAddr, tlsOpt)
	require.NoError(t, err, "NewH2ProxyTransport")
	connClient, err := NewConnectClient(tr)
	require.NoError(t, err, "NewConnectClient")

	verifyTunnel(t, connClient)
	pool := tr.(proxyRT).RoundTripper.(*h2ConnPool)
	// The tunnel's stream finishes asynchronously after the tunnel is closed.
	require.Eventually(t, func() bool {
		pool.CloseIdleConnections()
		pool.mu.Lock()
		defer pool.mu.Unlock()
		return len(pool.conns) == 0
	}, time.Second, 10*time.Millisecond, "connection should become idle and be closed")
	verifyTunnel(t, connClient)
	require.Equal(t, int32(2), dialCount.Load(), "expected a new connection after closing idle ones")
}
