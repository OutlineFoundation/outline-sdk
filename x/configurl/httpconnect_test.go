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

package configurl_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/x/configurl"
	"golang.getoutline.org/sdk/x/httpproxy"
	"golang.org/x/net/http2"
)

// Test_H2Connect_H2C tests the h2connect configurl type using h2c (cleartext HTTP/2).
// It starts a local h2c proxy, builds a stream dialer via "h2connect://host:port?plain=true",
// and verifies that an HTTP request is tunneled through to a target server.
func Test_H2Connect_H2C(t *testing.T) {
	t.Parallel()

	tcpDialer := &transport.TCPDialer{}

	// Start an h2c proxy server (plain HTTP/2 without TLS).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
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

	// Build a dialer using the configurl h2connect type.
	providers := configurl.NewDefaultProviders()
	dialer, err := providers.NewStreamDialer(context.Background(),
		fmt.Sprintf("h2connect://%s?plain=true", ln.Addr().String()),
	)
	require.NoError(t, err)

	// Start a target server that returns a JSON response.
	type Response struct {
		Message string `json:"message"`
	}
	want := Response{Message: "hello"}
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(want)
	}))
	t.Cleanup(targetSrv.Close)

	// Make an HTTP request through the tunnel.
	hc := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return dialer.DialStream(ctx, addr)
			},
		},
	}
	resp, err := hc.Get(targetSrv.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var got Response
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	require.Equal(t, want, got)
}

// recordingPacketListener is a [transport.PacketListener] that records whether ListenPacket was called.
// It returns conn, or err if set.
type recordingPacketListener struct {
	listenCalled bool
	conn         net.PacketConn
	err          error
}

func (l *recordingPacketListener) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	l.listenCalled = true
	if l.err != nil {
		return nil, l.err
	}
	return l.conn, nil
}

// testPacketConn wraps a [net.PacketConn], records whether Close was called, and returns
// writeErr from WriteTo if set.
type testPacketConn struct {
	net.PacketConn
	writeErr    error
	closeCalled atomic.Bool
}

func (c *testPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return c.PacketConn.WriteTo(p, addr)
}

func (c *testPacketConn) Close() error {
	c.closeCalled.Store(true)
	return c.PacketConn.Close()
}

// newTestPacketConn returns a [testPacketConn] over a loopback socket, so no packets leave the machine.
func newTestPacketConn(t *testing.T) *testPacketConn {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	return &testPacketConn{PacketConn: conn}
}

// newProvidersWithPacketListener returns the default providers with pl registered as the "fake"
// packet listener type.
func newProvidersWithPacketListener(pl transport.PacketListener) *configurl.ProviderContainer {
	providers := configurl.NewDefaultProviders()
	providers.PacketListeners.RegisterType("fake", func(ctx context.Context, config *configurl.Config) (transport.PacketListener, error) {
		return pl, nil
	})
	return providers
}

// Test_H3Connect_UsesBasePacketListener verifies that h3connect runs QUIC over the
// packet listener built from the element on its left, instead of ignoring it.
func Test_H3Connect_UsesBasePacketListener(t *testing.T) {
	t.Parallel()

	// A loopback socket, so no packets leave the machine. Building the dialer doesn't send any.
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	pl := &recordingPacketListener{conn: conn}
	var gotConfig *configurl.Config
	providers := configurl.NewDefaultProviders()
	providers.PacketListeners.RegisterType("fake", func(ctx context.Context, config *configurl.Config) (transport.PacketListener, error) {
		gotConfig = config
		return pl, nil
	})

	dialer, err := providers.NewStreamDialer(context.Background(), "fake://base|h3connect://proxy.example:443")
	require.NoError(t, err)
	require.NotNil(t, dialer)
	require.NotNil(t, gotConfig, "base packet listener was not built")
	require.Equal(t, "fake://base", gotConfig.URL.String())
	require.True(t, pl.listenCalled, "ListenPacket was not called on the base packet listener")
}

// Test_H3Connect_BasePacketListenerError verifies that errors from the base packet listener are propagated.
func Test_H3Connect_BasePacketListenerError(t *testing.T) {
	t.Parallel()

	providers := configurl.NewDefaultProviders()
	providers.PacketListeners.RegisterType("fail", func(ctx context.Context, config *configurl.Config) (transport.PacketListener, error) {
		return nil, errors.New("fail listener")
	})

	_, err := providers.NewStreamDialer(context.Background(), "fail:|h3connect://proxy.example:443")
	require.ErrorContains(t, err, "fail listener")
}

// Test_H3Connect_ListenPacketError verifies that errors from the base listener's ListenPacket are propagated.
func Test_H3Connect_ListenPacketError(t *testing.T) {
	t.Parallel()

	pl := &recordingPacketListener{err: errors.New("listen packet failed")}
	providers := newProvidersWithPacketListener(pl)

	_, err := providers.NewStreamDialer(context.Background(), "fake:|h3connect://proxy.example:443")
	require.ErrorContains(t, err, "failed to create packet connection")
	require.ErrorIs(t, err, pl.err)
}

// Test_H3Connect_ClosesConnOnTransportError verifies that the packet connection is closed
// if the HTTP/3 transport can't be created.
func Test_H3Connect_ClosesConnOnTransportError(t *testing.T) {
	t.Parallel()

	conn := newTestPacketConn(t)
	providers := newProvidersWithPacketListener(&recordingPacketListener{conn: conn})

	// A proxy address without a port makes the transport creation fail.
	_, err := providers.NewStreamDialer(context.Background(), "fake:|h3connect://proxy.example")
	require.ErrorContains(t, err, "failed to parse proxy address")
	require.True(t, conn.closeCalled.Load(), "packet connection was not closed")
}

// Test_H3Connect_WriteError verifies that a write error on the base packet connection is
// returned by DialStream.
func Test_H3Connect_WriteError(t *testing.T) {
	t.Parallel()

	conn := newTestPacketConn(t)
	conn.writeErr = errors.New("write failed")
	providers := newProvidersWithPacketListener(&recordingPacketListener{conn: conn})

	dialer, err := providers.NewStreamDialer(context.Background(), "fake:|h3connect://127.0.0.1:443")
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = dialer.DialStream(ctx, "example.com:443")
	require.ErrorContains(t, err, "write failed")
}
