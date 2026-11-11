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
	"encoding/binary"
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

// newProvidersWithPacketDialer returns the default providers with dial registered as the "fake"
// packet dialer type.
func newProvidersWithPacketDialer(dial transport.FuncPacketDialer) *configurl.ProviderContainer {
	providers := configurl.NewDefaultProviders()
	providers.PacketDialers.RegisterType("fake", func(ctx context.Context, config *configurl.Config) (transport.PacketDialer, error) {
		return dial, nil
	})
	return providers
}

// dialH3Connect opens a tunnel through dialer and returns the error. No proxy answers in these
// tests, so the context bounds how long the QUIC handshake is attempted.
func dialH3Connect(t *testing.T, dialer transport.StreamDialer, timeout time.Duration) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_, err := dialer.DialStream(ctx, "example.com:443")
	require.Error(t, err, "nothing answers the QUIC handshake")
	return err
}

// Test_H3Connect_UsesBasePacketDialer verifies that h3connect dials the proxy with the packet
// dialer built from the element on its left, and passes it the proxy hostname unresolved.
// Resolving the name is the dialer's decision: a relay may be the only one that can.
func Test_H3Connect_UsesBasePacketDialer(t *testing.T) {
	t.Parallel()

	var gotConfig *configurl.Config
	dialErr := errors.New("dial packet failed")
	var gotAddr atomic.Value
	providers := configurl.NewDefaultProviders()
	providers.PacketDialers.RegisterType("fake", func(ctx context.Context, config *configurl.Config) (transport.PacketDialer, error) {
		gotConfig = config
		return transport.FuncPacketDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			gotAddr.Store(addr)
			return nil, dialErr
		}), nil
	})

	dialer, err := providers.NewStreamDialer(context.Background(), "fake://base|h3connect://proxy-only.invalid:443")
	require.NoError(t, err)
	require.NotNil(t, gotConfig, "base packet dialer was not built")
	require.Equal(t, "fake://base", gotConfig.URL.String())
	require.Nil(t, gotAddr.Load(), "the proxy is dialed for a connection, not at construction")

	err = dialH3Connect(t, dialer, 5*time.Second)
	require.ErrorIs(t, err, dialErr)
	require.Equal(t, "proxy-only.invalid:443", gotAddr.Load())
}

// Test_H3Connect_BasePacketDialerError verifies that errors from building the base packet dialer are propagated.
func Test_H3Connect_BasePacketDialerError(t *testing.T) {
	t.Parallel()

	providers := configurl.NewDefaultProviders()
	providers.PacketDialers.RegisterType("fail", func(ctx context.Context, config *configurl.Config) (transport.PacketDialer, error) {
		return nil, errors.New("fail dialer")
	})

	_, err := providers.NewStreamDialer(context.Background(), "fail:|h3connect://proxy.example:443")
	require.ErrorContains(t, err, "fail dialer")
}

// Test_H3Connect_InvalidProxyAddress verifies that a proxy address without a port is rejected
// when the dialer is built.
func Test_H3Connect_InvalidProxyAddress(t *testing.T) {
	t.Parallel()

	_, err := configurl.NewDefaultProviders().NewStreamDialer(context.Background(), "h3connect://proxy.example")
	require.ErrorContains(t, err, "failed to parse proxy address")
}

// failingWriteConn returns writeErr from Write and records whether Close was called.
type failingWriteConn struct {
	net.Conn
	writeErr    error
	closeCalled atomic.Bool
}

func (c *failingWriteConn) Write([]byte) (int, error) { return 0, c.writeErr }

func (c *failingWriteConn) Close() error {
	c.closeCalled.Store(true)
	return c.Conn.Close()
}

// Test_H3Connect_WriteError verifies that a write error on the dialed packet connection is
// returned by DialStream, and that the connection is closed.
func Test_H3Connect_WriteError(t *testing.T) {
	t.Parallel()

	// A loopback socket, so no packets leave the machine.
	sink, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { sink.Close() })

	var conn *failingWriteConn
	providers := newProvidersWithPacketDialer(func(ctx context.Context, addr string) (net.Conn, error) {
		udpConn, err := net.Dial("udp", sink.LocalAddr().String())
		if err != nil {
			return nil, err
		}
		conn = &failingWriteConn{Conn: udpConn, writeErr: errors.New("write failed")}
		return conn, nil
	})

	dialer, err := providers.NewStreamDialer(context.Background(), "fake:|h3connect://proxy.example:443")
	require.NoError(t, err)

	err = dialH3Connect(t, dialer, 5*time.Second)
	require.ErrorContains(t, err, "write failed")
	require.True(t, conn.closeCalled.Load(), "packet connection was not closed")
}

// listenOnLocalhost returns a UDP socket on the loopback address that a UDP dial to "localhost"
// selects, which may be 127.0.0.1 or ::1. A UDP dial does not fall back to another address.
func listenOnLocalhost(t *testing.T) *net.UDPConn {
	t.Helper()
	probe, err := net.Dial("udp", "localhost:9")
	require.NoError(t, err)
	loopback := probe.RemoteAddr().(*net.UDPAddr).IP
	require.NoError(t, probe.Close())
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: loopback})
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	return conn
}

// startH3Connect opens a tunnel through dialer in the background, and stops when the test ends.
// Nothing answers the QUIC handshake in these tests; they inspect the packets that are sent.
func startH3Connect(t *testing.T, dialer transport.StreamDialer) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = dialer.DialStream(ctx, "example.com:443")
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

// quicVersion returns the version of a QUIC long header packet.
func quicVersion(t *testing.T, packet []byte) uint32 {
	t.Helper()
	require.GreaterOrEqual(t, len(packet), 5)
	require.Equal(t, byte(0x80), packet[0]&0x80, "not a QUIC long header packet")
	return binary.BigEndian.Uint32(packet[1:5])
}

// Test_H3Connect_DirectHostname verifies that h3connect reaches a proxy given by hostname
// over the default transport: the QUIC Initial arrives at the address the name resolves to.
// QUIC-Go used to panic here, because a UDP socket cannot send to a name. Regression test for
// https://github.com/OutlineFoundation/outline-sdk/issues/643.
func Test_H3Connect_DirectHostname(t *testing.T) {
	t.Parallel()

	// Stands in for the proxy. It never answers; the test only inspects what arrives.
	proxy := listenOnLocalhost(t)
	port := proxy.LocalAddr().(*net.UDPAddr).Port

	dialer, err := configurl.NewDefaultProviders().NewStreamDialer(context.Background(), fmt.Sprintf("h3connect://localhost:%d", port))
	require.NoError(t, err)
	startH3Connect(t, dialer)

	require.NoError(t, proxy.SetReadDeadline(time.Now().Add(5*time.Second)))
	buf := make([]byte, 2048)
	n, _, err := proxy.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, uint32(1), quicVersion(t, buf[:n]), "expected a QUIC v1 Initial")
}

// Test_H3Connect_QUICPreludeHostname verifies that quicprelude composes with h3connect for a
// hostname proxy: the prelude and the QUIC Initial arrive from the same socket, in that order.
func Test_H3Connect_QUICPreludeHostname(t *testing.T) {
	t.Parallel()

	proxy := listenOnLocalhost(t)
	port := proxy.LocalAddr().(*net.UDPAddr).Port

	dialer, err := configurl.NewDefaultProviders().NewStreamDialer(context.Background(),
		fmt.Sprintf("quicprelude:version=0x1a2a3a4a|h3connect://localhost:%d", port))
	require.NoError(t, err)
	startH3Connect(t, dialer)

	require.NoError(t, proxy.SetReadDeadline(time.Now().Add(5*time.Second)))
	buf := make([]byte, 2048)
	n, preludeFrom, err := proxy.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, uint32(0x1a2a3a4a), quicVersion(t, buf[:n]), "expected the prelude first")
	n, initialFrom, err := proxy.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, uint32(1), quicVersion(t, buf[:n]), "expected the QUIC v1 Initial second")
	require.Equal(t, preludeFrom.String(), initialFrom.String(), "prelude and Initial must share a flow")
}
