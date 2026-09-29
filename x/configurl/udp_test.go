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

package configurl

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
	"golang.getoutline.org/sdk/transport"
)

func TestDirectUDPResolvesAndPinsHostname(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	receiver, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer receiver.Close()
	listener, err := NewDefaultProviders().NewPacketListener(ctx, "")
	require.NoError(t, err)
	conn, err := listener.ListenPacket(ctx)
	require.NoError(t, err)
	defer conn.Close()
	_, optimized := conn.(quic.OOBCapablePacketConn)
	require.False(t, optimized, "QUIC-Go must call WriteTo for unresolved addresses")
	c := conn.(*resolvingUDPConn)
	var lookups atomic.Int32
	c.lookup = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		if host != "direct.invalid" {
			return nil, errors.New("unexpected lookup: " + host)
		}
		lookups.Add(1)
		return []net.IPAddr{{IP: net.ParseIP("::1")}, {IP: net.ParseIP("127.0.0.1")}}, nil
	}
	_, port, err := net.SplitHostPort(receiver.LocalAddr().String())
	require.NoError(t, err)
	addr, err := transport.MakeNetAddr("udp", net.JoinHostPort("direct.invalid", port))
	require.NoError(t, err)
	// Concurrent writes must share one answer, including a prelude and QUIC packets.
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := conn.WriteTo([]byte("hello"), addr)
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	require.EqualValues(t, 1, lookups.Load())
	require.NoError(t, receiver.SetReadDeadline(time.Now().Add(time.Second)))
	for range 4 {
		buf := make([]byte, 20)
		n, _, err := receiver.ReadFrom(buf)
		require.NoError(t, err)
		require.Equal(t, "hello", string(buf[:n]))
	}
	// Literal IP destinations never invoke the resolver.
	c.lookup = func(context.Context, string) ([]net.IPAddr, error) {
		t.Error("unexpected lookup")
		return nil, errors.New("unexpected lookup")
	}
	_, err = conn.WriteTo([]byte("ip"), receiver.LocalAddr())
	require.NoError(t, err)
}

func TestDirectUDPResolutionCancelledOnClose(t *testing.T) {
	conn, err := (resolvingUDPListener{}).ListenPacket(context.Background())
	require.NoError(t, err)
	defer conn.Close()
	c := conn.(*resolvingUDPConn)
	started := make(chan struct{})
	c.lookup = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	addr, err := transport.MakeNetAddr("udp", "blocked.invalid:443")
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { _, err := conn.WriteTo([]byte("hello"), addr); done <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("lookup did not start")
	}
	require.NoError(t, conn.Close())
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("close did not cancel DNS")
	}
}

func TestDirectUDPResolutionFailure(t *testing.T) {
	conn, err := (resolvingUDPListener{}).ListenPacket(context.Background())
	require.NoError(t, err)
	defer conn.Close()
	c := conn.(*resolvingUDPConn)
	failure := errors.New("resolver failure")
	c.lookup = func(context.Context, string) ([]net.IPAddr, error) { return nil, failure }
	addr, err := transport.MakeNetAddr("udp", "failed.invalid:443")
	require.NoError(t, err)
	_, err = conn.WriteTo([]byte("hello"), addr)
	require.ErrorIs(t, err, failure)
	c.lookup = func(context.Context, string) ([]net.IPAddr, error) { return nil, nil }
	_, err = conn.WriteTo([]byte("hello"), addr)
	require.ErrorContains(t, err, "no addresses found")
}
