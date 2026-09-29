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
	// A failed lookup must not poison the cache: a later attempt can succeed.
	c.lookup = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}, nil
	}
	resolved, err := c.resolve(addr.String())
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1:443", resolved.String())
}

func TestDirectUDPResolutionOutlivesSetupContext(t *testing.T) {
	setupCtx, cancelSetup := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelSetup()
	conn, err := (resolvingUDPListener{}).ListenPacket(setupCtx)
	require.NoError(t, err)
	defer conn.Close()
	cancelSetup()

	receiver, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer receiver.Close()
	_, port, err := net.SplitHostPort(receiver.LocalAddr().String())
	require.NoError(t, err)
	addr, err := transport.MakeNetAddr("udp", net.JoinHostPort("after-setup.invalid", port))
	require.NoError(t, err)
	c := conn.(*resolvingUDPConn)
	c.lookup = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if _, ok := ctx.Deadline(); ok {
			return nil, errors.New("lookup inherited the setup deadline")
		}
		return []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}, nil
	}
	_, err = conn.WriteTo([]byte("after setup"), addr)
	require.NoError(t, err)
	require.NoError(t, receiver.SetReadDeadline(time.Now().Add(time.Second)))
	buf := make([]byte, 32)
	n, _, err := receiver.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, "after setup", string(buf[:n]))
}

func TestDirectUDPSlowLookupDoesNotBlockOtherDestinations(t *testing.T) {
	conn, err := (resolvingUDPListener{}).ListenPacket(context.Background())
	require.NoError(t, err)
	defer conn.Close()
	receiver, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer receiver.Close()
	_, port, err := net.SplitHostPort(receiver.LocalAddr().String())
	require.NoError(t, err)
	addresses := make(map[string]net.Addr)
	for _, host := range []string{"cached.invalid", "slow.invalid", "new.invalid"} {
		addresses[host], err = transport.MakeNetAddr("udp", net.JoinHostPort(host, port))
		require.NoError(t, err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	var cachedLookups atomic.Int32
	c := conn.(*resolvingUDPConn)
	c.lookup = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		if host == "cached.invalid" {
			cachedLookups.Add(1)
		}
		if host == "slow.invalid" {
			close(started)
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}, nil
	}
	_, err = conn.WriteTo([]byte("prime cache"), addresses["cached.invalid"])
	require.NoError(t, err)
	slowDone := make(chan error, 1)
	go func() {
		_, err := conn.WriteTo([]byte("slow"), addresses["slow.invalid"])
		slowDone <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("slow lookup did not start")
	}
	// Both a cache hit and a new lookup must finish while the slow one is blocked.
	done := make(chan error, 2)
	for _, host := range []string{"cached.invalid", "new.invalid"} {
		go func() {
			_, err := conn.WriteTo([]byte(host), addresses[host])
			done <- err
		}()
	}
	for range 2 {
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(time.Second):
			t.Fatal("slow lookup blocked an unrelated destination")
		}
	}
	require.EqualValues(t, 1, cachedLookups.Load())
	close(release)
	select {
	case err := <-slowDone:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("released lookup did not finish")
	}
}
