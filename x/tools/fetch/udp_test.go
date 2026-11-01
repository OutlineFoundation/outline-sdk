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

package main

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
	"golang.getoutline.org/sdk/x/quicprelude"
)

// Concurrent writes to one hostname must use one DNS answer and reach the same
// receiver. Returning IPv6 first also checks that the adapter prefers IPv4 when
// available. A final write to an IP address must bypass DNS entirely.
func TestDirectUDPResolvesAndPinsHostname(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	receiver, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer receiver.Close()
	conn, err := (resolvingUDPListener{}).ListenPacket(ctx)
	require.NoError(t, err)
	defer conn.Close()
	// Exposing QUIC-Go's optimized interface would bypass WriteTo and panic on
	// a domain address, even if the direct WriteTo calls below succeeded.
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

// Closing a packet connection must unblock a WriteTo that is waiting for DNS.
// The injected lookup waits only for cancellation, avoiding a real DNS timeout.
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
	go func() {
		_, err := conn.WriteTo([]byte("hello"), addr)
		done <- err
	}()
	// Wait until WriteTo is inside the lookup before closing the connection.
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

// Resolver errors and empty answers must reach the caller without being cached.
// Retry the same destination after each failure, then let its lookup succeed.
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

// ListenPacket's context controls setup, not the lifetime of the connection.
// Cancel it before the first write and verify DNS still runs without inheriting
// its cancellation or deadline, and the datagram reaches the receiver.
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

// A blocked lookup must not hold a connection-wide lock. While one destination's
// lookup is paused, writes to both an already cached name and a new name must
// finish. The cached name must not be looked up again.
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
	// Keep slow.invalid blocked until both unrelated writes have completed.
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

// Adapt a test callback so quicprelude can wrap our connection with injected DNS.
type packetListenerFunc func(context.Context) (net.PacketConn, error)

func (f packetListenerFunc) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	return f(ctx)
}

// A quicprelude wrapper hides the concrete UDP connection from the caller.
// Resolving at the base listener must still deliver its prelude and the original
// Initial to the same destination, in order, with one DNS lookup and one source
// address. This covers the case missed when only bare UDPConns were resolved.
func TestQUICPreludeResolvesHostnameAtBaseListener(t *testing.T) {
	receiver, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer receiver.Close()
	base, err := (resolvingUDPListener{}).ListenPacket(context.Background())
	require.NoError(t, err)
	defer base.Close()
	var lookups atomic.Int32
	base.(*resolvingUDPConn).lookup = func(context.Context, string) ([]net.IPAddr, error) {
		lookups.Add(1)
		return []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}, nil
	}
	_, port, err := net.SplitHostPort(receiver.LocalAddr().String())
	require.NoError(t, err)
	addr, err := transport.MakeNetAddr("udp", net.JoinHostPort("prelude.invalid", port))
	require.NoError(t, err)
	// Use a recognizable prelude so we can distinguish it from the QUIC packet.
	listener, err := quicprelude.NewConfig().WithGenerator(func(quicprelude.GeneratorInput) ([][]byte, error) {
		return [][]byte{[]byte("prelude")}, nil
	}).NewPacketListener(packetListenerFunc(func(context.Context) (net.PacketConn, error) { return base, nil }))
	require.NoError(t, err)
	conn, err := listener.ListenPacket(context.Background())
	require.NoError(t, err)
	defer conn.Close()
	// Only the Initial header is needed to trigger the prelude; its deliberately
	// invalid encrypted payload is fine because the receiver is a raw UDP socket.
	version, err := quicprelude.FixedVersion(quicprelude.Version2)
	require.NoError(t, err)
	initial, err := quicprelude.InvalidInitial(version, quicprelude.DefaultLength)
	require.NoError(t, err)
	packets, err := initial(quicprelude.GeneratorInput{Destination: addr})
	require.NoError(t, err)
	n, err := conn.WriteTo(packets[0], addr)
	require.NoError(t, err)
	require.Equal(t, len(packets[0]), n)
	require.EqualValues(t, 1, lookups.Load(), "the prelude and Initial must share one answer")
	// Read both datagrams and compare their source IP and port to check the flow.
	require.NoError(t, receiver.SetReadDeadline(time.Now().Add(time.Second)))
	var source string
	for _, want := range [][]byte{[]byte("prelude"), packets[0]} {
		buf := make([]byte, 2048)
		n, from, err := receiver.ReadFrom(buf)
		require.NoError(t, err)
		require.Equal(t, want, buf[:n])
		if source != "" {
			require.Equal(t, source, from.String())
		}
		source = from.String()
	}
}
