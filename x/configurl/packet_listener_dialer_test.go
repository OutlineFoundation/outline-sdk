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
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.getoutline.org/sdk/transport"
)

// relayPacketListener stands in for a relay client such as SOCKS5 or Shadowsocks:
// its connections accept a domain name destination, deliver to target, and
// report the source of replies as target's IP address.
type relayPacketListener struct {
	target net.Addr
	// sentTo receives the destination of every packet written.
	sentTo chan net.Addr
}

func (l *relayPacketListener) ListenPacket(context.Context) (net.PacketConn, error) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	return &relayPacketConn{PacketConn: conn, listener: l}, nil
}

type relayPacketConn struct {
	net.PacketConn
	listener *relayPacketListener
}

func (c *relayPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.listener.sentTo <- addr
	return c.PacketConn.WriteTo(p, c.listener.target)
}

// newEchoServer returns the address of a UDP server that echoes every datagram.
func newEchoServer(t *testing.T) net.Addr {
	t.Helper()
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { server.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := server.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = server.WriteTo(buf[:n], addr)
		}
	}()
	return server.LocalAddr()
}

// A relay resolves a domain name destination and replies from an IP address.
// The reply must still be delivered, although its source is not the name.
func TestPacketListenerDialer_DomainDestinationReceivesReply(t *testing.T) {
	listener := &relayPacketListener{target: newEchoServer(t), sentTo: make(chan net.Addr, 1)}

	conn, err := packetListenerDialer{Listener: listener}.DialPacket(context.Background(), "relay-only.invalid:443")
	require.NoError(t, err)
	defer conn.Close()
	require.Equal(t, "relay-only.invalid:443", conn.RemoteAddr().String())

	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)
	require.Equal(t, "relay-only.invalid:443", (<-listener.sentTo).String(), "the listener receives the name unresolved")

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "ping", string(buf[:n]))
}

// The stock dialer drops that reply. This documents why packetListenerDialer
// exists; when it starts failing, the stock dialer can be used again.
func TestTransportPacketListenerDialer_DomainDestinationDropsReply(t *testing.T) {
	listener := &relayPacketListener{target: newEchoServer(t), sentTo: make(chan net.Addr, 1)}

	conn, err := transport.PacketListenerDialer{Listener: listener}.DialPacket(context.Background(), "relay-only.invalid:443")
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(500*time.Millisecond)))
	_, err = conn.Read(make([]byte, 16))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
}

// An IP destination keeps the stock behavior: replies from other sources are dropped.
func TestPacketListenerDialer_IPDestinationFiltersSource(t *testing.T) {
	listener := &relayPacketListener{target: newEchoServer(t), sentTo: make(chan net.Addr, 1)}

	// The echo server is not 192.0.2.1, so its reply has the wrong source.
	conn, err := packetListenerDialer{Listener: listener}.DialPacket(context.Background(), "192.0.2.1:443")
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(500*time.Millisecond)))
	_, err = conn.Read(make([]byte, 16))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
}
