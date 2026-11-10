// Copyright 2026 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package configurl

import (
	"context"
	"fmt"
	"net"

	"golang.getoutline.org/sdk/transport"
)

// packetListenerDialer is a [transport.PacketDialer] that sends through a new
// connection from a [transport.PacketListener] on every dial.
//
// It differs from [transport.PacketListenerDialer] for a domain name
// destination. That dialer keeps only replies whose source equals the
// destination, but a relay resolves the name and reports the source as an IP
// address, so no reply ever matches. Here such a connection accepts every
// reply: it was created for this one destination, and the listener gives no
// way to learn which address the relay resolved the name to.
//
// TODO: Remove once transport.PacketListenerDialer handles domain names.
type packetListenerDialer struct {
	Listener transport.PacketListener
}

var _ transport.PacketDialer = packetListenerDialer{}

func (d packetListenerDialer) DialPacket(ctx context.Context, address string) (net.Conn, error) {
	remoteAddr, err := transport.MakeNetAddr("udp", address)
	if err != nil {
		return nil, err
	}
	if _, isIP := remoteAddr.(*net.UDPAddr); isIP {
		return transport.PacketListenerDialer{Listener: d.Listener}.DialPacket(ctx, address)
	}
	packetConn, err := d.Listener.ListenPacket(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not create PacketConn: %w", err)
	}
	return &domainBoundPacketConn{PacketConn: packetConn, remoteAddr: remoteAddr}, nil
}

type domainBoundPacketConn struct {
	net.PacketConn
	remoteAddr net.Addr
}

var _ net.Conn = (*domainBoundPacketConn)(nil)

func (c *domainBoundPacketConn) Read(packet []byte) (int, error) {
	n, _, err := c.PacketConn.ReadFrom(packet)
	return n, err
}

func (c *domainBoundPacketConn) Write(packet []byte) (int, error) {
	return c.PacketConn.WriteTo(packet, c.remoteAddr)
}

func (c *domainBoundPacketConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}
