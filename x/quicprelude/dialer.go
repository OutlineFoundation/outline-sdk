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
package quicprelude

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"golang.getoutline.org/sdk/transport"
)

// NewPacketDialer returns a [transport.PacketDialer] whose connections send the
// configured prelude before every datagram that may carry a QUIC ClientHello,
// and pass everything else through unchanged.
//
// It is the counterpart of [Config.NewPacketListener] for a flow to a single
// destination. The inner dialer resolves the destination address.
func (c *Config) NewPacketDialer(inner transport.PacketDialer) (transport.PacketDialer, error) {
	if inner == nil {
		return nil, errors.New("quicprelude: inner dialer must not be nil")
	}
	if c.generator == nil {
		return nil, errors.New("quicprelude: generator must not be nil")
	}
	// Copied, so configuring the Config afterwards does not reach this dialer.
	return &packetDialer{inner: inner, generator: c.generator}, nil
}

type packetDialer struct {
	inner     transport.PacketDialer
	generator Generator
}

func (d *packetDialer) DialPacket(ctx context.Context, addr string) (net.Conn, error) {
	conn, err := d.inner.DialPacket(ctx, addr)
	if err != nil {
		return nil, err
	}
	return &preludeDialedConn{Conn: conn, generator: d.generator}, nil
}

// preludeDialedConn is [preludeConn] for a connection bound to one destination.
//
// Embedding net.Conn as an interface exposes only its methods, so a caller
// cannot reach a send method of the inner connection that skips the prelude.
type preludeDialedConn struct {
	net.Conn

	generator Generator

	// mu keeps a prelude adjacent to the packet it precedes, and means a
	// Generator is never called concurrently.
	mu sync.Mutex
}

// Write sends the prelude datagrams if p may carry a ClientHello, then writes p.
func (c *preludeDialedConn) Write(p []byte) (int, error) {
	if !mayCarryClientHello(p) {
		return c.Conn.Write(p)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	datagrams, err := c.generator(GeneratorInput{Packet: p, Destination: c.Conn.RemoteAddr()})
	if err != nil {
		return 0, fmt.Errorf("quicprelude: build prelude: %w", err)
	}
	for i, datagram := range datagrams {
		if _, err := c.Conn.Write(datagram); err != nil {
			return 0, fmt.Errorf("quicprelude: send datagram %d: %w", i+1, err)
		}
	}
	return c.Conn.Write(p)
}
