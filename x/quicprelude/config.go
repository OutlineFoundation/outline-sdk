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

package quicprelude

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"golang.getoutline.org/sdk/transport"
)

// Config describes the datagrams to send ahead of a flow's real traffic, and
// produces the listener that sends them. Create one with [NewConfig]. A zero
// Config has no generator, and [Config.NewPacketListener] rejects it.
//
// A Config may be reused to create several listeners. Each listener takes a
// copy of the settings, so configuring the Config afterwards does not affect
// listeners already created.
type Config struct {
	generator Generator
}

// NewConfig returns a Config that sends one Initial-shaped datagram, sized to
// match the packet it precedes and carrying a codepoint drawn fresh from the
// reserved range.
// It never fails; problems with the configuration surface in
// [Config.NewPacketListener].
func NewConfig() *Config {
	// The default arguments are constants known to be valid, so the error
	// cannot occur.
	generator, err := InvalidInitial(RandomReservedVersion(), MatchPacketLength)
	if err != nil {
		panic("quicprelude: default generator is invalid: " + err.Error())
	}
	return &Config{generator: generator}
}

// WithGenerator sets what the datagrams contain, replacing the default.
func (c *Config) WithGenerator(generator Generator) *Config {
	c.generator = generator
	return c
}

// NewPacketListener returns a [transport.PacketListener] whose connections send
// the configured prelude before every datagram that may carry a QUIC
// ClientHello, and pass everything else through unchanged.
//
// The prelude is written to the same connection as the traffic that follows,
// so both share a four-tuple by construction. That is the property the
// technique depends on: a middlebox keying on the flow must see them as one.
// On Linux, macOS, FreeBSD and Windows, connections that support UDP socket
// control and message I/O retain those capabilities. Both WriteTo and
// WriteMsgUDP inject preludes; UDP segmentation batches without a qualifying
// Initial pass through unchanged.
func (c *Config) NewPacketListener(inner transport.PacketListener) (transport.PacketListener, error) {
	if inner == nil {
		return nil, errors.New("quicprelude: inner listener must not be nil")
	}
	if c.generator == nil {
		return nil, errors.New("quicprelude: generator must not be nil")
	}
	// Copied, so configuring the Config afterwards does not reach this listener.
	return &packetListener{inner: inner, generator: c.generator}, nil
}

type packetListener struct {
	inner     transport.PacketListener
	generator Generator
}

func (l *packetListener) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	conn, err := l.inner.ListenPacket(ctx)
	if err != nil {
		return nil, err
	}
	return wrapPacketConn(&preludeConn{PacketConn: conn, generator: l.generator}), nil
}

// preludeConn sends the prelude before every datagram that may carry a QUIC
// ClientHello. Everything else is delegated to the embedded [net.PacketConn].
//
// It keeps no record of destinations. Deciding from the packet alone means a new
// connection on a reused socket gets a prelude like the first one did, including
// one made after a middlebox has forgotten the flow, and that traffic which is
// not QUIC never gets one. The cost is a prelude before each retransmitted or
// resent ClientHello, which is also when a lost prelude most needs replacing,
// and before some Initials that only acknowledge the server's. See
// [mayCarryClientHello] for which datagrams qualify.
//
// Only net.PacketConn is embedded: extra send methods must explicitly inject
// preludes, as preludeUDPConn.WriteMsgUDP does. Promoting an inner UDPConn's
// methods would expose writes that bypass this wrapper.
type preludeConn struct {
	net.PacketConn

	generator Generator

	// mu serializes both write APIs, including non-Initial writes, so a prelude
	// stays adjacent to its packet and the generator is never called concurrently.
	mu sync.Mutex
}

// WriteTo sends the prelude datagrams if p may carry a ClientHello, then writes
// p.
func (c *preludeConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.writePrelude(p, addr, func(datagram []byte) (int, error) {
		return c.PacketConn.WriteTo(datagram, addr)
	}); err != nil {
		return 0, err
	}
	return c.PacketConn.WriteTo(p, addr)
}

// writePrelude requires mu to be held. write must use the inner connection,
// preserving the original write's destination and any source-routing metadata.
func (c *preludeConn) writePrelude(p []byte, addr net.Addr, write func([]byte) (int, error)) error {
	if !mayCarryClientHello(p) {
		return nil
	}
	datagrams, err := c.generator(GeneratorInput{Packet: p, Destination: addr})
	if err != nil {
		return fmt.Errorf("quicprelude: build prelude: %w", err)
	}
	for i, datagram := range datagrams {
		n, err := write(datagram)
		if err == nil && n != len(datagram) {
			err = io.ErrShortWrite
		}
		if err != nil {
			return fmt.Errorf("quicprelude: send datagram %d: %w", i+1, err)
		}
	}
	return nil
}
