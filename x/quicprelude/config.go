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
	return &preludeConn{PacketConn: conn, generator: l.generator}, nil
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
// Embedding net.PacketConn as an interface deliberately exposes only its
// methods, even when the inner connection is a *net.UDPConn. QUIC-Go v0.48.1
// probes for SyscallConn, SetReadBuffer, ReadMsgUDP and WriteMsgUDP to select
// its optimized UDP path on supported platforms. Without that interface it
// sends through WriteTo, which is where this wrapper injects the prelude.
// Forwarding WriteMsgUDP unchanged would bypass injection: the QUIC handshake
// could still succeed while the prelude is silently omitted. Any additional
// send method must inject the prelude before forwarding the original packet.
//
// This implementation gives up UDP segmentation offload, ECN and QUIC-Go's
// socket-buffer tuning and DF setup for path MTU discovery where supported.
// Those optimizations can be restored by conditionally exposing the inner
// connection's capabilities and intercepting the optimized send path as well.
type preludeConn struct {
	net.PacketConn

	generator Generator

	// mu keeps a prelude adjacent to the packet it precedes when several
	// goroutines write ClientHellos at once, and means a Generator is never called
	// concurrently.
	mu sync.Mutex
}

// WriteTo sends the prelude datagrams if p may carry a ClientHello, then writes
// p.
func (c *preludeConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if !mayCarryClientHello(p) {
		return c.PacketConn.WriteTo(p, addr)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	datagrams, err := c.generator(GeneratorInput{Packet: p, Destination: addr})
	if err != nil {
		return 0, fmt.Errorf("quicprelude: build prelude: %w", err)
	}
	for i, datagram := range datagrams {
		if _, err := c.PacketConn.WriteTo(datagram, addr); err != nil {
			return 0, fmt.Errorf("quicprelude: send datagram %d: %w", i+1, err)
		}
	}
	return c.PacketConn.WriteTo(p, addr)
}
