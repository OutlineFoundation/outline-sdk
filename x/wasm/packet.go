// Copyright 2026 The Outline Authors. SPDX-License-Identifier: Apache-2.0
package wasm

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"golang.getoutline.org/sdk/transport"
)

type PacketListener struct {
	session *Session
	handle  uint32
	base    transport.PacketListener
	once    sync.Once
}

func (s *Session) NewPacketListener(name string, param uint32, base transport.PacketListener) (*PacketListener, error) {
	if base == nil {
		return nil, errors.New("nil base packet listener")
	}
	kind, e := s.Profile(name)
	if e != nil {
		return nil, e
	}
	if kind != 2 {
		return nil, errors.New("constructor is not a PacketListener")
	}
	h, e := s.create(name, param, "")
	if e != nil {
		return nil, e
	}
	return &PacketListener{session: s, handle: h, base: base}, nil
}
func (l *PacketListener) Close() error { l.once.Do(func() { l.session.release(l.handle) }); return nil }
func (l *PacketListener) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	setup, cancel := context.WithCancel(ctx)
	stopSetup := context.AfterFunc(l.session.ctx, cancel)
	defer cancel()
	defer stopSetup()
	ctx = setup
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	h, e := l.session.open(l.handle)
	if e != nil {
		return nil, e
	}
	base, e := l.base.ListenPacket(ctx)
	if e != nil {
		l.session.release(h)
		return nil, e
	}
	if e = ctx.Err(); e != nil {
		base.Close()
		l.session.release(h)
		return nil, e
	}
	if e = l.session.ctx.Err(); e != nil {
		base.Close()
		l.session.release(h)
		return nil, e
	}
	stop := context.AfterFunc(l.session.ctx, func() { base.Close() })
	return &packetConn{PacketConn: base, session: l.session, handle: h, stop: stop}, nil
}

type packetConn struct {
	net.PacketConn
	session  *Session
	handle   uint32
	rmu, wmu sync.Mutex
	once     sync.Once
	closed   atomic.Bool
	stop     func() bool
}

func (c *packetConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if c.closed.Load() {
		return 0, nil, net.ErrClosed
	}
	// One extra byte relative to the guest limit detects truncated oversized input.
	wire := make([]byte, BufferSize)
	n, addr, e := c.PacketConn.ReadFrom(wire)
	if e != nil {
		return 0, addr, e
	}
	if n > BufferSize-4 {
		return 0, addr, errors.New("wire datagram exceeds spike limit")
	}
	out, e := c.session.transform(c.handle, false, wire[:n])
	if e != nil {
		return 0, addr, e
	}
	return copy(p, out), addr, nil // remainder of this datagram is discarded
}
func (c *packetConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if len(p) > MaxPayload {
		return 0, errors.New("datagram exceeds spike limit")
	}
	if addr == nil {
		return 0, errors.New("nil packet destination")
	}
	out, e := c.session.transform(c.handle, true, p)
	if e != nil {
		return 0, e
	}
	n, e := c.PacketConn.WriteTo(out, addr)
	if e != nil {
		return 0, e
	}
	if n != len(out) {
		return 0, io.ErrShortWrite
	}
	return len(p), nil
}
func (c *packetConn) Close() error {
	var e error
	c.once.Do(func() { c.closed.Store(true); e = c.PacketConn.Close(); c.stop(); c.session.release(c.handle) })
	return e
}

var _ transport.PacketListener = (*PacketListener)(nil)
var _ net.PacketConn = (*packetConn)(nil)
