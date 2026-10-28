// Copyright 2026 The Outline Authors. SPDX-License-Identifier: Apache-2.0
package wasm

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.getoutline.org/sdk/transport"
)

type StreamDialer struct {
	session *Session
	handle  uint32
	base    transport.StreamDialer
	once    sync.Once
}

func (s *Session) NewStreamDialer(name string, param uint32, relay string, base transport.StreamDialer) (*StreamDialer, error) {
	if base == nil {
		return nil, errors.New("nil base stream dialer")
	}
	kind, e := s.Profile(name)
	if e != nil {
		return nil, e
	}
	if kind != 1 {
		return nil, errors.New("constructor is not a StreamDialer")
	}
	if relay != "" {
		if _, _, e = net.SplitHostPort(relay); e != nil {
			return nil, e
		}
	}
	h, e := s.create(name, param, relay)
	if e != nil {
		return nil, e
	}
	return &StreamDialer{session: s, handle: h, base: base}, nil
}

// Close releases the factory; existing children have their own copied state.
func (d *StreamDialer) Close() error { d.once.Do(func() { d.session.release(d.handle) }); return nil }
func (d *StreamDialer) DialStream(ctx context.Context, addr string) (transport.StreamConn, error) {
	setup, cancel := context.WithCancel(ctx)
	stopSetup := context.AfterFunc(d.session.ctx, cancel)
	defer cancel()
	defer stopSetup()
	ctx = setup
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	h, e := d.session.open(d.handle)
	if e != nil {
		return nil, e
	}
	success := false
	defer func() {
		if !success {
			d.session.release(h)
		}
	}()
	_, target, e := d.session.bufferCall("dial_target", h, []byte(addr))
	if e != nil {
		return nil, e
	}
	if _, _, e = net.SplitHostPort(string(target)); e != nil {
		return nil, e
	}
	// No session lock is held when a base might call back into this session.
	base, e := d.base.DialStream(ctx, string(target))
	if e != nil {
		return nil, e
	}
	defer func() {
		if !success {
			base.Close()
		}
	}()
	stopped := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { base.Close(); close(stopped) })
	defer func() {
		if stop != nil && !stop() {
			<-stopped
		}
	}()
	if deadline, ok := ctx.Deadline(); ok {
		if e = base.SetDeadline(deadline); e != nil {
			return nil, e
		}
	}
	stopSession := context.AfterFunc(d.session.ctx, func() { base.Close() })
	defer func() {
		if !success {
			stopSession()
		}
	}()
	var input []byte
	ready := false
	for i := 0; i < 16; i++ {
		var action uint32
		var output []byte
		action, output, e = d.session.bufferCall("handshake", h, input)
		if e != nil {
			return nil, e
		}
		input = nil
		switch action >> 16 {
		case 0:
			if action != 0 {
				return nil, errors.New("invalid ready action")
			}
			ready = true
		case 1:
			e = writeAll(base, output)
		case 2:
			if len(output) == 0 {
				return nil, errors.New("empty handshake read")
			}
			input = make([]byte, len(output))
			_, e = io.ReadFull(base, input)
		default:
			return nil, errors.New("invalid handshake action")
		}
		if e != nil {
			return nil, e
		}
		if ready {
			break
		}
	}
	if !ready {
		return nil, errors.New("handshake action budget exhausted")
	}
	if !stop() {
		<-stopped
		stop = nil
		return nil, ctx.Err()
	}
	stop = nil
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	if e = d.session.ctx.Err(); e != nil {
		return nil, e
	}
	if e = base.SetDeadline(time.Time{}); e != nil {
		return nil, e
	}
	success = true
	return &streamConn{StreamConn: base, session: d.session, handle: h, stop: stopSession}, nil
}
func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, e := w.Write(p)
		if e != nil {
			return e
		}
		if n <= 0 || n > len(p) {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

type streamConn struct {
	transport.StreamConn
	session  *Session
	handle   uint32
	rmu, wmu sync.Mutex
	once     sync.Once
	closed   atomic.Bool
	stop     func() bool
}

func (c *streamConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if len(p) == 0 {
		return 0, nil
	}
	if len(p) > MaxPayload {
		p = p[:MaxPayload]
	}
	n, e := c.StreamConn.Read(p)
	if n == 0 {
		return n, e
	}
	out, err := c.session.transform(c.handle, false, p[:n])
	if err != nil {
		c.Close()
		return 0, err
	}
	if len(out) != n {
		c.Close()
		return 0, errors.New("spike stream transform must preserve length")
	}
	copy(p, out)
	return n, e
}
func (c *streamConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	total := 0
	for len(p) > 0 {
		size := len(p)
		if size > MaxPayload {
			size = MaxPayload
		}
		size, e := c.session.limit(c.handle, size)
		if e != nil {
			return total, e
		}
		out, e := c.session.transform(c.handle, true, p[:size])
		if e != nil {
			return total, e
		}
		if len(out) != size {
			return total, errors.New("spike stream transform must preserve length")
		}
		n, e := c.StreamConn.Write(out)
		if n < 0 || n > size {
			c.Close()
			return total, errors.New("invalid base write count")
		}
		total += n
		if e != nil {
			return total, e
		}
		if n != size {
			return total, io.ErrShortWrite
		}
		p = p[size:]
	}
	return total, nil
}
func (c *streamConn) Close() error {
	var e error
	c.once.Do(func() { c.closed.Store(true); e = c.StreamConn.Close(); c.stop(); c.session.release(c.handle) })
	return e
}

var _ transport.StreamDialer = (*StreamDialer)(nil)
var _ transport.StreamConn = (*streamConn)(nil)
