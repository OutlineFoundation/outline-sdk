//go:build darwin || linux || freebsd || windows

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
	"fmt"
	"io"
	"net"
	"syscall"

	"golang.org/x/net/ipv4"
)

// udpPacketConn matches the capability interface used by QUIC-Go. Keep it
// local so this package does not depend on a particular QUIC implementation.
type udpPacketConn interface {
	net.PacketConn
	SyscallConn() (syscall.RawConn, error)
	SetReadBuffer(int) error
	ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error)
	WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error)
}

type batchReader interface {
	ReadBatch([]ipv4.Message, int) (int, error)
}

type writeBufferSetter interface {
	SetWriteBuffer(int) error
}

func wrapPacketConn(base *preludeConn) net.PacketConn {
	inner, ok := base.PacketConn.(udpPacketConn)
	if !ok {
		return base
	}
	c := &preludeUDPConn{preludeConn: base, inner: inner}
	if batch, ok := inner.(batchReader); ok {
		c.batch = batch
	} else if udp, ok := inner.(*net.UDPConn); ok {
		// A native socket has no receive wrapper to bypass. Keep batched reads.
		c.batch = ipv4.NewPacketConn(udp)
	}
	if setter, ok := inner.(writeBufferSetter); ok {
		return &preludeUDPWriteBufferConn{preludeUDPConn: c, setter: setter}
	}
	return c
}

// preludeUDPConn explicitly forwards capabilities and intercepts message
// writes. Do not embed the inner connection: that could promote other write
// methods. SyscallConn exposes the descriptor for socket options and native
// receive batching; callers that write directly to it bypass preludes.
type preludeUDPConn struct {
	*preludeConn
	inner udpPacketConn
	batch batchReader
}

func (c *preludeUDPConn) SyscallConn() (syscall.RawConn, error) { return c.inner.SyscallConn() }
func (c *preludeUDPConn) SetReadBuffer(n int) error             { return c.inner.SetReadBuffer(n) }
func (c *preludeUDPConn) ReadMsgUDP(b, oob []byte) (int, int, int, *net.UDPAddr, error) {
	return c.inner.ReadMsgUDP(b, oob)
}

type preludeUDPWriteBufferConn struct {
	*preludeUDPConn
	setter writeBufferSetter
}

func (c *preludeUDPWriteBufferConn) SetWriteBuffer(n int) error { return c.setter.SetWriteBuffer(n) }

// ReadBatch preserves an inner batch implementation, or adapts ReadMsgUDP
// for custom wrappers. Without this method QUIC-Go would read the descriptor
// directly, bypassing any receive processing performed by the inner wrapper.
func (c *preludeUDPConn) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	if c.batch != nil {
		return c.batch.ReadBatch(ms, flags)
	}
	if flags != 0 {
		return 0, fmt.Errorf("quicprelude: ReadMsgUDP cannot implement ReadBatch flags %d", flags)
	}
	if len(ms) == 0 {
		return 0, nil
	}
	m := &ms[0]
	var b []byte
	if len(m.Buffers) == 1 {
		b = m.Buffers[0]
	} else {
		size := 0
		for _, buf := range m.Buffers {
			size += len(buf)
		}
		b = make([]byte, size)
	}
	n, nn, msgFlags, addr, err := c.inner.ReadMsgUDP(b, m.OOB)
	m.N, m.NN, m.Flags, m.Addr = n, nn, msgFlags, addr
	if len(m.Buffers) != 1 {
		rest := b[:min(n, len(b))]
		for _, buf := range m.Buffers {
			rest = rest[copy(buf, rest):]
		}
	}
	if err != nil {
		return 0, err
	}
	return 1, nil
}

func (c *preludeUDPConn) WriteMsgUDP(p, oob []byte, addr *net.UDPAddr) (int, int, error) {
	segmentation, err := parseUDPSegmentation(oob)
	if err != nil {
		return 0, 0, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// An ordinary GSO batch stays a single send. Classify individual datagrams,
	// not the concatenated buffer: a later segment may carry an Initial.
	split := false
	if segmentation.size > 0 && len(p) > segmentation.size {
		for rest := p; len(rest) > 0; {
			size := min(segmentation.size, len(rest))
			if mayCarryClientHello(rest[:size]) {
				split = true
				break
			}
			rest = rest[size:]
		}
		if !split {
			return c.inner.WriteMsgUDP(p, oob, addr)
		}
	}

	if !split && !mayCarryClientHello(p) {
		return c.inner.WriteMsgUDP(p, oob, addr)
	}
	// Strip metadata only when injecting, keeping the usual GSO path free of
	// control-buffer allocations.
	singleOOB := segmentation.singlePacketOOB(oob)

	var destination net.Addr
	if addr != nil {
		destination = addr
	} else if connected, ok := c.inner.(interface{ RemoteAddr() net.Addr }); ok {
		destination = connected.RemoteAddr()
	}
	writePrelude := func(packet []byte) error {
		return c.writePrelude(packet, destination, func(datagram []byte) (int, error) {
			n, _, err := c.inner.WriteMsgUDP(datagram, singleOOB, addr)
			return n, err
		})
	}
	if !split {
		if err := writePrelude(p); err != nil {
			return 0, 0, err
		}
		return c.inner.WriteMsgUDP(p, oob, addr)
	}

	// Only batches needing preludes are expanded. Removing UDP_SEGMENT keeps
	// custom-sized preludes intact and preserves each original datagram boundary.
	// n counts only original payload; oobn reports the caller's control data once
	// an original datagram has been accepted, rather than counting injected I/O.
	written, oobn := 0, 0
	for rest := p; len(rest) > 0; {
		size := min(segmentation.size, len(rest))
		if err := writePrelude(rest[:size]); err != nil {
			return written, oobn, err
		}
		n, _, err := c.inner.WriteMsgUDP(rest[:size], singleOOB, addr)
		written += n
		if err == nil && n != size {
			err = io.ErrShortWrite
		}
		if err != nil {
			return written, oobn, err
		}
		oobn = len(oob)
		rest = rest[size:]
	}
	return written, oobn, nil
}

// udpSegmentation records the boundaries of a per-message UDP_SEGMENT option.
// Keeping offsets lets passthrough writes retain their original buffer.
type udpSegmentation struct {
	size       int
	start, end int
}

func (s udpSegmentation) singlePacketOOB(oob []byte) []byte {
	if s.start == s.end {
		return oob
	}
	result := make([]byte, 0, len(oob)-(s.end-s.start))
	result = append(result, oob[:s.start]...)
	return append(result, oob[s.end:]...)
}
