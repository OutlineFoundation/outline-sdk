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
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"
)

type messageWrite struct {
	packet, oob []byte
	addr        *net.UDPAddr
}
type messageConn struct {
	recordingConn
	messages   []messageWrite
	failAt     int
	shortAt    int
	failure    error
	readBuffer int
	raw        syscall.RawConn
	remote     net.Addr
}

func (c *messageConn) SyscallConn() (syscall.RawConn, error) { return c.raw, c.failure }
func (c *messageConn) SetReadBuffer(n int) error             { c.readBuffer = n; return c.failure }
func (c *messageConn) RemoteAddr() net.Addr                  { return c.remote }
func (c *messageConn) ReadMsgUDP(b, oob []byte) (int, int, int, *net.UDPAddr, error) {
	return copy(b, "wrapped read"), copy(oob, "control"), 7, &net.UDPAddr{Port: 443}, c.failure
}
func (c *messageConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (int, int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.messages = append(c.messages, messageWrite{bytes.Clone(b), bytes.Clone(oob), addr})
	if len(c.messages) == c.failAt {
		return 0, 0, c.failure
	}
	if len(c.messages) == c.shortAt {
		return len(b) - 1, 0, nil
	}
	c.writes = append(c.writes, bytes.Clone(b))
	if addr != nil {
		c.addrs = append(c.addrs, addr.String())
	} else {
		c.addrs = append(c.addrs, "connected")
	}
	return len(b), len(oob), nil
}

func wrapForTest(t *testing.T, inner net.PacketConn, generator Generator) net.PacketConn {
	t.Helper()
	listener, err := NewConfig().WithGenerator(generator).NewPacketListener(&fixedListener{conn: inner})
	require.NoError(t, err)
	conn, err := listener.ListenPacket(t.Context())
	require.NoError(t, err)
	return conn
}

func TestUDPMethodsAreConditional(t *testing.T) {
	plain := wrapForTest(t, &recordingConn{}, mustDefaultGenerator(t))
	require.NotImplements(t, (*udpPacketConn)(nil), plain)
	require.NotImplements(t, (*interface {
		WriteMsgUDP([]byte, []byte, *net.UDPAddr) (int, int, error)
	})(nil), plain)
	require.NotImplements(t, (*interface {
		SyscallConn() (syscall.RawConn, error)
	})(nil), plain)

	inner := &messageConn{}
	conn := wrapForTest(t, inner, mustDefaultGenerator(t))
	require.Implements(t, (*udpPacketConn)(nil), conn)
	require.NotImplements(t, (*writeBufferSetter)(nil), conn)
	// Embedding a native UDPConn would accidentally expose additional send paths.
	require.NotImplements(t, (*interface{ Write([]byte) (int, error) })(nil), conn)
	require.NotImplements(t, (*interface {
		WriteToUDP([]byte, *net.UDPAddr) (int, error)
	})(nil), conn)

	udp := conn.(udpPacketConn)
	inner.failure = errors.New("socket option failure")
	require.ErrorIs(t, udp.SetReadBuffer(123), inner.failure)
	require.Equal(t, 123, inner.readBuffer)
	_, err := udp.SyscallConn()
	require.ErrorIs(t, err, inner.failure)
}

type bufferMessageConn struct {
	*messageConn
	writeBuffer int
}

func (c *bufferMessageConn) SetWriteBuffer(n int) error { c.writeBuffer = n; return c.failure }

func TestUDPWriteBufferIsConditional(t *testing.T) {
	inner := &bufferMessageConn{messageConn: &messageConn{}}
	conn := wrapForTest(t, inner, mustDefaultGenerator(t))
	require.Implements(t, (*writeBufferSetter)(nil), conn)
	require.NoError(t, conn.(writeBufferSetter).SetWriteBuffer(456))
	require.Equal(t, 456, inner.writeBuffer)
}

func TestWriteMsgUDPPreludesAndCountsOnlyOriginal(t *testing.T) {
	inner := &messageConn{}
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443}
	payload := clientInitial(1350)
	conn := wrapForTest(t, inner, func(input GeneratorInput) ([][]byte, error) {
		require.Equal(t, payload, input.Packet)
		require.Equal(t, addr, input.Destination)
		return [][]byte{[]byte("first"), []byte("second")}, nil
	}).(udpPacketConn)
	n, nn, err := conn.WriteMsgUDP(payload, nil, addr)
	require.NoError(t, err)
	require.Equal(t, len(payload), n)
	require.Zero(t, nn)
	require.Len(t, inner.messages, 3)
	require.Equal(t, []byte("first"), inner.messages[0].packet)
	require.Equal(t, []byte("second"), inner.messages[1].packet)
	require.Equal(t, payload, inner.messages[2].packet)
	for _, msg := range inner.messages {
		require.Equal(t, addr, msg.addr)
	}
}

func TestWriteMsgUDPPassthroughAndDecline(t *testing.T) {
	inner := &messageConn{}
	calls := 0
	conn := wrapForTest(t, inner, func(GeneratorInput) ([][]byte, error) { calls++; return nil, nil }).(udpPacketConn)
	payload := []byte("not an Initial")
	n, _, err := conn.WriteMsgUDP(payload, nil, nil)
	require.NoError(t, err)
	require.Equal(t, len(payload), n)
	require.Zero(t, calls)
	require.Equal(t, payload, inner.messages[0].packet)
	_, _, err = conn.WriteMsgUDP(clientInitial(1200), nil, nil)
	require.NoError(t, err)
	require.Equal(t, 1, calls)
	require.Len(t, inner.messages, 2)
}

func TestWriteMsgUDPConnectedDestination(t *testing.T) {
	inner := &messageConn{remote: &net.UDPAddr{Port: 443}}
	conn := wrapForTest(t, inner, func(input GeneratorInput) ([][]byte, error) {
		require.Equal(t, inner.remote, input.Destination)
		return [][]byte{[]byte("prelude")}, nil
	}).(udpPacketConn)
	_, _, err := conn.WriteMsgUDP(clientInitial(1200), nil, nil)
	require.NoError(t, err)
	require.Len(t, inner.messages, 2)
	require.Nil(t, inner.messages[0].addr)
	require.Nil(t, inner.messages[1].addr)
}

func TestWriteMsgUDPErrorsPreventUnpreludedWrite(t *testing.T) {
	failure := errors.New("send failure")
	inner := &messageConn{}
	conn := wrapForTest(t, inner, func(GeneratorInput) ([][]byte, error) { return nil, failure }).(udpPacketConn)
	n, nn, err := conn.WriteMsgUDP(clientInitial(1200), nil, nil)
	require.ErrorIs(t, err, failure)
	require.Zero(t, n)
	require.Zero(t, nn)
	require.Empty(t, inner.messages)

	inner = &messageConn{failAt: 1, failure: failure}
	conn = wrapForTest(t, inner, mustDefaultGenerator(t)).(udpPacketConn)
	n, nn, err = conn.WriteMsgUDP(clientInitial(1200), nil, nil)
	require.ErrorIs(t, err, failure)
	require.Zero(t, n)
	require.Zero(t, nn)
	require.Len(t, inner.messages, 1)

	inner = &messageConn{shortAt: 1}
	conn = wrapForTest(t, inner, mustDefaultGenerator(t)).(udpPacketConn)
	_, _, err = conn.WriteMsgUDP(clientInitial(1200), nil, nil)
	require.ErrorIs(t, err, io.ErrShortWrite)
	require.Len(t, inner.messages, 1)

	inner = &messageConn{failAt: 2, failure: failure}
	conn = wrapForTest(t, inner, mustDefaultGenerator(t)).(udpPacketConn)
	n, nn, err = conn.WriteMsgUDP(clientInitial(1200), nil, nil)
	require.ErrorIs(t, err, failure)
	require.Zero(t, n)
	require.Zero(t, nn)
	require.Len(t, inner.messages, 2)
}

func TestConcurrentUDPWriteAPIsKeepPreludeAdjacent(t *testing.T) {
	inner := &messageConn{}
	conn := wrapForTest(t, inner, mustDefaultGenerator(t)).(udpPacketConn)
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443}
	const writers = 24
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var err error
			switch i % 3 {
			case 0:
				_, err = conn.WriteTo(clientInitial(1200), addr)
			case 1:
				_, _, err = conn.WriteMsgUDP(clientInitial(1200), nil, addr)
			case 2:
				_, err = conn.WriteTo([]byte("other"), addr)
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	writes, _ := inner.snapshot()
	require.Len(t, writes, writers/3*5)
	for i := 0; i < len(writes); i++ {
		if bytes.Equal(writes[i], []byte("other")) {
			continue
		}
		version, ok := longHeaderVersion(writes[i])
		require.True(t, ok)
		require.True(t, isReservedVersion(version))
		i++
		require.Less(t, i, len(writes))
		require.Equal(t, clientInitial(1200), writes[i])
	}
}

func TestUDPBatchFallbackPreservesWrappedReads(t *testing.T) {
	conn := wrapForTest(t, &messageConn{}, mustDefaultGenerator(t))
	reader := conn.(batchReader)
	messages := []ipv4.Message{{Buffers: [][]byte{make([]byte, 4), make([]byte, 20)}, OOB: make([]byte, 20)}, {}}
	n, err := reader.ReadBatch(messages, 0)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	require.Equal(t, "wrapped read", string(append(messages[0].Buffers[0], messages[0].Buffers[1][:8]...)))
	require.Equal(t, 12, messages[0].N)
	require.Equal(t, 7, messages[0].NN)
	require.Equal(t, 7, messages[0].Flags)
	require.Equal(t, "control", string(messages[0].OOB[:7]))
	require.Equal(t, &net.UDPAddr{Port: 443}, messages[0].Addr)
	_, err = reader.ReadBatch(messages, 1)
	require.Error(t, err)
	n, err = reader.ReadBatch(nil, 0)
	require.NoError(t, err)
	require.Zero(t, n)

	inner := &messageConn{failure: errors.New("read failed")}
	_, err = wrapForTest(t, inner, mustDefaultGenerator(t)).(batchReader).ReadBatch(messages, 0)
	require.ErrorIs(t, err, inner.failure)
}

type batchMessageConn struct {
	*messageConn
	flags int
}

func (c *batchMessageConn) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	c.flags = flags
	ms[0].N = 99
	return 1, c.failure
}

func TestUDPBatchForwardsInnerImplementation(t *testing.T) {
	inner := &batchMessageConn{messageConn: &messageConn{}}
	conn := wrapForTest(t, inner, mustDefaultGenerator(t))
	ms := make([]ipv4.Message, 1)
	n, err := conn.(batchReader).ReadBatch(ms, 42)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	require.Equal(t, 99, ms[0].N)
	require.Equal(t, 42, inner.flags)
}
