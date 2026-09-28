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
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// recordingConn records what was written, so a test can assert on the order and
// shape of the datagrams that reached the wire.
type recordingConn struct {
	mu       sync.Mutex
	writes   [][]byte
	addrs    []string
	writeErr error
}

func (c *recordingConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, errors.New("not implemented")
}

func (c *recordingConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	c.writes = append(c.writes, append([]byte(nil), p...))
	c.addrs = append(c.addrs, addr.String())
	return len(p), nil
}

func (*recordingConn) Close() error                     { return nil }
func (*recordingConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*recordingConn) SetDeadline(time.Time) error      { return nil }
func (*recordingConn) SetReadDeadline(time.Time) error  { return nil }
func (*recordingConn) SetWriteDeadline(time.Time) error { return nil }

func (c *recordingConn) snapshot() ([][]byte, []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes, c.addrs
}

func (c *recordingConn) setWriteErr(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeErr = err
}

// countPreludes counts datagrams carrying a reserved version, which the
// generators under test use and the traffic they precede never does.
func (c *recordingConn) countPreludes() int {
	writes, _ := c.snapshot()
	n := 0
	for _, w := range writes {
		if version, ok := longHeaderVersion(w); ok && isReservedVersion(version) {
			n++
		}
	}
	return n
}

type fixedListener struct {
	conn net.PacketConn
}

func (l *fixedListener) ListenPacket(context.Context) (net.PacketConn, error) {
	return l.conn, nil
}

// mustDefaultGenerator returns the generator NewConfig uses.
func mustDefaultGenerator(t *testing.T) Generator {
	t.Helper()
	generator, err := InvalidInitial(mustFixed(t, exampleReserved), MatchPacketLength)
	require.NoError(t, err)
	return generator
}

func newTestConn(t *testing.T, config *Config) (net.PacketConn, *recordingConn) {
	t.Helper()
	inner := &recordingConn{}
	listener, err := config.NewPacketListener(&fixedListener{conn: inner})
	require.NoError(t, err)
	conn, err := listener.ListenPacket(context.Background())
	require.NoError(t, err)
	return conn, inner
}

func udpAddr(t *testing.T, address string) net.Addr {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", address)
	require.NoError(t, err)
	return addr
}

func TestPreludePrecedesClientHello(t *testing.T) {
	repeated, err := Repeat(3, mustDefaultGenerator(t))
	require.NoError(t, err)
	conn, inner := newTestConn(t, NewConfig().WithGenerator(repeated))

	// A realistic Initial size, so the default generator's length matching is
	// exercised rather than its fallback.
	payload := clientInitial(1350)
	_, err = conn.WriteTo(payload, udpAddr(t, "192.0.2.1:443"))
	require.NoError(t, err)

	writes, addrs := inner.snapshot()
	require.Len(t, writes, 4, "expected 3 preludes followed by the payload")
	for i := range 3 {
		require.Len(t, writes[i], len(payload), "prelude %d should match the packet length", i+1)
		require.Equal(t, byte(0xc0), writes[i][0]&0xc0, "prelude %d is not long-header shaped", i+1)
		require.Equal(t, "192.0.2.1:443", addrs[i], "prelude %d destination", i+1)
	}
	// The ordering is the whole point: the prelude has to reach the wire first.
	require.Equal(t, payload, writes[3])
}

func TestPreludeSentForEveryClientHello(t *testing.T) {
	// Retransmissions, and new connections on the same socket, repeat the
	// ClientHello to the same destination. Each gets its own prelude, so a
	// connection made after a middlebox has forgotten the flow is still covered.
	conn, inner := newTestConn(t, NewConfig())
	destination := udpAddr(t, "192.0.2.1:443")

	for range 3 {
		_, err := conn.WriteTo(clientInitial(1200), destination)
		require.NoError(t, err)
	}

	writes, _ := inner.snapshot()
	require.Len(t, writes, 6, "expected a prelude before each of 3 Initials")
	require.Equal(t, 3, inner.countPreludes())
}

func TestPreludeSkipsPacketsWithoutClientHello(t *testing.T) {
	conn, inner := newTestConn(t, NewConfig())
	destination := udpAddr(t, "192.0.2.1:443")

	for _, packet := range [][]byte{
		dnsQuery(0x80ff, 0x0000), // reads as a draft Initial, but is too short to be one
		coalesce(longPacket(v1Initial, Version1, 100), longPacket(v1Handshake, Version1, 1100)), // the client's second flight
		longPacket(v1Handshake, Version1, 1200),
		append([]byte{0x40}, make([]byte, 1200)...), // short header
	} {
		_, err := conn.WriteTo(packet, destination)
		require.NoError(t, err)
	}

	writes, _ := inner.snapshot()
	require.Len(t, writes, 4, "every packet should pass through alone")
	require.Zero(t, inner.countPreludes())
}

func TestPreludeRetriedAfterWriteFailure(t *testing.T) {
	conn, inner := newTestConn(t, NewConfig())
	destination := udpAddr(t, "192.0.2.1:443")
	inner.setWriteErr(errors.New("network down"))

	_, err := conn.WriteTo(clientInitial(1200), destination)
	require.Error(t, err)

	// The client retransmits the Initial, which must get the prelude that failed.
	inner.setWriteErr(nil)
	_, err = conn.WriteTo(clientInitial(1200), destination)
	require.NoError(t, err)

	writes, _ := inner.snapshot()
	require.Len(t, writes, 2, "expected the prelude, then the payload")
	require.Equal(t, 1, inner.countPreludes())
}

func TestDecliningGeneratorSendsPacketAlone(t *testing.T) {
	declined := true
	conn, inner := newTestConn(t, NewConfig().WithGenerator(
		func(GeneratorInput) ([][]byte, error) {
			if declined {
				return nil, nil
			}
			return [][]byte{[]byte("prelude")}, nil
		}))
	destination := udpAddr(t, "192.0.2.1:443")

	_, err := conn.WriteTo(clientInitial(1200), destination)
	require.NoError(t, err)
	writes, _ := inner.snapshot()
	require.Len(t, writes, 1, "a declined prelude sends the payload alone")

	// Having declined once does not stop the generator being asked again.
	declined = false
	_, err = conn.WriteTo(clientInitial(1200), destination)
	require.NoError(t, err)
	writes, _ = inner.snapshot()
	require.Len(t, writes, 3)
	require.Equal(t, []byte("prelude"), writes[1])
}

func TestNewPacketListenerRequiresInnerListener(t *testing.T) {
	_, err := NewConfig().NewPacketListener(nil)
	require.Error(t, err)
}

func TestNewPacketListenerRequiresGenerator(t *testing.T) {
	_, err := NewConfig().WithGenerator(nil).NewPacketListener(&fixedListener{conn: &recordingConn{}})
	require.Error(t, err)
}

func TestListenersDoNotSeeLaterConfigChanges(t *testing.T) {
	config := NewConfig()
	inner := &recordingConn{}
	listener, err := config.NewPacketListener(&fixedListener{conn: inner})
	require.NoError(t, err)

	// Reconfiguring the Config must not reach a listener already created.
	repeated, err := Repeat(5, mustDefaultGenerator(t))
	require.NoError(t, err)
	config.WithGenerator(repeated)

	conn, err := listener.ListenPacket(context.Background())
	require.NoError(t, err)
	_, err = conn.WriteTo(clientInitial(1200), udpAddr(t, "192.0.2.1:443"))
	require.NoError(t, err)
	require.Equal(t, 1, inner.countPreludes())
}

func TestGeneratorReceivesDestinationAndErrorsPropagate(t *testing.T) {
	inner := &recordingConn{}
	var gotDst net.Addr
	var gotPacket []byte
	listener, err := NewConfig().
		WithGenerator(func(input GeneratorInput) ([][]byte, error) {
			gotDst = input.Destination
			gotPacket = append([]byte(nil), input.Packet...)
			return [][]byte{[]byte("custom prelude")}, nil
		}).
		NewPacketListener(&fixedListener{conn: inner})
	require.NoError(t, err)
	conn, err := listener.ListenPacket(context.Background())
	require.NoError(t, err)

	destination := udpAddr(t, "192.0.2.1:443")
	payload := clientInitial(1200)
	_, err = conn.WriteTo(payload, destination)
	require.NoError(t, err)

	require.Equal(t, destination.String(), gotDst.String(), "the generator is told where the datagram goes")
	require.Equal(t, payload, gotPacket, "the generator is given the packet it precedes")
	writes, _ := inner.snapshot()
	require.Len(t, writes, 2)
	require.Equal(t, []byte("custom prelude"), writes[0])

	// A generator that fails aborts the write rather than sending unpreluded.
	failing, err := NewConfig().
		WithGenerator(func(GeneratorInput) ([][]byte, error) { return nil, errors.New("no datagram") }).
		NewPacketListener(&fixedListener{conn: &recordingConn{}})
	require.NoError(t, err)
	conn, err = failing.ListenPacket(context.Background())
	require.NoError(t, err)
	_, err = conn.WriteTo(payload, destination)
	require.ErrorContains(t, err, "no datagram")
}

func TestConcurrentClientHellosEachGetAdjacentPrelude(t *testing.T) {
	conn, inner := newTestConn(t, NewConfig())
	destination := udpAddr(t, "192.0.2.1:443")

	const writers = 16
	var wg sync.WaitGroup
	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := conn.WriteTo(clientInitial(1200), destination)
			require.NoError(t, err)
		}()
	}
	wg.Wait()

	writes, _ := inner.snapshot()
	require.Len(t, writes, 2*writers)
	// Racing writers must not separate a prelude from the Initial it precedes.
	for i := 0; i < len(writes); i += 2 {
		version, _ := longHeaderVersion(writes[i])
		require.True(t, isReservedVersion(version), "write %d should be a prelude", i)
		version, _ = longHeaderVersion(writes[i+1])
		require.Equal(t, Version1, version, "write %d should be the Initial", i+1)
	}
}
