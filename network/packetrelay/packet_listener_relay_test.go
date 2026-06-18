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

package packetrelay

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewPacketRelayFromPacketListener(t *testing.T) {
	conn := &fakePacketConn{}
	pl := &fakePacketListener{conn: conn}

	relay, err := NewPacketRelayFromPacketListener(pl, 30*time.Second)
	require.NoError(t, err)
	require.NotNil(t, relay)

	_, _, err = relay.NewAssociation()
	require.NoError(t, err)
	require.Len(t, conn.deadlines, 1)
	requireDeadlineNear(t, conn.deadlines[0], 30*time.Second)
}

func TestNewPacketRelayFromPacketListenerRejectsInvalidTimeout(t *testing.T) {
	pl := &fakePacketListener{conn: &fakePacketConn{}}

	relay, err := NewPacketRelayFromPacketListener(pl, 0)
	require.Error(t, err)
	require.Nil(t, relay)

	relay, err = NewPacketRelayFromPacketListener(pl, -1*time.Second)
	require.Error(t, err)
	require.Nil(t, relay)
}

func TestPacketListenerRelaySetWriteIdleTimeout(t *testing.T) {
	conn := &fakePacketConn{}
	pl := &fakePacketListener{conn: conn}
	timeout := 5 * time.Minute

	relay, err := NewPacketRelayFromPacketListener(pl, 30*time.Second)
	require.NoError(t, err)
	require.NoError(t, relay.SetWriteIdleTimeout(timeout))

	sender, _, err := relay.NewAssociation()
	require.NoError(t, err)
	require.Len(t, conn.deadlines, 1)
	requireDeadlineNear(t, conn.deadlines[0], timeout)

	err = sender.SendPacket([]byte("hello"), netip.MustParseAddrPort("1.2.3.4:53"))
	require.NoError(t, err)
	require.Len(t, conn.deadlines, 2)
	requireDeadlineNear(t, conn.deadlines[1], timeout)
	require.Len(t, conn.writes, 1)
}

func TestPacketListenerRelaySetWriteIdleTimeoutRejectsInvalidTimeout(t *testing.T) {
	conn := &fakePacketConn{}
	pl := &fakePacketListener{conn: conn}

	relay, err := NewPacketRelayFromPacketListener(pl, 30*time.Second)
	require.NoError(t, err)
	require.Error(t, relay.SetWriteIdleTimeout(0))
}

func TestPacketListenerRelayReceiveTimeoutClosesAssociation(t *testing.T) {
	conn := &fakePacketConn{readErr: timeoutErr{}}
	pl := &fakePacketListener{conn: conn}

	relay, err := NewPacketRelayFromPacketListener(pl, 30*time.Second)
	require.NoError(t, err)
	_, receiver, err := relay.NewAssociation()
	require.NoError(t, err)

	err = receiver.ReceivePackets(&mockPacketHandler{})
	require.ErrorAs(t, err, &timeoutErr{})
	require.True(t, conn.isClosed())
}

func requireDeadlineNear(t *testing.T, deadline time.Time, timeout time.Duration) {
	t.Helper()
	require.WithinDuration(t, time.Now().Add(timeout), deadline, time.Second)
}

type fakePacketListener struct {
	conn *fakePacketConn
}

func (l *fakePacketListener) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	return l.conn, nil
}

type packetWrite struct {
	payload []byte
	addr    net.Addr
}

type fakePacketConn struct {
	mu        sync.Mutex
	deadlines []time.Time
	writes    []packetWrite
	readErr   error
	closed    bool
}

func (c *fakePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c.readErr != nil {
		return 0, nil, c.readErr
	}
	return 0, nil, net.ErrClosed
}

func (c *fakePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	payload := make([]byte, len(p))
	copy(payload, p)
	c.writes = append(c.writes, packetWrite{payload: payload, addr: addr})
	return len(p), nil
}

func (c *fakePacketConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *fakePacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

func (c *fakePacketConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadlines = append(c.deadlines, t)
	return nil
}

func (c *fakePacketConn) SetReadDeadline(t time.Time) error {
	return c.SetDeadline(t)
}

func (c *fakePacketConn) SetWriteDeadline(t time.Time) error {
	return c.SetDeadline(t)
}

func (c *fakePacketConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

type timeoutErr struct{}

func (timeoutErr) Error() string {
	return "timeout"
}

func (timeoutErr) Timeout() bool {
	return true
}

func (timeoutErr) Temporary() bool {
	return true
}
