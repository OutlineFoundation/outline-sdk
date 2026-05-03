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
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTimeoutPacketRelay_Timeout(t *testing.T) {
	mock := &mockPacketRelay{
		closeSig: make(chan struct{}),
	}
	timeoutRelay, err := NewTimeoutPacketRelay(mock, 50*time.Millisecond)
	require.NoError(t, err)

	sender, receiver, err := timeoutRelay.NewAssociation()
	require.NoError(t, err)
	require.NotNil(t, sender)
	require.NotNil(t, receiver)

	// Start receiver loop
	handler := &mockPacketHandler{}
	go func() {
		_ = receiver.ReceivePackets(handler)
	}()

	// Wait for timeout
	time.Sleep(100 * time.Millisecond)

	// Sender should be closed
	err = sender.SendPacket([]byte("hello"), netip.MustParseAddrPort("1.2.3.4:53"))
	require.ErrorIs(t, err, ErrClosed)

	// Mock should have been closed
	require.True(t, mock.isClosed())
}

func TestTimeoutPacketRelay_ResetOnSend(t *testing.T) {
	mock := &mockPacketRelay{
		closeSig: make(chan struct{}),
	}
	timeoutRelay, err := NewTimeoutPacketRelay(mock, 100*time.Millisecond)
	require.NoError(t, err)

	sender, receiver, err := timeoutRelay.NewAssociation()
	require.NoError(t, err)

	go func() {
		_ = receiver.ReceivePackets(&mockPacketHandler{})
	}()

	// Send packets every 50ms (less than 100ms timeout)
	for i := 0; i < 3; i++ {
		time.Sleep(50 * time.Millisecond)
		err = sender.SendPacket([]byte("hello"), netip.MustParseAddrPort("1.2.3.4:53"))
		require.NoError(t, err)
	}

	// Now stop sending and wait for timeout
	time.Sleep(150 * time.Millisecond)

	err = sender.SendPacket([]byte("hello"), netip.MustParseAddrPort("1.2.3.4:53"))
	require.ErrorIs(t, err, ErrClosed)
}

func TestTimeoutPacketRelay_NoResetOnReceive(t *testing.T) {
	mock := &mockPacketRelay{
		closeSig:    make(chan struct{}),
		handlerChan: make(chan PacketHandler, 1),
	}
	timeoutRelay, err := NewTimeoutPacketRelay(mock, 100*time.Millisecond)
	require.NoError(t, err)

	sender, receiver, err := timeoutRelay.NewAssociation()
	require.NoError(t, err)

	go func() {
		_ = receiver.ReceivePackets(&mockPacketHandler{})
	}()

	// Wait for the mock receiver to start and capture the handler
	handler := <-mock.handlerChan

	// Simulate receiving packets every 40ms (total time 120ms > 100ms timeout)
	for i := 0; i < 3; i++ {
		time.Sleep(40 * time.Millisecond)
		err = handler.HandlePacket([]byte("reply"), netip.MustParseAddrPort("1.2.3.4:53"))
		require.NoError(t, err)
	}

	// The timeout (100ms) should have fired by now, even though we were receiving packets.
	err = sender.SendPacket([]byte("hello"), netip.MustParseAddrPort("1.2.3.4:53"))
	require.ErrorIs(t, err, ErrClosed)
}

// Mock implementations

type mockPacketRelay struct {
	mu          sync.Mutex
	closed      bool
	closeSig    chan struct{}
	handlerChan chan PacketHandler
}

func (m *mockPacketRelay) NewAssociation() (PacketSender, PacketReceiver, error) {
	return &mockPacketSender{relay: m}, &mockPacketReceiver{relay: m}, nil
}

func (m *mockPacketRelay) isClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

func (m *mockPacketRelay) setClosed() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed {
		m.closed = true
		close(m.closeSig)
	}
}

type mockPacketSender struct {
	relay *mockPacketRelay
}

func (s *mockPacketSender) SendPacket(p []byte, dest netip.AddrPort) error {
	if s.relay.isClosed() {
		return ErrClosed
	}
	return nil
}

func (s *mockPacketSender) Close() error {
	s.relay.setClosed()
	return nil
}

type mockPacketReceiver struct {
	relay *mockPacketRelay
}

func (r *mockPacketReceiver) ReceivePackets(handler PacketHandler) error {
	if r.relay.handlerChan != nil {
		r.relay.handlerChan <- handler
	}
	<-r.relay.closeSig
	return nil
}

type mockPacketHandler struct{}

func (h *mockPacketHandler) HandlePacket(p []byte, src netip.AddrPort) error {
	return nil
}
