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
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLazyPacketRelay_Deferred(t *testing.T) {
	mock := &mockSessionCountRelay{
		closeSig: make(chan struct{}),
	}
	lazy := NewLazyPacketRelay(mock)

	sender, receiver, err := lazy.NewAssociation()
	require.NoError(t, err)
	require.NotNil(t, sender)
	require.NotNil(t, receiver)

	// Association should NOT have been established on the mock yet
	require.Equal(t, 0, mock.Count())

	// First send triggers it
	err = sender.SendPacket([]byte("hello"), netip.MustParseAddrPort("1.2.3.4:53"))
	require.NoError(t, err)
	require.Equal(t, 1, mock.Count())
}

func TestLazyPacketRelay_DeferredReceive(t *testing.T) {
	mock := &mockSessionCountRelay{
		closeSig: make(chan struct{}),
	}
	lazy := NewLazyPacketRelay(mock)

	_, receiver, err := lazy.NewAssociation()
	require.NoError(t, err)

	// ReceivePackets blocks and triggers it
	handler := &mockPacketHandler{}
	errChan := make(chan error, 1)
	go func() {
		errChan <- receiver.ReceivePackets(handler)
	}()

	// Give scheduling latency a moment
	time.Sleep(30 * time.Millisecond)
	require.Equal(t, 1, mock.Count())
}

func TestLazyPacketRelay_CloseUnblock(t *testing.T) {
	mock := &mockSessionCountRelay{
		closeSig: make(chan struct{}),
	}
	lazy := NewLazyPacketRelay(mock)

	sender, receiver, err := lazy.NewAssociation()
	require.NoError(t, err)

	errChan := make(chan error, 1)
	go func() {
		errChan <- receiver.ReceivePackets(&mockPacketHandler{})
	}()

	// Wait for condition and then close without sending
	time.Sleep(30 * time.Millisecond)
	require.NoError(t, sender.Close())

	// ReceivePackets must cleanly unblock and exit with nil or ErrClosed
	select {
	case err := <-errChan:
		require.True(t, err == nil || errors.Is(err, ErrClosed), "expected error to be nil or ErrClosed, got: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for ReceivePackets to unblock on close")
	}
}

type mockSessionCountRelay struct {
	cnt      atomic.Int32
	closeSig chan struct{}
}

func (m *mockSessionCountRelay) NewAssociation() (PacketSender, PacketReceiver, error) {
	m.cnt.Add(1)
	
	mockRelay := &mockPacketRelay{
		closeSig: m.closeSig,
	}
	return &mockPacketSender{relay: mockRelay}, &mockPacketReceiver{relay: mockRelay}, nil
}

func (m *mockSessionCountRelay) Count() int {
	return int(m.cnt.Load())
}
