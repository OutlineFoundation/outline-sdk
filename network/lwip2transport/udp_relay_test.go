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

package lwip2transport

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"

	"golang.getoutline.org/sdk/network/packetrelay"
	"github.com/stretchr/testify/require"
)

// Make sure calling Close on a session unblocks and deletes the sender mapping concurrently.
func TestUDPRelayCloseNoDeadlock(t *testing.T) {
	mockRelay := &noopSingleSessionPacketRelay{
		closeSig: make(chan struct{}),
	}
	h := newUDPRelayHandler(mockRelay)

	localAddr := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:60127"))
	destAddr := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("1.2.3.4:4321"))
	err := h.ReceiveTo(&noopLwIPUDPConn{localAddr}, []byte{}, destAddr)
	require.NoError(t, err)

	// Ensure the session was registered
	h.mu.Lock()
	require.Len(t, h.senders, 1)
	h.mu.Unlock()

	// Trigger concurrent closing on the relay/sender path
	const ConcurrentCloseCount = 50
	errChan := make(chan error, ConcurrentCloseCount)
	for i := 0; i < ConcurrentCloseCount; i++ {
		go func() {
			errChan <- h.closeSession(&noopLwIPUDPConn{localAddr})
		}()
	}

	nNilErr := 0
	for i := 0; i < ConcurrentCloseCount; i++ {
		if e := <-errChan; e == nil {
			nNilErr++
		}
	}
	
	// At least one closeSession must succeed cleanly, and the map must be empty
	require.GreaterOrEqual(t, nNilErr, 1)
	h.mu.Lock()
	require.Len(t, h.senders, 0)
	h.mu.Unlock()
}

func TestUDPRelayReceiveToNoDeadlockWhenError(t *testing.T) {
	h := newUDPRelayHandler(errPacketRelay{})
	localAddr := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:60127"))
	destAddr := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("1.2.3.4:4321"))
	err := h.ReceiveTo(&noopLwIPUDPConn{localAddr}, []byte{}, destAddr)
	require.ErrorIs(t, err, errNewAssociation)
}

/********** Test Utilities **********/

type noopSingleSessionPacketRelay struct {
	mu       sync.Mutex
	closeSig chan struct{}
	sender   *mockRelaySender
}

func (r *noopSingleSessionPacketRelay) NewAssociation() (packetrelay.PacketSender, packetrelay.PacketReceiver, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sender != nil {
		return nil, nil, errors.New("only supports a single session")
	}
	r.sender = &mockRelaySender{relay: r}
	return r.sender, &mockRelayReceiver{relay: r}, nil
}

type mockRelaySender struct {
	relay *noopSingleSessionPacketRelay
}

func (s *mockRelaySender) SendPacket([]byte, netip.AddrPort) error { return nil }
func (s *mockRelaySender) Close() error {
	s.relay.mu.Lock()
	defer s.relay.mu.Unlock()
	select {
	case <-s.relay.closeSig:
		return packetrelay.ErrClosed
	default:
		close(s.relay.closeSig)
		return nil
	}
}

type mockRelayReceiver struct {
	relay *noopSingleSessionPacketRelay
}

func (r *mockRelayReceiver) ReceivePackets(packetrelay.PacketHandler) error {
	<-r.relay.closeSig
	return nil
}

type errPacketRelay struct{}

var errNewAssociation = errors.New("error in NewAssociation")

func (errPacketRelay) NewAssociation() (packetrelay.PacketSender, packetrelay.PacketReceiver, error) {
	return nil, nil, errNewAssociation
}
