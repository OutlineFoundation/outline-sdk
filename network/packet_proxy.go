// Copyright 2023 The Outline Authors
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

package network

import (
	"errors"
	"net"
	"net/netip"

	"golang.getoutline.org/sdk/network/packetrelay"
)

// PacketProxy handles UDP traffic from the upstream network stack. The upstream network stack uses the NewSession
// function to create a new UDP session that can send or receive UDP packets from PacketProxy.
//
// Deprecated: Use [PacketRelay] instead.
//
// Multiple goroutines can simultaneously invoke methods on a PacketProxy.
type PacketProxy interface {
	// NewSession function tells the PacketProxy that a new UDP socket session has been started.
	// The PacketProxy then creates a PacketRequestSender object to handle requests from this session,
	// and it also uses the PacketResponseReceiver to send responses back to the upstream network stack.
	NewSession(PacketResponseReceiver) (PacketRequestSender, error)
}

// PacketRequestSender sends UDP request packets to the [PacketProxy].
//
// Deprecated: Use [PacketSender] instead.
type PacketRequestSender interface {
	// WriteTo sends a UDP request packet to the PacketProxy. The packet is destined for the remote server
	// identified by `destination` and the payload of the packet is stored in `p`.
	// WriteTo returns the number of bytes written from `p` and any error encountered.
	WriteTo(p []byte, destination netip.AddrPort) (int, error)

	// Close indicates that no more calls to WriteTo will be made.
	Close() error
}

// PacketResponseReceiver receives UDP response packets from the [PacketProxy].
//
// Deprecated: Use [PacketHandler] instead.
type PacketResponseReceiver interface {
	// WriteFrom is a callback function that is called by a PacketProxy when a UDP response packet is received.
	// The `source` identifies the remote server that sent the packet and the `p` contains the packet payload.
	// WriteFrom returns the number of bytes written from `p` and any error encountered.
	WriteFrom(p []byte, source net.Addr) (int, error)

	// Close indicates that no more calls to WriteFrom will be made.
	Close() error
}

// NewPacketProxyFromPacketRelay adapts a [packetrelay.PacketRelay] to the [PacketProxy] interface.
// This allows using new PacketRelay implementations where the old PacketProxy API is required.
//
// Deprecated: Use the new [packetrelay] API directly.
func NewPacketProxyFromPacketRelay(relay packetrelay.PacketRelay) PacketProxy {
	if relay == nil {
		return nil
	}
	return &packetRelayToProxyAdapter{relay: relay}
}

type packetRelayToProxyAdapter struct {
	relay packetrelay.PacketRelay
}

func (a *packetRelayToProxyAdapter) NewSession(respReceiver PacketResponseReceiver) (PacketRequestSender, error) {
	if respReceiver == nil {
		return nil, errors.New("respReceiver must not be nil")
	}

	sender, receiver, err := a.relay.NewAssociation()
	if err != nil {
		return nil, err
	}

	// Start the receive loop to push packets to respReceiver
	go func() {
		// When ReceivePackets returns, the stream has ended, so we close respReceiver.
		_ = receiver.ReceivePackets(&packetHandlerAdapter{respReceiver: respReceiver})
		_ = respReceiver.Close()
	}()

	return &packetSenderToRequestSenderAdapter{sender: sender}, nil
}

type packetHandlerAdapter struct {
	respReceiver PacketResponseReceiver
}

func (h *packetHandlerAdapter) HandlePacket(p []byte, source netip.AddrPort) error {
	// Convert netip.AddrPort to *net.UDPAddr for WriteFrom
	_, err := h.respReceiver.WriteFrom(p, net.UDPAddrFromAddrPort(source))
	return err
}

type packetSenderToRequestSenderAdapter struct {
	sender packetrelay.PacketSender
}

func (s *packetSenderToRequestSenderAdapter) WriteTo(p []byte, destination netip.AddrPort) (int, error) {
	err := s.sender.SendPacket(p, destination)
	if err != nil {
		if errors.Is(err, packetrelay.ErrClosed) {
			return 0, ErrClosed
		}
		return 0, err
	}
	return len(p), nil
}

func (s *packetSenderToRequestSenderAdapter) Close() error {
	err := s.sender.Close()
	if errors.Is(err, packetrelay.ErrClosed) {
		return ErrClosed
	}
	return err
}
