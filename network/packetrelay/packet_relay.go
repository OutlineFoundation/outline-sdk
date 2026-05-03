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
)

var (
	// ErrClosed is the error returned by an I/O call on a packet relay, sender, or receiver
	// that has already been closed.
	ErrClosed = errors.New("packet relay already closed")
)

// PacketRelay establishes packet associations to forward UDP traffic.
//
// Multiple goroutines can simultaneously invoke methods on a PacketRelay.
type PacketRelay interface {
	// NewAssociation creates a new UDP association (session). The caller can use the returned
	// PacketSender to send packets to the relay, and the PacketReceiver to receive packets from the relay.
	NewAssociation() (PacketSender, PacketReceiver, error)
}

// PacketSender sends UDP packets to the remote destination via the relay.
// It is typically called by an upstream component (such as a network stack).
// After the Close method is called, there will be no more packets sent to the sender,
// and all associated resources can be freed.
//
// Multiple goroutines can simultaneously invoke methods on a PacketSender.
type PacketSender interface {
	// SendPacket sends a UDP packet to the relay. The packet is destined for the remote server
	// identified by `destination` and the payload of the packet is stored in `p`.
	// SendPacket returns any error encountered that caused the function to stop early.
	//
	// `p` must not be modified, and it must not be referenced after SendPacket returns.
	SendPacket(p []byte, destination netip.AddrPort) error

	// Close indicates that no more calls to SendPacket will be made. Any future attempts
	// to call SendPacket should fail with ErrClosed.
	//
	// Additionally, calling Close MUST cause any active ReceivePackets call on the
	// associated PacketReceiver to return and release its resources.
	Close() error
}

// PacketReceiver allows the caller to receive UDP packets from the relay.
//
// Multiple goroutines can simultaneously invoke methods on a PacketReceiver.
type PacketReceiver interface {
	// ReceivePackets blocks and passes incoming packets from the relay to the handler.
	// It returns when the association is closed or an error occurs.
	//
	// Implementations MUST ensure that calling Close on the associated PacketSender
	// causes ReceivePackets to return.
	//
	// Before returning, ReceivePackets MUST call handler.Close() to indicate the end of the stream.
	ReceivePackets(handler PacketHandler) error
}

// PacketHandler processes packets received from the relay.
// It is implemented by the component that wants to consume packets (e.g. a network stack).
//
// Multiple goroutines can simultaneously invoke methods on a PacketHandler.
type PacketHandler interface {
	// HandlePacket is a callback function invoked for each received packet.
	// The `source` identifies the remote server that sent the packet and `p` contains the payload.
	// HandlePacket returns any error encountered that caused the function to stop early.
	//
	// `p` must not be modified, and it must not be referenced after HandlePacket returns.
	HandlePacket(p []byte, source netip.AddrPort) error
}
