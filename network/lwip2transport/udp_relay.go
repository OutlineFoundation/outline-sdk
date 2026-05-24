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
	"net"
	"net/netip"
	"sync"

	"golang.getoutline.org/sdk/network/packetrelay"
	lwip "github.com/eycorsican/go-tun2socks/core"
)

// pendingSession is used to coordinate concurrent ReceiveTo calls for the same
// local address. done is closed once the association attempt finishes; err holds
// the result. Readers must receive from done before reading err.
type pendingSession struct {
	done chan struct{}
	err  error
}

type udpRelayHandler struct {
	mu      sync.Mutex
	relay   packetrelay.PacketRelay
	senders map[string]packetrelay.PacketSender
	// pending tracks active, in-flight association creations for local addresses.
	// This allows multiple goroutines to wait on a single NewAssociation call,
	// preventing duplicate connections when concurrent packets arrive on a new port.
	pending map[string]*pendingSession
}

var _ lwip.UDPConnHandler = (*udpRelayHandler)(nil)

// newUDPRelayHandler returns a lwIP UDP connection handler natively integrated with PacketRelay.
func newUDPRelayHandler(pr packetrelay.PacketRelay) *udpRelayHandler {
	return &udpRelayHandler{
		relay:   pr,
		senders: make(map[string]packetrelay.PacketSender, 8),
		pending: make(map[string]*pendingSession, 8),
	}
}

func (h *udpRelayHandler) Connect(tunConn lwip.UDPConn, _ *net.UDPAddr) error {
	return nil
}

// ReceiveTo relays packets from the lwIP TUN device to the proxy. It is called concurrently by lwIP.
func (h *udpRelayHandler) ReceiveTo(tunConn lwip.UDPConn, data []byte, destAddr *net.UDPAddr) error {
	sender, err := h.getSender(tunConn)
	if err != nil {
		return err
	}
	return sender.SendPacket(data, destAddr.AddrPort())
}

// getSender returns the PacketSender for tunConn's local address, creating an
// association on first use. Concurrent calls for the same local address share a
// single NewAssociation call: the first goroutine creates the session while the
// rest wait on the pending entry, preventing duplicate (leaked) associations.
func (h *udpRelayHandler) getSender(tunConn lwip.UDPConn) (packetrelay.PacketSender, error) {
	laddr := tunConn.LocalAddr().String()

	for {
		h.mu.Lock()
		// Fast path: association already exists.
		if sender, ok := h.senders[laddr]; ok {
			h.mu.Unlock()
			return sender, nil
		}

		// If another goroutine is already establishing an association for this local address,
		// unlock and wait on the pending entry to avoid duplicate session creations.
		if p, ok := h.pending[laddr]; ok {
			h.mu.Unlock()
			<-p.done // Block until the association creation completes
			if p.err != nil {
				return nil, p.err // conn was already closed by the failing goroutine; don't retry
			}
			continue // Retry the lookup: sender is now in h.senders
		}

		// We are the first goroutine to encounter this local address. Register a pending
		// entry so subsequent concurrent packets on this address will wait for us.
		p := &pendingSession{done: make(chan struct{})}
		h.pending[laddr] = p
		h.mu.Unlock()

		// Call newSession (which performs I/O-bound NewAssociation) outside the lock.
		// This prevents blocking active, unrelated UDP flows on other ports.
		sender, receiver, err := h.newSession(tunConn)

		h.mu.Lock()
		delete(h.pending, laddr)
		p.err = err // written before close(p.done); readers see it after <-p.done
		if err == nil {
			h.senders[laddr] = sender
		}
		close(p.done) // Unblock any waiting goroutines
		h.mu.Unlock()

		if err == nil {
			// Start the receive loop AFTER the sender is registered in h.senders, so
			// that closeSession (triggered when the loop exits) is guaranteed to find
			// the sender and remove it. Otherwise an immediately-failing receiver could
			// leak a senderless entry into the map.
			go func() {
				forwarder := &udpRelayPacketForwarder{conn: tunConn, h: h}
				_ = receiver.ReceivePackets(forwarder)
				_ = h.closeSession(tunConn)
			}()
		}
		return sender, err
	}
}

// newSession opens a new packet relay association for conn. The caller is
// responsible for registering the returned sender in h.senders and starting the
// background receive loop on the returned receiver. On failure, conn is closed
// and (nil, nil, err) is returned.
func (h *udpRelayHandler) newSession(conn lwip.UDPConn) (packetrelay.PacketSender, packetrelay.PacketReceiver, error) {
	sender, receiver, err := h.relay.NewAssociation()
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return sender, receiver, nil
}

func (h *udpRelayHandler) closeSession(conn lwip.UDPConn) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	laddr := conn.LocalAddr().String()
	err := conn.Close()
	if sender, ok := h.senders[laddr]; ok {
		_ = sender.Close()
		delete(h.senders, laddr)
	}
	return err
}

type udpRelayPacketForwarder struct {
	conn lwip.UDPConn
	h    *udpRelayHandler
}

var _ packetrelay.PacketHandler = (*udpRelayPacketForwarder)(nil)

// HandlePacket relays standard response packets from the proxy back to the lwIP TUN device.
// This avoids dynamic string-parsing overhead by using allocation-free standard Go type conversions.
func (f *udpRelayPacketForwarder) HandlePacket(p []byte, source netip.AddrPort) error {
	srcAddr := net.UDPAddrFromAddrPort(source)
	_, err := f.conn.WriteFrom(p, srcAddr)
	return err
}
