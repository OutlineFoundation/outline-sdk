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

// Compilation guard against interface implementation
var _ lwip.UDPConnHandler = (*udpRelayHandler)(nil)
var _ packetrelay.PacketHandler = (*udpRelayPacketForwarder)(nil)

type udpRelayHandler struct {
	mu      sync.Mutex
	relay   packetrelay.PacketRelay
	senders map[string]packetrelay.PacketSender
}

// newUDPRelayHandler returns a lwIP UDP connection handler natively integrated with PacketRelay.
func newUDPRelayHandler(pr packetrelay.PacketRelay) *udpRelayHandler {
	return &udpRelayHandler{
		relay:   pr,
		senders: make(map[string]packetrelay.PacketSender, 8),
	}
}

func (h *udpRelayHandler) Connect(tunConn lwip.UDPConn, _ *net.UDPAddr) error {
	return nil
}

// ReceiveTo relays packets from the lwIP TUN device to the proxy. It is called concurrently by lwIP.
func (h *udpRelayHandler) ReceiveTo(tunConn lwip.UDPConn, data []byte, destAddr *net.UDPAddr) error {
	laddr := tunConn.LocalAddr().String()

	h.mu.Lock()
	sender, ok := h.senders[laddr]
	if !ok {
		// Synchronize new session creation completely under the lock to prevent proxy resource leaks 
		// when concurrent packets arrive on a new local port.
		var err error
		sender, err = h.newSession(tunConn)
		if err != nil {
			h.mu.Unlock()
			return err
		}
		h.senders[laddr] = sender
	}
	h.mu.Unlock()

	return sender.SendPacket(data, destAddr.AddrPort())
}

// newSession establishes a new packet relay association for the given UDP connection
// and spawns the background blocking receive loop. The caller must hold h.mu.
func (h *udpRelayHandler) newSession(conn lwip.UDPConn) (packetrelay.PacketSender, error) {
	sender, receiver, err := h.relay.NewAssociation()
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	forwarder := &udpRelayPacketForwarder{
		conn: conn,
		h:    h,
	}

	// Start the blocking receive loop to pull response packets using a clean Go routine
	go func() {
		_ = receiver.ReceivePackets(forwarder)
		_ = h.closeSession(conn)
	}()

	return sender, nil
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

// HandlePacket relays standard response packets from the proxy back to the lwIP TUN device.
// This avoids dynamic string-parsing overhead by using allocation-free standard Go type conversions.
func (f *udpRelayPacketForwarder) HandlePacket(p []byte, source netip.AddrPort) error {
	srcAddr := net.UDPAddrFromAddrPort(source)
	_, err := f.conn.WriteFrom(p, srcAddr)
	return err
}
