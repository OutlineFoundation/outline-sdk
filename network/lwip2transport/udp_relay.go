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

	"golang.getoutline.org/sdk/network/packetrelay"
	lwip "github.com/eycorsican/go-tun2socks/core"
)

// session holds the PacketRelay association for one lwIP UDPConn. It is
// created in Connect and torn down by runReceive when the relay ends the
// association.
type session struct {
	sender packetrelay.PacketSender
	done   chan struct{} // closed when runReceive returns
}

type udpRelayHandler struct {
	mu       sync.Mutex
	relay    packetrelay.PacketRelay
	sessions map[lwip.UDPConn]*session
}

var _ lwip.UDPConnHandler = (*udpRelayHandler)(nil)

// newUDPRelayHandler returns a lwIP UDP connection handler natively integrated
// with PacketRelay. Each lwIP UDPConn gets one association, created in Connect.
func newUDPRelayHandler(pr packetrelay.PacketRelay) *udpRelayHandler {
	return &udpRelayHandler{
		relay:    pr,
		sessions: make(map[lwip.UDPConn]*session, 8),
	}
}

// Connect is called by lwIP exactly once per UDPConn, in a goroutine, before
// any ReceiveTo for that conn: the conn's state stays udpConnecting until
// Connect returns, and packets arriving in that window are queued by lwIP
// (see go-tun2socks core/udp_conn.go). We use this hook to open the relay
// association and spawn its receive loop.
func (h *udpRelayHandler) Connect(tunConn lwip.UDPConn, _ *net.UDPAddr) error {
	sender, receiver, err := h.relay.NewAssociation()
	if err != nil {
		return err // lwIP will close tunConn for us
	}
	s := &session{
		sender: sender,
		done:   make(chan struct{}),
	}
	h.mu.Lock()
	h.sessions[tunConn] = s
	h.mu.Unlock()
	go h.runReceive(tunConn, receiver, s)
	return nil
}

// ReceiveTo relays a packet from lwIP to the relay. By the lwIP UDP state
// machine, the session is guaranteed to exist at this point.
func (h *udpRelayHandler) ReceiveTo(tunConn lwip.UDPConn, data []byte, destAddr *net.UDPAddr) error {
	h.mu.Lock()
	s := h.sessions[tunConn]
	h.mu.Unlock()
	if s == nil {
		return errors.New("lwip2transport: no session for conn (Connect not called or already closed)")
	}
	return s.sender.SendPacket(data, destAddr.AddrPort())
}

// runReceive drives the receive loop for a single association and cleans up
// when it returns. ReceivePackets blocks until the relay closes the
// association; on exit we remove ourselves from the session map and close
// both halves.
func (h *udpRelayHandler) runReceive(tunConn lwip.UDPConn, receiver packetrelay.PacketReceiver, s *session) {
	defer close(s.done)

	forwarder := &udpRelayPacketForwarder{conn: tunConn, h: h}
	_ = receiver.ReceivePackets(forwarder)

	h.mu.Lock()
	delete(h.sessions, tunConn)
	h.mu.Unlock()
	_ = s.sender.Close()
	_ = tunConn.Close()
}

// closeSession triggers shutdown of the session for tunConn (if any) and
// blocks until its receive goroutine has finished cleanup. Safe to call
// concurrently; a no-op if no session exists.
func (h *udpRelayHandler) closeSession(tunConn lwip.UDPConn) error {
	h.mu.Lock()
	s, ok := h.sessions[tunConn]
	h.mu.Unlock()
	if !ok {
		return nil
	}
	// Closing the sender unblocks ReceivePackets, letting runReceive's
	// cleanup run.
	err := s.sender.Close()
	<-s.done
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
