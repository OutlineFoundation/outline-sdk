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

package lwip2transport

import (
	"net"
	"sync"
	"sync/atomic"

	"golang.getoutline.org/sdk/network"
	lwip "github.com/OutlineFoundation/go-tun2socks/core"
)

// Compilation guard against interface implementation
var _ lwip.UDPConnHandler = (*udpHandler)(nil)

//lint:ignore SA1019 PacketProxy compat path until the PacketRelay migration (#618) completes.
var _ network.PacketResponseReceiver = (*udpConnResponseWriter)(nil)

type udpHandler struct {
	mu sync.Mutex // Protects the senders field
	//lint:ignore SA1019 PacketProxy compat path until the PacketRelay migration (#618) completes.
	proxy network.PacketProxy // A network stack neutral implementation of UDP PacketProxy
	//lint:ignore SA1019 PacketProxy compat path until the PacketRelay migration (#618) completes.
	senders map[string]network.PacketRequestSender // Maps local lwIP UDP socket to PacketRequestSender
}

// newUDPHandler returns a lwIP UDP connection handler.
//
// `pktProxy` is a PacketProxy that handles UDP packets.
//
//lint:ignore SA1019 PacketProxy compat path until the PacketRelay migration (#618) completes.
func newUDPHandler(pktProxy network.PacketProxy) *udpHandler {
	return &udpHandler{
		proxy: pktProxy,
		//lint:ignore SA1019 PacketProxy compat path until the PacketRelay migration (#618) completes.
		senders: make(map[string]network.PacketRequestSender, 8),
	}
}

// Connect does nothing. New UDP sessions will be created in ReceiveTo.
func (h *udpHandler) Connect(tunConn lwip.UDPConn, _ *net.UDPAddr) error {
	return nil
}

// ReceiveTo relays packets from the lwIP TUN device to the proxy. It's called by lwIP. ReceiveTo will also create a
// new UDP session if `data` is the first packet from the `tunConn`.
func (h *udpHandler) ReceiveTo(tunConn lwip.UDPConn, data []byte, destAddr *net.UDPAddr) (err error) {
	laddr := tunConn.LocalAddr().String()

	h.mu.Lock()
	reqSender, ok := h.senders[laddr]
	// TODO: address synchronization issues with h.senders[laddr] and the following `if` in the future
	h.mu.Unlock()
	if !ok {
		if reqSender, err = h.newSession(tunConn); err != nil {
			return
		}
		h.mu.Lock()
		h.senders[laddr] = reqSender
		h.mu.Unlock()
	}

	_, err = reqSender.WriteTo(data, destAddr.AddrPort())
	return
}

// newSession creates a new PacketRequestSender related to conn. The caller needs to put the new PacketRequestSender
// to the h.senders map.
//
//lint:ignore SA1019 PacketProxy compat path until the PacketRelay migration (#618) completes.
func (h *udpHandler) newSession(conn lwip.UDPConn) (network.PacketRequestSender, error) {
	respWriter := &udpConnResponseWriter{
		conn: conn,
		h:    h,
	}
	reqSender, err := h.proxy.NewSession(respWriter)
	if err != nil {
		respWriter.Close()
	}
	return reqSender, err
}

// closeSession cleans up resources related to conn.
func (h *udpHandler) closeSession(conn lwip.UDPConn) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	laddr := conn.LocalAddr().String()
	err := conn.Close()
	if reqSender, ok := h.senders[laddr]; ok {
		reqSender.Close()
		delete(h.senders, laddr)
	}
	return err
}

// The PacketResponseWriter that will write responses to the lwip network stack.
type udpConnResponseWriter struct {
	closed atomic.Bool
	conn   lwip.UDPConn
	h      *udpHandler
}

// Write relays packets from the proxy to the lwIP TUN device.
func (r *udpConnResponseWriter) WriteFrom(p []byte, source net.Addr) (int, error) {
	if r.closed.Load() {
		return 0, network.ErrClosed
	}

	// net.Addr -> *net.UDPAddr, because r.conn.WriteFrom requires *net.UDPAddr
	// and this is more reliable than type assertion
	// also the source address host will be an IP address, no actual resolution will be done
	srcAddr, err := net.ResolveUDPAddr("udp", source.String())
	if err != nil {
		return 0, err
	}

	return r.conn.WriteFrom(p, srcAddr)
}

// Close informs the udpHandler to close the UDPConn and clean up the UDP session.
func (r *udpConnResponseWriter) Close() error {
	if r.closed.CompareAndSwap(false, true) {
		return r.h.closeSession(r.conn)
	}
	return network.ErrClosed
}
