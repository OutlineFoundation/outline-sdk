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

package httpconnect

import (
	"net"
	"syscall"
)

// dialedPacketConn presents a packet connection that is already bound to one
// peer as the [net.PacketConn] QUIC-Go requires. Every packet goes to and comes
// from that peer, so the address arguments carry no information.
//
// It deliberately has no ReadMsgUDP or WriteMsgUDP: QUIC-Go would pass them a
// destination address, which a connected UDP socket rejects.
type dialedPacketConn struct {
	net.Conn
}

var _ net.PacketConn = dialedPacketConn{}

func (c dialedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Conn.Read(p)
	return n, c.Conn.RemoteAddr(), err
}

func (c dialedPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.Conn.Write(p)
}

// dialedUDPConn additionally lets QUIC-Go size the socket buffers and set the
// Don't Fragment bit, which it needs for path MTU discovery.
type dialedUDPConn struct {
	dialedPacketConn
	udp *net.UDPConn
}

func (c dialedUDPConn) SetReadBuffer(bytes int) error         { return c.udp.SetReadBuffer(bytes) }
func (c dialedUDPConn) SetWriteBuffer(bytes int) error        { return c.udp.SetWriteBuffer(bytes) }
func (c dialedUDPConn) SyscallConn() (syscall.RawConn, error) { return c.udp.SyscallConn() }

func newDialedPacketConn(conn net.Conn) net.PacketConn {
	if udp, ok := conn.(*net.UDPConn); ok {
		return dialedUDPConn{dialedPacketConn{conn}, udp}
	}
	return dialedPacketConn{conn}
}
