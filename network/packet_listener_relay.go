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

package network

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"

	"golang.getoutline.org/sdk/internal/slicepool"
	"golang.getoutline.org/sdk/transport"
)

// this was the buffer size used before, we may consider update it in the future
const packetMaxSize = 2048

// packetBufferPool is used to create buffers to read UDP response packets
var packetBufferPool = slicepool.MakePool(packetMaxSize)

// Compilation guard against interface implementation
var _ PacketRelay = (*PacketListenerRelay)(nil)
var _ PacketSender = (*packetListenerSender)(nil)
var _ PacketReceiver = (*packetListenerReceiver)(nil)

// PacketListenerRelay creates a new [PacketRelay] that uses the existing [transport.PacketListener] to
// create connections to a relay.
type PacketListenerRelay struct {
	listener transport.PacketListener
}

// NewPacketRelayFromPacketListener creates a new [PacketRelay] that uses the existing [transport.PacketListener] to
// create connections to a relay. You can also specify additional options.
// This function is useful if you already have an implementation of [transport.PacketListener] and you want to use it
// with one of the network stacks (for example, network/lwip2transport) as a UDP traffic handler.
func NewPacketRelayFromPacketListener(pl transport.PacketListener, options ...func(*PacketListenerRelay) error) (*PacketListenerRelay, error) {
	if pl == nil {
		return nil, errors.New("pl must not be nil")
	}
	r := &PacketListenerRelay{
		listener: pl,
	}
	for _, opt := range options {
		if err := opt(r); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// NewAssociation implements [PacketRelay].NewAssociation. It uses [transport.PacketListener].ListenPacket to create
// a [net.PacketConn], and returns a [PacketSender] and [PacketReceiver] based on this [net.PacketConn].
func (relay *PacketListenerRelay) NewAssociation() (PacketSender, PacketReceiver, error) {
	proxyConn, err := relay.listener.ListenPacket(context.Background())
	if err != nil {
		return nil, nil, err
	}

	sender := &packetListenerSender{
		proxyConn: proxyConn,
	}

	receiver := &packetListenerReceiver{
		proxyConn: proxyConn,
	}

	return sender, receiver, nil
}

type packetListenerSender struct {
	mu     sync.Mutex // Protects closed flag
	closed bool

	proxyConn net.PacketConn
}

// SendPacket implements [PacketSender].SendPacket. It simply forwards the packet to the underlying
// [net.PacketConn].WriteTo function.
func (s *packetListenerSender) SendPacket(p []byte, destination netip.AddrPort) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrClosed
	}
	s.mu.Unlock()

	_, err := s.proxyConn.WriteTo(p, net.UDPAddrFromAddrPort(destination))
	return err
}

// Close implements [PacketSender].Close. It closes the underlying [net.PacketConn]. This will also
// terminate the blocking loop in ReceivePackets because s.proxyConn.ReadFrom will return an error.
func (s *packetListenerSender) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrClosed
	}
	s.closed = true
	return s.proxyConn.Close()
}

type packetListenerReceiver struct {
	proxyConn net.PacketConn
}

// ReceivePackets implements [PacketReceiver].ReceivePackets. It blocks and passes incoming packets
// from the relay to the handler.
func (r *packetListenerReceiver) ReceivePackets(handler PacketHandler) error {
	defer handler.Close()

	// Allocate buffer from slicepool
	slice := packetBufferPool.LazySlice()
	buf := slice.Acquire()
	defer slice.Release()

	for {
		n, srcAddr, err := r.proxyConn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, io.ErrShortBuffer) {
				continue
			}
			return err
		}

		var srcPort netip.AddrPort
		if udpAddr, ok := srcAddr.(*net.UDPAddr); ok {
			srcPort = udpAddr.AddrPort()
		} else {
			var err error
			srcPort, err = netip.ParseAddrPort(srcAddr.String())
			if err != nil {
				return err
			}
		}

		if err := handler.HandlePacket(buf[:n], srcPort); err != nil {
			return err
		}
	}
}
