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
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.getoutline.org/sdk/internal/slicepool"
	"golang.getoutline.org/sdk/transport"
)

// packetMaxSize is the read buffer size per association. Packets larger than this are silently
// dropped (io.ErrShortBuffer). This is intentionally kept small to bound pool memory; callers
// should ensure traffic fits within this limit or configure a larger value if needed.
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
	mu               sync.RWMutex
	listener         transport.PacketListener
	writeIdleTimeout time.Duration
}

// NewPacketRelayFromPacketListener creates a new [PacketRelay] that uses the existing [transport.PacketListener] to
// create connections to a relay.
// This function is useful if you already have an implementation of [transport.PacketListener] and you want to use it
// with one of the network stacks (for example, network/lwip2transport) as a UDP traffic handler.
//
// Associations use a write-idle timeout that is reset only by [PacketSender.SendPacket], not by
// incoming packets.
func NewPacketRelayFromPacketListener(pl transport.PacketListener, writeIdleTimeout time.Duration) (*PacketListenerRelay, error) {
	if pl == nil {
		return nil, errors.New("pl must not be nil")
	}
	if writeIdleTimeout <= 0 {
		return nil, errors.New("writeIdleTimeout must be greater than 0")
	}
	r := &PacketListenerRelay{
		listener:         pl,
		writeIdleTimeout: writeIdleTimeout,
	}
	return r, nil
}

// SetWriteIdleTimeout sets the write-idle timeout for new associations.
// Existing associations keep the timeout they were created with.
func (relay *PacketListenerRelay) SetWriteIdleTimeout(timeout time.Duration) error {
	if timeout <= 0 {
		return errors.New("timeout must be greater than 0")
	}
	relay.mu.Lock()
	defer relay.mu.Unlock()
	relay.writeIdleTimeout = timeout
	return nil
}

// NewAssociation implements [PacketRelay].NewAssociation. It uses [transport.PacketListener].ListenPacket to create
// a [net.PacketConn], and returns a [PacketSender] and [PacketReceiver] based on this [net.PacketConn].
func (relay *PacketListenerRelay) NewAssociation() (PacketSender, PacketReceiver, error) {
	relay.mu.RLock()
	listener := relay.listener
	writeIdleTimeout := relay.writeIdleTimeout
	relay.mu.RUnlock()

	packetConn, err := listener.ListenPacket(context.Background())
	if err != nil {
		return nil, nil, err
	}

	association := &packetListenerAssociation{
		packetConn:       packetConn,
		writeIdleTimeout: writeIdleTimeout,
	}
	if err := association.refreshDeadline(); err != nil {
		_ = association.close()
		return nil, nil, err
	}

	sender := &packetListenerSender{
		association: association,
	}

	receiver := &packetListenerReceiver{
		association: association,
		packetConn:  packetConn,
	}

	return sender, receiver, nil
}

type packetListenerAssociation struct {
	mu               sync.Mutex
	closed           bool
	packetConn       net.PacketConn
	writeIdleTimeout time.Duration
}

func (a *packetListenerAssociation) refreshDeadline() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.closed {
		return ErrClosed
	}
	return a.packetConn.SetDeadline(time.Now().Add(a.writeIdleTimeout))
}

func (a *packetListenerAssociation) getPacketConn() (net.PacketConn, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.closed {
		return nil, ErrClosed
	}
	return a.packetConn, nil
}

func (a *packetListenerAssociation) close() error {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return ErrClosed
	}
	a.closed = true
	packetConn := a.packetConn
	a.packetConn = nil
	a.mu.Unlock()

	return packetConn.Close()
}

type packetListenerSender struct {
	association *packetListenerAssociation
}

// SendPacket implements [PacketSender].SendPacket. It simply forwards the packet to the underlying
// [net.PacketConn].WriteTo function.
func (s *packetListenerSender) SendPacket(p []byte, destination netip.AddrPort) error {
	if err := s.association.refreshDeadline(); err != nil {
		return err
	}
	packetConn, err := s.association.getPacketConn()
	if err != nil {
		return err
	}

	_, err = packetConn.WriteTo(p, net.UDPAddrFromAddrPort(destination))
	return err
}

// Close implements [PacketSender].Close. It closes the underlying [net.PacketConn]. This will also
// terminate the blocking loop in ReceivePackets because s.packetConn.ReadFrom will return an error.
func (s *packetListenerSender) Close() error {
	return s.association.close()
}

type packetListenerReceiver struct {
	association *packetListenerAssociation
	packetConn  net.PacketConn
}

// ReceivePackets implements [PacketReceiver].ReceivePackets. It blocks and passes incoming packets
// from the relay to the handler.
func (r *packetListenerReceiver) ReceivePackets(handler PacketHandler) error {
	// Allocate buffer from slicepool
	slice := packetBufferPool.LazySlice()
	buf := slice.Acquire()
	defer slice.Release()

	for {
		n, srcAddr, err := r.packetConn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, io.ErrShortBuffer) {
				continue
			}
			_ = r.association.close()
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
