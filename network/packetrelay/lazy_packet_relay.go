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
	"net/netip"
	"sync"
)

type lazyPacketRelay struct {
	inner PacketRelay
}

// NewLazyPacketRelay creates a decorator that defers calling NewAssociation
// on the underlying inner relay until the first SendPacket or ReceivePackets call.
func NewLazyPacketRelay(inner PacketRelay) PacketRelay {
	if inner == nil {
		return nil
	}
	return &lazyPacketRelay{inner: inner}
}

func (r *lazyPacketRelay) NewAssociation() (PacketSender, PacketReceiver, error) {
	s := &lazyPacketSender{relay: r.inner}
	rcv := &lazyPacketReceiver{sender: s}
	s.receiver = rcv
	return s, rcv, nil
}

type lazyPacketSender struct {
	mu       sync.Mutex
	relay    PacketRelay
	inner    PacketSender
	receiver *lazyPacketReceiver
	closed   bool
}

func (s *lazyPacketSender) getInner() (PacketSender, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	if s.inner != nil {
		return s.inner, nil
	}
	
	// Establish association lazily
	innerSender, innerReceiver, err := s.relay.NewAssociation()
	if err != nil {
		return nil, err
	}
	s.inner = innerSender
	s.receiver.setInner(innerReceiver)
	return s.inner, nil
}

func (s *lazyPacketSender) SendPacket(p []byte, destination netip.AddrPort) error {
	inner, err := s.getInner()
	if err != nil {
		return err
	}
	return inner.SendPacket(p, destination)
}

func (s *lazyPacketSender) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrClosed
	}
	s.closed = true
	inner := s.inner
	s.inner = nil
	s.mu.Unlock()

	// Unblock the lazy receiver if it was waiting and never initialized
	s.receiver.cancelWait()

	if inner != nil {
		return inner.Close()
	}
	return nil
}

type lazyPacketReceiver struct {
	mu       sync.Mutex
	inner    PacketReceiver
	sender   *lazyPacketSender
	cond     *sync.Cond
	canceled bool
}

func (r *lazyPacketReceiver) setInner(inner PacketReceiver) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.inner = inner
	if r.cond != nil {
		r.cond.Broadcast()
	}
}

func (r *lazyPacketReceiver) cancelWait() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.canceled = true
	if r.cond != nil {
		r.cond.Broadcast()
	}
}

func (r *lazyPacketReceiver) waitInner() (PacketReceiver, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.inner != nil {
		return r.inner, nil
	}
	if r.canceled {
		return nil, ErrClosed
	}
	
	// Trigger lazy initialization via the sender
	go func() {
		_, _ = r.sender.getInner()
	}()

	if r.cond == nil {
		r.cond = sync.NewCond(&r.mu)
	}
	for r.inner == nil && !r.canceled {
		r.cond.Wait()
	}
	
	if r.inner != nil {
		return r.inner, nil
	}
	return nil, ErrClosed
}

func (r *lazyPacketReceiver) ReceivePackets(handler PacketHandler) error {
	inner, err := r.waitInner()
	if err != nil {
		return err
	}
	return inner.ReceivePackets(handler)
}
