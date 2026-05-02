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
	"errors"
	"net/netip"
	"sync"
	"time"
)

// TimeoutPacketRelay is a [PacketRelay] decorator that manages an idle timeout for packet associations.
// If no packets are sent or received for the specified duration, the association is closed.
//
// Multiple goroutines can simultaneously invoke methods on a TimeoutPacketRelay.
type TimeoutPacketRelay struct {
	inner   PacketRelay
	timeout time.Duration
}

// NewTimeoutPacketRelay creates a new [TimeoutPacketRelay] wrapping `inner`.
// The `timeout` must be greater than 0.
func NewTimeoutPacketRelay(inner PacketRelay, timeout time.Duration) (*TimeoutPacketRelay, error) {
	if inner == nil {
		return nil, errors.New("inner relay must not be nil")
	}
	if timeout <= 0 {
		return nil, errors.New("timeout must be greater than 0")
	}
	return &TimeoutPacketRelay{inner: inner, timeout: timeout}, nil
}

// NewAssociation implements [PacketRelay].NewAssociation. It creates a new association
// and starts the idle timeout timer.
func (r *TimeoutPacketRelay) NewAssociation() (PacketSender, PacketReceiver, error) {
	sender, receiver, err := r.inner.NewAssociation()
	if err != nil {
		return nil, nil, err
	}

	shared := &sharedTimeoutState{
		sender:  sender,
		timeout: r.timeout,
	}

	shared.mu.Lock()
	shared.timer = time.AfterFunc(r.timeout, func() {
		_ = shared.Close()
	})
	shared.mu.Unlock()

	tSender := &timeoutPacketSender{
		inner:  sender,
		shared: shared,
	}

	tReceiver := &timeoutPacketReceiver{
		inner:  receiver,
		shared: shared,
	}

	return tSender, tReceiver, nil
}

type sharedTimeoutState struct {
	mu      sync.Mutex
	sender  PacketSender
	timer   *time.Timer
	timeout time.Duration
	closed  bool
}

func (s *sharedTimeoutState) resetTimer() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	s.timer.Reset(s.timeout)
	return nil
}

func (s *sharedTimeoutState) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	s.closed = true
	s.timer.Stop()
	return s.sender.Close()
}

type timeoutPacketSender struct {
	inner  PacketSender
	shared *sharedTimeoutState
}

func (s *timeoutPacketSender) SendPacket(p []byte, destination netip.AddrPort) error {
	if err := s.shared.resetTimer(); err != nil {
		return err
	}
	return s.inner.SendPacket(p, destination)
}

func (s *timeoutPacketSender) Close() error {
	return s.shared.Close()
}

type timeoutPacketReceiver struct {
	inner  PacketReceiver
	shared *sharedTimeoutState
}

func (r *timeoutPacketReceiver) ReceivePackets(handler PacketHandler) error {
	tHandler := &timeoutPacketHandler{
		inner:  handler,
		shared: r.shared,
	}

	err := r.inner.ReceivePackets(tHandler)

	// Ensure shared state is closed when the receive loop exits
	_ = r.shared.Close()

	return err
}

type timeoutPacketHandler struct {
	inner  PacketHandler
	shared *sharedTimeoutState
}

func (h *timeoutPacketHandler) HandlePacket(p []byte, source netip.AddrPort) error {
	if err := h.shared.resetTimer(); err != nil {
		return err
	}
	return h.inner.HandlePacket(p, source)
}

func (h *timeoutPacketHandler) Close() error {
	return h.inner.Close()
}
