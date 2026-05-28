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
	"sync"
	"time"
)

// TimeoutPacketRelay is a [PacketRelay] decorator that manages an idle timeout for packet associations.
// If no packets are sent for the specified duration, the association is closed.
//
// Note: To prevent Denial-of-Service (DoS) issues, the idle timer is ONLY reset on outgoing packets
// ([PacketSender.SendPacket]) and NOT on incoming packets. This aligns with the recommendation in
// RFC 4787 Section 4.3 (Mapping Refresh) to use unidirectional refresh to mitigate DoS attacks:
// https://www.rfc-editor.org/rfc/rfc4787.html#section-4.3
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
// and starts the idle timeout timer on the send path.
func (r *TimeoutPacketRelay) NewAssociation() (PacketSender, PacketReceiver, error) {
	sender, receiver, err := r.inner.NewAssociation()
	if err != nil {
		return nil, nil, err
	}

	tSender := &timeoutPacketSender{
		inner:        sender,
		timeout:      r.timeout,
		lastActivity: time.Now(),
	}

	// Lock before starting AfterFunc because the checkTimeout callback
	// accesses tSender.timer (via s.timer.Reset), and could theoretically
	// execute before the assignment below completes.
	tSender.mu.Lock()
	tSender.timer = time.AfterFunc(r.timeout, tSender.checkTimeout)
	tSender.mu.Unlock()

	return tSender, receiver, nil
}

type timeoutPacketSender struct {
	mu           sync.Mutex
	closed       bool
	inner        PacketSender
	timer        *time.Timer
	timeout      time.Duration
	lastActivity time.Time
}

func (s *timeoutPacketSender) SendPacket(p []byte, destination netip.AddrPort) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrClosed
	}
	s.lastActivity = time.Now()
	inner := s.inner
	s.mu.Unlock()

	return inner.SendPacket(p, destination)
}

func (s *timeoutPacketSender) checkTimeout() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}

	// We check the actual elapsed time since the last activity.
	// This is necessary because a time.AfterFunc goroutine can be scheduled
	// by the Go runtime but not yet executed when SendPacket is called. 
	// If we just blindly closed the session here, the Close() would execute
	// AFTER a successful SendPacket, leading to unexpected out-of-order
	// behavior (a successful send immediately followed by a close).
	elapsed := time.Since(s.lastActivity)
	if elapsed >= s.timeout {
		// Two-phase close: set state under the lock, then call inner.Close() outside it.
		// Calling s.Close() here instead would create a window between s.mu.Unlock() and
		// s.Close() where a concurrent SendPacket could update lastActivity and succeed,
		// only to have the association closed immediately after.
		s.closed = true
		s.timer.Stop()
		inner := s.inner
		s.inner = nil
		s.mu.Unlock()
		_ = inner.Close()
		return
	}

	// Not expired yet! Reschedule for the remaining time.
	s.timer.Reset(s.timeout - elapsed)
	s.mu.Unlock()
}

func (s *timeoutPacketSender) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrClosed
	}
	s.closed = true
	s.timer.Stop()
	inner := s.inner
	s.inner = nil
	s.mu.Unlock()

	return inner.Close()
}
