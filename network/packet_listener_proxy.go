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

package network

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

// this was the buffer size used before, we may consider update it in the future
const packetMaxSize = 2048

// packetBufferPool is used to create buffers to read UDP response packets
var packetBufferPool = slicepool.MakePool(packetMaxSize)

// Compilation guard against interface implementation
var _ PacketProxy = (*PacketListenerProxy)(nil)
var _ PacketRequestSender = (*packetListenerRequestSender)(nil)

type PacketListenerProxy struct {
	listener         transport.PacketListener
	writeIdleTimeout time.Duration
}

// packetListenerRequestSender implements [PacketRequestSender] to handle a UDP session.
//
// # State Machine
//
// The session operates in one of three states, determined by `closed` and `proxyConn`:
//
//  1. Uninitialized (!closed, proxyConn == nil)
//     Initial state after NewSession. No OS resources (sockets, goroutines) are allocated yet.
//     The writeIdleTimer is running.
//     Transitions to:
//     - Active: on first successful WriteTo.
//     - Closed: on Close() or idle timeout.
//     - Stays Uninitialized: if WriteTo fails to create the connection (retries allowed).
//
//  2. Active (!closed, proxyConn != nil)
//     The connection is established and the background response-relay goroutine is running.
//     Transitions to:
//     - Closed: on Close() or idle timeout.
//
//  3. Closed (closed == true, proxyConn == nil)
//     Terminal state. All OS resources are cleaned up (or stopping).
//     All future WriteTo or Close calls immediately return ErrClosed.
type packetListenerRequestSender struct {
	mu               sync.Mutex // Protects closed and timer function calls
	closed           bool

	listener         transport.PacketListener
	writeIdleTimeout time.Duration
	respReceiver     PacketResponseReceiver

	proxyConn      net.PacketConn
	writeIdleTimer *time.Timer
}

// NewPacketProxyFromPacketListener creates a new [PacketProxy] that uses the existing [transport.PacketListener] to
// create connections to a proxy. You can also specify additional options.
// This function is useful if you already have an implementation of [transport.PacketListener] and you want to use it
// with one of the network stacks (for example, network/lwip2transport) as a UDP traffic handler.
func NewPacketProxyFromPacketListener(pl transport.PacketListener, options ...func(*PacketListenerProxy) error) (*PacketListenerProxy, error) {
	if pl == nil {
		return nil, errors.New("pl must not be nil")
	}
	p := &PacketListenerProxy{
		listener:         pl,
		writeIdleTimeout: 30 * time.Second,
	}
	for _, opt := range options {
		if err := opt(p); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// WithPacketListenerWriteIdleTimeout sets the write idle timeout of the [PacketListenerProxy].
// This means that if there are no WriteTo operations on the UDP session created by NewSession for the specified amount
// of time, the proxy will end this session.
//
// This should be used together with the [NewPacketProxyFromPacketListenerWithOptions] function.
func WithPacketListenerWriteIdleTimeout(timeout time.Duration) func(*PacketListenerProxy) error {
	return func(p *PacketListenerProxy) error {
		if timeout <= 0 {
			return errors.New("timeout must be greater than 0")
		}
		p.writeIdleTimeout = timeout
		return nil
	}
}

// NewSession implements [PacketProxy].NewSession function. It uses [transport.PacketListener].ListenPacket to create
// a [net.PacketConn], and constructs a new [PacketRequestSender] that is based on this [net.PacketConn].
func (proxy *PacketListenerProxy) NewSession(respReceiver PacketResponseReceiver) (PacketRequestSender, error) {
	if respReceiver == nil {
		return nil, errors.New("respReceiver must not be nil")
	}

	reqSender := &packetListenerRequestSender{
		listener:         proxy.listener,
		writeIdleTimeout: proxy.writeIdleTimeout,
		respReceiver:     respReceiver,
	}

	// Terminate the session after timeout with no outgoing writes (deadline is refreshed by WriteTo).
	// We lock here because the timer goroutine could call Close() and access writeIdleTimer concurrently.
	reqSender.mu.Lock()
	reqSender.writeIdleTimer = time.AfterFunc(reqSender.writeIdleTimeout, func() {
		reqSender.Close()
	})
	reqSender.mu.Unlock()

	return reqSender, nil
}

func (s *packetListenerRequestSender) getProxyConnLocked() error {
	if s.proxyConn != nil {
		return nil
	}

	// Reset the timer before the slow ListenPacket call to prevent it from firing
	// while we are blocked here.
	s.writeIdleTimer.Reset(s.writeIdleTimeout)

	ctx, cancel := context.WithTimeout(context.Background(), s.writeIdleTimeout)
	defer cancel()

	proxyConn, err := s.listener.ListenPacket(ctx)
	if err != nil {
		return err
	}
	s.proxyConn = proxyConn

	// Relay incoming UDP responses from the proxy asynchronously until EOF, session expiration or error
	go func() {
		defer s.respReceiver.Close()

		// Allocate buffer from slicepool, because `go build -gcflags="-m"` shows a local array will escape to heap
		slice := packetBufferPool.LazySlice()
		buf := slice.Acquire()
		defer slice.Release()

		for {
			n, srcAddr, err := proxyConn.ReadFrom(buf)
			if err != nil {
				// Ignore some specific recoverable errors
				if errors.Is(err, io.ErrShortBuffer) {
					continue
				}
				return
			}
			if _, err := s.respReceiver.WriteFrom(buf[:n], srcAddr); err != nil {
				return
			}
		}
	}()

	return nil
}

// WriteTo implements [PacketRequestSender].WriteTo function. It simply forwards the packet to the underlying
// [net.PacketConn].WriteTo function.
func (s *packetListenerRequestSender) WriteTo(p []byte, destination netip.AddrPort) (int, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, ErrClosed
	}

	if err := s.getProxyConnLocked(); err != nil {
		s.mu.Unlock()
		return 0, err
	}

	// Refresh the idle timer and read deadline.
	s.writeIdleTimer.Reset(s.writeIdleTimeout)
	s.proxyConn.SetReadDeadline(time.Now().Add(s.writeIdleTimeout))

	conn := s.proxyConn
	s.mu.Unlock()

	return conn.WriteTo(p, net.UDPAddrFromAddrPort(destination))
}

// Close implements [PacketRequestSender].Close function. It closes the underlying [net.PacketConn]. This will also
// terminate the goroutine created in WriteTo because s.proxyConn.ReadFrom will return an error.
func (s *packetListenerRequestSender) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrClosed
	}
	s.closed = true
	if s.writeIdleTimer != nil {
		s.writeIdleTimer.Stop()
		s.writeIdleTimer = nil
	}

	conn := s.proxyConn
	s.proxyConn = nil
	s.mu.Unlock()

	if conn != nil {
		return conn.Close()
	}

	// If proxyConn was never created, we must close respReceiver here.
	return s.respReceiver.Close()
}
