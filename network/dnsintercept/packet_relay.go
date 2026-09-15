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

package dnsintercept

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"

	"golang.getoutline.org/sdk/dns"
	"golang.getoutline.org/sdk/network/packetrelay"
)

// Option configures an intercepting [packetrelay.PacketRelay] created with [New].
type Option func(*InterceptDNSPacketRelay)

// WithErrorHandler sets a function to be called with the errors of failed DNS exchanges.
//
// A failed exchange produces no packet, and there's no caller left to return the error to:
// [packetrelay.PacketSender.SendPacket] has long returned by the time the exchange finishes.
// The handler exists so those errors can be logged or counted; it must not block, since it
// runs on the goroutine driving the exchange. The default handler does nothing.
func WithErrorHandler(handler func(error)) Option {
	return func(r *InterceptDNSPacketRelay) {
		if handler != nil {
			r.onError = handler
		}
	}
}

// InterceptDNSPacketRelay is a [packetrelay.PacketRelay] decorator that answers the UDP packets
// addressed to a local resolver with a [dns.Exchanger], and forwards all other UDP traffic to a
// default relay. Use [New] to create one.
type InterceptDNSPacketRelay struct {
	defaultRelay  packetrelay.PacketRelay
	localResolver netip.AddrPort
	resolver      dns.Exchanger
	onError       func(error)
}

var _ packetrelay.PacketRelay = (*InterceptDNSPacketRelay)(nil)

// New creates a [packetrelay.PacketRelay] that answers the packets addressed to localResolver
// with resolver, and forwards everything else to defaultRelay.
//
// A packet whose destination is localResolver (comparing IPv4 and IPv4-mapped IPv6 addresses as
// equal) is handed to resolver as a wire-format DNS query. The response is delivered to the
// handler of the association that sent the query, with localResolver as the source address, so
// the client sees an answer from the resolver it queried. Packets addressed to anything else go
// to defaultRelay unmodified.
//
// The exchange runs on its own goroutine: SendPacket returns as soon as the query is dispatched,
// and never reports an exchange failure. Use [WithErrorHandler] to observe those errors. The
// exchange is given a context that is canceled when the association closes, and has no timeout
// of its own: enforcing one is the resolver's responsibility.
func New(defaultRelay packetrelay.PacketRelay, localResolver netip.AddrPort, resolver dns.Exchanger, opts ...Option) packetrelay.PacketRelay {
	r := &InterceptDNSPacketRelay{
		defaultRelay:  defaultRelay,
		localResolver: localResolver,
		resolver:      resolver,
		onError:       func(error) {},
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// NewInterceptDNSPacketRelay creates a [packetrelay.PacketRelay] that forwards the DNS queries
// addressed to dnsLocalResolver to dnsRemoteResolver over dnsRelay, and everything else to
// defaultRelay.
//
// Deprecated: use [New] with [NewPacketRelayExchanger] instead, which is what this does:
//
//	New(defaultRelay, dnsLocalResolver, NewPacketRelayExchanger(dnsRelay, dnsRemoteResolver))
func NewInterceptDNSPacketRelay(dnsRelay, defaultRelay packetrelay.PacketRelay, dnsLocalResolver, dnsRemoteResolver netip.AddrPort) packetrelay.PacketRelay {
	return New(defaultRelay, dnsLocalResolver, NewPacketRelayExchanger(dnsRelay, dnsRemoteResolver))
}

// State machine for lazy default association initialization:
//
// stateIdle: Initial state. No default association created yet.
// stateInitializing: A SendPacket call is currently invoking NewAssociation on the defaultRelay;
// other concurrent SendPacket calls will block waiting for this to finish.
// stateInitialized: The default association has been resolved (either success or error cached);
// future SendPacket calls will immediately use the cached result.
const (
	stateIdle = iota
	stateInitializing
	stateInitialized
)

// interceptAssoc manages the parent association lifecycle and its sub-associations.
// The "life of an association" is determined by the active sub-associations:
// 1. The parent association starts with 0 active sub-associations.
// 2. When a sub-association (the default one) or a DNS exchange starts, the active count increments.
// 3. When it terminates (e.g. after the DNS exchange completes or when the default relay closes), the active count decrements via Release().
// 4. If the active count drops back to 0, it automatically closes itself.
// 5. Explicitly calling Close() on the parent association forcefully closes the default sub-association and cancels the in-flight DNS exchanges.
//
// Why ref-counting rather than a fixed parent lifetime: in the common case the
// OS uses one DNS query per ephemeral UDP source port (so a parent only ever
// sees one short-lived DNS exchange at a time, and activeCount flickers 0↔1). The
// ref-count machinery becomes load-bearing only when that assumption is
// violated — a caller that reuses one source port across multiple DNS queries,
// or mixes DNS with other UDP traffic on the same port. There it keeps the
// parent alive until every exchange has finished. See doc.go for the broader
// rationale.
type interceptAssoc struct {
	relay *InterceptDNSPacketRelay

	mu          sync.Mutex
	cond        *sync.Cond
	isClosed    bool
	activeCount int

	defState        int
	defSender       packetrelay.PacketSender
	defInitErr      error
	defReceiverChan chan packetrelay.PacketReceiver

	// ctx is canceled when the association closes, which cancels the in-flight DNS exchanges.
	ctx    context.Context
	cancel context.CancelFunc

	closeChan    chan struct{}
	handler      packetrelay.PacketHandler
	handlerReady chan struct{}
}

// NewAssociation creates a new parent packet association.
// The returned PacketSender routes outgoing traffic to either the DNS resolver or the default relay
// based on the destination address.
// The default sub-association is not created immediately; it is established lazily upon sending packets.
func (r *InterceptDNSPacketRelay) NewAssociation() (packetrelay.PacketSender, packetrelay.PacketReceiver, error) {
	ctx, cancel := context.WithCancel(context.Background())
	a := &interceptAssoc{
		relay:           r,
		ctx:             ctx,
		cancel:          cancel,
		closeChan:       make(chan struct{}),
		handlerReady:    make(chan struct{}),
		defReceiverChan: make(chan packetrelay.PacketReceiver, 1),
	}
	a.cond = sync.NewCond(&a.mu)
	return &interceptSender{a}, &interceptReceiver{a}, nil
}

func (a *interceptAssoc) Release() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.activeCount--
	if a.activeCount == 0 && !a.isClosed {
		a.closeLocked()
	}
}

func (a *interceptAssoc) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.isClosed {
		return packetrelay.ErrClosed
	}
	a.closeLocked()
	return nil
}

func (a *interceptAssoc) closeLocked() {
	a.isClosed = true
	close(a.closeChan)
	a.cond.Broadcast()
	a.cancel()
	if a.defSender != nil {
		a.defSender.Close()
	}
}

// handleDNSQuery dispatches an intercepted query to the resolver and returns immediately:
// the exchange may take as long as the resolver needs, and the packet sender must not block on it.
func (a *interceptAssoc) handleDNSQuery(query []byte) error {
	a.mu.Lock()
	if a.isClosed {
		a.mu.Unlock()
		return packetrelay.ErrClosed
	}
	a.activeCount++
	a.mu.Unlock()

	// The caller may reuse query once SendPacket returns, and the exchange outlives it.
	go a.runExchange(bytes.Clone(query))
	return nil
}

// runExchange resolves a query and delivers the response to the association handler,
// with the source address rewritten to the intercepted local resolver.
func (a *interceptAssoc) runExchange(query []byte) {
	defer a.Release()

	response, err := a.relay.resolver.Exchange(a.ctx, query)
	if err != nil {
		a.relay.onError(fmt.Errorf("DNS exchange failed: %w", err))
		return
	}
	if len(response) == 0 {
		a.relay.onError(errors.New("DNS exchange returned an empty response"))
		return
	}

	// Don't race ahead of ReceivePackets: there may be no handler registered yet.
	select {
	case <-a.handlerReady:
	case <-a.closeChan:
		return
	}
	if err := a.handler.HandlePacket(response, a.relay.localResolver); err != nil {
		a.relay.onError(fmt.Errorf("failed to deliver DNS response: %w", err))
	}
}

func (a *interceptAssoc) getOrCreateDefaultSender() (packetrelay.PacketSender, error) {
	a.mu.Lock()
	if a.isClosed {
		a.mu.Unlock()
		return nil, packetrelay.ErrClosed
	}

	for a.defState == stateInitializing {
		a.cond.Wait()
		if a.isClosed {
			a.mu.Unlock()
			return nil, packetrelay.ErrClosed
		}
	}

	if a.defState == stateInitialized {
		sender, err := a.defSender, a.defInitErr
		a.mu.Unlock()
		return sender, err
	}

	a.defState = stateInitializing
	a.mu.Unlock()

	sender, receiver, err := a.relay.defaultRelay.NewAssociation()

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.isClosed {
		if err == nil {
			sender.Close()
		}
		a.defState = stateInitialized
		a.defInitErr = packetrelay.ErrClosed
		a.cond.Broadcast()
		return nil, packetrelay.ErrClosed
	}

	a.defState = stateInitialized
	a.defSender = sender
	a.defInitErr = err
	if err == nil {
		a.activeCount++
		a.defReceiverChan <- receiver
	}
	a.cond.Broadcast()
	return sender, err
}

// interceptSender implements packetrelay.PacketSender
type interceptSender struct {
	a *interceptAssoc
}

var _ packetrelay.PacketSender = (*interceptSender)(nil)

// SendPacket routes the packet to the appropriate destination.
// If the destination matches the intercepted local resolver, the packet is handed to the
// resolver as a DNS query, to be answered asynchronously.
// Otherwise, it lazily initializes and uses a single association on the default relay.
func (s *interceptSender) SendPacket(p []byte, destination netip.AddrPort) error {
	if isSameAddrPort(destination, s.a.relay.localResolver) {
		return s.a.handleDNSQuery(p)
	}

	defSender, err := s.a.getOrCreateDefaultSender()
	if err != nil {
		return err
	}
	return defSender.SendPacket(p, destination)
}

// isSameAddrPort treats IPv4 and IPv4-mapped IPv6 addresses as equivalent because
// some network stacks surface IPv4 UDP destinations in IPv4-mapped form.
func isSameAddrPort(a, b netip.AddrPort) bool {
	return a.Addr().Unmap() == b.Addr().Unmap() && a.Port() == b.Port()
}

// Close terminates the parent association: it closes the default sub-association and cancels
// the DNS exchanges still in flight.
func (s *interceptSender) Close() error {
	return s.a.Close()
}

// interceptReceiver implements packetrelay.PacketReceiver
type interceptReceiver struct {
	a *interceptAssoc
}

var _ packetrelay.PacketReceiver = (*interceptReceiver)(nil)

// ReceivePackets blocks and passes the incoming packets and the DNS responses back to the handler.
// DNS responses have their source address rewritten to the intercepted local resolver.
// It returns when the parent association is explicitly closed or all its activity has ceased.
func (r *interceptReceiver) ReceivePackets(handler packetrelay.PacketHandler) error {
	r.a.mu.Lock()
	if r.a.isClosed {
		r.a.mu.Unlock()
		return packetrelay.ErrClosed
	}
	if r.a.handler != nil {
		r.a.mu.Unlock()
		return errors.New("ReceivePackets called multiple times")
	}
	r.a.handler = handler
	close(r.a.handlerReady)
	r.a.mu.Unlock()

	select {
	case receiver := <-r.a.defReceiverChan:
		_ = receiver.ReceivePackets(r.a.handler)
		r.a.Release()
		<-r.a.closeChan // Wait for any remaining DNS exchanges to terminate
	case <-r.a.closeChan:
	}
	return nil
}
