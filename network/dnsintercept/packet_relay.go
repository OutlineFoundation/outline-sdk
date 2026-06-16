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
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"

	"golang.getoutline.org/sdk/network/packetrelay"
)

// InterceptDNSPacketRelay is a PacketRelay decorator that intelligently routes DNS queries
// directed at a specific local resolver to a dedicated DNS relay, rewriting the destination to a remote resolver.
// All other UDP traffic is routed through a default relay.
type InterceptDNSPacketRelay struct {
	dnsRelay          packetrelay.PacketRelay
	defaultRelay      packetrelay.PacketRelay
	dnsLocalResolver  netip.AddrPort
	dnsRemoteResolver netip.AddrPort
}

var _ packetrelay.PacketRelay = (*InterceptDNSPacketRelay)(nil)

// NewInterceptDNSPacketRelay creates a new InterceptDNSPacketRelay.
//
// Parameters:
//   - dnsRelay: The [packetrelay.PacketRelay] responsible for forwarding the intercepted DNS traffic.
//     This relay MUST be wrapped with a timeout mechanism (e.g. timeout_packet_relay)
//     to prevent dropped UDP packets from leaking associations.
//   - defaultRelay: The [packetrelay.PacketRelay] responsible for forwarding all non-DNS traffic.
//   - dnsLocalResolver: The destination address of outgoing packets that triggers DNS interception.
//     When a packet is sent to this address, it is routed to the dnsRelay.
//   - dnsRemoteResolver: The upstream address where the intercepted DNS queries will actually be sent.
//     The intercepted packet's destination address is rewritten to this address before sending.
func NewInterceptDNSPacketRelay(dnsRelay, defaultRelay packetrelay.PacketRelay, dnsLocalResolver, dnsRemoteResolver netip.AddrPort) packetrelay.PacketRelay {
	return &InterceptDNSPacketRelay{
		dnsRelay:          dnsRelay,
		defaultRelay:      defaultRelay,
		dnsLocalResolver:  dnsLocalResolver,
		dnsRemoteResolver: dnsRemoteResolver,
	}
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
// 2. When a sub-association (default or DNS) is created, the active count increments.
// 3. When a sub-association terminates (e.g. after receiving a DNS response or when the default relay closes), the active count decrements via Release().
// 4. If the active count drops back to 0, it automatically closes itself.
// 5. Explicitly calling Close() on the parent association forcefully closes all active sub-associations.
//
// Why ref-counting rather than a fixed parent lifetime: in the common case the
// OS uses one DNS query per ephemeral UDP source port (so a parent only ever
// sees one short-lived DNS sub at a time, and activeCount flickers 0↔1). The
// ref-count machinery becomes load-bearing only when that assumption is
// violated — a caller that reuses one source port across multiple DNS queries,
// or mixes DNS with other UDP traffic on the same port. There it keeps the
// parent alive until every sub has finished. See doc.go for the broader
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

	dnsSenders map[packetrelay.PacketSender]struct{}

	closeChan    chan struct{}
	handler      packetrelay.PacketHandler
	handlerReady chan struct{}
}

// NewAssociation creates a new parent packet association.
// The returned PacketSender routes outgoing traffic to either the DNS relay or the default relay
// based on the destination address.
// Sub-associations are not created immediately; they are established lazily upon sending packets.
func (r *InterceptDNSPacketRelay) NewAssociation() (packetrelay.PacketSender, packetrelay.PacketReceiver, error) {
	a := &interceptAssoc{
		relay:           r,
		dnsSenders:      make(map[packetrelay.PacketSender]struct{}),
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
	if a.defSender != nil {
		a.defSender.Close()
	}
	for s := range a.dnsSenders {
		s.Close()
	}
}

func (a *interceptAssoc) handleDNSQuery(p []byte) error {
	a.mu.Lock()
	if a.isClosed {
		a.mu.Unlock()
		return packetrelay.ErrClosed
	}
	a.activeCount++
	a.mu.Unlock()

	sender, receiver, err := a.relay.dnsRelay.NewAssociation()
	if err != nil {
		a.Release()
		return err
	}

	a.mu.Lock()
	if a.isClosed {
		a.mu.Unlock()
		sender.Close()
		a.Release()
		return packetrelay.ErrClosed
	}
	a.dnsSenders[sender] = struct{}{}
	a.mu.Unlock()

	// Send the packet, rewritten to remote resolver
	err = sender.SendPacket(p, a.relay.dnsRemoteResolver)
	if err != nil {
		a.removeDNSSender(sender)
		sender.Close()
		a.Release()
		return err
	}

	go a.runDNSReceiver(sender, receiver)
	return nil
}

func (a *interceptAssoc) removeDNSSender(s packetrelay.PacketSender) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.dnsSenders, s)
}

func (a *interceptAssoc) runDNSReceiver(sender packetrelay.PacketSender, receiver packetrelay.PacketReceiver) {
	defer a.Release()
	defer sender.Close()
	defer a.removeDNSSender(sender)

	handler := &singlePacketHandler{assoc: a, sender: sender}
	_ = receiver.ReceivePackets(handler)
}

// singlePacketHandler receives the first response packet from a short-lived DNS sub-association,
// rewrites its source address back to the intercepted local resolver, and forwards it to the parent handler.
// To ensure the sub-association is truly short-lived, it immediately closes the sub-association's sender
// upon receiving the first packet, which unblocks and terminates the receiver.
type singlePacketHandler struct {
	assoc   *interceptAssoc
	sender  packetrelay.PacketSender
	handled atomic.Bool
}

// HandlePacket processes the incoming DNS response.
// It guarantees that only the very first packet is forwarded, ignoring any subsequent packets.
// It rewrites the source address and then explicitly closes the sender to tear down the short-lived sub-association.
func (h *singlePacketHandler) HandlePacket(p []byte, source netip.AddrPort) error {
	if !h.handled.CompareAndSwap(false, true) {
		return nil // Ignore subsequent packets
	}

	select {
	case <-h.assoc.handlerReady:
		// Rewrite source to local resolver
		err := h.assoc.handler.HandlePacket(p, h.assoc.relay.dnsLocalResolver)
		// Close the sender to terminate ReceivePackets
		h.sender.Close()
		return err
	case <-h.assoc.closeChan:
		return packetrelay.ErrClosed
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

// SendPacket routes the packet to the appropriate sub-relay.
// If the destination matches the intercepted DNS resolver, it creates a new short-lived association
// on the DNS relay, rewrites the destination, and forwards the packet.
// Otherwise, it lazily initializes and uses a single association on the default relay.
func (s *interceptSender) SendPacket(p []byte, destination netip.AddrPort) error {
	if isSameAddrPort(destination, s.a.relay.dnsLocalResolver) {
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

// Close terminates the parent association and immediately closes all active sub-associations,
// including the default association and any pending DNS query associations.
func (s *interceptSender) Close() error {
	return s.a.Close()
}

// interceptReceiver implements packetrelay.PacketReceiver
type interceptReceiver struct {
	a *interceptAssoc
}

var _ packetrelay.PacketReceiver = (*interceptReceiver)(nil)

// ReceivePackets blocks and passes incoming packets from all sub-associations back to the handler.
// Packets returned from the DNS relay will have their source address rewritten back to the intercepted local resolver.
// It returns when the parent association is explicitly closed or all active sub-associations have terminated.
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
		<-r.a.closeChan // Wait for any remaining DNS queries to terminate
	case <-r.a.closeChan:
	}
	return nil
}
