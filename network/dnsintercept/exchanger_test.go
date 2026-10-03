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
	"net/netip"
	"sync"
	"testing"

	"golang.getoutline.org/sdk/network/packetrelay"
)

var testResolverAddr = netip.MustParseAddrPort("8.8.8.8:53")

// scriptedRelay creates associations that reply with a fixed list of datagrams, delivered
// synchronously from ReceivePackets, and then block until the association is closed.
type scriptedRelay struct {
	responses [][]byte
	newErr    error
	// created, if not nil, receives every new association.
	created chan *scriptedAssoc

	mu     sync.Mutex
	assocs []*scriptedAssoc
}

func (r *scriptedRelay) NewAssociation() (packetrelay.PacketSender, packetrelay.PacketReceiver, error) {
	if r.newErr != nil {
		return nil, nil, r.newErr
	}
	a := &scriptedAssoc{relay: r, closedCh: make(chan struct{})}
	r.mu.Lock()
	r.assocs = append(r.assocs, a)
	r.mu.Unlock()
	select {
	case r.created <- a:
	default:
	}
	return a, a, nil
}

func (r *scriptedRelay) assoc(i int) *scriptedAssoc {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.assocs[i]
}

func (r *scriptedRelay) assocCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.assocs)
}

type scriptedAssoc struct {
	relay    *scriptedRelay
	closedCh chan struct{}

	mu     sync.Mutex
	sent   []packetData
	closed bool
}

var _ packetrelay.PacketSender = (*scriptedAssoc)(nil)
var _ packetrelay.PacketReceiver = (*scriptedAssoc)(nil)

func (a *scriptedAssoc) SendPacket(p []byte, destination netip.AddrPort) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return packetrelay.ErrClosed
	}
	a.sent = append(a.sent, packetData{p: bytes.Clone(p), dest: destination})
	return nil
}

func (a *scriptedAssoc) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return packetrelay.ErrClosed
	}
	a.closed = true
	close(a.closedCh)
	return nil
}

func (a *scriptedAssoc) IsClosed() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.closed
}

func (a *scriptedAssoc) sentPackets() []packetData {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]packetData(nil), a.sent...)
}

// ReceivePackets delivers every scripted datagram, even after the handler closes the
// association, so that we can tell whether the handler ignores the extra ones.
func (a *scriptedAssoc) ReceivePackets(handler packetrelay.PacketHandler) error {
	for _, response := range a.relay.responses {
		if err := handler.HandlePacket(response, testResolverAddr); err != nil {
			return err
		}
	}
	<-a.closedCh
	return packetrelay.ErrClosed
}

func TestPacketRelayExchangerFirstDatagramWins(t *testing.T) {
	relay := &scriptedRelay{responses: [][]byte{[]byte("first"), []byte("second")}}
	exchanger := NewPacketRelayExchanger(relay, testResolverAddr)

	response, err := exchanger.Exchange(t.Context(), []byte("query"))
	if err != nil {
		t.Fatalf("Exchange failed: %v", err)
	}
	if !bytes.Equal(response, []byte("first")) {
		t.Errorf("Expected response %q, got %q", "first", response)
	}

	if got := relay.assocCount(); got != 1 {
		t.Fatalf("Expected 1 association, got %d", got)
	}
	assoc := relay.assoc(0)
	sent := assoc.sentPackets()
	if len(sent) != 1 {
		t.Fatalf("Expected 1 sent packet, got %d", len(sent))
	}
	if !bytes.Equal(sent[0].p, []byte("query")) {
		t.Errorf("Expected query %q, got %q", "query", sent[0].p)
	}
	if sent[0].dest != testResolverAddr {
		t.Errorf("Expected destination %v, got %v", testResolverAddr, sent[0].dest)
	}
	if !assoc.IsClosed() {
		t.Errorf("Expected the sub-association to be closed after the response")
	}
}

func TestPacketRelayExchangerEmptyResponse(t *testing.T) {
	relay := &scriptedRelay{responses: [][]byte{{}}}
	exchanger := NewPacketRelayExchanger(relay, testResolverAddr)

	response, err := exchanger.Exchange(t.Context(), []byte("query"))
	if err == nil {
		t.Fatalf("Expected an error for an empty response, got %q", response)
	}
	if !relay.assoc(0).IsClosed() {
		t.Errorf("Expected the sub-association to be closed")
	}
}

func TestPacketRelayExchangerAssociationClosed(t *testing.T) {
	relay := &scriptedRelay{created: make(chan *scriptedAssoc, 1)}
	exchanger := NewPacketRelayExchanger(relay, testResolverAddr)

	type result struct {
		response []byte
		err      error
	}
	results := make(chan result, 1)
	go func() {
		response, err := exchanger.Exchange(context.Background(), []byte("query"))
		results <- result{response, err}
	}()

	// Terminate the association without a response.
	(<-relay.created).Close()

	res := <-results
	if res.err == nil {
		t.Fatalf("Expected an error, got response %q", res.response)
	}
	if errors.Is(res.err, context.Canceled) {
		t.Errorf("Expected an association error, got %v", res.err)
	}
}

func TestPacketRelayExchangerContextCanceled(t *testing.T) {
	relay := &scriptedRelay{created: make(chan *scriptedAssoc, 1)}
	exchanger := NewPacketRelayExchanger(relay, testResolverAddr)
	ctx, cancel := context.WithCancel(context.Background())

	errs := make(chan error, 1)
	go func() {
		_, err := exchanger.Exchange(ctx, []byte("query"))
		errs <- err
	}()

	assoc := <-relay.created
	cancel()

	if err := <-errs; !errors.Is(err, context.Canceled) {
		t.Errorf("Expected context.Canceled, got %v", err)
	}
	if !assoc.IsClosed() {
		t.Errorf("Expected the sub-association to be closed on cancellation")
	}
}

func TestPacketRelayExchangerNewAssociationError(t *testing.T) {
	expected := errors.New("no association for you")
	exchanger := NewPacketRelayExchanger(&scriptedRelay{newErr: expected}, testResolverAddr)

	if _, err := exchanger.Exchange(t.Context(), []byte("query")); !errors.Is(err, expected) {
		t.Errorf("Expected %v, got %v", expected, err)
	}
}
