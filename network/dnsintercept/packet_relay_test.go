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
	"net/netip"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"golang.getoutline.org/sdk/network/packetrelay"
)

type packetData struct {
	p    []byte
	dest netip.AddrPort
}

type mockRelay struct {
	newAssocCount int
	senders       []*mockSender
}

func (r *mockRelay) NewAssociation() (packetrelay.PacketSender, packetrelay.PacketReceiver, error) {
	r.newAssocCount++
	sender := &mockSender{
		packets:  make(chan packetData, 100),
		receiver: &mockReceiver{packets: make(chan packetData, 100)},
	}
	r.senders = append(r.senders, sender)
	return sender, sender.receiver, nil
}

type mockSender struct {
	packets  chan packetData
	receiver *mockReceiver
	closed   atomic.Bool
}

func (s *mockSender) SendPacket(p []byte, destination netip.AddrPort) error {
	if s.closed.Load() {
		return packetrelay.ErrClosed
	}
	cpy := make([]byte, len(p))
	copy(cpy, p)
	select {
	case s.packets <- packetData{p: cpy, dest: destination}:
	default:
	}
	return nil
}

func (s *mockSender) Close() error {
	if s.closed.Swap(true) {
		return packetrelay.ErrClosed
	}
	close(s.receiver.packets)
	return nil
}

func (s *mockSender) IsClosed() bool {
	return s.closed.Load()
}

type mockReceiver struct {
	packets chan packetData
}

func (r *mockReceiver) ReceivePackets(handler packetrelay.PacketHandler) error {
	for pd := range r.packets {
		if err := handler.HandlePacket(pd.p, pd.dest); err != nil {
			return err
		}
	}
	return nil
}

func (r *mockReceiver) PushResponse(p []byte, source netip.AddrPort) {
	cpy := make([]byte, len(p))
	copy(cpy, p)
	r.packets <- packetData{p: cpy, dest: source}
}

type mockHandler struct {
	packets chan packetData
}

func (h *mockHandler) HandlePacket(p []byte, source netip.AddrPort) error {
	cpy := make([]byte, len(p))
	copy(cpy, p)
	h.packets <- packetData{p: cpy, dest: source}
	return nil
}

// blockingMockRelay blocks NewAssociation until its ch is closed.
type blockingMockRelay struct {
	ch chan struct{}
}

func (r *blockingMockRelay) NewAssociation() (packetrelay.PacketSender, packetrelay.PacketReceiver, error) {
	<-r.ch
	sender := &mockSender{
		packets:  make(chan packetData, 100),
		receiver: &mockReceiver{packets: make(chan packetData, 100)},
	}
	return sender, sender.receiver, nil
}

func TestDNSQueryRouting(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dnsRelay := &mockRelay{}
		defaultRelay := &mockRelay{}
		localRes := netip.MustParseAddrPort("10.0.0.1:53")
		remoteRes := netip.MustParseAddrPort("8.8.8.8:53")
		relay := NewInterceptDNSPacketRelay(dnsRelay, defaultRelay, localRes, remoteRes)

		sender, receiver, err := relay.NewAssociation()
		if err != nil {
			t.Fatalf("NewAssociation failed: %v", err)
		}

		handler := &mockHandler{packets: make(chan packetData, 10)}
		go receiver.ReceivePackets(handler)

		reqData := []byte("dns_query")
		if err := sender.SendPacket(reqData, localRes); err != nil {
			t.Fatalf("SendPacket failed: %v", err)
		}
		synctest.Wait()

		if dnsRelay.newAssocCount != 1 {
			t.Fatalf("Expected 1 DNS association, got %d", dnsRelay.newAssocCount)
		}
		if defaultRelay.newAssocCount != 0 {
			t.Fatalf("Expected 0 default associations, got %d", defaultRelay.newAssocCount)
		}

		dnsSender := dnsRelay.senders[0]
		pd := <-dnsSender.packets
		if !bytes.Equal(pd.p, reqData) {
			t.Errorf("Expected packet %q, got %q", reqData, pd.p)
		}
		if pd.dest != remoteRes {
			t.Errorf("Expected dest %v, got %v", remoteRes, pd.dest)
		}

		respData := []byte("dns_response")
		dnsSender.receiver.PushResponse(respData, remoteRes)
		synctest.Wait()

		resp := <-handler.packets
		if !bytes.Equal(resp.p, respData) {
			t.Errorf("Expected response %q, got %q", respData, resp.p)
		}
		if resp.dest != localRes {
			t.Errorf("Expected rewritten source %v, got %v", localRes, resp.dest)
		}
		if !dnsSender.IsClosed() {
			t.Errorf("Expected DNS sender to be closed after one response")
		}
	})
}

func TestDNSQueryRoutingWithIPv4MappedLocalResolver(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dnsRelay := &mockRelay{}
		defaultRelay := &mockRelay{}
		localRes := netip.MustParseAddrPort("10.0.0.1:53")
		remoteRes := netip.MustParseAddrPort("8.8.8.8:53")
		relay := NewInterceptDNSPacketRelay(dnsRelay, defaultRelay, localRes, remoteRes)

		sender, receiver, err := relay.NewAssociation()
		if err != nil {
			t.Fatalf("NewAssociation failed: %v", err)
		}

		handler := &mockHandler{packets: make(chan packetData, 10)}
		go receiver.ReceivePackets(handler)

		reqData := []byte("dns_query")
		mappedLocalRes := netip.MustParseAddrPort("[::ffff:10.0.0.1]:53")
		if err := sender.SendPacket(reqData, mappedLocalRes); err != nil {
			t.Fatalf("SendPacket failed: %v", err)
		}
		synctest.Wait()

		if dnsRelay.newAssocCount != 1 {
			t.Fatalf("Expected 1 DNS association, got %d", dnsRelay.newAssocCount)
		}
		if defaultRelay.newAssocCount != 0 {
			t.Fatalf("Expected 0 default associations, got %d", defaultRelay.newAssocCount)
		}

		dnsSender := dnsRelay.senders[0]
		pd := <-dnsSender.packets
		if !bytes.Equal(pd.p, reqData) {
			t.Errorf("Expected packet %q, got %q", reqData, pd.p)
		}
		if pd.dest != remoteRes {
			t.Errorf("Expected dest %v, got %v", remoteRes, pd.dest)
		}

		respData := []byte("dns_response")
		dnsSender.receiver.PushResponse(respData, remoteRes)
		synctest.Wait()

		resp := <-handler.packets
		if !bytes.Equal(resp.p, respData) {
			t.Errorf("Expected response %q, got %q", respData, resp.p)
		}
		if resp.dest != localRes {
			t.Errorf("Expected rewritten source %v, got %v", localRes, resp.dest)
		}
		if !dnsSender.IsClosed() {
			t.Errorf("Expected DNS sender to be closed after one response")
		}
	})
}

func TestDefaultRouting(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dnsRelay := &mockRelay{}
		defaultRelay := &mockRelay{}
		localRes := netip.MustParseAddrPort("10.0.0.1:53")
		remoteRes := netip.MustParseAddrPort("8.8.8.8:53")
		relay := NewInterceptDNSPacketRelay(dnsRelay, defaultRelay, localRes, remoteRes)

		sender, receiver, err := relay.NewAssociation()
		if err != nil {
			t.Fatalf("NewAssociation failed: %v", err)
		}

		handler := &mockHandler{packets: make(chan packetData, 10)}
		go receiver.ReceivePackets(handler)

		otherDest := netip.MustParseAddrPort("192.168.1.1:80")
		reqData := []byte("other_data")
		if err := sender.SendPacket(reqData, otherDest); err != nil {
			t.Fatalf("SendPacket failed: %v", err)
		}
		synctest.Wait()

		if defaultRelay.newAssocCount != 1 {
			t.Fatalf("Expected 1 default association, got %d", defaultRelay.newAssocCount)
		}

		defSender := defaultRelay.senders[0]
		pd := <-defSender.packets
		if !bytes.Equal(pd.p, reqData) {
			t.Errorf("Expected packet %q, got %q", reqData, pd.p)
		}
		if pd.dest != otherDest {
			t.Errorf("Expected dest %v, got %v", otherDest, pd.dest)
		}

		respData := []byte("other_resp")
		defSender.receiver.PushResponse(respData, otherDest)
		synctest.Wait()

		resp := <-handler.packets
		if !bytes.Equal(resp.p, respData) {
			t.Errorf("Expected response %q, got %q", respData, resp.p)
		}
		if resp.dest != otherDest {
			t.Errorf("Expected source %v, got %v", otherDest, resp.dest)
		}
		if defSender.IsClosed() {
			t.Errorf("Expected default sender to remain open after response")
		}

		sender.Close()
		synctest.Wait()
		if !defSender.IsClosed() {
			t.Errorf("Expected default sender to be closed when parent is closed")
		}
	})
}

func TestAutoCloseOnZeroSubAssociations(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dnsRelay := &mockRelay{}
		defaultRelay := &mockRelay{}
		localRes := netip.MustParseAddrPort("10.0.0.1:53")
		remoteRes := netip.MustParseAddrPort("8.8.8.8:53")
		relay := NewInterceptDNSPacketRelay(dnsRelay, defaultRelay, localRes, remoteRes)

		sender, receiver, _ := relay.NewAssociation()

		handler := &mockHandler{packets: make(chan packetData, 10)}
		receiveDone := make(chan error, 1)
		go func() {
			receiveDone <- receiver.ReceivePackets(handler)
		}()

		sender.SendPacket([]byte("q1"), localRes)
		synctest.Wait()

		dnsSender := dnsRelay.senders[0]
		<-dnsSender.packets

		dnsSender.receiver.PushResponse([]byte("r1"), remoteRes)
		synctest.Wait()

		// DNS response delivered, sub-association closed, activeCount → 0, auto-close triggered
		select {
		case err := <-receiveDone:
			if err != nil {
				t.Errorf("Expected nil error from ReceivePackets, got %v", err)
			}
		default:
			t.Fatalf("ReceivePackets should have returned after auto-close")
		}

		err := sender.SendPacket([]byte("q2"), localRes)
		if err != packetrelay.ErrClosed {
			t.Errorf("Expected ErrClosed after auto-close, got %v", err)
		}
	})
}

// TestCloseWhileDefaultInitializing verifies that Close() correctly wakes goroutines
// blocked in cond.Wait() inside getOrCreateDefaultSender. Without the cond.Broadcast()
// call in closeLocked(), G2 would deadlock.
func TestCloseWhileDefaultInitializing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		blockCh := make(chan struct{})
		dnsRelay := &mockRelay{}
		defaultRelay := &blockingMockRelay{ch: blockCh}
		localRes := netip.MustParseAddrPort("10.0.0.1:53")
		remoteRes := netip.MustParseAddrPort("8.8.8.8:53")
		relay := NewInterceptDNSPacketRelay(dnsRelay, defaultRelay, localRes, remoteRes)

		sender, _, _ := relay.NewAssociation()
		otherDest := netip.MustParseAddrPort("192.168.1.1:80")
		results := make(chan error, 2)

		// G1: calls NewAssociation on the blocking relay, blocks on blockCh
		go func() {
			results <- sender.SendPacket([]byte("p1"), otherDest)
		}()
		synctest.Wait() // G1 is durably blocked in defaultRelay.NewAssociation (<-blockCh)

		// G2: sees stateInitializing, blocks in cond.Wait()
		go func() {
			results <- sender.SendPacket([]byte("p2"), otherDest)
		}()
		synctest.Wait() // G2 is durably blocked in cond.Wait()

		// Close while both goroutines are stuck — cond.Broadcast() must wake G2
		sender.Close()
		close(blockCh) // unblock G1's NewAssociation call
		synctest.Wait()

		for i := 0; i < 2; i++ {
			select {
			case err := <-results:
				if err != packetrelay.ErrClosed {
					t.Errorf("Expected ErrClosed, got %v", err)
				}
			default:
				t.Errorf("Expected result %d in channel", i)
			}
		}
		_ = remoteRes
	})
}

// TestMultipleDNSQueries verifies that concurrent DNS queries each get their own
// sub-association and all receive their responses correctly.
func TestMultipleDNSQueries(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dnsRelay := &mockRelay{}
		defaultRelay := &mockRelay{}
		localRes := netip.MustParseAddrPort("10.0.0.1:53")
		remoteRes := netip.MustParseAddrPort("8.8.8.8:53")
		relay := NewInterceptDNSPacketRelay(dnsRelay, defaultRelay, localRes, remoteRes)

		sender, receiver, _ := relay.NewAssociation()
		handler := &mockHandler{packets: make(chan packetData, 10)}
		go receiver.ReceivePackets(handler)

		queries := [][]byte{[]byte("query0"), []byte("query1"), []byte("query2")}
		for _, q := range queries {
			if err := sender.SendPacket(q, localRes); err != nil {
				t.Fatalf("SendPacket failed: %v", err)
			}
		}
		synctest.Wait()

		if dnsRelay.newAssocCount != len(queries) {
			t.Fatalf("Expected %d DNS associations, got %d", len(queries), dnsRelay.newAssocCount)
		}

		for i, s := range dnsRelay.senders {
			resp := []byte{byte('A' + i)}
			s.receiver.PushResponse(resp, remoteRes)
		}
		synctest.Wait()

		for range queries {
			select {
			case pd := <-handler.packets:
				if pd.dest != localRes {
					t.Errorf("Expected rewritten source %v, got %v", localRes, pd.dest)
				}
			default:
				t.Fatalf("Missing response in handler")
			}
		}
	})
}

// TestResponseBeforeReceivePackets verifies that a DNS response arriving before
// ReceivePackets is called is correctly buffered via handlerReady and delivered
// once the handler is registered.
func TestResponseBeforeReceivePackets(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dnsRelay := &mockRelay{}
		defaultRelay := &mockRelay{}
		localRes := netip.MustParseAddrPort("10.0.0.1:53")
		remoteRes := netip.MustParseAddrPort("8.8.8.8:53")
		relay := NewInterceptDNSPacketRelay(dnsRelay, defaultRelay, localRes, remoteRes)

		sender, receiver, _ := relay.NewAssociation()

		// Send DNS query before calling ReceivePackets
		if err := sender.SendPacket([]byte("dns_query"), localRes); err != nil {
			t.Fatalf("SendPacket failed: %v", err)
		}
		synctest.Wait() // DNS receiver goroutine is blocked on r.packets

		dnsRelay.senders[0].receiver.PushResponse([]byte("dns_response"), remoteRes)
		synctest.Wait() // DNS receiver goroutine is now blocked on handlerReady select

		// Register the handler now — should unblock the DNS receiver goroutine
		handler := &mockHandler{packets: make(chan packetData, 10)}
		go receiver.ReceivePackets(handler)
		synctest.Wait()

		resp := <-handler.packets
		if !bytes.Equal(resp.p, []byte("dns_response")) {
			t.Errorf("Expected dns_response, got %q", resp.p)
		}
		if resp.dest != localRes {
			t.Errorf("Expected rewritten source %v, got %v", localRes, resp.dest)
		}
	})
}

func BenchmarkDNSQueryRouting(b *testing.B) {
	dnsRelay := &mockRelay{}
	defaultRelay := &mockRelay{}

	localRes := netip.MustParseAddrPort("10.0.0.1:53")
	remoteRes := netip.MustParseAddrPort("8.8.8.8:53")

	relay := NewInterceptDNSPacketRelay(dnsRelay, defaultRelay, localRes, remoteRes)

	reqData := []byte("dns_query")
	respData := []byte("dns_response")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sender, receiver, _ := relay.NewAssociation()
		handler := &mockHandler{packets: make(chan packetData, 1)}
		go receiver.ReceivePackets(handler)

		sender.SendPacket(reqData, localRes)
		dnsSender := dnsRelay.senders[len(dnsRelay.senders)-1]
		<-dnsSender.packets

		dnsSender.receiver.PushResponse(respData, remoteRes)
		<-handler.packets
	}
}

func BenchmarkDefaultRouting(b *testing.B) {
	dnsRelay := &mockRelay{}
	defaultRelay := &mockRelay{}

	localRes := netip.MustParseAddrPort("10.0.0.1:53")
	remoteRes := netip.MustParseAddrPort("8.8.8.8:53")

	relay := NewInterceptDNSPacketRelay(dnsRelay, defaultRelay, localRes, remoteRes)

	sender, _, _ := relay.NewAssociation()
	otherDest := netip.MustParseAddrPort("192.168.1.1:80")
	reqData := []byte("other_data")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sender.SendPacket(reqData, otherDest)
	}
}
