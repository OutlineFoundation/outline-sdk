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

	"golang.getoutline.org/sdk/dns"
	"golang.getoutline.org/sdk/network/packetrelay"
)

// NewPacketRelayExchanger creates a [dns.Exchanger] that sends each query to resolverAddr over
// a new, short-lived association on relay.
//
// The exchange is intentionally minimal, mirroring what a stub resolver does with a datagram
// socket: one association per query, the first datagram received wins, and the association is
// closed as soon as that datagram arrives. The datagram is returned as received; matching it
// against the query (see [RFC 5452]) is the caller's responsibility, and is usually done by the
// client that produced the query.
//
// The exchange has no timeout of its own: it ends when a datagram arrives, when the association
// terminates (which is how the relay's own idle timeout surfaces), or when ctx is done. Callers
// that need a deadline must put it in ctx.
//
// [RFC 5452]: https://datatracker.ietf.org/doc/html/rfc5452#section-4
func NewPacketRelayExchanger(relay packetrelay.PacketRelay, resolverAddr netip.AddrPort) dns.Exchanger {
	return dns.FuncExchanger(func(ctx context.Context, query []byte) ([]byte, error) {
		sender, receiver, err := relay.NewAssociation()
		if err != nil {
			return nil, err
		}
		defer sender.Close()

		// Closing the sender is what terminates ReceivePackets, so it's also how we honor ctx.
		stopOnDone := context.AfterFunc(ctx, func() { sender.Close() })
		defer stopOnDone()

		if err := sender.SendPacket(query, resolverAddr); err != nil {
			return nil, err
		}

		handler := &firstPacketHandler{sender: sender}
		_ = receiver.ReceivePackets(handler)

		response, ok := handler.response()
		if !ok {
			// No datagram arrived: either ctx is done, or the association went away.
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return nil, errors.New("association terminated before a response was received")
		}
		if len(response) == 0 {
			return nil, errors.New("received an empty response")
		}
		return response, nil
	})
}

// firstPacketHandler keeps the first datagram of an association and drops the rest, closing the
// sender as soon as that datagram arrives so the association doesn't outlive the exchange.
type firstPacketHandler struct {
	sender packetrelay.PacketSender

	mu       sync.Mutex
	received bool
	first    []byte
}

var _ packetrelay.PacketHandler = (*firstPacketHandler)(nil)

// HandlePacket implements [packetrelay.PacketHandler].
func (h *firstPacketHandler) HandlePacket(p []byte, source netip.AddrPort) error {
	h.mu.Lock()
	if h.received {
		h.mu.Unlock()
		return nil // Ignore subsequent packets.
	}
	h.received = true
	// p must not be referenced after HandlePacket returns.
	h.first = bytes.Clone(p)
	h.mu.Unlock()

	// Terminate the association, and with it ReceivePackets.
	h.sender.Close()
	return nil
}

// response returns the first datagram received, if any.
func (h *firstPacketHandler) response() ([]byte, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.first, h.received
}
