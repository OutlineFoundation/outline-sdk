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

package dnstruncate

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"

	"golang.getoutline.org/sdk/network"
	"golang.getoutline.org/sdk/network/packetrelay"
)

// From [RFC 1035], the DNS message header contains the following fields:
//
//		                              1  1  1  1  1  1
//		0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//
//	 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	 |                      ID                       |
//	 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	 |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
//	 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	 |                    QDCOUNT                    |
//	 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	 |                    ANCOUNT                    |
//	 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	 |                    NSCOUNT                    |
//	 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	 |                    ARCOUNT                    |
//	 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
// [RFC 1035]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
const (
	standardDNSPort = uint16(53) // https://datatracker.ietf.org/doc/html/rfc1035#section-4.2
	dnsUdpMinMsgLen = 12         // A DNS message must at least contain the header
	dnsUdpMaxMsgLen = 512        // https://datatracker.ietf.org/doc/html/rfc1035#section-2.3.4

	dnsUdpAnswerByte   = 2           // The byte in the header containing QR and TC bit
	dnsUdpResponseBit  = uint8(0x80) // The QR bit within dnsUdpAnswerByte
	dnsUdpTruncatedBit = uint8(0x02) // The TC bit within dnsUdpAnswerByte
	dnsUdpRCodeByte    = 3           // The byte in the header containing RCODE
	dnsUdpRCodeMask    = uint8(0x0f) // The RCODE bits within dnsUdpRCodeByte
	dnsQDCntStartByte  = 4           // The starting byte of QDCOUNT
	dnsQDCntEndByte    = 5           // The ending byte (inclusive) of QDCOUNT
	dnsARCntStartByte  = 6           // The starting byte of ANCOUNT
	dnsARCntEndByte    = 7           // The ending byte (inclusive) of ANCOUNT
)

// dnsTruncateProxy is a network.PacketRelay that creates dnsTruncateSender to handle DNS requests locally.
//
// Multiple goroutines may invoke methods on a dnsTruncateProxy simultaneously.
type dnsTruncateProxy struct{}

type dnsPacket struct {
	payload []byte
	source  netip.AddrPort
}

// dnsTruncateSender is a network.PacketSender that handles DNS requests in UDP protocol locally,
// without sending the requests to the actual DNS resolver. It sets the TC (truncated) bit in the DNS response header
// to tell the caller to resend the DNS request over TCP.
type dnsTruncateSender struct {
	mu     sync.Mutex
	closed bool
	ch     chan dnsPacket
}

type dnsTruncateReceiver struct {
	ch chan dnsPacket
}

// Compilation guard against interface implementation
var _ packetrelay.PacketRelay = (*dnsTruncateProxy)(nil)
var _ packetrelay.PacketSender = (*dnsTruncateSender)(nil)
var _ packetrelay.PacketReceiver = (*dnsTruncateReceiver)(nil)

// NewPacketRelay creates a new [packetrelay.PacketRelay] that can be used to handle DNS requests if the remote proxy
// doesn't support UDP traffic. It sets the TC (truncated) bit in the DNS response header to tell the caller to resend
// the DNS request over TCP.
//
// This [packetrelay.PacketRelay] should only be used if the remote proxy server doesn't support UDP traffic at all. Note
// that all other non-DNS UDP packets will be dropped by this [packetrelay.PacketRelay].
func NewPacketRelay() (packetrelay.PacketRelay, error) {
	return &dnsTruncateProxy{}, nil
}

// NewPacketProxy creates a new [network.PacketProxy] that can be used to handle DNS requests if the remote proxy
// doesn't support UDP traffic. It sets the TC (truncated) bit in the DNS response header to tell the caller to resend
// the DNS request over TCP.
//
// Deprecated: Use [NewPacketRelay] instead.
func NewPacketProxy() (network.PacketProxy, error) {
	relay, err := NewPacketRelay()
	if err != nil {
		return nil, err
	}
	return network.NewPacketProxyFromPacketRelay(relay), nil
}

// NewAssociation implements [packetrelay.PacketRelay].NewAssociation(). It creates a new [packetrelay.PacketSender] and
// [packetrelay.PacketReceiver] that will set the TC (truncated) bit on incoming DNS requests and yield the response.
func (p *dnsTruncateProxy) NewAssociation() (packetrelay.PacketSender, packetrelay.PacketReceiver, error) {
	// Buffer size of 16 is a reasonable trade-off for local DNS truncation
	ch := make(chan dnsPacket, 16)
	sender := &dnsTruncateSender{
		ch: ch,
	}
	receiver := &dnsTruncateReceiver{
		ch: ch,
	}
	return sender, receiver, nil
}

// Close implements [packetrelay.PacketSender].Close(), and it closes the corresponding
// [packetrelay.PacketReceiver] channel.
func (s *dnsTruncateSender) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return packetrelay.ErrClosed
	}
	s.closed = true
	close(s.ch)
	return nil
}

// SendPacket implements [packetrelay.PacketSender].SendPacket(). It parses a packet from p, and determines whether it is
// a valid DNS request. If so, it will push a DNS response with TC (truncated) bit set to the receiver.
func (s *dnsTruncateSender) SendPacket(p []byte, destination netip.AddrPort) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return packetrelay.ErrClosed
	}

	if destination.Port() != standardDNSPort {
		return fmt.Errorf("UDP traffic to non-DNS port %v is not supported: %w", destination.Port(), network.ErrPortUnreachable)
	}
	if len(p) < dnsUdpMinMsgLen {
		return fmt.Errorf("invalid DNS message of length %v, it must be at least %v bytes", len(p), dnsUdpMinMsgLen)
	}

	// We need to copy p into a new buffer because we pass it through a channel
	buf := make([]byte, len(p))
	copy(buf, p)

	// Set "Response", "Truncated" and "NoError"
	buf[dnsUdpAnswerByte] |= (dnsUdpResponseBit | dnsUdpTruncatedBit)
	buf[dnsUdpRCodeByte] &= ^dnsUdpRCodeMask

	// Copy QDCOUNT to ANCOUNT. This is an incorrect workaround for some DNS clients (such as Windows 7);
	// because without these clients won't retry over TCP.
	copy(buf[dnsARCntStartByte:dnsARCntEndByte+1], buf[dnsQDCntStartByte:dnsQDCntEndByte+1])

	// Push to channel inside the lock using select with default to avoid deadlocks
	select {
	case s.ch <- dnsPacket{payload: buf, source: destination}:
		return nil
	default:
		// Queue is full!
		return errors.New("DNS truncation queue full")
	}
}

// ReceivePackets implements [packetrelay.PacketReceiver].ReceivePackets. It blocks and passes incoming DNS responses
// to the handler.
func (r *dnsTruncateReceiver) ReceivePackets(handler packetrelay.PacketHandler) error {
	for pkt := range r.ch {
		if err := handler.HandlePacket(pkt.payload, pkt.source); err != nil {
			return err
		}
	}
	return nil
}
