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

package quicprelude

import "encoding/binary"

// Long packet types, from bits 4 and 5 of the first byte. QUIC v2 rotates them,
// so the same bits mean different packets in the two versions.
const (
	v1InitialType   = 0b00
	v1HandshakeType = 0b10
	v2InitialType   = 0b01
	v2HandshakeType = 0b11
)

// mayCarryClientHello reports whether a datagram a client is sending may carry
// its TLS ClientHello, and so a Server Name Indication a filter could read. Only
// those datagrams get a prelude.
//
// A client sends several Initial packets on a connection, and a socket can carry
// several connections. The ones with a ClientHello are the first flight, the
// second half of a ClientHello too large for one packet, retransmissions, and
// the resend after a Retry, a TLS HelloRetryRequest, or Version Negotiation. A
// filter can read a name out of any of them. The others only acknowledge the
// server's Initial, and carry nothing to read.
//
// Telling the two apart for certain means decrypting the Initial, since the
// frames are protected. This reads the header instead. Some stacks coalesce the
// acknowledgment with the client's first Handshake packet, and a ClientHello
// rarely travels that way: Handshake keys only exist once the server has
// answered the ClientHello, by which point the flow has already been judged. So
// an Initial followed by a Handshake packet is skipped, and any other Initial
// gets a prelude.
//
// QUIC-Go v0.48 does not coalesce. It sends the acknowledgment as its own padded
// Initial, which therefore gets a prelude it does not need: one extra datagram
// per handshake. With Go 1.25's default post-quantum key share the ClientHello
// also spans two Initials, so a handshake sends three preludes, two of them
// useful. For an Initial that parses, the rule errs only in that direction.
//
// An Initial whose header does not parse is skipped. Its lengths point past the
// end of the datagram, which no QUIC stack sends and no server can process, so
// no handshake follows it and a prelude would protect nothing. Datagrams that
// merely look like a long header, without being QUIC, usually fail here too.
//
// Datagrams shorter than [MinimumInitialLength] are skipped first. RFC 9000
// section 14.1 requires a client to pad every datagram carrying an Initial to
// at least that size, so no compliant client sends a ClientHello in a shorter
// one. The check matters because the header test alone is loose: any datagram
// whose first byte has the top bit set passes as a long header, and its next
// four bytes are read as a version. A DNS query sent without Recursion Desired,
// with a transaction ID ending in 0xff, reads as a draft-range Initial one time
// in eight, and nothing after it looks like a Handshake packet, which would
// earn it a prelude. DNS queries, like most traffic that is not QUIC, are far
// shorter than 1200 bytes.
//
// Packets that are not a client Initial of a version this recognizes are
// skipped. That includes everything that is not QUIC, such as a DNS query on
// the same socket.
func mayCarryClientHello(p []byte) bool {
	if len(p) < MinimumInitialLength {
		return false
	}
	version, ok := longHeaderVersion(p)
	if !ok {
		return false
	}
	initialType, handshakeType, ok := packetTypes(version)
	if !ok || longPacketType(p[0]) != initialType {
		return false
	}
	end, ok := longPacketEnd(p)
	if !ok {
		return false
	}
	if end == len(p) {
		return true
	}
	next := p[end:]
	nextVersion, ok := longHeaderVersion(next)
	if !ok || nextVersion != version {
		return true
	}
	return longPacketType(next[0]) != handshakeType
}

// longHeaderVersion returns the version of a long-header packet. The Fixed Bit
// is not checked, since RFC 9287 lets endpoints grease it.
func longHeaderVersion(p []byte) (uint32, bool) {
	if len(p) < 5 || p[0]&0x80 == 0 {
		return 0, false
	}
	return binary.BigEndian.Uint32(p[1:5]), true
}

// packetTypes returns the Initial and Handshake type bits for versions whose
// header layout is known: QUIC v1, the IETF drafts that preceded it, and QUIC
// v2. Version Negotiation, version 0, is sent only by servers.
func packetTypes(version uint32) (initial, handshake byte, ok bool) {
	switch {
	case version == Version1, version&0xffffff00 == draftPrefix:
		return v1InitialType, v1HandshakeType, true
	case version == Version2:
		return v2InitialType, v2HandshakeType, true
	default:
		return 0, 0, false
	}
}

func longPacketType(firstByte byte) byte {
	return (firstByte >> 4) & 0b11
}

// longPacketEnd returns the offset just past an Initial packet, where a
// coalesced packet would begin. It reports false if the header does not parse.
func longPacketEnd(p []byte) (int, bool) {
	offset := 5
	// Destination and Source Connection IDs, each preceded by its length.
	for range 2 {
		if offset >= len(p) {
			return 0, false
		}
		offset += 1 + int(p[offset])
	}
	tokenLength, n, ok := readVarint(p, offset)
	if !ok {
		return 0, false
	}
	offset += n
	if tokenLength > uint64(len(p)-offset) {
		return 0, false
	}
	offset += int(tokenLength)
	length, n, ok := readVarint(p, offset)
	if !ok {
		return 0, false
	}
	offset += n
	if length > uint64(len(p)-offset) {
		return 0, false
	}
	return offset + int(length), true
}

// readVarint decodes the QUIC variable-length integer at offset, returning it
// and the number of bytes it occupied.
func readVarint(p []byte, offset int) (value uint64, n int, ok bool) {
	if offset >= len(p) {
		return 0, 0, false
	}
	n = 1 << (p[offset] >> 6)
	if len(p)-offset < n {
		return 0, 0, false
	}
	value = uint64(p[offset] & 0x3f)
	for _, b := range p[offset+1 : offset+n] {
		value = value<<8 | uint64(b)
	}
	return value, n, true
}
