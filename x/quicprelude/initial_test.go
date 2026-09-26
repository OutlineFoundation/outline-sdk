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

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

// First bytes of long-header packets, with the Header Form and Fixed Bit set.
const (
	v1Initial   byte = 0xc0
	v1ZeroRTT   byte = 0xd0
	v1Handshake byte = 0xe0
	v1Retry     byte = 0xf0
	v2Retry     byte = 0xc0
	v2Initial   byte = 0xd0
	v2ZeroRTT   byte = 0xe0
	v2Handshake byte = 0xf0
)

// longPacket builds a long-header packet with 8-byte connection IDs and
// payloadLength zero bytes. Only Initial packets carry a token field, and it is
// left empty, so an Initial's header is initialHeaderLength bytes.
func longPacket(firstByte byte, version uint32, payloadLength int) []byte {
	p := []byte{firstByte, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(p[1:5], version)
	p = append(p, 8, 1, 2, 3, 4, 5, 6, 7, 8)
	p = append(p, 8, 9, 10, 11, 12, 13, 14, 15, 16)
	initial := (version == Version2 && firstByte&0x30 == 0x10) ||
		(version != Version2 && firstByte&0x30 == 0)
	if initial {
		p = append(p, 0)
	}
	p = binary.BigEndian.AppendUint16(p, uint16(payloadLength)|0x4000)
	return append(p, make([]byte, payloadLength)...)
}

const initialHeaderLength = 26

// clientInitial builds a datagram of length bytes holding one v1 Initial, as a
// client's first flight would.
func clientInitial(length int) []byte {
	return longPacket(v1Initial, Version1, length-initialHeaderLength)
}

// dnsQuery builds a DNS query for example.com with the given transaction ID and
// flags, with an EDNS OPT record as most resolvers send.
func dnsQuery(id, flags uint16) []byte {
	p := binary.BigEndian.AppendUint16(nil, id)
	p = binary.BigEndian.AppendUint16(p, flags)
	p = append(p, 0, 1, 0, 0, 0, 0, 0, 1) // one question, one additional record
	p = append(p, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1)
	return append(p, 0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0) // OPT, 1232-byte UDP payload
}

func coalesce(packets ...[]byte) []byte {
	var p []byte
	for _, packet := range packets {
		p = append(p, packet...)
	}
	return p
}

func TestMayCarryClientHello(t *testing.T) {
	for _, tc := range []struct {
		name   string
		packet []byte
		want   bool
	}{
		// Datagrams that may carry a ClientHello. All are at least
		// MinimumInitialLength, so the other checks are what they test.
		{"v1 Initial", clientInitial(1200), true},
		{"v2 Initial", longPacket(v2Initial, Version2, 1200), true},
		{"draft-29 Initial", longPacket(v1Initial, 0xff00001d, 1200), true},
		{"Initial with padding after it", append(longPacket(v1Initial, Version1, 900), make([]byte, 300)...), true},
		{"Initial coalesced with 0-RTT", coalesce(longPacket(v1Initial, Version1, 1100), longPacket(v1ZeroRTT, Version1, 100)), true},
		{"v2 Initial coalesced with 0-RTT", coalesce(longPacket(v2Initial, Version2, 1100), longPacket(v2ZeroRTT, Version2, 100)), true},
		{"Initial followed by another version's Handshake", coalesce(longPacket(v1Initial, Version1, 1100), longPacket(v2Handshake, Version2, 100)), true},
		{"Initial with a Fixed Bit greased to zero", longPacket(0x80, Version1, 1200), true},

		// Initials that only acknowledge the server's, coalesced with Handshake.
		{"v1 Initial coalesced with Handshake", coalesce(longPacket(v1Initial, Version1, 100), longPacket(v1Handshake, Version1, 1100)), false},
		{"v2 Initial coalesced with Handshake", coalesce(longPacket(v2Initial, Version2, 100), longPacket(v2Handshake, Version2, 1100)), false},

		// Datagrams too short to carry an Initial under RFC 9000 section 14.1.
		{"v1 Initial one byte short", clientInitial(MinimumInitialLength - 1), false},
		{"Initial truncated inside its header", clientInitial(1200)[:10], false},
		{"DNS query that reads as a draft Initial", dnsQuery(0x80ff, 0x0000), false},

		// Initials whose header does not parse, which no server could process.
		{"Initial whose length overruns the datagram", longPacket(v1Initial, Version1, 1500)[:1250], false},
		{"Initial whose token overruns the datagram", append([]byte{v1Initial, 0, 0, 0, 1, 0, 0, 0x7f, 0xff}, make([]byte, 1200)...), false},

		// Everything else.
		{"empty", nil, false},
		{"short header", append([]byte{0x40}, make([]byte, 1200)...), false},
		{"recursive DNS query", dnsQuery(0x1234, 0x0100), false},
		{"long header shorter than a version", []byte{0xc0, 0, 0}, false},
		{"v1 Handshake", longPacket(v1Handshake, Version1, 1200), false},
		{"v1 0-RTT", longPacket(v1ZeroRTT, Version1, 1200), false},
		{"v1 Retry bits", longPacket(v1Retry, Version1, 1200), false},
		{"v2 Retry bits, the v1 Initial layout", longPacket(v2Retry, Version2, 1200), false},
		{"v2 Handshake", longPacket(v2Handshake, Version2, 1200), false},
		{"Version Negotiation", longPacket(0x80, 0, 1200), false},
		{"reserved version", longPacket(v1Initial, exampleReserved, 1200), false},
		{"unknown version", longPacket(v1Initial, 0xdeadbeef, 1200), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, mayCarryClientHello(tc.packet))
		})
	}
}

func TestReadVarint(t *testing.T) {
	for _, tc := range []struct {
		encoded []byte
		value   uint64
	}{
		// The examples from RFC 9000 Appendix A.1.
		{[]byte{0x25}, 37},
		{[]byte{0x40, 0x25}, 37},
		{[]byte{0x7b, 0xbd}, 15293},
		{[]byte{0x9d, 0x7f, 0x3e, 0x7d}, 494878333},
		{[]byte{0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c}, 151288809941952652},
	} {
		value, n, ok := readVarint(tc.encoded, 0)
		require.True(t, ok)
		require.Equal(t, tc.value, value)
		require.Equal(t, len(tc.encoded), n)
	}

	_, _, ok := readVarint([]byte{0x9d, 0x7f}, 0)
	require.False(t, ok, "a varint cut short must not parse")
	_, _, ok = readVarint([]byte{0x25}, 1)
	require.False(t, ok, "an offset past the end must not parse")
}
