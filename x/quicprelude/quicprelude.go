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

// Package quicprelude sends datagrams on a UDP flow before the traffic that
// follows it, to influence how a middlebox classifies that flow.
//
// Some middleboxes read the TLS Server Name Indication from the first QUIC
// Initial packet they can parse on a four-tuple, decide whether the flow is
// permitted, and apply that decision to everything that follows. An
// Initial-shaped datagram they cannot decrypt yields no server name, so no
// decision is reached and later packets on the flow are not matched against it.
//
// A prelude goes before every datagram that may carry a QUIC ClientHello, judged
// from the packet header alone, rather than once per destination. Nothing is
// remembered between writes, so a new connection on a reused socket is covered
// like the first, and traffic that is not QUIC passes untouched.
//
// A [Config] describes what to send and produces a [transport.PacketListener]:
//
//	config := quicprelude.NewConfig()
//	listener, err := config.NewPacketListener(inner)
//
// The datagrams come from a [Generator], which is handed the packet it is about
// to precede. [InvalidInitial] and [Random] cover the cases this package was
// written for, [Repeat] sends one of them several times, and a caller who needs
// something else supplies their own:
//
//	version, err := quicprelude.FixedVersion(quicprelude.Version2)
//	generator, err := quicprelude.InvalidInitial(version, quicprelude.MatchPacketLength)
//	generator, err = quicprelude.Repeat(2, generator)
//	listener, err := quicprelude.NewConfig().
//		WithGenerator(generator).
//		NewPacketListener(inner)
//
// The datagrams [InvalidInitial] produces are deliberately not valid QUIC. They
// carry a long header with a plausible version and connection IDs, and random
// bytes where the protected payload and authentication tag would be. A QUIC
// server discards them.
//
// The version must be one a middlebox recognizes as QUIC, or the datagram is
// ignored and the technique does nothing. Measurements for this package found
// the following, each against positive and negative controls:
//
//   - reserved 0x?a?a?a?a: effective on both paths measured, and the default
//   - draft codepoints 0xff0000xx: effective, except that an assigned one such
//     as draft-29 is dropped outright on the Iranian paths, which filter an
//     exact list of the versions in use
//   - QUIC v2: effective on both, but a single fixed value
//   - 0x0000xxxx, reserved for future IETF documents: largely ineffective, no
//     implementation uses it
//   - anything else: ineffective
package quicprelude

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
)

const (
	// MinimumInitialLength is the smallest datagram RFC 9000 allows a client to
	// carry an Initial packet in.
	MinimumInitialLength = 1200

	// DefaultLength matches the datagram size QUIC-Go uses for its own Initials,
	// so a prelude is not distinguishable from the traffic that follows it by
	// datagram size alone.
	DefaultLength = 1280

	// MatchPacketLength asks a generator to size each datagram to match the
	// packet it precedes, so the prelude is not distinguishable by size from the
	// traffic it is mixed with. [InvalidInitial] falls back to [DefaultLength]
	// when the packet's length could not carry an Initial. [Random] has no such
	// constraint and always matches, falling back only for an empty packet.
	MatchPacketLength = 0

	// MaxRepeat is the largest count [Repeat] accepts. Every datagram is built
	// before the first is sent, so an unbounded count would let one write
	// allocate without limit. Measurements for this package never needed more
	// than three.
	MaxRepeat = 16

	// Version1 and Version2 are the wire codepoints of RFC 9000 and RFC 9369.
	Version1 uint32 = 0x00000001
	Version2 uint32 = 0x6b3343cf

	// headerLength is the fixed part InvalidInitial emits: first byte, version,
	// two 8-byte connection IDs with their lengths, a zero-length token, and a
	// two-byte length field.
	headerLength = 26

	connectionIDLength = 8

	// maxProtectedLength is the largest payload a two-byte QUIC varint can
	// describe.
	maxProtectedLength = 1 << 14

	// reservedNibble is the low nibble every byte of a reserved codepoint
	// carries.
	reservedNibble = 0x0a

	// draftPrefix is the first three bytes of the codepoints the IETF drafts
	// used, the last byte being the draft number.
	draftPrefix uint32 = 0xff000000

	// lastAssignedDraft is the highest draft number QUIC used: draft-34 became
	// RFC 9000. Draft codepoints at or below it saw deployment, so they are the
	// ones filtering recognizes, and [RandomDraftVersion] chooses above it.
	//
	// If the IETF ever assigns codepoints in this range again, this floor needs
	// revisiting.
	lastAssignedDraft = 34
)

// GeneratorInput describes the write a prelude is about to precede.
//
// It is a struct so that fields can be added without breaking implementations
// of [Generator]. A generator should ignore fields it does not recognize.
type GeneratorInput struct {
	// Packet is the datagram about to be written. A generator may read it to
	// match its length, to find the Server Name Indication in an Initial, or to
	// decide whether to act at all. It must not be modified.
	Packet []byte

	// Destination is where Packet is addressed. It is not derivable from Packet,
	// and is what a generator needs to vary by target.
	Destination net.Addr
}

// Generator returns the datagrams to send ahead of the write described by
// input. Being given the packet lets a generator match its length, read the
// Server Name Indication out of an Initial, or decline.
//
// A generator is consulted only for datagrams that may carry a QUIC ClientHello,
// which includes retransmissions and the resends that follow a Retry, a TLS
// HelloRetryRequest, or Version Negotiation. Calls on one connection are never
// concurrent. Returning no datagrams sends the packet unchanged.
//
// Returning an error aborts the write, and the caller sees that error.
type Generator func(input GeneratorInput) ([][]byte, error)

// Random returns a [Generator] producing opaque random bytes. A middlebox that
// parses QUIC will not recognize them as QUIC at all, which makes this useful
// as a control rather than as a technique.
//
// With [MatchPacketLength] each datagram is exactly as long as the packet it
// precedes, whatever that length is, since random bytes need no Initial-sized
// minimum. That is what makes it a size-matched control.
func Random(length int) (Generator, error) {
	if length < 0 {
		return nil, fmt.Errorf("length must not be negative, got %d", length)
	}
	return func(input GeneratorInput) ([][]byte, error) {
		n := length
		if n == MatchPacketLength {
			n = len(input.Packet)
		}
		if n == 0 {
			n = DefaultLength
		}
		return [][]byte{randomBytes(n)}, nil
	}, nil
}

// VersionSource chooses the version codepoint for a datagram. It is called once
// per datagram, so a source that varies produces datagrams that differ on the
// wire and gives a middlebox no single constant to match.
type VersionSource func() uint32

// FixedVersion returns a [VersionSource] that always yields version.
func FixedVersion(version uint32) (VersionSource, error) {
	if version == 0 {
		return nil, fmt.Errorf("version must not be zero, which denotes Version Negotiation")
	}
	return func() uint32 { return version }, nil
}

// RandomReservedVersion returns a [VersionSource] yielding a fresh codepoint
// from the range RFC 9000, Section 15 reserves "for use in forcing version
// negotiation to be exercised", 0x?a?a?a?a. The same section says a client "MAY
// use one of these version numbers with the expectation that the server will
// initiate version negotiation", so sending one is sanctioned behavior.
//
// This is the default. The range holds 65536 values, none of which can collide
// with an assigned version, since it is reserved.
func RandomReservedVersion() VersionSource {
	return func() uint32 {
		var b [4]byte
		rand.Read(b[:])
		for i := range b {
			b[i] = b[i]&0xf0 | reservedNibble
		}
		return binary.BigEndian.Uint32(b[:])
	}
}

// RandomDraftVersion returns a [VersionSource] yielding a fresh codepoint from
// the range the IETF drafts used, 0xff0000xx, above the last draft number that
// was ever assigned.
//
// The floor matters. Filtering recognizes the versions that saw deployment: on
// the Iranian paths measured for this package, draft-29 is dropped outright
// while an unassigned codepoint sharing its prefix passes, so that filter
// matches an exact list rather than the prefix. Choosing above the assigned
// drafts stays clear of the list while remaining in a range a middlebox still
// recognizes as QUIC.
//
// This is an alternative to [RandomReservedVersion] for a path where the
// reserved range is filtered. It is a smaller pool.
func RandomDraftVersion() VersionSource {
	return func() uint32 {
		var b [1]byte
		rand.Read(b[:])
		span := 0xff - lastAssignedDraft
		return draftPrefix | uint32(lastAssignedDraft+1+int(b[0])%span)
	}
}

// InvalidInitial returns a [Generator] producing datagrams with a syntactically
// valid QUIC long header announcing an Initial packet, and random bytes beyond
// it. The payload cannot be decrypted and the authentication tag will not
// verify, so it is not a valid QUIC packet and no server acts on it.
//
// The version must be one a middlebox recognizes as QUIC, or the datagram is
// ignored and the prelude does nothing. See the package documentation for which
// ranges were measured to work.
func InvalidInitial(version VersionSource, length int) (Generator, error) {
	if version == nil {
		return nil, fmt.Errorf("version source must not be nil")
	}
	if length != MatchPacketLength {
		if err := ValidateInitialLength(length); err != nil {
			return nil, err
		}
	}
	return func(input GeneratorInput) ([][]byte, error) {
		datagram := invalidInitial(version(), lengthFor(length, input.Packet, DefaultLength))
		return [][]byte{datagram}, nil
	}, nil
}

// isReservedVersion reports whether a codepoint lies in the reserved
// 0x?a?a?a?a range.
func isReservedVersion(version uint32) bool {
	return version&0x0f0f0f0f == 0x0a0a0a0a
}

// isUnassignedDraftVersion reports whether a codepoint lies in the draft range
// above the last assigned draft number.
func isUnassignedDraftVersion(version uint32) bool {
	return version&0xffffff00 == draftPrefix && version&0xff > lastAssignedDraft
}

// Repeat returns a [Generator] that calls generator count times and
// concatenates the result. A count of zero yields a generator that sends
// nothing, which disables the prelude. count may not exceed [MaxRepeat].
func Repeat(count int, generator Generator) (Generator, error) {
	if count < 0 || count > MaxRepeat {
		return nil, fmt.Errorf("count must be between 0 and %d, got %d", MaxRepeat, count)
	}
	if generator == nil {
		return nil, fmt.Errorf("generator must not be nil")
	}
	return func(input GeneratorInput) ([][]byte, error) {
		var datagrams [][]byte
		for range count {
			next, err := generator(input)
			if err != nil {
				return nil, err
			}
			datagrams = append(datagrams, next...)
		}
		return datagrams, nil
	}, nil
}

// lengthFor resolves a configured length against the packet being preceded.
// MatchPacketLength takes the packet's own length, so the prelude is not
// distinguishable by size, falling back when that length could not carry an
// Initial.
func lengthFor(configured int, packet []byte, fallback int) int {
	if configured != MatchPacketLength {
		return configured
	}
	if ValidateInitialLength(len(packet)) != nil {
		return fallback
	}
	return len(packet)
}

// ValidateInitialLength reports whether length can carry an Initial-shaped
// datagram. It is exported so a caller parsing a length from configuration can
// reject a bad value before building a [Generator].
func ValidateInitialLength(length int) error {
	if length < MinimumInitialLength {
		return fmt.Errorf("length must be at least %d bytes, got %d", MinimumInitialLength, length)
	}
	if length-headerLength >= maxProtectedLength {
		return fmt.Errorf("length must be under %d bytes, got %d", headerLength+maxProtectedLength, length)
	}
	return nil
}

func randomBytes(length int) []byte {
	p := make([]byte, length)
	rand.Read(p)
	return p
}

func invalidInitial(version uint32, length int) []byte {
	p := randomBytes(length)

	// Header Form and Fixed Bit are set. The long packet type encodes Initial,
	// which is 0b00 in QUIC v1 and 0b01 in QUIC v2. For any other version the
	// v1 layout is used, since RFC 8999 defines only the header form and the
	// version field for a version the reader does not know. The low nibble and
	// the packet number bytes stay random, mimicking header protection.
	typeBits := byte(0xc0)
	if version == Version2 {
		typeBits = 0xd0
	}
	p[0] = typeBits | (p[0] & 0x0f)
	binary.BigEndian.PutUint32(p[1:5], version)

	p[5] = connectionIDLength
	// p[6:14] is the random Destination Connection ID.
	p[14] = connectionIDLength
	// p[15:23] is the random Source Connection ID.
	p[23] = 0 // zero-length token

	// Two-byte QUIC varint for the length of the protected remainder.
	binary.BigEndian.PutUint16(p[24:26], uint16(length-headerLength)|(1<<14))
	return p
}
