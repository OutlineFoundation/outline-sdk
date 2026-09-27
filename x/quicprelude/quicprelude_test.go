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
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// requireLongHeader asserts the invariants every Initial-shaped datagram must
// hold, and returns the version and long packet type it declares.
func requireLongHeader(t *testing.T, p []byte, length int) (version uint32, packetType byte) {
	t.Helper()
	require.Len(t, p, length)
	require.Equal(t, byte(0xc0), p[0]&0xc0, "long-header and fixed bits must be set")
	require.Equal(t, byte(connectionIDLength), p[5], "destination connection ID length")
	require.Equal(t, byte(connectionIDLength), p[14], "source connection ID length")
	require.Zero(t, p[23], "token length")
	require.Equal(t, byte(0x40), p[24]&0xc0, "length must be a two-byte varint")
	require.Equal(t, len(p)-headerLength, int(p[24]&0x3f)<<8|int(p[25]), "protected length")
	version = uint32(p[1])<<24 | uint32(p[2])<<16 | uint32(p[3])<<8 | uint32(p[4])
	return version, p[0] & 0x30
}

// exampleReserved is one codepoint from the reserved range, used where a test
// needs a stable value.
const exampleReserved uint32 = 0x1a2a3a4a

// mustFixed builds a VersionSource that always yields version.
func mustFixed(t *testing.T, version uint32) VersionSource {
	t.Helper()
	source, err := FixedVersion(version)
	require.NoError(t, err)
	return source
}

// generate calls a generator once with a placeholder packet and destination,
// and requires it to return exactly one datagram.
func generate(t *testing.T, generator Generator) []byte {
	t.Helper()
	datagrams := generateFor(t, generator, make([]byte, DefaultLength))
	require.Len(t, datagrams, 1)
	return datagrams[0]
}

// generateFor calls a generator with the packet it would precede.
func generateFor(t *testing.T, generator Generator, packet []byte) [][]byte {
	t.Helper()
	datagrams, err := generator(GeneratorInput{
		Packet:      packet,
		Destination: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443},
	})
	require.NoError(t, err)
	return datagrams
}

func TestInvalidInitialV1UsesInitialTypeBits(t *testing.T) {
	generator, err := InvalidInitial(mustFixed(t, Version1), 1280)
	require.NoError(t, err)

	version, packetType := requireLongHeader(t, generate(t, generator), 1280)
	require.Equal(t, Version1, version)
	// QUIC v1 encodes Initial as 0b00.
	require.Equal(t, byte(0x00), packetType)
}

func TestInvalidInitialV2UsesInitialTypeBits(t *testing.T) {
	generator, err := InvalidInitial(mustFixed(t, Version2), 1280)
	require.NoError(t, err)

	version, packetType := requireLongHeader(t, generate(t, generator), 1280)
	require.Equal(t, Version2, version)
	// QUIC v2 encodes Initial as 0b01. Writing v1's 0b00 here would announce a
	// Retry packet instead, which is not what we want to be seen sending.
	require.Equal(t, byte(0x10), packetType)
}

func TestInvalidInitialUnknownVersionUsesV1Layout(t *testing.T) {
	// RFC 8999 defines only the header form and version field for a version the
	// reader does not know, so anything else falls back to the v1 layout.
	generator, err := InvalidInitial(mustFixed(t, exampleReserved), 1280)
	require.NoError(t, err)

	version, packetType := requireLongHeader(t, generate(t, generator), 1280)
	require.Equal(t, exampleReserved, version)
	require.Equal(t, byte(0x00), packetType)

	generator, err = InvalidInitial(mustFixed(t, 0xdeadbeef), 1280)
	require.NoError(t, err)

	version, packetType = requireLongHeader(t, generate(t, generator), 1280)
	require.Equal(t, uint32(0xdeadbeef), version)
	require.Equal(t, byte(0x00), packetType)
}

func TestInvalidInitialRejectsBadArguments(t *testing.T) {
	// A nil source cannot produce a version.
	_, err0 := InvalidInitial(nil, 1280)
	require.Error(t, err0)

	// RFC 9000 requires a client Initial to travel in a datagram of at least
	// MinimumInitialLength bytes.
	_, err := InvalidInitial(mustFixed(t, Version1), MinimumInitialLength-1)
	require.Error(t, err)

	// The length field is written as a two-byte varint, which caps the payload.
	_, err = InvalidInitial(mustFixed(t, Version1), headerLength+maxProtectedLength)
	require.Error(t, err)
}

func TestInvalidInitialAcceptsBoundaryLengths(t *testing.T) {
	_, err := InvalidInitial(mustFixed(t, Version1), MinimumInitialLength)
	require.NoError(t, err)

	_, err = InvalidInitial(mustFixed(t, Version1), headerLength+maxProtectedLength-1)
	require.NoError(t, err)
}

func TestValidateInitialLength(t *testing.T) {
	require.NoError(t, ValidateInitialLength(MinimumInitialLength))
	require.NoError(t, ValidateInitialLength(DefaultLength))
	require.Error(t, ValidateInitialLength(MinimumInitialLength-1))
	require.Error(t, ValidateInitialLength(headerLength+maxProtectedLength))
}

func TestDatagramsDifferBetweenCalls(t *testing.T) {
	generator, err := InvalidInitial(mustFixed(t, exampleReserved), DefaultLength)
	require.NoError(t, err)

	first := generate(t, generator)
	second := generate(t, generator)

	// Connection IDs and payload are random, so two datagrams must not match.
	// Identical datagrams would make a repeated prelude trivially fingerprintable.
	require.NotEqual(t, first, second)
	require.NotEqual(t, first[6:14], second[6:14], "destination connection IDs")
}

func TestRandomIsNotInitialShaped(t *testing.T) {
	generator, err := Random(1280)
	require.NoError(t, err)

	// The first byte is random, so check over enough samples that a datagram
	// which always looked like a long header would be caught.
	sawNonLongHeader := false
	for range 64 {
		p := generate(t, generator)
		require.Len(t, p, 1280)
		if p[0]&0xc0 != 0xc0 {
			sawNonLongHeader = true
		}
	}
	require.True(t, sawNonLongHeader, "every random datagram set the long-header bits")
}

func TestRandomRejectsNegativeLength(t *testing.T) {
	_, err := Random(-1)
	require.Error(t, err)
}

func TestInvalidInitialMatchesPacketLength(t *testing.T) {
	generator, err := InvalidInitial(mustFixed(t, exampleReserved), MatchPacketLength)
	require.NoError(t, err)

	// A prelude sized like the packet it precedes is not separable by size.
	for _, length := range []int{MinimumInitialLength, 1280, 1350} {
		datagrams := generateFor(t, generator, make([]byte, length))
		require.Len(t, datagrams, 1)
		require.Len(t, datagrams[0], length)
		requireLongHeader(t, datagrams[0], length)
	}
}

func TestInvalidInitialFallsBackWhenPacketCannotCarryAnInitial(t *testing.T) {
	generator, err := InvalidInitial(mustFixed(t, exampleReserved), MatchPacketLength)
	require.NoError(t, err)

	// A short packet, such as a DNS query, is not a length an Initial can have,
	// so the generator falls back rather than emitting an invalid datagram.
	datagrams := generateFor(t, generator, make([]byte, 40))
	require.Len(t, datagrams, 1)
	require.Len(t, datagrams[0], DefaultLength)
}

func TestRandomMatchesPacketLength(t *testing.T) {
	generator, err := Random(MatchPacketLength)
	require.NoError(t, err)

	datagrams := generateFor(t, generator, make([]byte, 1300))
	require.Len(t, datagrams, 1)
	require.Len(t, datagrams[0], 1300)

	// Random bytes need no Initial-sized minimum, so a short packet is matched
	// exactly rather than replaced by a fallback that would stand out.
	datagrams = generateFor(t, generator, make([]byte, 40))
	require.Len(t, datagrams[0], 40)

	// Only an empty packet, which has no length to match, falls back.
	datagrams = generateFor(t, generator, nil)
	require.Len(t, datagrams[0], DefaultLength)
}

func TestRepeatRejectsCountOutOfRange(t *testing.T) {
	inner, err := Random(1280)
	require.NoError(t, err)
	_, err = Repeat(-1, inner)
	require.Error(t, err)
	_, err = Repeat(MaxRepeat+1, inner)
	require.Error(t, err)
	_, err = Repeat(MaxRepeat, inner)
	require.NoError(t, err)
}

func TestRepeatConcatenatesDatagrams(t *testing.T) {
	inner, err := InvalidInitial(mustFixed(t, Version1), 1280)
	require.NoError(t, err)
	generator, err := Repeat(3, inner)
	require.NoError(t, err)

	datagrams := generateFor(t, generator, make([]byte, DefaultLength))
	require.Len(t, datagrams, 3)
	// Each call generates fresh randomness, so the repeats must differ.
	require.NotEqual(t, datagrams[0], datagrams[1])
	require.NotEqual(t, datagrams[1], datagrams[2])
}

func TestRepeatZeroDisablesThePrelude(t *testing.T) {
	inner, err := InvalidInitial(mustFixed(t, Version1), 1280)
	require.NoError(t, err)
	generator, err := Repeat(0, inner)
	require.NoError(t, err)

	require.Empty(t, generateFor(t, generator, make([]byte, DefaultLength)))
}

func TestRepeatRejectsBadArguments(t *testing.T) {
	inner, err := InvalidInitial(mustFixed(t, Version1), 1280)
	require.NoError(t, err)

	_, err = Repeat(-1, inner)
	require.Error(t, err)

	_, err = Repeat(1, nil)
	require.Error(t, err)
}

func TestGeneratorCanSplitAndDecline(t *testing.T) {
	// A generator returning several datagrams sends all of them, which is how a
	// split Initial would be expressed.
	split := Generator(func(input GeneratorInput) ([][]byte, error) {
		half := len(input.Packet) / 2
		return [][]byte{input.Packet[:half], input.Packet[half:]}, nil
	})
	require.Len(t, generateFor(t, split, make([]byte, 100)), 2)

	// Returning nothing is how a generator declines.
	decline := Generator(func(GeneratorInput) ([][]byte, error) { return nil, nil })
	require.Empty(t, generateFor(t, decline, make([]byte, 100)))
}

func TestNewConfigDefaults(t *testing.T) {
	inner := &recordingConn{}
	listener, err := NewConfig().NewPacketListener(&fixedListener{conn: inner})
	require.NoError(t, err)
	conn, err := listener.ListenPacket(t.Context())
	require.NoError(t, err)

	_, err = conn.WriteTo(clientInitial(DefaultLength), udpAddr(t, "192.0.2.1:443"))
	require.NoError(t, err)

	// One Initial-shaped datagram sized to match the packet it preceded, and
	// carrying a chosen codepoint rather than a constant.
	writes, _ := inner.snapshot()
	require.Len(t, writes, 2)
	version, packetType := requireLongHeader(t, writes[0], len(writes[1]))
	require.True(t, isReservedVersion(version), "default must use a reserved codepoint")
	require.Equal(t, byte(0x00), packetType)
}

func TestRandomVersionVariesButStaysReserved(t *testing.T) {
	generator, err := InvalidInitial(RandomReservedVersion(), 1280)
	require.NoError(t, err)

	seen := map[uint32]int{}
	for range 256 {
		version, _ := requireLongHeader(t, generate(t, generator), 1280)
		// Staying in the reserved range is what makes the prelude work: a
		// codepoint outside it is not recognized as QUIC and is ignored, which
		// leaves the real Initial to be the first QUIC packet seen.
		require.True(t, isReservedVersion(version), "chose %#08x, outside 0x?a?a?a?a", version)
		seen[version]++
	}

	// No single constant for a middlebox to match. The range holds 65536 values,
	// so 256 draws should be nearly all distinct.
	require.Greater(t, len(seen), 200, "versions should almost all differ")
}

func TestIsexampleReserved(t *testing.T) {
	require.True(t, isReservedVersion(exampleReserved))
	require.True(t, isReservedVersion(0x0a0a0a0a))
	require.True(t, isReservedVersion(0xfafafafa))

	require.False(t, isReservedVersion(Version1))
	require.False(t, isReservedVersion(Version2))
	require.False(t, isReservedVersion(0xff00001d), "draft-29")
	require.False(t, isReservedVersion(0xdeadbeef))
}

func TestExplicitVersionIsStable(t *testing.T) {
	generator, err := InvalidInitial(mustFixed(t, exampleReserved), 1280)
	require.NoError(t, err)

	// An explicitly chosen codepoint must be used verbatim, every time.
	for range 8 {
		version, _ := requireLongHeader(t, generate(t, generator), 1280)
		require.Equal(t, exampleReserved, version)
	}
}

func TestFixedVersionRejectsZero(t *testing.T) {
	// Zero denotes Version Negotiation, which a client never sends.
	_, err := FixedVersion(0)
	require.Error(t, err)
}

func TestInvalidInitialChoosesVersionForEachDatagram(t *testing.T) {
	versions := []uint32{Version1, Version2}
	calls := 0
	generator, err := InvalidInitial(func() uint32 {
		require.Less(t, calls, len(versions), "one version choice per datagram")
		version := versions[calls]
		calls++
		return version
	}, DefaultLength)
	require.NoError(t, err)
	generator, err = Repeat(2, generator)
	require.NoError(t, err)
	require.Zero(t, calls, "construction must not consume a version")

	datagrams := generateFor(t, generator, make([]byte, DefaultLength))
	require.Len(t, datagrams, 2)
	require.Equal(t, 2, calls)
	version, packetType := requireLongHeader(t, datagrams[0], DefaultLength)
	require.Equal(t, Version1, version)
	require.Equal(t, byte(0x00), packetType)
	version, packetType = requireLongHeader(t, datagrams[1], DefaultLength)
	require.Equal(t, Version2, version)
	require.Equal(t, byte(0x10), packetType)
}

func TestRandomDraftVersionStaysAboveAssignedDrafts(t *testing.T) {
	source := RandomDraftVersion()

	seen := map[uint32]int{}
	for range 512 {
		version := source()
		require.Equal(t, draftPrefix, version&0xffffff00, "%#08x is outside the draft range", version)
		// draft-34 became RFC 9000. At or below it the codepoints saw
		// deployment, which is what filtering recognizes: the Iranian paths
		// measured for this package drop draft-29 outright.
		require.Greater(t, version&0xff, uint32(lastAssignedDraft), "%#08x is an assigned draft", version)
		require.True(t, isUnassignedDraftVersion(version))
		seen[version]++
	}
	require.Greater(t, len(seen), 100, "draft codepoints should vary")
}

func TestIsUnassignedDraftVersion(t *testing.T) {
	require.True(t, isUnassignedDraftVersion(0xff0000fe))
	require.True(t, isUnassignedDraftVersion(0xff000023), "draft-35, never assigned")

	require.False(t, isUnassignedDraftVersion(0xff00001d), "draft-29")
	require.False(t, isUnassignedDraftVersion(0xff000022), "draft-34, became RFC 9000")
	require.False(t, isUnassignedDraftVersion(exampleReserved))
	require.False(t, isUnassignedDraftVersion(Version1))
}
