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

package configurl

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.getoutline.org/sdk/x/quicprelude"
)

// recordingConn records what was written, so a test can assert on the datagrams
// the configured prelude produced.
type recordingConn struct {
	writes [][]byte
}

func (c *recordingConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, errors.New("not implemented")
}

func (c *recordingConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.writes = append(c.writes, append([]byte(nil), p...))
	return len(p), nil
}

func (*recordingConn) Close() error                     { return nil }
func (*recordingConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*recordingConn) SetDeadline(time.Time) error      { return nil }
func (*recordingConn) SetReadDeadline(time.Time) error  { return nil }
func (*recordingConn) SetWriteDeadline(time.Time) error { return nil }

type fixedListener struct {
	conn net.PacketConn
}

func (l *fixedListener) ListenPacket(context.Context) (net.PacketConn, error) {
	return l.conn, nil
}

// preludesFor parses quicprelude options and returns the datagrams sent before
// a single payload write. Asserting on the wire keeps these tests independent
// of the package's internal representation.
func preludesFor(t *testing.T, options string) [][]byte {
	t.Helper()
	// An Initial-sized payload, since shorter packets get no prelude.
	return preludesForPacket(t, options, initialPacket(quicprelude.DefaultLength))
}

// initialPacket returns a datagram of length bytes that reads as a QUIC v1
// Initial, which is what the listener sends a prelude ahead of.
func initialPacket(length int) []byte {
	p := make([]byte, length)
	p[0] = 0xc0
	binary.BigEndian.PutUint32(p[1:5], quicprelude.Version1)
	return p
}

func preludesForPacket(t *testing.T, options string, payload []byte) [][]byte {
	t.Helper()
	config, err := ParseConfig("quicprelude:" + options)
	require.NoError(t, err)
	preludeConfig, err := newQUICPreludeConfigFromURL(config.URL)
	require.NoError(t, err)

	inner := &recordingConn{}
	listener, err := preludeConfig.NewPacketListener(&fixedListener{conn: inner})
	require.NoError(t, err)
	conn, err := listener.ListenPacket(t.Context())
	require.NoError(t, err)

	_, err = conn.WriteTo(payload, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443})
	require.NoError(t, err)

	require.NotEmpty(t, inner.writes)
	require.Equal(t, payload, inner.writes[len(inner.writes)-1], "the payload must be written last")
	return inner.writes[:len(inner.writes)-1]
}

func errorFor(t *testing.T, options string) error {
	t.Helper()
	config, err := ParseConfig("quicprelude:" + options)
	require.NoError(t, err)
	_, err = newQUICPreludeConfigFromURL(config.URL)
	return err
}

func versionOf(p []byte) uint32 { return binary.BigEndian.Uint32(p[1:5]) }

func TestRegisterQUICPreludePacketListener(t *testing.T) {
	providers := NewDefaultProviders()

	_, err := providers.NewPacketListener(context.Background(), "quicprelude:count=2&version=0x1a2a3a4a")
	require.NoError(t, err)

	// The prelude must sit above another packet listener, which is how it shares
	// a four-tuple with proxied traffic.
	_, err = providers.NewPacketListener(context.Background(),
		"ss://ChaCha20-IETF-Poly1305:password@example.com:1234|quicprelude:count=1")
	require.NoError(t, err)

	// With no options the colon may be dropped, which is the documented form.
	_, err = providers.NewPacketListener(context.Background(), "quicprelude")
	require.NoError(t, err)

	_, err = providers.NewPacketListener(context.Background(),
		"ss://ChaCha20-IETF-Poly1305:password@example.com:1234|quicprelude")
	require.NoError(t, err)
}

func TestQUICPreludeDefaults(t *testing.T) {
	// By default one Initial-shaped datagram carrying the reserved codepoint,
	// sized to match the packet it precedes.
	payload := initialPacket(1350)
	preludes := preludesForPacket(t, "", payload)

	require.Len(t, preludes, 1)
	require.Len(t, preludes[0], len(payload))

	// The default codepoint is chosen per datagram rather than fixed, so a
	// middlebox has no constant to match.
	first := versionOf(preludes[0])
	second := versionOf(preludesForPacket(t, "", payload)[0])
	require.NotEqual(t, first, second, "default version should not repeat")

	// A packet shorter than RFC 9000 allows a client Initial gets no prelude.
	require.Empty(t, preludesForPacket(t, "", initialPacket(quicprelude.MinimumInitialLength-1)))
}

func TestQUICPreludeOptionCount(t *testing.T) {
	require.Len(t, preludesFor(t, "count=3"), 3)

	// Zero disables the prelude, leaving only the payload.
	require.Empty(t, preludesFor(t, "count=0"))

	require.Error(t, errorFor(t, "count=-1"))
	require.Error(t, errorFor(t, "count=17"), "an unbounded count would let one write allocate without limit")
	require.Len(t, preludesFor(t, "count=16"), 16)
	require.Error(t, errorFor(t, "count=many"))
}

func TestQUICPreludeOptionMode(t *testing.T) {
	initial := preludesFor(t, "mode=invalid-initial")
	require.Len(t, initial, 1)
	require.Equal(t, byte(0xc0), initial[0][0]&0xc0, "invalid-initial must be long-header shaped")

	random := preludesFor(t, "mode=random&length=1200")
	require.Len(t, random, 1)
	require.Len(t, random[0], 1200)

	require.Error(t, errorFor(t, "mode=handshake"))
}

func TestQUICPreludeOptionLength(t *testing.T) {
	preludes := preludesFor(t, "length=1300")
	require.Len(t, preludes[0], 1300)

	// "match" is the default, and can also be written explicitly.
	payload := initialPacket(1350)
	preludes = preludesForPacket(t, "length=match", payload)
	require.Len(t, preludes[0], len(payload))
	preludes = preludesForPacket(t, "length=MATCH", payload)
	require.Len(t, preludes[0], len(payload))

	// An Initial-shaped datagram has an RFC 9000 minimum size.
	require.Error(t, errorFor(t, "length=100"))
	require.Error(t, errorFor(t, "length=big"))

	// Zero is not a spelling of "match"; it would be a magic number in a config
	// string.
	require.Error(t, errorFor(t, "length=0"))
	require.Error(t, errorFor(t, "length=-1"))
}

func TestQUICPreludeVersionRanges(t *testing.T) {
	// "reserved" is the default and can also be written explicitly. Each
	// datagram draws a fresh codepoint, so nothing fixed identifies a prelude.
	first := versionOf(preludesFor(t, "version=reserved")[0])
	second := versionOf(preludesFor(t, "version=reserved")[0])
	require.NotEqual(t, first, second)
	for _, version := range []uint32{first, second} {
		require.Equal(t, uint32(0x0a0a0a0a), version&0x0f0f0f0f, "%#08x is outside 0x?a?a?a?a", version)
	}

	// "draft" draws from the IETF draft range, above the assigned draft numbers
	// that filtering recognizes.
	for range 4 {
		version := versionOf(preludesFor(t, "version=draft")[0])
		require.Equal(t, uint32(0xff000000), version&0xffffff00, "%#08x is outside the draft range", version)
		require.Greater(t, version&0xff, uint32(34), "%#08x is an assigned draft", version)
	}

	// Zero denotes Version Negotiation and is not a spelling of a range.
	require.Error(t, errorFor(t, "version=0x0"))
	// The old synonym is gone, so it must not silently succeed.
	require.Error(t, errorFor(t, "version=greased"))
}

func TestQUICPreludeOptionVersion(t *testing.T) {
	require.Equal(t, uint32(0xdeadbeef), versionOf(preludesFor(t, "version=0xdeadbeef")[0]))

	// The 0x prefix is optional.
	require.Equal(t, uint32(0x1a2a3a4a), versionOf(preludesFor(t, "version=1a2a3a4a")[0]))

	require.Equal(t, quicprelude.Version1, versionOf(preludesFor(t, "version=v1")[0]))

	v2 := preludesFor(t, "version=v2")[0]
	require.Equal(t, quicprelude.Version2, versionOf(v2))
	// v2 encodes Initial as 0b01, so the type bits must differ from v1's.
	require.Equal(t, byte(0x10), v2[0]&0x30)

	require.Error(t, errorFor(t, "version=zzz"))
}

func TestQUICPreludeRejectsUnknownAndRepeatedOptions(t *testing.T) {
	require.Error(t, errorFor(t, "colour=blue"))
	require.Error(t, errorFor(t, "count=1&count=2"))
}
