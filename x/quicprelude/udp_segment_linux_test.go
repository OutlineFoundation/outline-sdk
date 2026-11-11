//go:build linux

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
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

func segmentOOB(size uint16) []byte {
	b := make([]byte, unix.CmsgSpace(2))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level, h.Type = unix.IPPROTO_UDP, unix.UDP_SEGMENT
	h.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(b[unix.CmsgLen(0):], size)
	return b
}

func sourceOOB() []byte {
	return (&ipv4.ControlMessage{Src: []byte{192, 0, 2, 10}, IfIndex: 2}).Marshal()
}

func ecnOOB() []byte {
	b := make([]byte, unix.CmsgSpace(1))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level, h.Type = unix.IPPROTO_IP, unix.IP_TOS
	h.SetLen(unix.CmsgLen(1))
	b[unix.CmsgLen(0)] = 2 // ECT(0)
	return b
}

func TestWriteMsgUDPPreservesRoutingAndOriginalOOB(t *testing.T) {
	inner := &messageConn{}
	conn := wrapForTest(t, inner, mustDefaultGenerator(t)).(udpPacketConn)
	oob := append(sourceOOB(), ecnOOB()...)
	original := bytes.Clone(oob)
	n, nn, err := conn.WriteMsgUDP(clientInitial(1200), oob, nil)
	require.NoError(t, err)
	require.Equal(t, 1200, n)
	require.Equal(t, len(oob), nn)
	require.Len(t, inner.messages, 2)
	require.Equal(t, original, inner.messages[0].oob)
	require.Equal(t, original, inner.messages[1].oob)
	require.Equal(t, original, oob)
}

func TestGSOBatchWithoutInitialPassesThrough(t *testing.T) {
	inner := &messageConn{}
	conn := wrapForTest(t, inner, mustDefaultGenerator(t)).(udpPacketConn)
	payload := bytes.Repeat([]byte{0x40}, 2500)
	oob := append(sourceOOB(), segmentOOB(1200)...)
	n, nn, err := conn.WriteMsgUDP(payload, oob, nil)
	require.NoError(t, err)
	require.Equal(t, len(payload), n)
	require.Equal(t, len(oob), nn)
	require.Len(t, inner.messages, 1)
	require.Equal(t, payload, inner.messages[0].packet)
	require.Equal(t, oob, inner.messages[0].oob)
}

func TestGSOBatchPreludesEachInitialAndMatchesSegmentLength(t *testing.T) {
	inner := &messageConn{}
	conn := wrapForTest(t, inner, mustDefaultGenerator(t)).(udpPacketConn)
	first := bytes.Repeat([]byte{0x40}, 1200)
	initial := clientInitial(1200)
	tail := []byte("last datagram")
	payload := bytes.Join([][]byte{first, initial, initial, tail}, nil)
	routing := append(sourceOOB(), ecnOOB()...)
	// Put UDP_SEGMENT first to also exercise retaining later control messages.
	oob := append(segmentOOB(1200), routing...)
	originalOOB, originalPayload := bytes.Clone(oob), bytes.Clone(payload)
	n, nn, err := conn.WriteMsgUDP(payload, oob, nil)
	require.NoError(t, err)
	require.Equal(t, len(payload), n)
	require.Equal(t, len(oob), nn)
	require.Len(t, inner.messages, 6)
	require.Equal(t, first, inner.messages[0].packet)
	require.Equal(t, initial, inner.messages[2].packet)
	require.Equal(t, initial, inner.messages[4].packet)
	require.Equal(t, tail, inner.messages[5].packet)
	for _, i := range []int{1, 3} {
		version, _ := requireLongHeader(t, inner.messages[i].packet, 1200)
		require.Equal(t, exampleReserved, version)
	}
	for _, msg := range inner.messages {
		require.Equal(t, routing, msg.oob)
	}
	require.Equal(t, originalOOB, oob)
	require.Equal(t, originalPayload, payload)
}

func TestGSOCustomPreludeIsNotSegmented(t *testing.T) {
	inner := &messageConn{}
	prelude := bytes.Repeat([]byte{0x23}, 1500)
	conn := wrapForTest(t, inner, func(GeneratorInput) ([][]byte, error) { return [][]byte{prelude}, nil }).(udpPacketConn)
	oob := append(sourceOOB(), segmentOOB(1200)...)
	// Even a one-segment message must strip segmentation from its larger prelude.
	_, _, err := conn.WriteMsgUDP(clientInitial(1200), oob, nil)
	require.NoError(t, err)
	require.Len(t, inner.messages, 2)
	require.Equal(t, prelude, inner.messages[0].packet)
	require.Equal(t, sourceOOB(), inner.messages[0].oob)
	require.Equal(t, oob, inner.messages[1].oob)
}

func TestGSOPartialFailureCountsOnlySentOriginals(t *testing.T) {
	failure := errors.New("send failed")
	inner := &messageConn{failAt: 3, failure: failure}
	conn := wrapForTest(t, inner, mustDefaultGenerator(t)).(udpPacketConn)
	payload := append(clientInitial(1200), clientInitial(1200)...)
	oob := segmentOOB(1200)
	n, nn, err := conn.WriteMsgUDP(payload, oob, nil)
	require.ErrorIs(t, err, failure)
	require.Equal(t, 1200, n)
	require.Equal(t, len(oob), nn)
	require.Len(t, inner.messages, 3)
	require.Len(t, inner.writes, 2, "failed second prelude must prevent its Initial")
}

func TestMalformedSegmentMetadataSendsNothing(t *testing.T) {
	inner := &messageConn{}
	conn := wrapForTest(t, inner, mustDefaultGenerator(t)).(udpPacketConn)
	_, _, err := conn.WriteMsgUDP(clientInitial(1200), []byte{1}, nil)
	require.Error(t, err)
	_, _, err = conn.WriteMsgUDP(clientInitial(1200), append(segmentOOB(1200), segmentOOB(1200)...), nil)
	require.Error(t, err)
	malformed := segmentOOB(1200)
	(*unix.Cmsghdr)(unsafe.Pointer(&malformed[0])).SetLen(unix.CmsgLen(1))
	_, _, err = conn.WriteMsgUDP(clientInitial(1200), malformed, nil)
	require.Error(t, err)
	require.Empty(t, inner.messages)
}

// Exercise actual sendmsg control messages and native receive batching, not
// just the recording fake. Each prelude is larger than the GSO segment size.
func TestNativeUDPMessageRoutingAndBatchRead(t *testing.T) {
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer receiver.Close()
	require.NoError(t, receiver.SetDeadline(time.Now().Add(5*time.Second)))
	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	require.NoError(t, err)
	defer sender.Close()
	require.NoError(t, sender.SetDeadline(time.Now().Add(5*time.Second)))
	prelude := bytes.Repeat([]byte{0x23}, 1500)
	wrapped := wrapForTest(t, sender, func(GeneratorInput) ([][]byte, error) { return [][]byte{prelude}, nil })
	require.Implements(t, (*writeBufferSetter)(nil), wrapped)
	source := net.IPv4(127, 0, 0, 2)
	oob := append((&ipv4.ControlMessage{Src: source}).Marshal(), segmentOOB(1200)...)
	initial := clientInitial(1200)
	n, nn, err := wrapped.(udpPacketConn).WriteMsgUDP(append(bytes.Clone(initial), initial...), oob, receiver.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	require.Equal(t, 2400, n)
	require.Equal(t, len(oob), nn)
	var from *net.UDPAddr
	for _, expected := range [][]byte{prelude, initial, prelude, initial} {
		b := make([]byte, 2048)
		n, from, err = receiver.ReadFromUDP(b)
		require.NoError(t, err)
		require.Equal(t, expected, b[:n], "datagram boundaries must survive segmentation handling")
		require.True(t, source.Equal(from.IP), "source-routing metadata must survive")
		require.Equal(t, sender.LocalAddr().(*net.UDPAddr).Port, from.Port)
	}
	_, err = receiver.WriteToUDP([]byte("reply"), from)
	require.NoError(t, err)
	messages := []ipv4.Message{{Buffers: [][]byte{make([]byte, 128)}, OOB: make([]byte, 128)}}
	n, err = wrapped.(batchReader).ReadBatch(messages, 0)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	require.Equal(t, "reply", string(messages[0].Buffers[0][:messages[0].N]))
}
