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
	"context"
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.getoutline.org/sdk/transport"
)

// dialedRecordingConn is a recordingConn bound to one destination.
type dialedRecordingConn struct {
	*recordingConn
	remote net.Addr
}

func (c *dialedRecordingConn) Read([]byte) (int, error)    { return 0, errors.New("not implemented") }
func (c *dialedRecordingConn) Write(p []byte) (int, error) { return c.WriteTo(p, c.remote) }
func (c *dialedRecordingConn) RemoteAddr() net.Addr        { return c.remote }

// newTestDialedConn dials address through a prelude dialer and returns the
// connection with the recorder standing in for the network.
func newTestDialedConn(t *testing.T, config *Config, address string) (net.Conn, *recordingConn) {
	t.Helper()
	inner := &recordingConn{}
	dialer, err := config.NewPacketDialer(transport.FuncPacketDialer(
		func(_ context.Context, addr string) (net.Conn, error) {
			remote, err := transport.MakeNetAddr("udp", addr)
			if err != nil {
				return nil, err
			}
			return &dialedRecordingConn{recordingConn: inner, remote: remote}, nil
		}))
	require.NoError(t, err)
	conn, err := dialer.DialPacket(context.Background(), address)
	require.NoError(t, err)
	return conn, inner
}

func TestDialerPreludePrecedesClientHello(t *testing.T) {
	repeated, err := Repeat(3, mustDefaultGenerator(t))
	require.NoError(t, err)
	// A hostname destination: the inner dialer, not the prelude, resolves it.
	conn, inner := newTestDialedConn(t, NewConfig().WithGenerator(repeated), "proxy.example:443")

	payload := clientInitial(1350)
	n, err := conn.Write(payload)
	require.NoError(t, err)
	require.Equal(t, len(payload), n, "Write reports the payload length, not the preludes'")

	writes, addrs := inner.snapshot()
	require.Len(t, writes, 4, "expected 3 preludes followed by the payload")
	for i := range 3 {
		require.Len(t, writes[i], len(payload), "prelude %d should match the packet length", i+1)
		require.Equal(t, byte(0xc0), writes[i][0]&0xc0, "prelude %d is not long-header shaped", i+1)
		require.Equal(t, "proxy.example:443", addrs[i], "prelude %d destination", i+1)
	}
	require.Equal(t, payload, writes[3])
}

func TestDialerPreludeSkipsPacketsWithoutClientHello(t *testing.T) {
	conn, inner := newTestDialedConn(t, NewConfig(), "192.0.2.1:443")

	// A short-header packet, as sent after the handshake.
	payload := []byte{0x40, 1, 2, 3}
	_, err := conn.Write(payload)
	require.NoError(t, err)

	writes, _ := inner.snapshot()
	require.Equal(t, [][]byte{payload}, writes)
}

func TestDialerGeneratorSeesDestination(t *testing.T) {
	var got net.Addr
	conn, _ := newTestDialedConn(t, NewConfig().WithGenerator(
		func(input GeneratorInput) ([][]byte, error) {
			got = input.Destination
			return nil, nil
		}), "192.0.2.1:443")

	_, err := conn.Write(clientInitial(1200))
	require.NoError(t, err)
	require.Equal(t, "192.0.2.1:443", got.String())
}

func TestDialerPreludeWriteFailure(t *testing.T) {
	conn, inner := newTestDialedConn(t, NewConfig(), "192.0.2.1:443")
	inner.setWriteErr(errors.New("network down"))

	_, err := conn.Write(clientInitial(1200))
	require.ErrorContains(t, err, "send datagram 1: network down")
}

func TestNewPacketDialerRejectsBadArguments(t *testing.T) {
	_, err := NewConfig().NewPacketDialer(nil)
	require.Error(t, err)

	_, err = (&Config{}).NewPacketDialer(&transport.UDPDialer{})
	require.Error(t, err)
}

func TestDialerPropagatesDialError(t *testing.T) {
	dialErr := errors.New("dial failed")
	dialer, err := NewConfig().NewPacketDialer(transport.FuncPacketDialer(
		func(context.Context, string) (net.Conn, error) { return nil, dialErr }))
	require.NoError(t, err)

	_, err = dialer.DialPacket(context.Background(), "192.0.2.1:443")
	require.ErrorIs(t, err, dialErr)
}
