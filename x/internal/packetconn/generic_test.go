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

package packetconn

import (
	"errors"
	"net"
	"testing"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
	"golang.getoutline.org/sdk/transport"
)

type recordingConn struct {
	*net.UDPConn
	destination         net.Addr
	readSize, writeSize int
	err                 error
}

func (c *recordingConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.destination = addr
	return len(p), c.err
}
func (c *recordingConn) SetReadBuffer(n int) error  { c.readSize = n; return c.err }
func (c *recordingConn) SetWriteBuffer(n int) error { c.writeSize = n; return c.err }

func TestGenericDelegatesWithoutUDPOptimizations(t *testing.T) {
	failure := errors.New("underlying error")
	underlying := &recordingConn{err: failure}
	require.Implements(t, (*quic.OOBCapablePacketConn)(nil), underlying)
	conn := Generic{PacketConn: underlying}
	_, optimized := any(conn).(quic.OOBCapablePacketConn)
	require.False(t, optimized)
	addr, err := transport.MakeNetAddr("udp", "proxy-only.invalid:443")
	require.NoError(t, err)
	n, err := conn.WriteTo([]byte("packet"), addr)
	require.Equal(t, 6, n)
	require.ErrorIs(t, err, failure)
	require.Same(t, addr, underlying.destination)
	require.ErrorIs(t, conn.SetReadBuffer(123), failure)
	require.ErrorIs(t, conn.SetWriteBuffer(456), failure)
	require.Equal(t, 123, underlying.readSize)
	require.Equal(t, 456, underlying.writeSize)
}

func TestGenericUnsupportedBuffers(t *testing.T) {
	conn := Generic{PacketConn: struct{ net.PacketConn }{}}
	require.ErrorIs(t, conn.SetReadBuffer(123), errors.ErrUnsupported)
	require.ErrorIs(t, conn.SetWriteBuffer(456), errors.ErrUnsupported)
}
