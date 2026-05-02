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

package lwip2transport

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"golang.getoutline.org/sdk/network"
	"github.com/stretchr/testify/require"
)

// Make sure PacketResponseReceiver Closes the corresponding PacketRequestSender.
func TestUDPResponseWriterCloseNoDeadlock(t *testing.T) {
	proxy := &noopSingleSessionPacketProxy{}
	h := newUDPHandler(proxy)

	// Create one and only one session in the proxy
	localAddr := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:60127"))
	destAddr := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("1.2.3.4:4321"))
	err := h.ReceiveTo(&noopLwIPUDPConn{localAddr}, []byte{}, destAddr)
	require.NoError(t, err)

	// Close proxy.respWriter, it should indirectly Close the proxy only once.
	const ConcurrentCloseCount = 50
	errChan := make(chan error, ConcurrentCloseCount)
	for i := 0; i < ConcurrentCloseCount; i++ {
		go func(k int) {
			errChan <- proxy.respWriter.Close()
		}(i)
	}

	nNilErr := 0
	for i := 0; i < ConcurrentCloseCount; i++ {
		if e := <-errChan; e == nil {
			nNilErr++
		} else {
			require.ErrorIs(t, e, network.ErrClosed)
		}
	}
	require.Equal(t, 1, nNilErr)
	require.Equal(t, 1, proxy.closeCnt)
}

// Make sure ReceiveTo can handle errors without deadlock.
func TestReceiveToNoDeadlockWhenError(t *testing.T) {
	h := newUDPHandler(errPacketProxy{})
	localAddr := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:60127"))
	destAddr := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("1.2.3.4:4321"))
	err := h.ReceiveTo(&noopLwIPUDPConn{localAddr}, []byte{}, destAddr)
	require.ErrorIs(t, err, errNewSession)
}

/********** Test Utilities **********/

// noopSingleSessionPacketProxy returns a single PacketRequestSender that does nothing.
type noopSingleSessionPacketProxy struct {
	closeCnt   int
	respWriter network.PacketResponseReceiver
}

func (p *noopSingleSessionPacketProxy) NewSession(respWriter network.PacketResponseReceiver) (network.PacketRequestSender, error) {
	if p.respWriter != nil {
		return nil, errors.New("don't support multiple sessions in this proxy")
	}
	p.respWriter = respWriter
	return p, nil
}

func (p *noopSingleSessionPacketProxy) Close() error {
	p.closeCnt++
	return p.respWriter.Close()
}

func (p *noopSingleSessionPacketProxy) WriteTo([]byte, netip.AddrPort) (int, error) {
	return 0, nil
}

// noopLwIPUDPConn is a UDPConn that does nothing.
type noopLwIPUDPConn struct {
	localAddr *net.UDPAddr
}

func (*noopLwIPUDPConn) Close() error {
	return nil
}

func (conn *noopLwIPUDPConn) LocalAddr() *net.UDPAddr {
	return conn.localAddr
}

func (*noopLwIPUDPConn) ReceiveTo(data []byte, addr *net.UDPAddr) error {
	return nil
}

func (*noopLwIPUDPConn) WriteFrom(data []byte, addr *net.UDPAddr) (int, error) {
	return 0, nil
}

// noopSingleSessionPacketProxy always returns an error in NewSession.
type errPacketProxy struct {
}

var errNewSession = errors.New("error in NewSession")

func (errPacketProxy) NewSession(network.PacketResponseReceiver) (network.PacketRequestSender, error) {
	return nil, errNewSession
}
