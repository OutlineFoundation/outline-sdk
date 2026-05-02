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

// Make sure PacketHandler Closes the corresponding PacketSender.
func TestUDPHandlerCloseNoDeadlock(t *testing.T) {
	relay := &noopSingleSessionPacketRelay{
		handlerChan: make(chan network.PacketHandler, 1),
		closeSig:    make(chan struct{}),
	}
	h := newUDPHandler(network.NewPacketProxyFromPacketRelay(relay))

	// Create one and only one session in the proxy
	localAddr := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:60127"))
	destAddr := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("1.2.3.4:4321"))
	err := h.ReceiveTo(&noopLwIPUDPConn{localAddr}, []byte{}, destAddr)
	require.NoError(t, err)

	// Wait for the handler to be captured in the goroutine spawned by newAssociation
	handler := <-relay.handlerChan

	// Close the handler, it should indirectly Close the relay only once.
	const ConcurrentCloseCount = 50
	errChan := make(chan error, ConcurrentCloseCount)
	for i := 0; i < ConcurrentCloseCount; i++ {
		go func() {
			errChan <- handler.Close()
		}()
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
	require.Equal(t, 1, relay.closeCnt)
}

// Make sure ReceiveTo can handle errors without deadlock.
func TestReceiveToNoDeadlockWhenError(t *testing.T) {
	h := newUDPHandler(network.NewPacketProxyFromPacketRelay(errPacketRelay{}))
	localAddr := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:60127"))
	destAddr := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("1.2.3.4:4321"))
	err := h.ReceiveTo(&noopLwIPUDPConn{localAddr}, []byte{}, destAddr)
	require.ErrorIs(t, err, errNewAssociation)
}

/********** Test Utilities **********/

// noopSingleSessionPacketRelay returns a single PacketSender/Receiver that does nothing.
type noopSingleSessionPacketRelay struct {
	closeCnt    int
	handlerChan chan network.PacketHandler
	closeSig    chan struct{}
}

func (p *noopSingleSessionPacketRelay) NewAssociation() (network.PacketSender, network.PacketReceiver, error) {
	return p, p, nil
}

func (p *noopSingleSessionPacketRelay) SendPacket([]byte, netip.AddrPort) error {
	return nil
}

func (p *noopSingleSessionPacketRelay) ReceivePackets(handler network.PacketHandler) error {
	p.handlerChan <- handler
	<-p.closeSig
	return nil
}

func (p *noopSingleSessionPacketRelay) Close() error {
	p.closeCnt++
	return nil
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

// errPacketRelay always returns an error in NewAssociation.
type errPacketRelay struct{}

var errNewAssociation = errors.New("error in NewAssociation")

func (errPacketRelay) NewAssociation() (network.PacketSender, network.PacketReceiver, error) {
	return nil, nil, errNewAssociation
}
