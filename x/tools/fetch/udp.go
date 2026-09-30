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

package main

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"

	"golang.getoutline.org/sdk/transport"
)

// resolvingUDPListener is fetch's direct UDP base, below wrappers such as
// quicprelude. Proxy listeners keep their own destination-address handling.
type resolvingUDPListener struct{}

func (resolvingUDPListener) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	conn, err := (transport.UDPListener{}).ListenPacket(ctx)
	if err != nil {
		return nil, err
	}
	// The setup context does not own the returned connection.
	ctx, cancel := context.WithCancel(context.Background())
	return &resolvingUDPConn{
		udpSocket: conn.(*net.UDPConn), ctx: ctx, cancel: cancel,
		lookup: net.DefaultResolver.LookupIPAddr,
	}, nil
}

// Expose buffer sizing, but hide the UDP OOB methods: QUIC-Go must call WriteTo
// for domain addresses instead of asserting that they are *net.UDPAddr.
type udpSocket interface {
	net.PacketConn
	SetReadBuffer(int) error
	SetWriteBuffer(int) error
}

type resolvingUDPConn struct {
	udpSocket
	ctx       context.Context
	cancel    context.CancelFunc
	lookup    func(context.Context, string) ([]net.IPAddr, error)
	addresses sync.Map // address string -> *udpResolution
}

type udpResolution struct {
	once sync.Once
	addr *net.UDPAddr
	err  error
}

func (c *resolvingUDPConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if _, ok := addr.(*net.UDPAddr); ok {
		return c.udpSocket.WriteTo(p, addr)
	}
	resolved, err := c.resolve(addr.String())
	if err != nil {
		return 0, err
	}
	return c.udpSocket.WriteTo(p, resolved)
}

func (c *resolvingUDPConn) resolve(address string) (*net.UDPAddr, error) {
	entry, _ := c.addresses.LoadOrStore(address, &udpResolution{})
	result := entry.(*udpResolution)
	// Pin one answer so the prelude and QUIC packets reach the same endpoint.
	// Unrelated destinations do not wait on each other's DNS lookups.
	result.once.Do(func() { result.addr, result.err = c.lookupAddress(address) })
	if result.err != nil {
		c.addresses.CompareAndDelete(address, result)
	}
	return result.addr, result.err
}

func (c *resolvingUDPConn) lookupAddress(address string) (*net.UDPAddr, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	// MakeNetAddr has already converted service names to numeric ports.
	port, err := strconv.Atoi(portText)
	if err != nil {
		return nil, err
	}
	ips, err := c.lookup(c.ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses found for %s", host)
	}
	chosen := ips[0]
	for _, ip := range ips {
		if ip.IP.To4() != nil {
			chosen = ip
			break
		}
	}
	return &net.UDPAddr{IP: chosen.IP, Port: port, Zone: chosen.Zone}, nil
}

func (c *resolvingUDPConn) Close() error {
	c.cancel()
	return c.udpSocket.Close()
}
