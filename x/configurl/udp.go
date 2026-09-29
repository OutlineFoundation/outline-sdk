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
	"fmt"
	"net"
	"strconv"
	"sync"

	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/x/internal/packetconn"
)

// resolvingUDPListener accepts hostnames at the direct UDP boundary. Installing
// it as the base listener also supports direct QUIC preludes, without resolving
// the destinations carried by SOCKS5 or Shadowsocks packet listeners.
type resolvingUDPListener struct{}

func (resolvingUDPListener) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	conn, err := (transport.UDPListener{}).ListenPacket(ctx)
	if err != nil {
		return nil, err
	}
	// Like net.ListenConfig, the caller's context only governs socket setup.
	// Later writes use a connection-owned context, canceled by Close.
	ctx, cancel := context.WithCancel(context.Background())
	return &resolvingUDPConn{
		Generic: packetconn.Generic{PacketConn: conn}, ctx: ctx, cancel: cancel,
		lookup:    net.DefaultResolver.LookupIPAddr,
		addresses: make(map[string]*udpResolution),
	}, nil
}

// resolvingUDPConn owns resolution only for direct UDP, never for a proxy's
// logical destination. The cached answer keeps a QUIC flow on one endpoint.
type resolvingUDPConn struct {
	packetconn.Generic
	ctx       context.Context
	cancel    context.CancelFunc
	lookup    func(context.Context, string) ([]net.IPAddr, error)
	mu        sync.Mutex
	addresses map[string]*udpResolution
}

// The result is immutable once ready is closed. Successful entries stay pinned;
// failed entries are removed so a later write can retry.
type udpResolution struct {
	ready chan struct{}
	addr  *net.UDPAddr
	err   error
}

func (c *resolvingUDPConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if _, ok := addr.(*net.UDPAddr); ok {
		return c.PacketConn.WriteTo(p, addr)
	}
	resolved, err := c.resolve(addr.String())
	if err != nil {
		return 0, err
	}
	return c.PacketConn.WriteTo(p, resolved)
}

func (c *resolvingUDPConn) resolve(address string) (*net.UDPAddr, error) {
	c.mu.Lock()
	if pending := c.addresses[address]; pending != nil {
		c.mu.Unlock()
		<-pending.ready
		return pending.addr, pending.err
	}
	pending := &udpResolution{ready: make(chan struct{})}
	c.addresses[address] = pending
	c.mu.Unlock()

	// Deduplicate lookups for this destination without blocking other addresses,
	// including already cached ones, behind a potentially slow DNS request.
	pending.addr, pending.err = c.lookupAddress(address)
	c.mu.Lock()
	if pending.err != nil {
		delete(c.addresses, address)
	}
	close(pending.ready)
	c.mu.Unlock()
	return pending.addr, pending.err
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
	return c.PacketConn.Close()
}
