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

package httpconnect

import (
	"context"
	"net/http"
	"slices"
	"sync"
)

// h2ConnPool is an [http.RoundTripper] that sends requests over HTTP/2 connections to a single
// proxy created with [http.Transport.NewClientConn].
//
// Unlike [http.Transport.RoundTrip], which may dial one connection per concurrent request
// before it learns that the server speaks HTTP/2, it dials one connection at a time and
// multiplexes requests on it. It only dials another connection when the existing ones
// can't take more requests (closed, or at their concurrent streams limit).
type h2ConnPool struct {
	tr      *http.Transport
	scheme  string
	address string

	mu    sync.Mutex
	conns []*http.ClientConn
	// dialDone is non-nil while a dial is in progress, and is closed when it finishes.
	dialDone chan struct{}
}

var _ http.RoundTripper = (*h2ConnPool)(nil)

func newH2ConnPool(tr *http.Transport, scheme scheme, address string) *h2ConnPool {
	return &h2ConnPool{tr: tr, scheme: string(scheme), address: address}
}

// RoundTrip implements [http.RoundTripper].
func (p *h2ConnPool) RoundTrip(req *http.Request) (*http.Response, error) {
	cc, err := p.reserveConn(req.Context())
	if err != nil {
		return nil, err
	}
	// RoundTrip consumes the reservation.
	return cc.RoundTrip(req)
}

// reserveConn returns a connection with a reserved slot for one request, dialing one if needed.
func (p *h2ConnPool) reserveConn(ctx context.Context) (*http.ClientConn, error) {
	for {
		p.mu.Lock()
		p.conns = slices.DeleteFunc(p.conns, func(cc *http.ClientConn) bool { return cc.Err() != nil })
		for _, cc := range p.conns {
			if cc.Reserve() == nil {
				p.mu.Unlock()
				return cc, nil
			}
		}
		if dialDone := p.dialDone; dialDone != nil {
			// Another request is dialing. Wait for it and try its connection.
			p.mu.Unlock()
			select {
			case <-dialDone:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		dialDone := make(chan struct{})
		p.dialDone = dialDone
		p.mu.Unlock()

		cc, err := p.tr.NewClientConn(ctx, p.scheme, p.address)

		p.mu.Lock()
		p.dialDone = nil
		close(dialDone)
		if err != nil {
			p.mu.Unlock()
			return nil, err
		}
		// Reserve before publishing the connection, so other requests can't take all its slots.
		reserveErr := cc.Reserve()
		p.conns = append(p.conns, cc)
		p.mu.Unlock()
		if reserveErr != nil {
			return nil, reserveErr
		}
		return cc, nil
	}
}

// CloseIdleConnections closes the connections that have no requests in flight.
func (p *h2ConnPool) CloseIdleConnections() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.conns = slices.DeleteFunc(p.conns, func(cc *http.ClientConn) bool {
		if cc.InFlight() == 0 {
			cc.Close()
			return true
		}
		return cc.Err() != nil
	})
}
