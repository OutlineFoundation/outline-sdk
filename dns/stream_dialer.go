// Copyright 2024 The Outline Authors
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

package dns

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"golang.getoutline.org/sdk/transport"
	"golang.org/x/net/dns/dnsmessage"
)

func resolveIP(ctx context.Context, resolver Resolver, rrType dnsmessage.Type, hostname string) ([]netip.Addr, error) {
	ips := []netip.Addr{}
	q, err := NewQuestion(hostname, rrType)
	if err != nil {
		return nil, err
	}
	response, err := resolver.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	if response.RCode != dnsmessage.RCodeSuccess {
		return nil, fmt.Errorf("got %v (%d)", response.RCode.String(), response.RCode)
	}
	for _, answer := range response.Answers {
		if answer.Header.Type != rrType {
			continue
		}
		if rr, ok := answer.Body.(*dnsmessage.AResource); ok {
			ips = append(ips, netip.AddrFrom4(rr.A))
		}
		if rr, ok := answer.Body.(*dnsmessage.AAAAResource); ok {
			ips = append(ips, netip.AddrFrom16(rr.AAAA))
		}
	}
	return ips, nil
}

// NewStreamDialer creates a [transport.StreamDialer] that uses Happy Eyeballs v2 to establish a connection.
// It uses resolver to map host names to IP addresses, and the given dialer to attempt connections.
func NewStreamDialer(resolver Resolver, dialer transport.StreamDialer) (transport.StreamDialer, error) {
	if resolver == nil {
		return nil, errors.New("resolver must not be nil")
	}
	if dialer == nil {
		return nil, errors.New("dialer must not be nil")
	}
	return &transport.HappyEyeballsStreamDialer{
		Dialer: dialer,
		Resolve: transport.NewParallelHappyEyeballsResolveFunc(
			func(ctx context.Context, hostname string) ([]netip.Addr, error) {
				return resolveIP(ctx, resolver, dnsmessage.TypeAAAA, hostname)
			},
			func(ctx context.Context, hostname string) ([]netip.Addr, error) {
				return resolveIP(ctx, resolver, dnsmessage.TypeA, hostname)
			},
		),
	}, nil
}
