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

//go:build !android && !(cgo && (linux || freebsd || openbsd || netbsd || dragonfly || solaris)) && !(darwin && cgo)

// Fallback resolver using net.DefaultResolver. Only A and AAAA record types
// are supported. Other record types return [ErrUnsupported].

package sysresolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"golang.getoutline.org/sdk/dns"
	"golang.org/x/net/dns/dnsmessage"
)

var defaultResolver = net.DefaultResolver

// ErrUnsupported is returned when the current platform's fallback resolver
// does not support the requested DNS record type.
var ErrUnsupported = errors.New("record type not supported by fallback resolver")

// NewResolver returns a [dns.Resolver] backed by [net.DefaultResolver].
// Only [dnsmessage.TypeA] and [dnsmessage.TypeAAAA] are supported on this platform.
// For full record-type support, use a platform with CGO enabled.
func NewResolver() dns.Resolver {
	return dns.FuncResolver(func(ctx context.Context, q dnsmessage.Question) (*dnsmessage.Message, error) {
		switch q.Type {
		case dnsmessage.TypeA:
			return lookupAddrs(ctx, q, "ip4")
		case dnsmessage.TypeAAAA:
			return lookupAddrs(ctx, q, "ip6")
		default:
			return nil, fmt.Errorf("%w: %v", ErrUnsupported, q.Type)
		}
	})
}

func lookupAddrs(ctx context.Context, q dnsmessage.Question, network string) (*dnsmessage.Message, error) {
	// Strip trailing dot for net.DefaultResolver.
	host := q.Name.String()
	if len(host) > 0 && host[len(host)-1] == '.' {
		host = host[:len(host)-1]
	}

	addrs, err := defaultLookupNetIP(ctx, network, host)
	if err != nil {
		return nil, err
	}

	msg := &dnsmessage.Message{
		Header: dnsmessage.Header{Response: true},
		Questions: []dnsmessage.Question{q},
	}
	for _, addr := range addrs {
		var body dnsmessage.ResourceBody
		if addr.Is4() {
			body = &dnsmessage.AResource{A: addr.As4()}
		} else {
			body = &dnsmessage.AAAAResource{AAAA: addr.As16()}
		}
		msg.Answers = append(msg.Answers, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name:  q.Name,
				Type:  q.Type,
				Class: q.Class,
				TTL:   0,
			},
			Body: body,
		})
	}
	return msg, nil
}

// defaultLookupNetIP wraps net.DefaultResolver.LookupNetIP. Defined as a
// variable to allow overriding in tests.
var defaultLookupNetIP = func(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return defaultResolver.LookupNetIP(ctx, network, host)
}
