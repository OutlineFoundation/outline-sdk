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

//go:build nettest

package dns

import (
	"context"
	"testing"

	"golang.getoutline.org/sdk/transport"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
)

// TODO: Make tests not depend on the network.
func newTestContext(t *testing.T) context.Context {
	if deadline, ok := t.Deadline(); ok {
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		t.Cleanup(cancel)
		return ctx
	}
	return context.Background()
}

func TestNewUDPResolver(t *testing.T) {
	ctx := newTestContext(t)
	resolver := NewUDPResolver(&transport.UDPDialer{}, "8.8.8.8")
	q, err := NewQuestion("getoutline.org.", dnsmessage.TypeAAAA)
	require.NoError(t, err)
	resp, err := resolver.Query(ctx, q)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(resp.Answers), 1)
}

func TestNewTCPResolver(t *testing.T) {
	ctx := newTestContext(t)
	resolver := NewTCPResolver(&transport.TCPDialer{}, "8.8.8.8")
	q, err := NewQuestion("getoutline.org.", dnsmessage.TypeAAAA)
	require.NoError(t, err)
	resp, err := resolver.Query(ctx, q)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(resp.Answers), 1)
}

func TestNewTLSResolver(t *testing.T) {
	ctx := newTestContext(t)
	resolver := NewTLSResolver(&transport.TCPDialer{}, "8.8.8.8", "8.8.8.8")
	q, err := NewQuestion("getoutline.org.", dnsmessage.TypeAAAA)
	require.NoError(t, err)
	resp, err := resolver.Query(ctx, q)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(resp.Answers), 1)
}

func TestNewHTTPSResolver(t *testing.T) {
	ctx := newTestContext(t)
	resolver := NewHTTPSResolver(&transport.TCPDialer{}, "8.8.8.8", "https://8.8.8.8/dns-query")
	q, err := NewQuestion("getoutline.org.", dnsmessage.TypeAAAA)
	require.NoError(t, err)
	resp, err := resolver.Query(ctx, q)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(resp.Answers), 1)
}
