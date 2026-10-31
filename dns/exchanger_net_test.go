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

//go:build nettest

package dns

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.getoutline.org/sdk/transport"
	"golang.org/x/net/dns/dnsmessage"
)

// requireResolves exchanges a query for getoutline.org. and checks that the response is a
// valid answer to it, returned in wire format.
func requireResolves(t *testing.T, exchanger Exchanger, id uint16) {
	t.Helper()
	ctx := newTestContext(t)
	q, err := NewQuestion("getoutline.org.", dnsmessage.TypeAAAA)
	require.NoError(t, err)
	query, err := appendRequest(id, *q, make([]byte, 0, maxUDPMessageSize))
	require.NoError(t, err)

	response, err := exchanger.Exchange(ctx, query)
	require.NoError(t, err)

	info, err := parseQuery(query)
	require.NoError(t, err)
	require.NoError(t, checkRawResponse(response, info))
	var msg dnsmessage.Message
	require.NoError(t, msg.Unpack(response))
	require.GreaterOrEqual(t, len(msg.Answers), 1)
}

func TestNewUDPExchanger(t *testing.T) {
	requireResolves(t, NewUDPExchanger(&transport.UDPDialer{}, "8.8.8.8"), 0x1234)
}

func TestNewTCPExchanger(t *testing.T) {
	requireResolves(t, NewTCPExchanger(&transport.TCPDialer{}, "8.8.8.8"), 0x1234)
}

func TestNewTLSExchanger(t *testing.T) {
	requireResolves(t, NewTLSExchanger(&transport.TCPDialer{}, "8.8.8.8", "8.8.8.8"), 0x1234)
}

func TestNewHTTPSExchangerNet(t *testing.T) {
	// RFC 8484 recommends an ID of 0 for DNS-over-HTTPS.
	requireResolves(t, NewHTTPSExchanger(&transport.TCPDialer{}, "8.8.8.8", "https://8.8.8.8/dns-query"), 0)
}
