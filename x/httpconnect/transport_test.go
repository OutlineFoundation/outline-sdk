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
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_protocolsForALPN(t *testing.T) {
	tests := []struct {
		name       string
		plainHTTP  bool
		nextProtos []string
		wantHTTP1  bool
		wantHTTP2  bool
	}{
		{name: "no ALPN", wantHTTP1: true},
		{name: "h2 only", nextProtos: []string{"h2"}, wantHTTP2: true},
		{name: "h2 and http/1.1", nextProtos: []string{"h2", "http/1.1"}, wantHTTP1: true, wantHTTP2: true},
		{name: "http/1.1 only", nextProtos: []string{"http/1.1"}, wantHTTP1: true},
		{name: "other protocol", nextProtos: []string{"foo"}, wantHTTP1: true},
		{name: "plain HTTP ignores ALPN", plainHTTP: true, nextProtos: []string{"h2"}, wantHTTP1: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := protocolsForALPN(tc.plainHTTP, tc.nextProtos)
			require.Equal(t, tc.wantHTTP1, p.HTTP1(), "HTTP1")
			require.Equal(t, tc.wantHTTP2, p.HTTP2(), "HTTP2")
			require.False(t, p.UnencryptedHTTP2(), "UnencryptedHTTP2")
		})
	}
}
