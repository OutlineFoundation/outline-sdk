// Copyright 2025 The Outline Authors
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

package configurl_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/x/configurl"
	"golang.getoutline.org/sdk/x/httpproxy"
	"golang.org/x/net/http2"
)

// Test_H2Connect_H2C tests the h2connect configurl type using h2c (cleartext HTTP/2).
// It starts a local h2c proxy, builds a stream dialer via "h2connect://host:port?plain=true",
// and verifies that an HTTP request is tunneled through to a target server.
func Test_H2Connect_H2C(t *testing.T) {
	t.Parallel()

	tcpDialer := &transport.TCPDialer{}

	// Start an h2c proxy server (plain HTTP/2 without TLS).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	h2srv := &http2.Server{}
	handler := httpproxy.NewConnectHandler(tcpDialer)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go h2srv.ServeConn(conn, &http2.ServeConnOpts{Handler: handler})
		}
	}()

	// Build a dialer using the configurl h2connect type.
	providers := configurl.NewDefaultProviders()
	dialer, err := providers.NewStreamDialer(context.Background(),
		fmt.Sprintf("h2connect://%s?plain=true", ln.Addr().String()),
	)
	require.NoError(t, err)

	// Start a target server that returns a JSON response.
	type Response struct {
		Message string `json:"message"`
	}
	want := Response{Message: "hello"}
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(want)
	}))
	t.Cleanup(targetSrv.Close)

	// Make an HTTP request through the tunnel.
	hc := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return dialer.DialStream(ctx, addr)
			},
		},
	}
	resp, err := hc.Get(targetSrv.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var got Response
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	require.Equal(t, want, got)
}
