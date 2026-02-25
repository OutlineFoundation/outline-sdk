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

package httpconnect

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"

	"golang.getoutline.org/sdk/transport"
)

// ConnectClient is a [transport.StreamDialer] that establishes an HTTP CONNECT tunnel over an abstract HTTP transport.
//
// The package also includes transport builders:
// [NewHTTPProxyTransport],
// [NewHTTP3ProxyTransport].
//
// Options:
// [WithHeaders] appends the provided headers to every CONNECT request.
type ConnectClient struct {
	proxyRT ProxyRoundTripper
	headers http.Header
}

var _ transport.StreamDialer = (*ConnectClient)(nil)

type ProxyRoundTripper interface {
	http.RoundTripper
	Scheme() string
}

type ClientOption func(c *clientConfig)

func NewConnectClient(proxyRT ProxyRoundTripper, opts ...ClientOption) (*ConnectClient, error) {
	if proxyRT == nil {
		return nil, fmt.Errorf("transport must not be nil")
	}

	cfg := &clientConfig{
		headers: make(http.Header),
	}
	for _, opt := range opts {
		opt(cfg)
	}

	return &ConnectClient{
		proxyRT: proxyRT,
		headers: cfg.headers,
	}, nil
}

// WithHeaders appends the given headers to the CONNECT request.
func WithHeaders(headers http.Header) ClientOption {
	return func(c *clientConfig) {
		c.headers = headers.Clone()
	}
}

type clientConfig struct {
	headers http.Header
}

func (cc *ConnectClient) DialStream(ctx context.Context, remoteAddr string) (transport.StreamConn, error) {
	raddr, err := transport.MakeNetAddr("tcp", remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse remote address %s: %w", remoteAddr, err)
	}

	reqReader, reqWriter := net.Pipe()

	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, fmt.Sprintf("%s://%s", cc.proxyRT.Scheme(), remoteAddr), reqReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.ContentLength = -1 // -1 means length unknown
	mergeHeaders(req.Header, cc.headers)

	hc := http.Client{
		Transport: cc.proxyRT,
	}

	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// to provide the SetReadDeadline function of the returned connection, at the expense of an extra copy
	respReader, respWriter := net.Pipe()
	go func() {
		defer resp.Body.Close()
		_, _ = io.Copy(respWriter, resp.Body)
	}()

	return newPipeConn(reqWriter, respReader, raddr), nil
}

func mergeHeaders(dst http.Header, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}
