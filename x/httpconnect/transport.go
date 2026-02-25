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
	stdTLS "crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/transport/tls"
	"golang.org/x/net/http2"
)

type TransportOption func(c *transportConfig)

// WithTLSOptions configures the transport to use the given TLS options.
// The default behavior is to use TLS.
func WithTLSOptions(opts ...tls.ClientOption) TransportOption {
	return func(c *transportConfig) {
		c.tlsOptions = append(c.tlsOptions, opts...)
		c.plainHTTP = false
	}
}

// WithPlainHTTP configures the transport to use HTTP instead of HTTPS.
func WithPlainHTTP() TransportOption {
	return func(c *transportConfig) {
		c.plainHTTP = true
	}
}

// NewHTTPProxyTransport creates a net/http Transport that establishes a connection to the proxy using the given [transport.StreamDialer].
// The proxy address must be in the form "host:port".
//
// For HTTP/1 (plain and over TLS) and HTTP/2 (over TLS) over a stream connection.
// When using TLS, pass [WithTLSOptions] with [tls.WithALPN] to enable or enforce HTTP/2.
func NewHTTPProxyTransport(dialer transport.StreamDialer, proxyAddr string, opts ...TransportOption) (ProxyRoundTripper, error) {
	if dialer == nil {
		return nil, errors.New("dialer must not be nil")
	}
	host, _, err := net.SplitHostPort(proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse proxy address %s: %w", proxyAddr, err)
	}

	cfg := &transportConfig{}
	cfg.applyOptions(opts...)

	tlsCfg := &tls.ClientConfig{ServerName: host}
	for _, opt := range cfg.tlsOptions {
		opt(host, tlsCfg)
	}

	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialStream(ctx, proxyAddr)
		},
	}
	err = http2.ConfigureTransport(tr)
	if err != nil {
		return nil, fmt.Errorf("failed to configure http2 transport: %w", err)
	}

	// TLS config must be applied AFTER http2.ConfigureTransport, as it appends h2 to the list of supported protocols.
	tr.TLSClientConfig = tls.ToGoTLSConfig(tlsCfg)

	sch := schemeHTTPS
	if cfg.plainHTTP {
		sch = schemeHTTP
	}

	return proxyRT{
		RoundTripper: tr,
		scheme:       sch,
	}, nil
}

// NewHTTP3ProxyTransport creates an HTTP/3 transport that establishes a QUIC connection to the proxy using the given [net.PacketConn].
// The proxy address must be in the form "host:port".
//
// For HTTP/3 over QUIC over a datagram connection.
// [tls.WithALPN] has no effect on this transport.
func NewHTTP3ProxyTransport(conn net.PacketConn, proxyAddr string, opts ...TransportOption) (ProxyRoundTripper, error) {
	if conn == nil {
		return nil, errors.New("conn must not be nil")
	}
	host, _, err := net.SplitHostPort(proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse proxy address %s: %w", proxyAddr, err)
	}

	cfg := &transportConfig{}
	cfg.applyOptions(opts...)

	tlsConfig := &tls.ClientConfig{ServerName: host}
	for _, opt := range cfg.tlsOptions {
		opt(host, tlsConfig)
	}

	tr := &http3.Transport{
		Dial: func(ctx context.Context, _ string, tlsCfg *stdTLS.Config, quicCfg *quic.Config) (quic.EarlyConnection, error) {
			parsedProxyAddr, err := transport.MakeNetAddr("udp", proxyAddr)
			if err != nil {
				return nil, fmt.Errorf("failed to parse proxy address %s: %w", proxyAddr, err)
			}

			return quic.DialEarly(ctx, conn, parsedProxyAddr, tlsCfg, quicCfg)
		},
		TLSClientConfig: tls.ToGoTLSConfig(tlsConfig),
	}

	return proxyRT{
		RoundTripper: tr,
		scheme:       schemeHTTPS, // HTTP/3 is always over TLS
	}, nil
}

type transportConfig struct {
	tlsOptions []tls.ClientOption
	plainHTTP  bool
}

func (c *transportConfig) applyOptions(opts ...TransportOption) {
	for _, opt := range opts {
		opt(c)
	}
}

type scheme string

const (
	schemeHTTP  scheme = "http"
	schemeHTTPS scheme = "https"
)

type proxyRT struct {
	http.RoundTripper
	scheme scheme
}

func (rt proxyRT) Scheme() string {
	return string(rt.scheme)
}
