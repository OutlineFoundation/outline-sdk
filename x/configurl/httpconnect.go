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

package configurl

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"

	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/transport/tls"
	"golang.getoutline.org/sdk/x/httpconnect"
)

// parseConnectOptions parses query parameters from a hierarchical config URL
// (e.g. h2connect://host:port?sni=example.com&plain=true) into TransportOptions.
//
// Supported parameters:
//   - sni: TLS server name for SNI.
//   - certname: name to validate against the server certificate.
//   - plain: if "true", use cleartext (no TLS). Only meaningful for h2connect (h2c).
func parseConnectOptions(configURL url.URL) ([]httpconnect.TransportOption, error) {
	values, err := url.ParseQuery(configURL.RawQuery)
	if err != nil {
		return nil, err
	}
	var opts []httpconnect.TransportOption
	var tlsOpts []tls.ClientOption
	for key, vals := range values {
		switch strings.ToLower(key) {
		case "sni":
			if len(vals) != 1 {
				return nil, fmt.Errorf("sni option must have one value, found %v", len(vals))
			}
			tlsOpts = append(tlsOpts, tls.WithSNI(vals[0]))
		case "certname":
			if len(vals) != 1 {
				return nil, fmt.Errorf("certname option must have one value, found %v", len(vals))
			}
			tlsOpts = append(tlsOpts, tls.WithCertVerifier(&tls.StandardCertVerifier{CertificateName: vals[0]}))
		case "plain":
			if len(vals) != 1 {
				return nil, fmt.Errorf("plain option must have one value, found %v", len(vals))
			}
			if vals[0] == "true" {
				opts = append(opts, httpconnect.WithPlainHTTP())
			}
		default:
			return nil, fmt.Errorf("unsupported option %v", key)
		}
	}
	if len(tlsOpts) > 0 {
		opts = append(opts, httpconnect.WithTLSOptions(tlsOpts...))
	}
	return opts, nil
}

// registerHTTPConnectStreamDialer registers an HTTP CONNECT proxy transport (H1.1, or H2 via ALPN).
//
// Config format: httpconnect://host:port[?sni=SNI][&certname=CERTNAME]
//
// The base dialer (from the previous element in the pipe chain) is used to establish
// the TCP connection to the proxy. TLS is negotiated by the transport itself.
// When H2 is negotiated via ALPN, CONNECT streams are multiplexed over the single TCP connection.
func registerHTTPConnectStreamDialer(r TypeRegistry[transport.StreamDialer], typeID string, newSD BuildFunc[transport.StreamDialer]) {
	r.RegisterType(typeID, func(ctx context.Context, config *Config) (transport.StreamDialer, error) {
		sd, err := newSD(ctx, config.BaseConfig)
		if err != nil {
			return nil, err
		}
		opts, err := parseConnectOptions(config.URL)
		if err != nil {
			return nil, err
		}
		tr, err := httpconnect.NewHTTPProxyTransport(sd, config.URL.Host, opts...)
		if err != nil {
			return nil, err
		}
		return httpconnect.NewConnectClient(tr)
	})
}

// registerH2ConnectStreamDialer registers a pure HTTP/2 CONNECT proxy transport.
//
// Config format: h2connect://host:port[?sni=SNI][&certname=CERTNAME]
//
// Unlike httpconnect, all CONNECT streams are multiplexed over a single TCP connection
// to the proxy. The base dialer is used to establish that connection.
func registerH2ConnectStreamDialer(r TypeRegistry[transport.StreamDialer], typeID string, newSD BuildFunc[transport.StreamDialer]) {
	r.RegisterType(typeID, func(ctx context.Context, config *Config) (transport.StreamDialer, error) {
		sd, err := newSD(ctx, config.BaseConfig)
		if err != nil {
			return nil, err
		}
		opts, err := parseConnectOptions(config.URL)
		if err != nil {
			return nil, err
		}
		tr, err := httpconnect.NewH2ProxyTransport(sd, config.URL.Host, opts...)
		if err != nil {
			return nil, err
		}
		return httpconnect.NewConnectClient(tr)
	})
}

// registerH3ConnectStreamDialer registers an HTTP/3 CONNECT proxy transport over QUIC.
//
// Config format: h3connect://host:port[?sni=SNI][&certname=CERTNAME]
//
// A UDP socket is created internally and shared across all CONNECT streams (QUIC multiplexing).
// The base stream dialer is not used; QUIC always runs over a fresh UDP connection.
func registerH3ConnectStreamDialer(r TypeRegistry[transport.StreamDialer], typeID string) {
	r.RegisterType(typeID, func(ctx context.Context, config *Config) (transport.StreamDialer, error) {
		opts, err := parseConnectOptions(config.URL)
		if err != nil {
			return nil, err
		}
		udpConn, err := net.ListenPacket("udp", ":0")
		if err != nil {
			return nil, fmt.Errorf("failed to create UDP socket: %w", err)
		}
		tr, err := httpconnect.NewH3ProxyTransport(udpConn, config.URL.Host, opts...)
		if err != nil {
			udpConn.Close()
			return nil, err
		}
		return httpconnect.NewConnectClient(tr)
	})
}
