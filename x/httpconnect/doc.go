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

// Package httpconnect provides an HTTP CONNECT tunnel client that works over
// HTTP/1.1, HTTP/2, and HTTP/3.
//
// # Overview
//
// An HTTP CONNECT proxy accepts a CONNECT request from the client, dials the
// requested host:port, responds with 200 OK, and then relays bytes in both
// directions. This package implements the client side of that exchange.
//
// The entry points are:
//   - [NewConnectClient]: creates a [transport.StreamDialer] that tunnels through the proxy.
//   - [NewHTTPProxyTransport]: HTTP/1.1 (or H2 via ALPN) transport for [NewConnectClient].
//   - [NewH2ProxyTransport]: pure HTTP/2 transport; supports h2c and multiplexes all CONNECT
//     streams over a single TCP connection.
//   - [NewH3ProxyTransport]: HTTP/3 over QUIC transport. It multiplexes all CONNECT streams
//     over a single QUIC connection.
//
// # Manual testing with Caddy
//
// Caddy (https://caddyserver.com) with the forward_proxy community module
// (https://github.com/caddyserver/forwardproxy) is a convenient way to run a
// local CONNECT proxy that supports H1, H2, and H3. Use xcaddy to build it:
//
//	go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
//	xcaddy build --with github.com/caddyserver/forwardproxy
//
// Then write a Caddyfile. Use tls internal for a locally-trusted certificate
// (requires the Caddy root CA to be trusted — run "caddy trust" once):
//
//	# Caddyfile
//	:8443 {
//	    tls internal
//	    forward_proxy
//	}
//
// Or supply your own certificate:
//
//	# Caddyfile
//	:8443 {
//	    tls /path/to/cert.pem /path/to/key.pem
//	    forward_proxy
//	}
//
// Start the proxy:
//
//	caddy run --config Caddyfile
//
// Caddy serves H1, H2, and H3 on the same port. H3 runs over UDP on the same
// port number as the TLS listener.
//
// # Connecting with this package
//
// Connect over H2 (multiplexed — all CONNECT streams share one TCP connection):
//
//	tr, err := httpconnect.NewH2ProxyTransport(&transport.TCPDialer{}, "127.0.0.1:8443",
//	    httpconnect.WithTLSOptions(
//	        tls.WithCertVerifier(&tls.StandardCertVerifier{}), // uses system roots
//	    ),
//	)
//	client, err := httpconnect.NewConnectClient(tr)
//	conn, err := client.DialStream(ctx, "example.com:443")
//
// Connect over H3 (QUIC):
//
//	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
//	tr, err := httpconnect.NewH3ProxyTransport(udpConn, "127.0.0.1:8443",
//	    httpconnect.WithTLSOptions(
//	        tls.WithCertVerifier(&tls.StandardCertVerifier{}),
//	    ),
//	)
//	client, err := httpconnect.NewConnectClient(tr)
//	conn, err := client.DialStream(ctx, "example.com:443")
//
// # Notes on the forward_proxy module and localhost
//
// By default the forward_proxy module denies connections to private/loopback
// addresses (127.0.0.0/8, 10.0.0.0/8, etc.) as an SSRF mitigation. To allow
// them in a test environment, add an explicit ACL rule in the Caddyfile:
//
//	:8443 {
//	    tls internal
//	    forward_proxy {
//	        acl {
//	            allow 127.0.0.0/8
//	        }
//	    }
//	}
package httpconnect
