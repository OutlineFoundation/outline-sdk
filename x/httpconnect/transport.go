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

	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/transport/tls"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
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
// When using TLS, pass WithTLSOptions(tls.WithALPN()) to enable or enforce HTTP/2.
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

	tlsCfg := tls.ClientConfig{ServerName: host}
	for _, opt := range cfg.tlsOptions {
		opt(host, &tlsCfg)
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
	tr.TLSClientConfig = toStdConfig(tlsCfg)

	sch := schemeHTTPS
	if cfg.plainHTTP {
		sch = schemeHTTP
	}

	return proxyRT{
		RoundTripper: tr,
		scheme:       sch,
	}, nil
}

// NewH2ProxyTransport creates a pure HTTP/2 transport that establishes a connection to the proxy
// using the given [transport.StreamDialer].
// The proxy address must be in the form "host:port".
//
// Unlike [NewHTTPProxyTransport], this uses [golang.org/x/net/http2.Transport] directly, enabling:
//   - h2c (cleartext HTTP/2 via prior knowledge) with [WithPlainHTTP] — no TLS required
//   - Pure H2 from byte 1: multiple concurrent CONNECT tunnels share one TCP connection
func NewH2ProxyTransport(dialer transport.StreamDialer, proxyAddr string, opts ...TransportOption) (ProxyRoundTripper, error) {
	if dialer == nil {
		return nil, errors.New("dialer must not be nil")
	}
	host, _, err := net.SplitHostPort(proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse proxy address %s: %w", proxyAddr, err)
	}

	cfg := &transportConfig{}
	cfg.applyOptions(opts...)

	var tr *http2.Transport
	if cfg.plainHTTP {
		tr = &http2.Transport{
			AllowHTTP: true,
			// DialTLSContext is used even for plaintext when AllowHTTP is true.
			DialTLSContext: func(ctx context.Context, _, _ string, _ *stdTLS.Config) (net.Conn, error) {
				return dialer.DialStream(ctx, proxyAddr)
			},
		}
	} else {
		tlsCfg := tls.ClientConfig{ServerName: host}
		for _, opt := range cfg.tlsOptions {
			opt(host, &tlsCfg)
		}
		stdCfg := toStdConfig(tlsCfg)
		// Ensure "h2" is in ALPN NextProtos so the server negotiates HTTP/2.
		stdCfg.NextProtos = append([]string{"h2"}, stdCfg.NextProtos...)
		tr = &http2.Transport{
			// http2.Transport type-asserts to *tls.Conn to read NegotiatedProtocol,
			// so we must return *stdTLS.Conn directly — not an sdk tls.WrapConn wrapper.
			DialTLSContext: func(ctx context.Context, _, _ string, _ *stdTLS.Config) (net.Conn, error) {
				conn, err := dialer.DialStream(ctx, proxyAddr)
				if err != nil {
					return nil, err
				}
				tlsConn := stdTLS.Client(conn, stdCfg)
				if err := tlsConn.HandshakeContext(ctx); err != nil {
					conn.Close()
					return nil, err
				}
				return tlsConn, nil
			},
		}
	}

	sch := schemeHTTPS
	if cfg.plainHTTP {
		sch = schemeHTTP
	}

	return proxyRT{
		RoundTripper: tr,
		scheme:       sch,
	}, nil
}

// NewH3ProxyTransport creates an HTTP/3 transport that establishes a QUIC connection to the proxy using the given [net.PacketConn].
// The proxy address must be in the form "host:port".
//
// The connection must accept the proxy address in WriteTo. A UDP socket only accepts IP addresses,
// so a hostname is rejected for a connection with the UDP-specific methods QUIC-Go looks for.
// Use [NewH3ProxyTransportFromDialer] to let the transport resolve the proxy address.
//
// For HTTP/3 over QUIC over a datagram connection.
// [tls.WithALPN] has no effect on this transport.
func NewH3ProxyTransport(conn net.PacketConn, proxyAddr string, opts ...TransportOption) (ProxyRoundTripper, error) {
	if conn == nil {
		return nil, errors.New("conn must not be nil")
	}
	return newH3ProxyTransport(proxyAddr, opts, func(ctx context.Context, tlsCfg *stdTLS.Config, quicCfg *quic.Config) (quic.EarlyConnection, error) {
		parsedProxyAddr, err := transport.MakeNetAddr("udp", proxyAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse proxy address %s: %w", proxyAddr, err)
		}
		// QUIC-Go writes to such a connection with WriteMsgUDP, and panics if the address is not a UDP address.
		if _, isUDPConn := conn.(quic.OOBCapablePacketConn); isUDPConn {
			if _, isUDPAddr := parsedProxyAddr.(*net.UDPAddr); !isUDPAddr {
				return nil, fmt.Errorf("proxy address %s must be an IP address for a UDP connection", proxyAddr)
			}
		}
		return quic.DialEarly(ctx, conn, parsedProxyAddr, tlsCfg, quicCfg)
	})
}

// NewH3ProxyTransportFromDialer creates an HTTP/3 transport that establishes each QUIC connection to the proxy
// over a packet connection dialed with the given [transport.PacketDialer].
// The proxy address must be in the form "host:port".
//
// The dialer decides how the address is resolved: a [transport.UDPDialer] resolves a hostname locally,
// while a dialer that goes through a relay can send the hostname to it. A new QUIC connection dials again.
//
// For HTTP/3 over QUIC over a datagram connection.
// [tls.WithALPN] has no effect on this transport.
func NewH3ProxyTransportFromDialer(dialer transport.PacketDialer, proxyAddr string, opts ...TransportOption) (ProxyRoundTripper, error) {
	if dialer == nil {
		return nil, errors.New("dialer must not be nil")
	}
	return newH3ProxyTransport(proxyAddr, opts, func(ctx context.Context, tlsCfg *stdTLS.Config, quicCfg *quic.Config) (quic.EarlyConnection, error) {
		conn, err := dialer.DialPacket(ctx, proxyAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to dial proxy %s: %w", proxyAddr, err)
		}
		qconn, err := quic.DialEarly(ctx, newDialedPacketConn(conn), conn.RemoteAddr(), tlsCfg, quicCfg)
		if err != nil {
			conn.Close()
			return nil, err
		}
		// QUIC-Go does not close a connection it did not create.
		context.AfterFunc(qconn.Context(), func() { conn.Close() })
		return qconn, nil
	})
}

type quicDialFunc func(ctx context.Context, tlsCfg *stdTLS.Config, quicCfg *quic.Config) (quic.EarlyConnection, error)

func newH3ProxyTransport(proxyAddr string, opts []TransportOption, dial quicDialFunc) (ProxyRoundTripper, error) {
	host, _, err := net.SplitHostPort(proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse proxy address %s: %w", proxyAddr, err)
	}

	cfg := &transportConfig{}
	cfg.applyOptions(opts...)

	tlsConfig := tls.ClientConfig{ServerName: host}
	for _, opt := range cfg.tlsOptions {
		opt(host, &tlsConfig)
	}

	tr := &http3.Transport{
		Dial: func(ctx context.Context, _ string, tlsCfg *stdTLS.Config, quicCfg *quic.Config) (quic.EarlyConnection, error) {
			return dial(ctx, tlsCfg, quicCfg)
		},
		TLSClientConfig: toStdConfig(tlsConfig),
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

// TODO: Replace with tls.ToGoTLSConfig call once outline-sdk dependency version for this module is bumped.
// It is basically a copy of the implementation ToGoTLSConfig
func toStdConfig(cfg tls.ClientConfig) *stdTLS.Config {
	certVerifier := cfg.CertVerifier
	if certVerifier == nil {
		certVerifier = &tls.StandardCertVerifier{CertificateName: cfg.ServerName}
	}
	return &stdTLS.Config{
		ServerName:         cfg.ServerName,
		NextProtos:         cfg.NextProtos,
		ClientSessionCache: cfg.SessionCache,
		// Set InsecureSkipVerify to skip the default validation we are
		// replacing. This will not disable VerifyConnection.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs stdTLS.ConnectionState) error {
			return certVerifier.VerifyCertificate(&tls.CertVerificationContext{
				PeerCertificates: cs.PeerCertificates,
			})
		},
	}
}
