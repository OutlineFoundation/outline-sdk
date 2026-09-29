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
// The proxy address must be in the form "host:port". The host may be an IP address or a hostname.
// A hostname is resolved with the system resolver each time a QUIC connection is established,
// preferring an address of the same IP family as the connection's local address.
//
// For HTTP/3 over QUIC over a datagram connection.
// [tls.WithALPN] has no effect on this transport.
func NewH3ProxyTransport(conn net.PacketConn, proxyAddr string, opts ...TransportOption) (ProxyRoundTripper, error) {
	if conn == nil {
		return nil, errors.New("conn must not be nil")
	}
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
			// QUIC writes datagrams to this address, so it must be a resolved *net.UDPAddr:
			// net.UDPConn rejects any other net.Addr type.
			proxyUDPAddr, err := resolveUDPAddr(ctx, conn.LocalAddr(), proxyAddr)
			if err != nil {
				return nil, fmt.Errorf("failed to resolve proxy address %s: %w", proxyAddr, err)
			}

			return quic.DialEarly(ctx, conn, proxyUDPAddr, tlsCfg, quicCfg)
		},
		TLSClientConfig: toStdConfig(tlsConfig),
	}

	return proxyRT{
		RoundTripper: tr,
		scheme:       schemeHTTPS, // HTTP/3 is always over TLS
	}, nil
}

// resolveUDPAddr resolves a "host:port" address to a [net.UDPAddr] that can be written to from a
// packet connection bound to localAddr. An IP literal is used as is. A hostname is looked up with
// [net.DefaultResolver] and the address is chosen with [chooseIPAddr].
func resolveUDPAddr(ctx context.Context, localAddr net.Addr, address string) (*net.UDPAddr, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	port, err := net.DefaultResolver.LookupPort(ctx, "udp", portStr)
	if err != nil {
		return nil, err
	}

	if ip := net.ParseIP(host); ip != nil {
		return &net.UDPAddr{IP: ip, Port: port}, nil
	}

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses found for host %q", host)
	}

	chosen := chooseIPAddr(localAddr, ips)

	return &net.UDPAddr{IP: chosen.IP, Port: port, Zone: chosen.Zone}, nil
}

// chooseIPAddr picks, from the non-empty list ips, the address a packet connection bound to
// localAddr should send to. A connection bound to a specific IPv6 address can only reach IPv6, so
// IPv6 is preferred for it. Anything else (an IPv4 address, the unspecified address, which Go binds
// dual-stack, or a local address that is not a [net.UDPAddr], such as a proxied connection) prefers
// IPv4, like [net.ResolveUDPAddr] does for the "udp" network. If no address of the preferred family
// exists, the first address is returned.
func chooseIPAddr(localAddr net.Addr, ips []net.IPAddr) net.IPAddr {
	preferIPv6 := false

	if udpAddr, ok := localAddr.(*net.UDPAddr); ok && udpAddr != nil {
		ip := udpAddr.IP
		preferIPv6 = len(ip) > 0 && ip.To4() == nil && !ip.IsUnspecified()
	}

	for _, ipAddr := range ips {
		if (ipAddr.IP.To4() == nil) == preferIPv6 {
			return ipAddr
		}
	}

	return ips[0]
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
