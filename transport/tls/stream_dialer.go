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

package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"

	"golang.getoutline.org/sdk/transport"
)

// StreamDialer is a [transport.StreamDialer] that uses TLS to wrap the inner StreamDialer.
type StreamDialer struct {
	// dialer provides the underlying connection to be wrapped.
	dialer transport.StreamDialer
	// options to configure the tls.Config.
	options []ClientOption
}

var _ transport.StreamDialer = (*StreamDialer)(nil)

// NewStreamDialer creates a [StreamDialer] that wraps the connections from the baseDialer with TLS
// configured with the given options.
func NewStreamDialer(baseDialer transport.StreamDialer, options ...ClientOption) (*StreamDialer, error) {
	if baseDialer == nil {
		return nil, errors.New("base dialer must not be nil")
	}
	return &StreamDialer{baseDialer, options}, nil
}

// streamConn wraps a [tls.Conn] to provide a [transport.StreamConn] interface.
type streamConn struct {
	*tls.Conn
	innerConn transport.StreamConn
}

var _ transport.StreamConn = (*streamConn)(nil)

func (c streamConn) CloseWrite() error {
	tlsErr := c.Conn.CloseWrite()
	return errors.Join(tlsErr, c.innerConn.CloseWrite())
}

func (c streamConn) CloseRead() error {
	return c.innerConn.CloseRead()
}

// DialStream implements [transport.StreamDialer].DialStream.
func (d *StreamDialer) DialStream(ctx context.Context, remoteAddr string) (transport.StreamConn, error) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %w", err)
	}
	innerConn, err := d.dialer.DialStream(ctx, remoteAddr)
	if err != nil {
		return nil, err
	}
	conn, err := WrapConn(ctx, innerConn, host, d.options...)
	if err != nil {
		innerConn.Close()
		return nil, err
	}
	return conn, nil
}

func normalizeHost(host string) string {
	return strings.ToLower(host)
}

// ClientConfig holds configuration parameters used for establishing a TLS client connection.
type ClientConfig struct {
	// ServerName specifies the hostname sent for Server Name Indication (SNI).
	// This is often the same as the dialed hostname but can be overridden using [WithSNI].
	ServerName string

	// NextProtos lists the application-layer protocols (e.g., "h2", "http/1.1")
	// supported by the client for Application-Layer Protocol Negotiation (ALPN).
	// See [WithALPN].
	NextProtos []string

	// SessionCache enables TLS session resumption by providing a cache for session tickets.
	// If nil, session resumption is disabled. See [WithSessionCache].
	SessionCache tls.ClientSessionCache

	// CertVerifier specifies a custom verifier for the peer's certificate chain.
	// If nil, [StandardCertVerifier] is used by default, validating against the dialed
	// server name. See [WithCertVerifier].
	CertVerifier CertVerifier
}

// ToGoTLSConfig converts the ClientConfig to a [tls.Config].
func ToGoTLSConfig(cfg *ClientConfig) *tls.Config {
	return cfg.toStdConfig()
}

// toStdConfig creates a [tls.Config] based on the configured parameters.
func (cfg *ClientConfig) toStdConfig() *tls.Config {
	certVerifier := cfg.CertVerifier
	if certVerifier == nil {
		certVerifier = &StandardCertVerifier{CertificateName: cfg.ServerName}
	}
	return &tls.Config{
		ServerName:         cfg.ServerName,
		NextProtos:         cfg.NextProtos,
		ClientSessionCache: cfg.SessionCache,
		// Set InsecureSkipVerify to skip the default validation we are
		// replacing. This will not disable VerifyConnection.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			return certVerifier.VerifyCertificate(&CertVerificationContext{
				PeerCertificates: cs.PeerCertificates,
			})
		},
	}
}

// WrapConn wraps a [transport.StreamConn] in a TLS connection.
func WrapConn(ctx context.Context, conn transport.StreamConn, serverName string, options ...ClientOption) (transport.StreamConn, error) {
	cfg := ClientConfig{ServerName: serverName}
	normName := normalizeHost(serverName)
	for _, option := range options {
		option(normName, &cfg)
	}
	if cfg.CertVerifier == nil {
		// If CertVerifier is not provided, use the default verification logic,
		// which validates the peer certificate against the provided serverName.
		cfg.CertVerifier = &StandardCertVerifier{CertificateName: serverName}
	}
	tlsConn := tls.Client(conn, cfg.toStdConfig())
	err := tlsConn.HandshakeContext(ctx)
	if err != nil {
		return nil, err
	}
	return streamConn{tlsConn, conn}, nil
}

// WithSNI sets the host name for [Server Name Indication] (SNI).
// If absent, defaults to the dialed hostname.
// Note that this only changes what is sent in the SNI, not what host is used for certificate verification.
//
// [Server Name Indication]: https://datatracker.ietf.org/doc/html/rfc6066#section-3
func WithSNI(hostName string) ClientOption {
	return func(_ string, config *ClientConfig) {
		config.ServerName = hostName
	}
}

// IfHost applies the given option if the host matches the dialed one.
func IfHost(matchHost string, option ClientOption) ClientOption {
	matchHost = normalizeHost(matchHost)
	return func(host string, config *ClientConfig) {
		if matchHost != "" && matchHost != host {
			return
		}
		option(host, config)
	}
}

// WithALPN sets the protocol name list for [Application-Layer Protocol Negotiation] (ALPN).
// The list of protocol IDs can be found in [IANA's registry].
//
// [Application-Layer Protocol Negotiation]: https://datatracker.ietf.org/doc/html/rfc7301
// [IANA's registry]: https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
func WithALPN(protocolNameList []string) ClientOption {
	return func(_ string, config *ClientConfig) {
		config.NextProtos = protocolNameList
	}
}

// WithSessionCache sets the [tls.ClientSessionCache] to enable session resumption of TLS connections.
func WithSessionCache(sessionCache tls.ClientSessionCache) ClientOption {
	return func(_ string, config *ClientConfig) {
		config.SessionCache = sessionCache
	}
}

// WithCertVerifier sets the verifier to be used for the certificate verification.
func WithCertVerifier(verifier CertVerifier) ClientOption {
	return func(_ string, config *ClientConfig) {
		config.CertVerifier = verifier
	}
}

// CertVerificationContext provides connection-time context for the certificate verification.
type CertVerificationContext struct {
	// PeerCertificates are the parsed certificates sent by the peer, in the
	// order in which they were sent. The first element is the leaf certificate
	// that the connection is verified against.
	//
	// On the client side, it can't be empty. On the server side, it can be
	// empty if Config.ClientAuth is not RequireAnyClientCert or
	// RequireAndVerifyClientCert.
	//
	// PeerCertificates and its contents should not be modified.
	PeerCertificates []*x509.Certificate
}

// CertVerifier verifies peer certificates for TLS connections.
type CertVerifier interface {
	// VerifyCertificate verified a peer certificate given the context.
	VerifyCertificate(info *CertVerificationContext) error
}

// StandardCertVerifier implements [CertVerifier] using standard TLS certificate chain verification.
type StandardCertVerifier struct {
	// CertificateName specifies the expected DNS name (or IP address) against which
	// the peer's leaf certificate is verified.
	CertificateName string
	// Roots contains the set of trusted root certificate authorities.
	// If nil, the host's default root CAs are used for certificate chain validation.
	Roots *x509.CertPool
}

// VerifyCertificate implements [CertVerifier].
func (v *StandardCertVerifier) VerifyCertificate(certContext *CertVerificationContext) error {
	// This replicates the logic in the standard library verification:
	// https://cs.opensource.google/go/go/+/master:src/crypto/tls/handshake_client.go;l=982;drc=b5f87b5407916c4049a3158cc944cebfd7a883a9
	// And the documentation example:
	// https://pkg.go.dev/crypto/tls#example-Config-VerifyConnection
	opts := x509.VerifyOptions{
		DNSName:       v.CertificateName,
		Roots:         v.Roots,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range certContext.PeerCertificates[1:] {
		opts.Intermediates.AddCert(cert)
	}
	_, err := certContext.PeerCertificates[0].Verify(opts)
	return err
}

// ClientOption allows configuring the parameters to be used for a client TLS connection.
type ClientOption func(serverName string, config *ClientConfig)
