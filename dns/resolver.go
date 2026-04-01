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

package dns

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/transport/tls"
	"golang.org/x/net/dns/dnsmessage"
)

var (
	ErrBadRequest  = errors.New("request input is invalid")
	ErrDial        = errors.New("dial DNS resolver failed")
	ErrSend        = errors.New("send DNS message failed")
	ErrReceive     = errors.New("receive DNS message failed")
	ErrBadResponse = errors.New("response message is invalid")
)

// nestedError allows us to use errors.Is and still preserve the error cause.
// This is unlike fmt.Errorf, which creates a new error and preserves the cause,
// but you can't specify the type of the resulting top-level error.
type nestedError struct {
	is      error
	wrapped error
}

func (e *nestedError) Is(target error) bool { return target == e.is }

func (e *nestedError) Unwrap() error { return e.wrapped }

func (e *nestedError) Error() string { return e.is.Error() + ": " + e.wrapped.Error() }

// Resolver can query the DNS with a question, and obtain a DNS message as response.
// This abstraction helps hide the underlying transport protocol.
type Resolver interface {
	Query(ctx context.Context, q dnsmessage.Question) (*dnsmessage.Message, error)
}

// FuncResolver is a [Resolver] that uses the given function to query DNS.
type FuncResolver func(ctx context.Context, q dnsmessage.Question) (*dnsmessage.Message, error)

// Query implements the [Resolver] interface.
func (f FuncResolver) Query(ctx context.Context, q dnsmessage.Question) (*dnsmessage.Message, error) {
	return f(ctx, q)
}

// RawResolver can query DNS and return the raw wire-format response bytes as defined in RFC 1035.
// Using plain name and qtype avoids a dependency on any specific DNS parsing library,
// allowing callers to parse the response with any library — including those that support
// record types not yet recognized by golang.org/x/net/dns/dnsmessage.
type RawResolver interface {
	QueryRaw(ctx context.Context, name string, qtype uint16, buf []byte) ([]byte, error)
}

// FuncRawResolver is a [RawResolver] that uses the given function to query DNS.
type FuncRawResolver func(ctx context.Context, name string, qtype uint16, buf []byte) ([]byte, error)

// QueryRaw implements the [RawResolver] interface.
func (f FuncRawResolver) QueryRaw(ctx context.Context, name string, qtype uint16, buf []byte) ([]byte, error) {
	return f(ctx, name, qtype, buf)
}

// RawToResolver wraps a [RawResolver] in a [Resolver] that parses the wire-format
// response bytes using golang.org/x/net/dns/dnsmessage.
// The underlying [RawResolver] is responsible for ID matching and returning valid bytes;
// this adapter only unpacks the result.
func RawToResolver(r RawResolver) Resolver {
	return FuncResolver(func(ctx context.Context, q dnsmessage.Question) (*dnsmessage.Message, error) {
		buf := make([]byte, 0, maxUDPMessageSize)
		raw, err := r.QueryRaw(ctx, q.Name.String(), uint16(q.Type), buf)
		if err != nil {
			return nil, err
		}
		var msg dnsmessage.Message
		if err := msg.Unpack(raw); err != nil {
			return nil, &nestedError{ErrBadResponse, fmt.Errorf("failed to unpack DNS response: %w", err)}
		}
		return &msg, nil
	})
}

// NewQuestion is a convenience function to create a [dnsmessage.Question].
// The input domain is interpreted as fully-qualified. If the end "." is missing, it's added.
func NewQuestion(domain string, qtype dnsmessage.Type) (*dnsmessage.Question, error) {
	fullDomain := domain
	if len(domain) == 0 || domain[len(domain)-1] != '.' {
		fullDomain += "."
	}
	name, err := dnsmessage.NewName(fullDomain)
	if err != nil {
		return nil, fmt.Errorf("cannot parse domain name: %w", err)
	}
	return &dnsmessage.Question{
		Name:  name,
		Type:  qtype,
		Class: dnsmessage.ClassINET,
	}, nil
}

// Maximum UDP message size that we support.
// The value is taken from https://dnsflagday.net/2020/, which says:
// "An EDNS buffer size of 1232 bytes will avoid fragmentation on nearly all current networks.
// This is based on an MTU of 1280, which is required by the IPv6 specification, minus 48 bytes
// for the IPv6 and UDP headers".
const maxUDPMessageSize = 1232

// appendName splits a dot-separated domain name into DNS wire-format labels and appends them to buf.
func appendName(buf []byte, name string) ([]byte, error) {
	if len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	if len(name) == 0 {
		return append(buf, 0), nil
	}
	startLength := len(buf)
	for len(name) > 0 {
		idx := strings.IndexByte(name, '.')
		var label string
		if idx == -1 {
			label = name
			name = ""
		} else {
			label = name[:idx]
			name = name[idx+1:]
		}
		if len(label) == 0 {
			return nil, errors.New("empty label")
		}
		if len(label) > 63 {
			return nil, errors.New("label too long")
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0)
	if len(buf)-startLength > 255 {
		return nil, errors.New("name too long")
	}
	return buf, nil
}

// appendRequestRaw constructs a complete wire-format DNS request (Header, Question, OPT) and appends it to buf.
func appendRequestRaw(id uint16, name string, qtype uint16, buf []byte) ([]byte, error) {
	udpSize := uint16(cap(buf))
	if udpSize < 512 {
		udpSize = 512
	}
	
	// Header: 12 bytes
	buf = append(buf,
		byte(id>>8), byte(id), // ID
		0x01, 0x00, // Flags: RD=1
		0x00, 0x01, // QDCOUNT=1
		0x00, 0x00, // ANCOUNT=0
		0x00, 0x00, // NSCOUNT=0
		0x00, 0x01, // ARCOUNT=1 (OPT)
	)

	// Question Section
	var err error
	buf, err = appendName(buf, name)
	if err != nil {
		return nil, fmt.Errorf("invalid question name: %w", err)
	}
	buf = append(buf,
		byte(qtype>>8), byte(qtype), // QTYPE
		0x00, 0x01, // QCLASS (INET=1)
	)

	// Additional Section (OPT)
	// As per https://datatracker.ietf.org/doc/html/rfc6891#section-4.3
	buf = append(buf,
		0x00,       // Name (root, 0 bytes)
		0x00, 41,   // Type (OPT=41)
		byte(udpSize>>8), byte(udpSize&0xFF), // UDP payload size
		0x00, 0x00, 0x00, 0x00, // Ext RCODE, Version, Z
		0x00, 0x00, // RDLENGTH (0)
	)
	return buf, nil
}

// Fold case as clarified in https://datatracker.ietf.org/doc/html/rfc4343#section-3.
func foldCase(char byte) byte {
	if 'a' <= char && char <= 'z' {
		return char - 'a' + 'A'
	}
	return char
}

// equalASCIIName compares DNS name as specified in https://datatracker.ietf.org/doc/html/rfc1035#section-3.1 and
// https://datatracker.ietf.org/doc/html/rfc4343#section-3.
func equalASCIIName(x, y dnsmessage.Name) bool {
	if x.Length != y.Length {
		return false
	}
	for i := 0; i < int(x.Length); i++ {
		if foldCase(x.Data[i]) != foldCase(y.Data[i]) {
			return false
		}
	}
	return true
}

// checkResponseRaw verifies the DNS response matches the request parameters directly on the wire bytes.
func checkResponseRaw(reqID uint16, name string, qtype uint16, rawResp []byte) error {
	if len(rawResp) < 12 {
		return errors.New("response too short for header")
	}
	// Check Response bit (QR) which is bit 7 of byte 2 (flags top byte)
	if rawResp[2]&0x80 == 0 {
		return errors.New("response bit not set")
	}
	// Check ID
	// https://datatracker.ietf.org/doc/html/rfc5452#section-4.3
	respID := binary.BigEndian.Uint16(rawResp[0:2])
	if reqID != respID {
		return fmt.Errorf("message id does not match. Expected %v, got %v", reqID, respID)
	}
	// Check QDCOUNT (Question count)
	// https://datatracker.ietf.org/doc/html/rfc5452#section-4.2
	qdCount := binary.BigEndian.Uint16(rawResp[4:6])
	if qdCount == 0 {
		return errors.New("response had no questions")
	}

	// Verify the first question echoes exactly our request question.
	// We construct the expected question name dynamically to avoid allocation.
	var expectedNameBuf [255]byte
	expectedName, err := appendName(expectedNameBuf[:0], name)
	if err != nil {
		return fmt.Errorf("failed to format expected question name: %w", err)
	}

	reqQLen := len(expectedName) + 4
	if len(rawResp) < 12+reqQLen {
		return errors.New("response too short for echoed question")
	}
	
	respQName := rawResp[12 : 12+len(expectedName)]

	// Case-insensitive comparison, as the server may echo back randomized caps (e.g. 0x20 encoding)
	for i := 0; i < len(expectedName); i++ {
		if foldCase(expectedName[i]) != foldCase(respQName[i]) {
			return fmt.Errorf("response question name doesn't match request. Expected %x, got %x", expectedName, respQName)
		}
	}
	
	respQType := binary.BigEndian.Uint16(rawResp[12+len(expectedName):])
	if respQType != qtype {
		return fmt.Errorf("response question type doesn't match request. Expected %v, got %v", qtype, respQType)
	}
	
	respQClass := binary.BigEndian.Uint16(rawResp[12+len(expectedName)+2:])
	if respQClass != uint16(dnsmessage.ClassINET) {
		return fmt.Errorf("response question class doesn't match request. Expected %v, got %v", uint16(dnsmessage.ClassINET), respQClass)
	}
	
	return nil
}

// queryDatagram implements a DNS query over a datagram protocol.
// It validates the response ID and question echo before returning raw wire-format bytes.
func queryDatagram(conn io.ReadWriter, name string, qtype uint16, buf []byte) ([]byte, error) {
	// Reference: https://cs.opensource.google/go/go/+/master:src/net/dnsclient_unix.go?q=func:dnsPacketRoundTrip&ss=go%2Fgo
	id := uint16(rand.Uint32())
	buf = buf[:0]
	buf, err := appendRequestRaw(id, name, qtype, buf)
	if err != nil {
		return nil, &nestedError{ErrBadRequest, fmt.Errorf("append request failed: %w", err)}
	}

	if _, err := conn.Write(buf); err != nil {
		return nil, &nestedError{ErrSend, err}
	}
	buf = buf[:cap(buf)]
	var returnErr error
	for {
		n, err := conn.Read(buf)
		// Handle bad io.Reader.
		if err == io.EOF && n > 0 {
			err = nil
		}
		if err != nil {
			return nil, &nestedError{ErrReceive, errors.Join(returnErr, fmt.Errorf("read message failed: %w", err))}
		}
		
		// Ignore invalid packets that fail to parse. It could be injected.
		if err := checkResponseRaw(id, name, qtype, buf[:n]); err != nil {
			returnErr = errors.Join(returnErr, err)
			continue
		}
		
		return buf[:n], nil
	}
}

// queryStream implements a DNS query over a stream protocol. It frames the messages by prepending them with a 2-byte length prefix.
// It validates the response ID and question echo before returning raw wire-format bytes.
func queryStream(conn io.ReadWriter, name string, qtype uint16, buf []byte) ([]byte, error) {
	// Reference: https://cs.opensource.google/go/go/+/master:src/net/dnsclient_unix.go?q=func:dnsStreamRoundTrip&ss=go%2Fgo
	id := uint16(rand.Uint32())
	
	// Pre-allocate 2 bytes for the length prefix, so we don't have to shift later.
	if cap(buf) < 2 {
		buf = make([]byte, 2, 514)
	} else {
		buf = buf[:2]
		buf[0], buf[1] = 0, 0
	}
	buf, err := appendRequestRaw(id, name, qtype, buf)
	if err != nil {
		return nil, &nestedError{ErrBadRequest, err}
	}
	// Buffer length must fit in a uint16.
	if len(buf) > 1<<16-1 {
		return nil, &nestedError{ErrBadRequest, fmt.Errorf("message too large: %v bytes", len(buf))}
	}
	binary.BigEndian.PutUint16(buf[:2], uint16(len(buf)-2))

	// TODO: Consider writer.ReadFrom(net.Buffers) in case the writer is a TCPConn.
	if _, err := conn.Write(buf); err != nil {
		return nil, &nestedError{ErrSend, err}
	}

	var msgLen uint16
	if err := binary.Read(conn, binary.BigEndian, &msgLen); err != nil {
		return nil, &nestedError{ErrReceive, fmt.Errorf("read message length failed: %w", err)}
	}
	if int(msgLen) <= cap(buf) {
		buf = buf[:msgLen]
	} else {
		buf = make([]byte, msgLen)
	}
	if _, err = io.ReadFull(conn, buf); err != nil {
		return nil, &nestedError{ErrReceive, fmt.Errorf("read message failed: %w", err)}
	}

	// Ignore invalid packets that fail to parse. It could be injected.
	if err := checkResponseRaw(id, name, qtype, buf); err != nil {
		return nil, &nestedError{ErrBadResponse, err}
	}
	return buf, nil
}

func ensurePort(address string, defaultPort string) string {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		// Failed to parse as host:port. Assume address is a host.
		return net.JoinHostPort(address, defaultPort)
	}
	if port == "" {
		return net.JoinHostPort(host, defaultPort)
	}
	return address
}

// NewUDPRawResolver creates a [RawResolver] that implements the DNS-over-UDP protocol, using a [transport.PacketDialer] for transport.
// It uses a different port for every request.
//
// [DNS-over-UDP]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.2.1
func NewUDPRawResolver(pd transport.PacketDialer, resolverAddr string) RawResolver {
	resolverAddr = ensurePort(resolverAddr, "53")
	return FuncRawResolver(func(ctx context.Context, name string, qtype uint16, buf []byte) ([]byte, error) {
		conn, err := pd.DialPacket(ctx, resolverAddr)
		if err != nil {
			return nil, &nestedError{ErrDial, err}
		}
		defer conn.Close()
		if deadline, ok := ctx.Deadline(); ok {
			conn.SetDeadline(deadline)
		}
		return queryDatagram(conn, name, qtype, buf)
	})
}

// NewUDPResolver creates a [Resolver] that implements the DNS-over-UDP protocol, using a [transport.PacketDialer] for transport.
// It uses a different port for every request.
//
// [DNS-over-UDP]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.2.1
func NewUDPResolver(pd transport.PacketDialer, resolverAddr string) Resolver {
	return RawToResolver(NewUDPRawResolver(pd, resolverAddr))
}

type streamRawResolver struct {
	NewConn func(context.Context) (transport.StreamConn, error)
}

func (r *streamRawResolver) QueryRaw(ctx context.Context, name string, qtype uint16, buf []byte) ([]byte, error) {
	conn, err := r.NewConn(ctx)
	if err != nil {
		return nil, &nestedError{ErrDial, err}
	}
	// TODO: reuse connection, as per https://datatracker.ietf.org/doc/html/rfc7766#section-6.2.1.
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	return queryStream(conn, name, qtype, buf)
}

// NewTCPRawResolver creates a [RawResolver] that implements the [DNS-over-TCP] protocol, using a [transport.StreamDialer] for transport.
// It creates a new connection to the resolver for every request.
//
// [DNS-over-TCP]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.2.2
func NewTCPRawResolver(sd transport.StreamDialer, resolverAddr string) RawResolver {
	// TODO: Consider handling Authenticated Data.
	resolverAddr = ensurePort(resolverAddr, "53")
	return &streamRawResolver{
		NewConn: func(ctx context.Context) (transport.StreamConn, error) {
			return sd.DialStream(ctx, resolverAddr)
		},
	}
}

// NewTCPResolver creates a [Resolver] that implements the [DNS-over-TCP] protocol, using a [transport.StreamDialer] for transport.
// It creates a new connection to the resolver for every request.
//
// [DNS-over-TCP]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.2.2
func NewTCPResolver(sd transport.StreamDialer, resolverAddr string) Resolver {
	return RawToResolver(NewTCPRawResolver(sd, resolverAddr))
}

// NewTLSRawResolver creates a [RawResolver] that implements the [DNS-over-TLS] protocol, using a [transport.StreamDialer]
// to connect to the resolverAddr, and the resolverName as the TLS server name.
// It creates a new connection to the resolver for every request.
//
// [DNS-over-TLS]: https://datatracker.ietf.org/doc/html/rfc7858
func NewTLSRawResolver(sd transport.StreamDialer, resolverAddr string, resolverName string) RawResolver {
	resolverAddr = ensurePort(resolverAddr, "853")
	return &streamRawResolver{
		NewConn: func(ctx context.Context) (transport.StreamConn, error) {
			baseConn, err := sd.DialStream(ctx, resolverAddr)
			if err != nil {
				return nil, err
			}
			return tls.WrapConn(ctx, baseConn, resolverName)
		},
	}
}

// NewTLSResolver creates a [Resolver] that implements the [DNS-over-TLS] protocol, using a [transport.StreamDialer]
// to connect to the resolverAddr, and the resolverName as the TLS server name.
// It creates a new connection to the resolver for every request.
//
// [DNS-over-TLS]: https://datatracker.ietf.org/doc/html/rfc7858
func NewTLSResolver(sd transport.StreamDialer, resolverAddr string, resolverName string) Resolver {
	return RawToResolver(NewTLSRawResolver(sd, resolverAddr, resolverName))
}

// NewHTTPSRawResolver creates a [RawResolver] that implements the [DNS-over-HTTPS] protocol, using a [transport.StreamDialer]
// to connect to the resolverAddr, and the url as the DoH template URI.
// It uses an internal HTTP client that reuses connections when possible.
//
// [DNS-over-HTTPS]: https://datatracker.ietf.org/doc/html/rfc8484
func NewHTTPSRawResolver(sd transport.StreamDialer, resolverAddr string, url string) RawResolver {
	resolverAddr = ensurePort(resolverAddr, "443")
	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if !strings.HasPrefix(network, "tcp") {
			// TODO: Support UDP for QUIC.
			return nil, fmt.Errorf("protocol not supported: %v", network)
		}
		conn, err := sd.DialStream(ctx, resolverAddr)
		if err != nil {
			return nil, &nestedError{ErrDial, err}
		}
		return conn, nil
	}
	// TODO: add mechanism to close idle connections.
	// Copied from Intra: https://github.com/Jigsaw-Code/Intra/blob/d3554846a1146ae695e28a8ed6dd07f0cd310c5a/Android/tun2socks/intra/doh/doh.go#L213-L219
	httpClient := http.Client{
		Transport: &http.Transport{
			DialContext:           dialContext,
			ForceAttemptHTTP2:     true,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 20 * time.Second, // Same value as Android DNS-over-TLS
		},
	}
	return FuncRawResolver(func(ctx context.Context, name string, qtype uint16, buf []byte) ([]byte, error) {
		// Prepare request.
		// DoH uses ID=0 per RFC 8484.
		buf = buf[:0]
		buf, err := appendRequestRaw(0, name, qtype, buf)
		if err != nil {
			return nil, &nestedError{ErrBadRequest, err}
		}

		httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(buf))
		if err != nil {
			return nil, &nestedError{ErrBadRequest, fmt.Errorf("create HTTP request failed: %w", err)}
		}
		const mimetype = "application/dns-message"
		httpReq.Header.Add("Accept", mimetype)
		httpReq.Header.Add("Content-Type", mimetype)

		// Send request and get response.
		httpResp, err := httpClient.Do(httpReq)
		if err != nil {
			return nil, &nestedError{ErrReceive, fmt.Errorf("failed to get HTTP response: %w", err)}
		}
		defer httpResp.Body.Close()
		if httpResp.StatusCode != http.StatusOK {
			return nil, &nestedError{ErrReceive, fmt.Errorf("got HTTP status %v", httpResp.StatusCode)}
		}
		buf, err = readAllInto(httpResp.Body, buf, httpResp.ContentLength)
		if err != nil {
			return nil, &nestedError{ErrReceive, fmt.Errorf("failed to read response: %w", err)}
		}

		// Process response.
		// Ignore invalid packets that fail to parse. It could be injected.
		if err := checkResponseRaw(0, name, qtype, buf); err != nil {
			return nil, &nestedError{ErrBadResponse, err}
		}
		return buf, nil
	})
}

// readAllInto reads everything from r into buf, reusing its capacity.
// It pre-grows the buffer if expectedSize is known and reasonable for DNS.
func readAllInto(r io.Reader, buf []byte, expectedSize int64) ([]byte, error) {
	buf = buf[:0]
	// Pre-grow buffer if we know the size and it's reasonable for DNS (< 64KB).
	if expectedSize > 0 && expectedSize <= 65535 && int64(cap(buf)) < expectedSize {
		buf = make([]byte, 0, expectedSize)
	}
	for {
		if len(buf) == cap(buf) {
			buf = append(buf, 0)[:len(buf)]
		}
		n, err := r.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if err != nil {
			if err == io.EOF {
				break
			}
			return buf, err
		}
	}
	return buf, nil
}

// NewHTTPSResolver creates a [Resolver] that implements the [DNS-over-HTTPS] protocol, using a [transport.StreamDialer]
// to connect to the resolverAddr, and the url as the DoH template URI.
// It uses an internal HTTP client that reuses connections when possible.
//
// [DNS-over-HTTPS]: https://datatracker.ietf.org/doc/html/rfc8484
func NewHTTPSResolver(sd transport.StreamDialer, resolverAddr string, url string) Resolver {
	return RawToResolver(NewHTTPSRawResolver(sd, resolverAddr, url))
}
