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

package dns

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/transport/tls"
	"golang.org/x/net/dns/dnsmessage"
)

// Exchanger exchanges DNS messages in [wire format], without interpreting them.
//
// It is the low-level counterpart of [Resolver]: while a [Resolver] takes a question and
// returns a parsed message, an Exchanger takes and returns opaque message bytes. Use an
// Exchanger when you are relaying messages produced by someone else — a stub resolver on
// the device, for example — and must preserve the query exactly as it was issued. The
// message ID, the header flags (such as RD, CD and the EDNS(0) DO bit) and the EDNS(0)
// options are all significant to the client that produced the query, and a response that
// doesn't echo them may be rejected.
//
// Implementations must not modify query, and must return a response that matches it.
//
// [wire format]: https://datatracker.ietf.org/doc/html/rfc1035#section-4
type Exchanger interface {
	Exchange(ctx context.Context, query []byte) (response []byte, err error)
}

// FuncExchanger is an [Exchanger] that uses the given function to exchange DNS messages.
type FuncExchanger func(ctx context.Context, query []byte) ([]byte, error)

// Exchange implements the [Exchanger] interface.
func (f FuncExchanger) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	return f(ctx, query)
}

// Maximum size of a DNS message carried over UDP. The length of a DNS message over TCP is
// encoded as a uint16, and a UDP datagram cannot carry more than that either.
const maxMessageSize = math.MaxUint16

// readBufferPool recycles the buffers used to read datagram responses. We always read into a
// full-size buffer because the requestor's advertised EDNS(0) payload size is chosen by
// whoever wrote the query, which may not be us: reading into a smaller buffer would silently
// truncate the datagram and make a valid response look corrupt.
var readBufferPool = sync.Pool{
	New: func() any {
		buf := make([]byte, maxMessageSize)
		return &buf
	},
}

// queryInfo is what a response must match for us to accept it, as per [RFC 5452].
//
// [RFC 5452]: https://datatracker.ietf.org/doc/html/rfc5452#section-4
type queryInfo struct {
	id uint16
	// question is nil if the query carries no question section.
	question *dnsmessage.Question
}

// parseQuery extracts from a wire-format query what is needed to match a response to it.
func parseQuery(query []byte) (queryInfo, error) {
	var info queryInfo
	var p dnsmessage.Parser
	hdr, err := p.Start(query)
	if err != nil {
		return info, fmt.Errorf("query failed to parse: %w", err)
	}
	if hdr.Response {
		return info, errors.New("message is a response, not a query")
	}
	info.id = hdr.ID
	q, err := p.Question()
	switch {
	case err == nil:
		info.question = &q
	case errors.Is(err, dnsmessage.ErrSectionDone):
		// A query with no question is unusual, but it's not our business to reject it.
		// We will match the response on the ID alone.
	default:
		return info, fmt.Errorf("query question failed to parse: %w", err)
	}
	return info, nil
}

// checkRawResponse reports whether response is a valid answer to the query described by info,
// without unpacking the entire message.
func checkRawResponse(response []byte, info queryInfo) error {
	var p dnsmessage.Parser
	hdr, err := p.Start(response)
	if err != nil {
		return fmt.Errorf("response failed to parse: %w", err)
	}
	if !hdr.Response {
		return errors.New("response bit not set")
	}
	// https://datatracker.ietf.org/doc/html/rfc5452#section-4.3
	if hdr.ID != info.id {
		return fmt.Errorf("message id does not match. Expected %v, got %v", info.id, hdr.ID)
	}
	if info.question == nil {
		return nil
	}
	// https://datatracker.ietf.org/doc/html/rfc5452#section-4.2
	respQ, err := p.Question()
	if err != nil {
		return fmt.Errorf("response had no questions: %w", err)
	}
	if info.question.Type != respQ.Type || info.question.Class != respQ.Class ||
		!equalASCIIName(info.question.Name, respQ.Name) {
		return errors.New("response question doesn't match request")
	}
	return nil
}

// exchangeDatagram sends query over conn and returns the first datagram that is a valid
// response to it.
//
// Unlike the stream-based transports, a datagram transport has no framing to tell us which
// datagram belongs to our query, and an off-path attacker can race the real resolver. We
// therefore keep reading, discarding datagrams that don't match, until one does or the read
// fails (which is how a deadline surfaces).
func exchangeDatagram(conn io.ReadWriter, query []byte, info queryInfo) ([]byte, error) {
	if _, err := conn.Write(query); err != nil {
		return nil, &nestedError{ErrSend, err}
	}
	bufPtr := readBufferPool.Get().(*[]byte)
	defer readBufferPool.Put(bufPtr)
	buf := *bufPtr
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
		if err := checkRawResponse(buf[:n], info); err != nil {
			// Ignore responses that don't match the query. They could have been injected.
			returnErr = errors.Join(returnErr, err)
			continue
		}
		return bytes.Clone(buf[:n]), nil
	}
}

// exchangeStream sends query over conn and reads the response, framing both messages with a
// 2-byte length prefix, as per [RFC 7766].
//
// [RFC 7766]: https://datatracker.ietf.org/doc/html/rfc7766#section-8
func exchangeStream(conn io.ReadWriter, query []byte) ([]byte, error) {
	if len(query) > maxMessageSize {
		return nil, &nestedError{ErrBadRequest, fmt.Errorf("message too large: %v bytes", len(query))}
	}
	// Copy the query rather than issuing two writes, so the length prefix and the message go
	// out in a single segment.
	// TODO: Consider conn.ReadFrom(net.Buffers) in case the writer is a TCPConn.
	buf := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(query)))
	copy(buf[2:], query)
	if _, err := conn.Write(buf); err != nil {
		return nil, &nestedError{ErrSend, err}
	}

	var msgLen uint16
	if err := binary.Read(conn, binary.BigEndian, &msgLen); err != nil {
		return nil, &nestedError{ErrReceive, fmt.Errorf("read message length failed: %w", err)}
	}
	response := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, response); err != nil {
		return nil, &nestedError{ErrReceive, fmt.Errorf("read message failed: %w", err)}
	}
	return response, nil
}

// NewUDPExchanger creates an [Exchanger] that implements the [DNS-over-UDP] protocol, using a
// [transport.PacketDialer] for transport. It uses a different port for every exchange.
//
// Because UDP is unauthenticated, the returned Exchanger must parse the query in order to
// recognize its response: queries that fail to parse are rejected with [ErrBadRequest], and
// datagrams that don't match the query are discarded rather than returned.
//
// [DNS-over-UDP]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.2.1
func NewUDPExchanger(pd transport.PacketDialer, resolverAddr string) Exchanger {
	resolverAddr = ensurePort(resolverAddr, "53")
	return FuncExchanger(func(ctx context.Context, query []byte) ([]byte, error) {
		info, err := parseQuery(query)
		if err != nil {
			return nil, &nestedError{ErrBadRequest, err}
		}
		conn, err := pd.DialPacket(ctx, resolverAddr)
		if err != nil {
			return nil, &nestedError{ErrDial, err}
		}
		defer conn.Close()
		if deadline, ok := ctx.Deadline(); ok {
			conn.SetDeadline(deadline)
		}
		return exchangeDatagram(conn, query, info)
	})
}

// newStreamExchanger creates an [Exchanger] that exchanges length-prefixed messages over a
// fresh connection from newConn.
func newStreamExchanger(newConn func(context.Context) (transport.StreamConn, error)) Exchanger {
	return FuncExchanger(func(ctx context.Context, query []byte) ([]byte, error) {
		conn, err := newConn(ctx)
		if err != nil {
			return nil, &nestedError{ErrDial, err}
		}
		// TODO: reuse connection, as per https://datatracker.ietf.org/doc/html/rfc7766#section-6.2.1.
		defer conn.Close()
		if deadline, ok := ctx.Deadline(); ok {
			conn.SetDeadline(deadline)
		}
		return exchangeStream(conn, query)
	})
}

// NewTCPExchanger creates an [Exchanger] that implements the [DNS-over-TCP] protocol, using a
// [transport.StreamDialer] for transport. It creates a new connection to the resolver for
// every exchange.
//
// The response is returned as received: unlike the datagram transports, the stream framing
// identifies the response, so matching it against the query is left to the caller.
//
// [DNS-over-TCP]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.2.2
func NewTCPExchanger(sd transport.StreamDialer, resolverAddr string) Exchanger {
	resolverAddr = ensurePort(resolverAddr, "53")
	return newStreamExchanger(func(ctx context.Context) (transport.StreamConn, error) {
		return sd.DialStream(ctx, resolverAddr)
	})
}

// NewTLSExchanger creates an [Exchanger] that implements the [DNS-over-TLS] protocol, using a
// [transport.StreamDialer] to connect to the resolverAddr, and the resolverName as the TLS
// server name. It creates a new connection to the resolver for every exchange.
//
// [DNS-over-TLS]: https://datatracker.ietf.org/doc/html/rfc7858
func NewTLSExchanger(sd transport.StreamDialer, resolverAddr string, resolverName string) Exchanger {
	resolverAddr = ensurePort(resolverAddr, "853")
	return newStreamExchanger(func(ctx context.Context) (transport.StreamConn, error) {
		baseConn, err := sd.DialStream(ctx, resolverAddr)
		if err != nil {
			return nil, err
		}
		return tls.WrapConn(ctx, baseConn, resolverName)
	})
}

// NewHTTPSExchanger creates an [Exchanger] that implements the [DNS-over-HTTPS] protocol,
// using a [transport.StreamDialer] to connect to the resolverAddr, and the url as the DoH
// template URI. It uses an internal HTTP client that reuses connections when possible.
//
// The query is sent as the body of a POST request, unmodified. Note that [RFC 8484] recommends
// a message ID of 0 for cache friendliness; callers that build their own queries and care
// about HTTP caching should set it.
//
// [DNS-over-HTTPS]: https://datatracker.ietf.org/doc/html/rfc8484
// [RFC 8484]: https://datatracker.ietf.org/doc/html/rfc8484#section-4.1
func NewHTTPSExchanger(sd transport.StreamDialer, resolverAddr string, url string) Exchanger {
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
	return FuncExchanger(func(ctx context.Context, query []byte) ([]byte, error) {
		httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(query))
		if err != nil {
			return nil, &nestedError{ErrBadRequest, fmt.Errorf("create HTTP request failed: %w", err)}
		}
		const mimetype = "application/dns-message"
		httpReq.Header.Add("Accept", mimetype)
		httpReq.Header.Add("Content-Type", mimetype)

		httpResp, err := httpClient.Do(httpReq)
		if err != nil {
			return nil, &nestedError{ErrReceive, fmt.Errorf("failed to get HTTP response: %w", err)}
		}
		defer httpResp.Body.Close()
		if httpResp.StatusCode != http.StatusOK {
			return nil, &nestedError{ErrReceive, fmt.Errorf("got HTTP status %v", httpResp.StatusCode)}
		}
		response, err := io.ReadAll(io.LimitReader(httpResp.Body, maxMessageSize))
		if err != nil {
			return nil, &nestedError{ErrReceive, fmt.Errorf("failed to read response: %w", err)}
		}
		return response, nil
	})
}
