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

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"golang.getoutline.org/sdk/dns"
	"golang.getoutline.org/sdk/transport"
	"golang.org/x/net/dns/dnsmessage"
)

func TestParseQueryType(t *testing.T) {
	for name, want := range map[string]dnsmessage.Type{
		"A": dnsmessage.TypeA, "AAAA": dnsmessage.TypeAAAA,
		"CNAME": dnsmessage.TypeCNAME, "NS": dnsmessage.TypeNS,
		"SOA": dnsmessage.TypeSOA, "TXT": dnsmessage.TypeTXT,
		"HTTPS": 65, "SVCB": 64,
	} {
		for _, input := range []string{name, strings.ToLower(name)} {
			t.Run(input, func(t *testing.T) {
				got, err := parseQueryType(input)
				if err != nil || got != want {
					t.Fatalf("parseQueryType(%q) = %v, %v; want %v", input, got, err, want)
				}
			})
		}
	}
	if _, err := parseQueryType("invalid"); err == nil {
		t.Fatal("accepted unsupported query type")
	}
}

func TestPrintAnswersExistingTypes(t *testing.T) {
	name := dnsmessage.MustNewName("example.com.")
	for _, tc := range []struct {
		qtype dnsmessage.Type
		body  dnsmessage.ResourceBody
		want  string
	}{
		{dnsmessage.TypeA, &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}}, "192.0.2.1\n"},
		{dnsmessage.TypeAAAA, &dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}, "2001:db8::1\n"},
		{dnsmessage.TypeCNAME, &dnsmessage.CNAMEResource{CNAME: name}, "example.com.\n"},
		{dnsmessage.TypeNS, &dnsmessage.NSResource{NS: name}, "example.com.\n"},
		{dnsmessage.TypeSOA, &dnsmessage.SOAResource{NS: name, MBox: name, MinTTL: 60}, "ns: example.com. email: example.com. minTTL: 60\n"},
		{dnsmessage.TypeTXT, &dnsmessage.TXTResource{TXT: []string{"first", "second"}}, "first, second\n"},
	} {
		t.Run(tc.qtype.String(), func(t *testing.T) {
			answers := []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Type: tc.qtype}, Body: tc.body}}
			var out bytes.Buffer
			if err := printAnswers(&out, answers, tc.qtype); err != nil {
				t.Fatal(err)
			}
			if out.String() != tc.want {
				t.Fatalf("got %q, want %q", out.String(), tc.want)
			}
		})
	}
}

func TestPrintAnswersMalformedBinding(t *testing.T) {
	var out bytes.Buffer
	err := printAnswers(&out, []dnsmessage.Resource{bindingAnswer(typeHTTPS, []byte{0, 1})}, typeHTTPS)
	if err == nil || !strings.Contains(err.Error(), "example.com.") {
		t.Fatalf("expected error naming record owner, got %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("printed malformed answer: %q", out.String())
	}
}

// Exercise the real SDK UDP and TCP resolver codecs over in-memory connections.
// The fixture checks the question on the wire and returns both matching and
// unrelated records so output filtering is tested after DNS message unpacking.
func TestServiceBindingQuery(t *testing.T) {
	for _, queryType := range []string{"HTTPS", "SVCB"} {
		for _, tcp := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/tcp=%v", queryType, tcp), func(t *testing.T) {
				qtype, err := parseQueryType(queryType)
				if err != nil {
					t.Fatal(err)
				}
				client, server := net.Pipe()
				t.Cleanup(func() { client.Close(); server.Close() })
				if err := server.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
					t.Fatal(err)
				}
				errCh := make(chan error, 1)
				data := decodeHex(t, serviceData)
				go func() {
					defer server.Close()
					errCh <- serveBinding(server, tcp, qtype, data)
				}()
				checkAddress := func(address string) {
					if address != "resolver.example:53" {
						t.Errorf("unexpected resolver address: %q", address)
					}
				}
				var resolver dns.Resolver
				if tcp {
					dialStream := func(_ context.Context, address string) (transport.StreamConn, error) {
						checkAddress(address)
						return testStreamConn{client}, nil
					}
					resolver = dns.NewTCPResolver(transport.FuncStreamDialer(dialStream), "resolver.example")
				} else {
					dialPacket := func(_ context.Context, address string) (net.Conn, error) {
						checkAddress(address)
						return client, nil
					}
					resolver = dns.NewUDPResolver(transport.FuncPacketDialer(dialPacket), "resolver.example")
				}
				question, err := dns.NewQuestion("example.com", qtype)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				response, queryErr := resolver.Query(ctx, *question)
				if err := <-errCh; err != nil {
					t.Fatal(err)
				}
				if queryErr != nil {
					t.Fatal(queryErr)
				}
				var out bytes.Buffer
				if err := printAnswers(&out, response.Answers, qtype); err != nil {
					t.Fatal(err)
				}
				want := serviceText + "\n2 .\n"
				if out.String() != want {
					t.Fatalf("got %q, want %q", out.String(), want)
				}
			})
		}
	}
}

type testStreamConn struct{ net.Conn }

func (c testStreamConn) CloseRead() error  { return c.Close() }
func (c testStreamConn) CloseWrite() error { return c.Close() }

func serveBinding(conn net.Conn, tcp bool, qtype dnsmessage.Type, data []byte) error {
	packet := make([]byte, 4096)
	if tcp {
		var size uint16
		if err := binary.Read(conn, binary.BigEndian, &size); err != nil {
			return err
		}
		packet = make([]byte, size)
		if _, err := io.ReadFull(conn, packet); err != nil {
			return err
		}
	} else {
		n, err := conn.Read(packet)
		if err != nil {
			return err
		}
		packet = packet[:n]
	}
	var query dnsmessage.Message
	if err := query.Unpack(packet); err != nil {
		return err
	}
	if len(query.Questions) != 1 || query.Questions[0].Type != qtype || query.Questions[0].Name.String() != "example.com." {
		return fmt.Errorf("unexpected wire question: %+v", query.Questions)
	}
	response := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: query.ID, Response: true, RecursionAvailable: true},
		Questions: query.Questions,
		Answers: []dnsmessage.Resource{
			{Header: dnsmessage.ResourceHeader{Name: query.Questions[0].Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET}, Body: &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("alias.example.")}},
			bindingAnswer(qtype, data), bindingAnswer(qtype, []byte{0, 2, 0}),
		},
	}
	wire, err := response.Pack()
	if err != nil {
		return err
	}
	if tcp {
		wire = append([]byte{byte(len(wire) >> 8), byte(len(wire))}, wire...)
	}
	_, err = conn.Write(wire)
	return err
}
