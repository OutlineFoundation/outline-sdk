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
	"encoding/hex"
	"strings"
	"testing"

	mdns "github.com/miekg/dns"
	"golang.org/x/net/dns/dnsmessage"
)

// The alias, root target and port cases use the wire layout from RFC 9460
// Appendix D. The combined case keeps each parameter's wire bytes explicit.
const serviceData = "000100" +
	"0000000400010003" +
	"00010006026832026833" +
	"00020000" +
	"0003000201bb" +
	"00040008c0000201c6336402" +
	"000500060004fe0d0000" +
	"0006001020010db8000000000000000000000001" +
	"fde8000400225cff"

const serviceText = `1 . mandatory="alpn,port" alpn="h2,h3" no-default-alpn="" port="443" ipv4hint="192.0.2.1,198.51.100.2" ech="AAT+DQAA" ipv6hint="2001:db8::1" key65000="\000\"\\\255"`

func decodeHex(t testing.TB, text string) []byte {
	t.Helper()
	data, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func bindingAnswer(qtype dnsmessage.Type, data []byte) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName("example.com."),
			Type:  qtype,
			Class: dnsmessage.ClassINET,
			TTL:   60,
		},
		Body: &dnsmessage.UnknownResource{Type: qtype, Data: data},
	}
}

func TestFormatSVCB(t *testing.T) {
	for _, tc := range []struct{ name, wire, want string }{
		{"alias", "000003666f6f076578616d706c6503636f6d00", "0 foo.example.com."},
		{"root", "000100", "1 ."},
		{"port", "001003666f6f076578616d706c6503636f6d00000300020035", `16 foo.example.com. port="53"`},
		{"parameters", serviceData, serviceText},
		{"unknown empty", "000100fde80000", `1 . key65000=""`},
		{"escaped target", "000103612e6200", `1 a\.b.`},
		{"escaped ALPN", "0001000001000706612c625c6322", `1 . alpn="a\\\044b\\\092c\""`},
	} {
		for _, qtype := range []dnsmessage.Type{typeHTTPS, typeSVCB} {
			t.Run(tc.name+"/"+qtype.String(), func(t *testing.T) {
				got, err := formatSVCB(bindingAnswer(qtype, decodeHex(t, tc.wire)))
				if err != nil {
					t.Fatal(err)
				}
				if got != tc.want {
					t.Fatalf("got %q, want %q", got, tc.want)
				}
			})
		}
	}
}

func TestFormatSVCBMalformed(t *testing.T) {
	for _, tc := range []struct{ name, wire string }{
		{"empty", ""},
		{"short priority", "00"},
		{"missing target", "0001"},
		{"short label", "00010261"},
		{"missing root label", "00010161"},
		{"compressed target", "0001c000"},
		{"extended label", "000140"},
		{"short key", "00010000"},
		{"short length", "000100000100"},
		{"short value", "0001000003000201"},
		{"duplicate key", "0001000003000200350003000201bb"},
		{"out of order", "00010000030002003500010003026832"},
		{"reserved key", "000100ffff0000"},
		{"empty mandatory", "00010000000000"},
		{"odd mandatory", "0001000000000101"},
		{"mandatory includes itself", "000100000000020000"},
		{"duplicate mandatory", "0001000000000400010001"},
		{"out of order mandatory", "0001000000000400030001"},
		{"reserved mandatory", "00010000000002ffff"},
		{"empty ALPN", "00010000010000"},
		{"empty ALPN identifier", "0001000001000100"},
		{"short ALPN", "00010000010003036832"},
		{"nonempty no-default-alpn", "0001000002000101"},
		{"short port", "0001000003000101"},
		{"empty IPv4 hints", "00010000040000"},
		{"short IPv4 hint", "00010000040003c00002"},
		{"empty IPv6 hints", "00010000060000"},
		{"short IPv6 hint", "0001000006000120"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := formatSVCB(bindingAnswer(typeHTTPS, decodeHex(t, tc.wire))); err == nil {
				t.Fatal("accepted malformed record")
			}
		})
	}
	t.Run("oversized RDATA", func(t *testing.T) {
		if _, err := formatSVCB(bindingAnswer(typeHTTPS, make([]byte, 65536))); err == nil {
			t.Fatal("accepted oversized record")
		}
	})
	t.Run("oversized target", func(t *testing.T) {
		data := []byte{0, 1}
		for i := 0; i < 4; i++ {
			data = append(data, 63)
			data = append(data, bytes.Repeat([]byte{'a'}, 63)...)
		}
		data = append(data, 0)
		if _, err := formatSVCB(bindingAnswer(typeHTTPS, data)); err == nil {
			t.Fatal("accepted oversized target")
		}
	})
	t.Run("unexpected body", func(t *testing.T) {
		answer := bindingAnswer(typeHTTPS, nil)
		answer.Body = &dnsmessage.AResource{}
		if _, err := formatSVCB(answer); err == nil {
			t.Fatal("accepted unexpected resource body")
		}
	})
}

func FuzzFormatSVCB(f *testing.F) {
	for _, wire := range []string{"000100", "000003666f6f076578616d706c6503636f6d00", serviceData, "0001c000", "0001000001000706612c625c6322"} {
		f.Add(decodeHex(f, wire))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		text, err := formatSVCB(bindingAnswer(typeHTTPS, data))
		if err != nil {
			return
		}
		if strings.ContainsAny(text, "\r\n\x00") {
			t.Fatalf("unescaped control character in %q", text)
		}
		// Verify that presentation output preserves every accepted RDATA byte.
		rr, err := mdns.NewRR("example.com. 60 IN HTTPS " + text)
		if err != nil {
			t.Fatalf("output cannot be parsed: %v; %q", err, text)
		}
		wire := make([]byte, 65536+512)
		end, err := mdns.PackRR(rr, wire, 0, nil, false)
		if err != nil {
			t.Fatal(err)
		}
		got := wire[end-int(rr.Header().Rdlength) : end]
		if !bytes.Equal(got, data) {
			t.Fatalf("RDATA changed: got %x, want %x", got, data)
		}
	})
}
