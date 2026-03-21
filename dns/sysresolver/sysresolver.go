// Copyright 2024 The Outline Authors
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

package sysresolver

import (
	"fmt"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// resourceBodyFromRData parses DNS record data (wire format) into a typed
// [dnsmessage.ResourceBody]. For well-known types (A, AAAA, CNAME, NS, PTR,
// MX, TXT) it returns the appropriate concrete type. For unrecognized or
// malformed records it falls back to [dnsmessage.UnknownResource], so callers
// can still access the raw bytes of any record type.
func resourceBodyFromRData(rrtype dnsmessage.Type, rdata []byte) dnsmessage.ResourceBody {
	switch rrtype {
	case dnsmessage.TypeA:
		if len(rdata) == 4 {
			return &dnsmessage.AResource{A: [4]byte(rdata)}
		}
	case dnsmessage.TypeAAAA:
		if len(rdata) == 16 {
			return &dnsmessage.AAAAResource{AAAA: [16]byte(rdata)}
		}
	case dnsmessage.TypeCNAME:
		if name, err := parseDNSLabels(rdata); err == nil {
			return &dnsmessage.CNAMEResource{CNAME: name}
		}
	case dnsmessage.TypeNS:
		if name, err := parseDNSLabels(rdata); err == nil {
			return &dnsmessage.NSResource{NS: name}
		}
	case dnsmessage.TypePTR:
		if name, err := parseDNSLabels(rdata); err == nil {
			return &dnsmessage.PTRResource{PTR: name}
		}
	case dnsmessage.TypeMX:
		if len(rdata) >= 3 {
			pref := uint16(rdata[0])<<8 | uint16(rdata[1])
			if mx, err := parseDNSLabels(rdata[2:]); err == nil {
				return &dnsmessage.MXResource{Pref: pref, MX: mx}
			}
		}
	case dnsmessage.TypeTXT:
		if txts, ok := parseTXTRData(rdata); ok {
			return &dnsmessage.TXTResource{TXT: txts}
		}
	}
	return &dnsmessage.UnknownResource{Type: rrtype, Data: append([]byte(nil), rdata...)}
}

// parseDNSLabels parses a DNS name encoded as uncompressed wire-format labels.
// Pointer compression (0xC0 prefix) is rejected since rdata from native OS
// callbacks is not part of a full DNS message.
func parseDNSLabels(data []byte) (dnsmessage.Name, error) {
	var b strings.Builder
	remaining := data
	for len(remaining) > 0 {
		labelLen := int(remaining[0])
		if labelLen == 0 {
			break
		}
		if labelLen >= 0xC0 {
			return dnsmessage.Name{}, fmt.Errorf("unexpected pointer in DNS label sequence")
		}
		if labelLen+1 > len(remaining) {
			return dnsmessage.Name{}, fmt.Errorf("label length %d overflows data", labelLen)
		}
		b.Write(remaining[1 : labelLen+1])
		b.WriteByte('.')
		remaining = remaining[labelLen+1:]
	}
	if b.Len() == 0 {
		b.WriteByte('.')
	}
	return dnsmessage.NewName(b.String())
}

// parseTXTRData parses the rdata of a TXT record, which is a sequence of
// length-prefixed strings.
func parseTXTRData(rdata []byte) ([]string, bool) {
	var txts []string
	for remaining := rdata; len(remaining) > 0; {
		l := int(remaining[0])
		if l+1 > len(remaining) {
			return nil, false
		}
		txts = append(txts, string(remaining[1:l+1]))
		remaining = remaining[l+1:]
	}
	return txts, true
}
