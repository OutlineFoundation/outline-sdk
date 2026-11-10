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
	"errors"
	"fmt"
	"strings"

	mdns "github.com/miekg/dns"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	typeSVCB  = dnsmessage.Type(mdns.TypeSVCB)
	typeHTTPS = dnsmessage.Type(mdns.TypeHTTPS)
)

// formatSVCB formats the RDATA of either an HTTPS or SVCB answer. The pinned
// dnsmessage version exposes these records as UnknownResource.
func formatSVCB(answer dnsmessage.Resource) (string, error) {
	body, ok := answer.Body.(*dnsmessage.UnknownResource)
	if !ok || body == nil || (answer.Header.Type != typeHTTPS && answer.Header.Type != typeSVCB) {
		return "", errors.New("expected HTTPS or SVCB resource data")
	}
	data := body.Data
	if len(data) < 3 || len(data) > 65535 {
		return "", errors.New("invalid HTTPS/SVCB data length")
	}
	// RFC 9460 section 2.2 forbids compression in TargetName. Check this before
	// decoding standalone RDATA, where pointers into the original message would
	// otherwise be interpreted relative to the wrong buffer.
	for off := 2; ; {
		if off >= len(data) {
			return "", errors.New("unterminated HTTPS/SVCB target")
		}
		size := int(data[off])
		off++
		if size > 63 || off+size > len(data) || off+size-2 > 255 {
			return "", errors.New("invalid or compressed HTTPS/SVCB target")
		}
		if size == 0 {
			break
		}
		off += size
	}
	header := mdns.RR_Header{
		Name:     answer.Header.Name.String(),
		Rrtype:   uint16(answer.Header.Type),
		Class:    uint16(answer.Header.Class),
		Ttl:      answer.Header.TTL,
		Rdlength: uint16(len(data)),
	}
	rr, _, err := mdns.UnpackRRWithHeader(header, data, 0)
	if err != nil {
		return "", fmt.Errorf("invalid HTTPS/SVCB data: %w", err)
	}
	var record *mdns.SVCB
	switch rr := rr.(type) {
	case *mdns.SVCB:
		record = rr
	case *mdns.HTTPS:
		record = &rr.SVCB
	}
	// The codec checks parameter framing, ordering and most value lengths, but
	// leaves these format constraints to its caller.
	for _, param := range record.Value {
		switch param := param.(type) {
		case *mdns.SVCBAlpn:
			if len(param.Alpn) == 0 {
				return "", errors.New("empty HTTPS/SVCB alpn list")
			}
			for _, protocol := range param.Alpn {
				if protocol == "" {
					return "", errors.New("empty HTTPS/SVCB alpn identifier")
				}
			}
		case *mdns.SVCBMandatory:
			if len(param.Code) == 0 {
				return "", errors.New("empty HTTPS/SVCB mandatory list")
			}
			var previous mdns.SVCBKey
			for _, key := range param.Code {
				if key <= previous || key == 65535 {
					return "", errors.New("invalid HTTPS/SVCB mandatory key order or value")
				}
				previous = key
			}
		}
	}
	// Keep the existing CLI's answer-only output. The library supplies DNS
	// presentation escaping, including ALPN lists and opaque unknown parameters.
	return strings.TrimPrefix(rr.String(), rr.Header().String()), nil
}
