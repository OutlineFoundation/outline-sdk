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
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
)

func TestResourceBodyFromRData_A(t *testing.T) {
	rdata := []byte{1, 2, 3, 4}
	body := resourceBodyFromRData(dnsmessage.TypeA, rdata)
	a, ok := body.(*dnsmessage.AResource)
	require.True(t, ok)
	require.Equal(t, [4]byte{1, 2, 3, 4}, a.A)
}

func TestResourceBodyFromRData_A_Short(t *testing.T) {
	body := resourceBodyFromRData(dnsmessage.TypeA, []byte{1, 2, 3})
	_, ok := body.(*dnsmessage.UnknownResource)
	require.True(t, ok)
}

func TestResourceBodyFromRData_AAAA(t *testing.T) {
	rdata := make([]byte, 16)
	for i := range rdata {
		rdata[i] = byte(i + 1)
	}
	body := resourceBodyFromRData(dnsmessage.TypeAAAA, rdata)
	aaaa, ok := body.(*dnsmessage.AAAAResource)
	require.True(t, ok)
	require.Equal(t, [16]byte(rdata), aaaa.AAAA)
}

func TestResourceBodyFromRData_CNAME(t *testing.T) {
	// Wire format for "example.com.": \x07example\x03com\x00
	rdata := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	body := resourceBodyFromRData(dnsmessage.TypeCNAME, rdata)
	cname, ok := body.(*dnsmessage.CNAMEResource)
	require.True(t, ok)
	require.Equal(t, "example.com.", cname.CNAME.String())
}

func TestResourceBodyFromRData_NS(t *testing.T) {
	// Wire format for "ns1.example.com."
	rdata := []byte{3, 'n', 's', '1', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	body := resourceBodyFromRData(dnsmessage.TypeNS, rdata)
	ns, ok := body.(*dnsmessage.NSResource)
	require.True(t, ok)
	require.Equal(t, "ns1.example.com.", ns.NS.String())
}

func TestResourceBodyFromRData_TXT(t *testing.T) {
	// Two strings: "hello" and "world"
	rdata := []byte{5, 'h', 'e', 'l', 'l', 'o', 5, 'w', 'o', 'r', 'l', 'd'}
	body := resourceBodyFromRData(dnsmessage.TypeTXT, rdata)
	txt, ok := body.(*dnsmessage.TXTResource)
	require.True(t, ok)
	require.Equal(t, []string{"hello", "world"}, txt.TXT)
}

func TestResourceBodyFromRData_MX(t *testing.T) {
	// Priority 10, then wire format for "mail.example.com."
	rdata := []byte{0, 10, 4, 'm', 'a', 'i', 'l', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	body := resourceBodyFromRData(dnsmessage.TypeMX, rdata)
	mx, ok := body.(*dnsmessage.MXResource)
	require.True(t, ok)
	require.Equal(t, uint16(10), mx.Pref)
	require.Equal(t, "mail.example.com.", mx.MX.String())
}

func TestResourceBodyFromRData_Unknown(t *testing.T) {
	rdata := []byte{1, 2, 3, 4, 5}
	body := resourceBodyFromRData(dnsmessage.Type(999), rdata)
	unk, ok := body.(*dnsmessage.UnknownResource)
	require.True(t, ok)
	require.Equal(t, dnsmessage.Type(999), unk.Type)
	require.Equal(t, rdata, unk.Data)
}

func TestParseDNSLabels_Root(t *testing.T) {
	name, err := parseDNSLabels([]byte{0})
	require.NoError(t, err)
	require.Equal(t, ".", name.String())
}

func TestParseDNSLabels_Simple(t *testing.T) {
	// "example.com."
	data := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	name, err := parseDNSLabels(data)
	require.NoError(t, err)
	require.Equal(t, "example.com.", name.String())
}

func TestParseDNSLabels_Pointer(t *testing.T) {
	_, err := parseDNSLabels([]byte{0xC0, 0x0C})
	require.Error(t, err)
}

func TestParseDNSLabels_Overflow(t *testing.T) {
	_, err := parseDNSLabels([]byte{100, 1, 2})
	require.Error(t, err)
}
