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

package smart

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWinningStrategy_MarshalProxyless(t *testing.T) {
	cases := []struct {
		name string
		dns  *dnsEntryConfig
		tls  string
		yaml string
	}{{
		name: "DNS_System",
		dns:  &dnsEntryConfig{System: &struct{}{}},
		yaml: "{dns: [{system: {}}]}",
	}, {
		name: "DNS_UDP",
		dns:  &dnsEntryConfig{UDP: &udpEntryConfig{Address: "4.3.2.1:53"}},
		yaml: `{dns: [{udp: {address: "4.3.2.1:53"}}]}`,
	}, {
		name: "DNS_TCP",
		dns:  &dnsEntryConfig{TCP: &tcpEntryConfig{Address: "1.1.4.4:53"}},
		yaml: `{dns: [{tcp: {address: "1.1.4.4:53"}}]}`,
	}, {
		name: "DNS_TLS",
		dns:  &dnsEntryConfig{TLS: &tlsEntryConfig{Name: "dot.example.com", Address: "5.6.7.8:853"}},
		yaml: `{dns: [{tls: {name: dot.example.com, address: "5.6.7.8:853"}}]}`,
	}, {
		name: "DNS_HTTPS",
		dns:  &dnsEntryConfig{HTTPS: &httpsEntryConfig{Name: "doh.example.com", Address: "8.7.6.5:443"}},
		yaml: `{dns: [{https: {name: doh.example.com, address: "8.7.6.5:443"}}]}`,
	}, {
		name: "Empty",
		yaml: `{}`,
	}, {
		name: "TLS_Split",
		tls:  "split:5",
		yaml: `{tls: ["split:5"]}`,
	}, {
		name: "TLS_Frag",
		tls:  "tlsfrag:8",
		yaml: `{tls: ["tlsfrag:8"]}`,
	}, {
		name: "DNS_System_TLS_Frag",
		dns:  &dnsEntryConfig{System: &struct{}{}},
		tls:  "tlsfrag:8",
		yaml: `{dns: [{system: {}}], tls: ["tlsfrag:8"]}`,
	}, {
		name: "DNS_HTTPS_TLS_Pipe",
		dns:  &dnsEntryConfig{HTTPS: &httpsEntryConfig{Name: "doh.example.com", Address: "9.9.9.9:443"}},
		tls:  "split:314|tlsfrag:159",
		yaml: `{dns: [{https: {name: doh.example.com, address: "9.9.9.9:443"}}], tls: ["split:314|tlsfrag:159"]}`,
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newProxylessWinningConfig(tc.dns, tc.tls)
			actual, err := w.toYAML()
			require.NoError(t, err)
			require.Equal(t, tc.yaml, strings.TrimSpace(string(actual)))

			finder := &finder{}
			cfg, err := finder.parseConfig([]byte(tc.yaml))
			require.NoError(t, err)
			require.Equal(t, cfg, configConfig(w))
		})
	}
}

func TestWinningStrategy_MarshalFallback(t *testing.T) {
	cases := []struct {
		name string
		conf fallbackEntryConfig
		yaml string
	}{{
		name: "Shadowsocks",
		conf: "ss://Y2hhY2hh@1.2.3.4:9999/?outline=1",
		yaml: `{fallback: ["ss://Y2hhY2hh@1.2.3.4:9999/?outline=1"]}`,
	}, {
		name: "StructPsiphon",
		conf: map[string]any{
			"psiphon": map[string]any{
				"PropagationChannelId": "42",
				"SponsorId":            "TBD",
			},
		},
		yaml: `{fallback: [{psiphon: {PropagationChannelId: "42", SponsorId: TBD}}]}`,
	}, {
		name: "Empty",
		yaml: `{}`,
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newFallbackWinningConfig(tc.conf)
			actual, err := w.toYAML()
			require.NoError(t, err)
			require.Equal(t, tc.yaml, strings.TrimSpace(string(actual)))

			finder := &finder{}
			cfg, err := finder.parseConfig([]byte(tc.yaml))
			require.NoError(t, err)
			require.Equal(t, cfg, configConfig(w))
		})
	}
}

func TestWinningStrategy_PromoteProxylessToFront(t *testing.T) {
	var (
		httpsDNS  = dnsEntryConfig{HTTPS: &httpsEntryConfig{Name: "h1.example.com", Address: "h1.example.com:443"}}
		https2DNS = dnsEntryConfig{HTTPS: &httpsEntryConfig{Name: "failed DoH", Address: "failed.doh.com"}}
		tcpDNS    = dnsEntryConfig{TCP: &tcpEntryConfig{Address: "12.34.43.21:53"}}
		tcpSplit  = "split:888"
		tlsFrag   = "tlsfrag:-314"
	)
	cases := []struct {
		name     string
		winner   string
		input    configConfig
		expected configConfig
	}{{
		name:     "Single DNS Entry",
		winner:   `{dns: [{https: {name: "h1.example.com", address: "h1.example.com:443"}}]}`,
		input:    configConfig{DNS: []dnsEntryConfig{httpsDNS}},
		expected: configConfig{DNS: []dnsEntryConfig{httpsDNS}},
	}, {
		name:     "Single TLS Entry",
		winner:   `{tls: ["tlsfrag:-314"]}`,
		input:    configConfig{TLS: []string{tlsFrag}},
		expected: configConfig{TLS: []string{tlsFrag}},
	}, {
		name:     "Multiple DNS and TLS Entries",
		winner:   `{dns: [{https: {name: "h1.example.com", address: "h1.example.com:443"}}], tls: ["tlsfrag:-314"]}`,
		input:    configConfig{DNS: []dnsEntryConfig{https2DNS, tcpDNS, httpsDNS}, TLS: []string{tcpSplit, tlsFrag}},
		expected: configConfig{DNS: []dnsEntryConfig{httpsDNS, https2DNS, tcpDNS}, TLS: []string{tlsFrag, tcpSplit}},
	}, {
		name:     "Entries not Found",
		winner:   `{dns: [{https: {name: "h1.example.com"}}], tls: ["tlsfrag:+314"]}`,
		input:    configConfig{DNS: []dnsEntryConfig{https2DNS, tcpDNS, httpsDNS}, TLS: []string{tcpSplit, tlsFrag}},
		expected: configConfig{DNS: []dnsEntryConfig{https2DNS, tcpDNS, httpsDNS}, TLS: []string{tcpSplit, tlsFrag}},
	}, {
		name:     "No Input Config",
		winner:   `{dns: [{udp: {address: "88.88.88.88:53"}}], tls: ["tlsfrag:-314"]}`,
		input:    configConfig{},
		expected: configConfig{},
	}, {
		name:     "TLS only Winner",
		winner:   `{tls: ["split:888"]}`,
		input:    configConfig{DNS: []dnsEntryConfig{tcpDNS, httpsDNS}, TLS: []string{tlsFrag, tcpSplit}},
		expected: configConfig{DNS: []dnsEntryConfig{tcpDNS, httpsDNS}, TLS: []string{tcpSplit, tlsFrag}},
	}, {
		name:     "DNS only Winner",
		winner:   `{dns: [{https: {name: "h1.example.com", address: "h1.example.com:443"}}]}`,
		input:    configConfig{DNS: []dnsEntryConfig{tcpDNS, httpsDNS}, TLS: []string{tlsFrag, tcpSplit}},
		expected: configConfig{DNS: []dnsEntryConfig{httpsDNS, tcpDNS}, TLS: []string{tlsFrag, tcpSplit}},
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			winner, err := (&finder{}).parseConfig([]byte(tc.winner))
			require.NoError(t, err)

			winningConfig(winner).promoteProxylessToFront(&tc.input)
			require.Equal(t, tc.expected, tc.input)
			require.Nil(t, tc.input.Fallback)

			// No exclusive fallback config
			fb, ok := winningConfig(winner).getFallbackIfExclusive(&tc.input)
			require.False(t, ok)
			require.Nil(t, fb)
		})
	}
}

func TestWinningStrategy_GetFallbackIfExclusive(t *testing.T) {
	var (
		shadowsocksFb  = "ss://Y2hhY2hh@11.22.33.44:19999/?outline=1"
		shadowsocksFb2 = "ssconf://Here-is-the-dynamic-key.com"
		psiphonFb      = map[string]any{"psiphon": map[string]any{
			"PropagationChannelId": "19980904",
			"SponsorId":            "G00gle",
		}}
	)
	cases := []struct {
		name     string
		winner   string
		input    configConfig
		expected fallbackEntryConfig
	}{{
		name:     "Single Shadowsocks",
		winner:   `{fallback: ["ss://Y2hhY2hh@11.22.33.44:19999/?outline=1"]}`,
		input:    configConfig{Fallback: []fallbackEntryConfig{shadowsocksFb}},
		expected: shadowsocksFb,
	}, {
		name:     "Multiple Entries Found Shadowsocks",
		winner:   `{fallback: ["ss://Y2hhY2hh@11.22.33.44:19999/?outline=1"]}`,
		input:    configConfig{Fallback: []fallbackEntryConfig{psiphonFb, shadowsocksFb}},
		expected: shadowsocksFb,
	}, {
		name:     "Multiple Entries Found Psiphon",
		winner:   `{fallback: [{psiphon: {PropagationChannelId: "19980904", SponsorId: G00gle}}]}`,
		input:    configConfig{Fallback: []fallbackEntryConfig{shadowsocksFb, psiphonFb}},
		expected: psiphonFb,
	}, {
		name:     "Shadowsocks not Found",
		winner:   `{fallback: ["https://a-different-dynamic-key.com"]}`,
		input:    configConfig{Fallback: []fallbackEntryConfig{shadowsocksFb, shadowsocksFb2}},
		expected: nil,
	}, {
		name:     "Psiphon not Found",
		winner:   `{fallback: [{psiphon: {PropagationChannelId: "19980904", SponsorId: Google}}]}`,
		input:    configConfig{Fallback: []fallbackEntryConfig{psiphonFb}},
		expected: nil,
	}, {
		name:     "Fallback not Exclusive cuz DNS",
		winner:   `{dns: [{https: {name: "h1.example.com"}}], fallback: ["not-really-matter"]}`,
		input:    configConfig{Fallback: []fallbackEntryConfig{shadowsocksFb}},
		expected: nil,
	}, {
		name:     "Fallback not Exclusive cuz TLS",
		winner:   `{tls: ["n1.example.com"], fallback: ["not-really-matter"]}`,
		input:    configConfig{Fallback: []fallbackEntryConfig{psiphonFb}},
		expected: nil,
	}, {
		name:     "Fallback not Exclusive cuz Multiple Winners",
		winner:   `{fallback: ["not-really-matter", "not-really-matter"]}`,
		input:    configConfig{Fallback: []fallbackEntryConfig{shadowsocksFb, psiphonFb}},
		expected: nil,
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			winner, err := (&finder{}).parseConfig([]byte(tc.winner))
			require.NoError(t, err)

			actual, found := winningConfig(winner).getFallbackIfExclusive(&tc.input)
			if tc.expected != nil {
				require.True(t, found)
				require.Equal(t, tc.expected, actual)
			} else {
				require.False(t, found)
				require.Nil(t, actual)
			}

			// No changes for proxyless
			winningConfig(winner).promoteProxylessToFront(&tc.input)
			require.Nil(t, tc.input.DNS)
			require.Nil(t, tc.input.TLS)
		})
	}
}
