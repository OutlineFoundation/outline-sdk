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

//go:build nettest
// +build nettest

package integrationtest

import (
	"bytes"
	"context"
	"log"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.getoutline.org/sdk/x/configurl"
	"golang.getoutline.org/sdk/x/smart"
	"github.com/stretchr/testify/require"
)

func Test_Integration_NewDialer_BrokenConfig(t *testing.T) {
	if runtime.GOOS == "android" {
		// See https://golang.getoutline.org/sdk/issues/504
		t.Skip("Skip Smart Dialer integration test on Android until storage is made compatible with android emulator testing")
	}

	configBytes := []byte(`
dns:
    # We get censored DNS responses when we send queries to an IP in China.
    - udp: { address: china.cn }
    # We get censored DNS responses when we send queries to a resolver in Iran.
    - udp: { address: ns1.tic.ir }
    - tcp: { address: ns1.tic.ir }
    # We get censored DNS responses when we send queries to an IP in Turkmenistan.
    - udp: { address: tmcell.tm }
    # Testing captive portal.
    - tls:
        name: captive-portal.badssl.com
        address: captive-portal.badssl.com:443
    # Testing forged TLS certificate.
    - https: { name: mitm-software.badssl.com }
tls:
    - ""
    - split:1
    - split:2
    - split:5
    - tlsfrag:1
fallback:
    # Nonexistent Outline Server
    - ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTprSzdEdHQ0MkJLOE9hRjBKYjdpWGFK@1.2.3.4:9999/?outline=1
    # Psiphon disabled: psiphon-tls is incompatible with Go 1.25 (https://github.com/OutlineFoundation/outline-sdk/issues/513).
    # - psiphon: {
    #     "PropagationChannelId":"ID1",
    #     "SponsorId":"ID2",
    #     "DisableLocalSocksProxy" : true,
    #     "DisableLocalHTTPProxy" : true,
    #     "EstablishTunnelTimeoutSeconds": 1,
    #     }
    # Nonexistant local socks5 proxy
    - socks5://192.168.1.10:1080
`)

	testDomains := []string{"www.example.com", "example.com"}
	transportType := ""

	logBuffer := new(bytes.Buffer)
	logger := log.New(logBuffer, "", log.LstdFlags)

	providers := configurl.NewDefaultProviders()
	packetDialer, err := providers.NewPacketDialer(context.Background(), transportType)
	if err != nil {
		require.NoError(t, err)
	}
	streamDialer, err := providers.NewStreamDialer(context.Background(), transportType)
	if err != nil {
		require.NoError(t, err)
	}

	finder := smart.StrategyFinder{
		LogWriter:    logger.Writer(),
		TestTimeout:  5 * time.Second,
		StreamDialer: streamDialer,
		PacketDialer: packetDialer,
	}
	// Psiphon disabled: psiphon-tls is incompatible with Go 1.25 (https://github.com/OutlineFoundation/outline-sdk/issues/513).
	// finder.RegisterFallbackParser("psiphon", psiphon.ParseConfig)

	_, err = finder.NewDialer(context.Background(), testDomains, configBytes)

	require.Error(t, err)
	require.Contains(t, err.Error(), "could not find a working fallback: all tests failed")

	// Check the content of the log writer.
	// Different systems have different network error messages,
	// so we only check the broad strokes.
	expectedLogs := []string{
		"request for A query failed: dial DNS resolver failed:",
		`request for A query failed: receive DNS message failed: failed to get HTTP response: Post "https://mitm-software.badssl.com:443/dns-query": tls:`,
		"🏃 running test: 'ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTprSzdEdHQ0MkJLOE9hRjBKYjdpWGFK@1.2.3.4:9999/?outline=1'",
		// Psiphon disabled: psiphon-tls is incompatible with Go 1.25 (https://github.com/OutlineFoundation/outline-sdk/issues/513).
		// "❌ Failed to create fallback[1]: [{psiphon: {DisableLocalHTTPProxy: true, DisableLocalSocksProxy: true, Establish…]: failed to start psiphon dialer: clientlib: tunnel establishment timeout",
		"🏃 running test: 'socks5://192.168.1.10:1080' (domain: www.example.com.)",
	}
	logContent := logBuffer.String()
	for _, expectedLog := range expectedLogs {
		require.True(t, strings.Contains(logContent, expectedLog), "Expected log '%s' not found in: %s", expectedLog, logContent)
	}
}
