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

package integrationtest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/x/smart"
	"github.com/stretchr/testify/require"
)

// mockStreamDialer intercepts stream connections made by StrategyFinder.
// It redirects connection attempts for specific badssl.com endpoints to local mock servers,
// and fails all other connections to simulate a completely broken network environment.
type mockStreamDialer struct {
	base                     transport.StreamDialer
	untrustedHTTPSServerAddr string // Address of the local mock HTTPS server representing mitm-software.badssl.com
	captivePortalServerAddr  string // Address of the local mock TCP server representing captive-portal.badssl.com:443
}

func (d *mockStreamDialer) DialStream(ctx context.Context, addr string) (transport.StreamConn, error) {
	if addr == "mitm-software.badssl.com:443" {
		return d.base.DialStream(ctx, d.untrustedHTTPSServerAddr)
	}
	if addr == "captive-portal.badssl.com:443" {
		return d.base.DialStream(ctx, d.captivePortalServerAddr)
	}
	return nil, errors.New("mock network: no route to host")
}

// errorPacketDialer simulates UDP dial failures by immediately returning an error.
// This mocks broken DNS-over-UDP resolvers (like china.cn, ns1.tic.ir, tmcell.tm).
type errorPacketDialer struct{}

func (d *errorPacketDialer) DialPacket(ctx context.Context, addr string) (net.Conn, error) {
	return nil, errors.New("dial DNS resolver failed")
}

// startMockCaptivePortalTCPServer starts a local TCP server that accepts and immediately closes connections.
// This is used to mock a captive portal that interrupts TLS handshakes.
func startMockCaptivePortalTCPServer(t *testing.T) string {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
	})
	return listener.Addr().String()
}

func Test_Integration_NewDialer_BrokenConfig(t *testing.T) {
	if runtime.GOOS == "android" {
		// See https://golang.getoutline.org/sdk/issues/504
		t.Skip("Skip Smart Dialer integration test on Android until storage is made compatible with android emulator testing")
	}

	ts := httptest.NewTLSServer(nil)
	t.Cleanup(ts.Close)

	captivePortalAddr := startMockCaptivePortalTCPServer(t)

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
    - error: {
        "error": "failed to start dialer"
      }
    # Nonexistant local socks5 proxy
    - socks5://192.168.1.10:1080
`)

	testDomains := []string{"www.example.com", "example.com"}

	logBuffer := new(bytes.Buffer)
	logger := log.New(logBuffer, "", log.LstdFlags)

	finder := smart.StrategyFinder{
		LogWriter:    logger.Writer(),
		TestTimeout:  5 * time.Second,
		StreamDialer: &mockStreamDialer{
			base:                     &transport.TCPDialer{},
			untrustedHTTPSServerAddr: ts.Listener.Addr().String(),
			captivePortalServerAddr:  captivePortalAddr,
		},
		PacketDialer: &errorPacketDialer{},
	}
	finder.RegisterFallbackParser("error", func(ctx context.Context, config smart.YAMLNode) (transport.StreamDialer, string, error) {
		m, ok := config.(map[string]any)
		if !ok {
			return nil, "", fmt.Errorf("invalid config of type %T", config)
		}
		errStr, _ := m["error"].(string)
		return nil, "signature_placeholder", errors.New(errStr)
	})

	_, err := finder.NewDialer(context.Background(), testDomains, configBytes)

	require.Error(t, err)
	require.Contains(t, err.Error(), "could not find a working fallback: all tests failed")

	// Check the content of the log writer.
	// Different systems have different network error messages, so we only check the broad strokes.
	expectedLogs := []string{
		"request for A query failed: dial DNS resolver failed:",
		`request for A query failed: receive DNS message failed: failed to get HTTP response: Post "https://mitm-software.badssl.com:443/dns-query": tls:`,
		"🏃 running test: 'ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTprSzdEdHQ0MkJLOE9hRjBKYjdpWGFK@1.2.3.4:9999/?outline=1'",
		"❌ Failed to create fallback[1]:",
		"failed to start dialer",
		"🏃 running test: 'socks5://192.168.1.10:1080' (domain: www.example.com.)",
	}
	logContent := logBuffer.String()
	for _, expectedLog := range expectedLogs {
		require.True(t, strings.Contains(logContent, expectedLog), "Expected log '%s' not found in: %s", expectedLog, logContent)
	}
}
