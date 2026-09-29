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
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/shadowsocks/go-shadowsocks2/socks"
	"github.com/stretchr/testify/require"
	"golang.getoutline.org/sdk/transport/shadowsocks"
)

// Run the actual CLI in a child so main's flags and os.Exit cannot affect tests.
func TestFetchProcess(t *testing.T) {
	if os.Getenv("OUTLINE_FETCH_TEST_PROCESS") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{"fetch"}, os.Args[i+1:]...)
			break
		}
	}
	flag.CommandLine = flag.NewFlagSet("fetch", flag.ExitOnError)
	// Any local destination lookup must fail; the proxy endpoint is an IP.
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("local DNS disabled by test")
	}}
	main()
	os.Exit(0)
}

func TestFetchHTTP3SendsHostnameToShadowsocks(t *testing.T) {
	relay, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer relay.Close()
	secret := make([]byte, 32)
	_, err = rand.Read(secret)
	require.NoError(t, err)
	password := base64.RawURLEncoding.EncodeToString(secret)
	key, err := shadowsocks.NewEncryptionKey("chacha20-ietf-poly1305", password)
	require.NoError(t, err)
	config := "ss://" + base64.RawURLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:"+password)) + "@" + relay.LocalAddr().String()
	executable, err := os.Executable()
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	args := []string{"-test.run=^TestFetchProcess$", "--", "-proto", "h3", "-timeout", "3", "-quic-versions", "2", "-transport", config, "https://remote-only.invalid/"}
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Env = append(os.Environ(), "OUTLINE_FETCH_TEST_PROCESS=1")
	require.NoError(t, cmd.Start())
	defer func() { cancel(); _ = cmd.Wait() }()
	require.NoError(t, relay.SetReadDeadline(time.Now().Add(4*time.Second)))
	buf := make([]byte, 65535)
	n, _, err := relay.ReadFrom(buf)
	require.NoError(t, err, "fetch must send QUIC via the relay without resolving the target locally")
	plaintext, err := shadowsocks.Unpack(nil, buf[:n], key)
	require.NoError(t, err)
	addr := socks.SplitAddr(plaintext)
	require.NotNil(t, addr)
	require.Equal(t, byte(socks.AtypDomainName), addr[0])
	require.Equal(t, "remote-only.invalid:443", addr.String())
	packet := plaintext[len(addr):]
	require.Greater(t, len(packet), 5)
	// The caller's requested QUIC v2 must survive the change to address handling.
	require.Equal(t, []byte{0x6b, 0x33, 0x43, 0xcf}, packet[1:5])
}
