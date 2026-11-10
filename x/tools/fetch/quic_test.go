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
	"crypto/tls"
	"encoding/base64"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/shadowsocks/go-shadowsocks2/socks"
	"github.com/stretchr/testify/require"
	"golang.getoutline.org/sdk/transport/shadowsocks"
	"golang.getoutline.org/sdk/x/configurl"
)

// A QUIC dial deadline must stop both dialing and the DNS lookup started by
// WriteTo. The lookup deliberately waits for its connection-owned context to
// be canceled; returning from DialEarly alone would leave that work running.
func TestQUICDialTimeoutCancelsDNS(t *testing.T) {
	conn, err := (resolvingUDPListener{}).ListenPacket(context.Background())
	require.NoError(t, err)
	started := make(chan struct{})
	canceled := make(chan struct{})
	conn.(*resolvingUDPConn).lookup = func(ctx context.Context, _ string) ([]net.IPAddr, error) {
		close(started)
		<-ctx.Done()
		close(canceled)
		return nil, ctx.Err()
	}
	qt := &quic.Transport{Conn: conn}
	defer qt.Close()
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := dialQUICEarly(ctx, qt, "stalled.invalid:443",
			&tls.Config{ServerName: "stalled.invalid", NextProtos: []string{http3.NextProtoH3}}, nil)
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("QUIC did not start a DNS lookup")
	}
	// These timers are watchdogs, longer than the dial deadline. The deadline
	// must close the packet connection without help from the test's cleanup.
	select {
	case err := <-done:
		require.Error(t, err)
		require.ErrorIs(t, ctx.Err(), context.DeadlineExceeded)
	case <-time.After(3 * time.Second):
		t.Fatal("QUIC dial did not honor its deadline")
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("QUIC dial timeout did not cancel DNS")
	}
}

// Dial through a real Shadowsocks packet listener and decrypt the first outgoing
// datagram. It must carry the original hostname for proxy-side resolution and
// the requested QUIC version. The relay only captures packets, so this test does
// not need DNS, a TLS certificate, or a completed QUIC handshake.
func TestQUICDialSendsHostnameToShadowsocks(t *testing.T) {
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
	providers := configurl.NewDefaultProviders()
	providers.PacketListeners.BaseInstance = resolvingUDPListener{}
	listener, err := providers.NewPacketListener(context.Background(), config)
	require.NoError(t, err)
	conn, err := listener.ListenPacket(context.Background())
	require.NoError(t, err)
	defer conn.Close()
	qt := &quic.Transport{Conn: conn}
	defer qt.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := dialQUICEarly(ctx, qt, "remote-only.invalid:443",
			&tls.Config{ServerName: "remote-only.invalid", NextProtos: []string{http3.NextProtoH3}},
			&quic.Config{Versions: []quic.Version{quic.Version2}})
		done <- err
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("QUIC dial did not stop after cancellation")
		}
	}()
	// An eager lookup would prevent the packet from reaching this IP-addressed
	// relay, or replace its domain address with an IP. Check the wire address.
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
	// Bytes 1..4 of the QUIC long header contain the v2 version codepoint.
	require.Equal(t, []byte{0x6b, 0x33, 0x43, 0xcf}, packet[1:5])
}
