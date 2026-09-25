//go:build darwin || linux || freebsd

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

package quicprelude

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"
)

// quicSocket records which send API QUIC-Go actually selects. Its receive
// batching must survive wrapping as well.
type quicSocket struct {
	*net.UDPConn
	batch         *ipv4.PacketConn
	messageWrites atomic.Int32
	plainWrites   atomic.Int32
	batchReads    atomic.Int32
}

func (c *quicSocket) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (int, int, error) {
	c.messageWrites.Add(1)
	return c.UDPConn.WriteMsgUDP(b, oob, addr)
}
func (c *quicSocket) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.plainWrites.Add(1)
	return c.UDPConn.WriteTo(b, addr)
}
func (c *quicSocket) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	c.batchReads.Add(1)
	return c.batch.ReadBatch(ms, flags)
}

// Expose only PacketConn on the server so receive observation cannot be
// bypassed by raw batch reads. Assertions below inspect datagrams on the wire.
type wireRecorder struct {
	net.PacketConn
	mu      sync.Mutex
	packets [][]byte
	sources []string
}

func (c *wireRecorder) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err == nil {
		c.mu.Lock()
		c.packets = append(c.packets, bytes.Clone(b[:n]))
		c.sources = append(c.sources, addr.String())
		c.mu.Unlock()
	}
	return n, addr, err
}

func TestQUICGoUDPPreludeV1(t *testing.T) { testQUICGoUDPPrelude(t, quic.Version1) }
func TestQUICGoUDPPreludeV2(t *testing.T) { testQUICGoUDPPrelude(t, quic.Version2) }

func testQUICGoUDPPrelude(t *testing.T, version quic.Version) {
	t.Helper()
	t.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	serverUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer serverUDP.Close()
	recorder := &wireRecorder{PacketConn: serverUDP}
	server, err := quic.Listen(recorder, &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}},
		NextProtos:   []string{"prelude-test"},
	}, &quic.Config{Versions: []quic.Version{version}})
	require.NoError(t, err)
	defer server.Close()

	body := bytes.Repeat([]byte("optimized QUIC data\n"), 8192)
	result := make(chan error, 1)
	go func() {
		conn, err := server.Accept(ctx)
		if err != nil {
			result <- err
			return
		}
		stream, err := conn.AcceptUniStream(ctx)
		if err != nil {
			result <- err
			return
		}
		got, err := io.ReadAll(stream)
		if err == nil && !bytes.Equal(got, body) {
			err = io.ErrUnexpectedEOF
		}
		result <- err
	}()

	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer socket.Close()
	inner := &quicSocket{UDPConn: socket, batch: ipv4.NewPacketConn(socket)}
	wrapped := wrapForTest(t, inner, mustDefaultGenerator(t))
	require.Implements(t, (*quic.OOBCapablePacketConn)(nil), wrapped)
	client, err := quic.Dial(ctx, wrapped, server.Addr(), &tls.Config{
		ServerName: "localhost", RootCAs: roots, NextProtos: []string{"prelude-test"},
	}, &quic.Config{Versions: []quic.Version{version}})
	require.NoError(t, err)
	defer client.CloseWithError(0, "done")
	stream, err := client.OpenUniStreamSync(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.SetWriteDeadline(time.Now().Add(10*time.Second)))
	_, err = stream.Write(body)
	require.NoError(t, err)
	require.NoError(t, stream.Close())
	select {
	case err := <-result:
		require.NoError(t, err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	require.Equal(t, version, client.ConnectionState().Version)
	require.Positive(t, inner.messageWrites.Load(), "QUIC-Go must use the intercepted UDP message path")
	require.Zero(t, inner.plainWrites.Load(), "the optimized connection must not fall back to WriteTo")
	require.Positive(t, inner.batchReads.Load(), "the inner receive wrapper must be preserved")
	t.Logf("QUIC %v: WriteMsgUDP=%d, ReadBatch=%d, GSO=%v", version, inner.messageWrites.Load(), inner.batchReads.Load(), client.ConnectionState().GSO)

	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	initials := 0
	for i, p := range recorder.packets {
		if !mayCarryClientHello(p) {
			continue
		}
		initials++
		require.Positive(t, i, "Initial arrived without a prelude")
		priorVersion, _ := requireLongHeader(t, recorder.packets[i-1], len(p))
		require.Equal(t, exampleReserved, priorVersion)
		require.Equal(t, recorder.sources[i-1], recorder.sources[i], "prelude must use the same UDP flow")
	}
	require.Positive(t, initials, "the wire must contain at least one preluded Initial")
}
