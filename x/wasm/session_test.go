// Copyright 2026 The Outline Authors. SPDX-License-Identifier: Apache-2.0
package wasm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"golang.getoutline.org/sdk/transport"
)

func testSession(t *testing.T) (*Manager, *Session) {
	t.Helper()
	b, e := os.ReadFile("examples/bundle.wasm")
	if e != nil {
		t.Fatal(e)
	}
	m := NewManager(context.Background(), false)
	t.Cleanup(func() { m.Close() })
	s, e := m.NewSession(context.Background(), b)
	if e != nil {
		t.Fatal(e)
	}
	return m, s
}
func TestObjectStateAndCodeReuse(t *testing.T) {
	m, s := testSession(t)
	b, _ := os.ReadFile("examples/bundle.wasm")
	s2, e := m.NewSession(context.Background(), b)
	if e != nil {
		t.Fatal(e)
	}
	if m.CompiledCount() != 1 {
		t.Fatal("compiled same artifact twice")
	}
	cat, e := s.Catalog()
	if e != nil || !bytes.Contains([]byte(cat), []byte("packet.xor")) {
		t.Fatal(cat, e)
	}
	a, e := s.create("stream.xor", 3, "")
	if e != nil {
		t.Fatal(e)
	}
	bhandle, e := s.create("stream.xor", 8, "")
	if e != nil {
		t.Fatal(e)
	}
	ac, _ := s.open(a)
	bc, _ := s.open(bhandle)
	second, _ := s.open(a)
	s.release(a)
	for h, key := range map[uint32]byte{ac: 3, bc: 8, second: 3} {
		out, e := s.transform(h, true, []byte("abc"))
		if e != nil || out[0] != 'a'^key {
			t.Fatal(out, e)
		}
		s.release(h)
	}
	if _, e = s.open(a); e == nil {
		t.Fatal("released factory reused")
	}
	stale, _ := s.open(bhandle)
	s.release(stale)
	fresh, _ := s.open(bhandle)
	if stale == fresh {
		t.Fatal("handle generation not advanced")
	}
	if _, e = s.transform(stale, true, []byte("x")); e == nil {
		t.Fatal("stale child accepted")
	}
	if _, e = s.transform(bhandle, true, []byte("x")); e == nil {
		t.Fatal("factory accepted as connection")
	}
	// Equal numeric handles in another session are not globally meaningful.
	f2, _ := s2.create("stream.xor", 91, "")
	c2, _ := s2.open(f2)
	s.Close()
	out, e := s2.transform(c2, true, []byte("a"))
	if e != nil || out[0] != 'a'^91 {
		t.Fatal("other session corrupted", e)
	}
}

type recorder struct {
	bytes.Buffer
	chunks []int
}

func (r *recorder) Write(p []byte) (int, error) {
	r.chunks = append(r.chunks, len(p))
	return r.Buffer.Write(p)
}
func (r *recorder) Close() error                     { return nil }
func (r *recorder) CloseRead() error                 { return nil }
func (r *recorder) CloseWrite() error                { return nil }
func (r *recorder) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (r *recorder) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (r *recorder) SetDeadline(time.Time) error      { return nil }
func (r *recorder) SetReadDeadline(time.Time) error  { return nil }
func (r *recorder) SetWriteDeadline(time.Time) error { return nil }

type fakeDialer struct{ conn transport.StreamConn }

func (d fakeDialer) DialStream(context.Context, string) (transport.StreamConn, error) {
	return d.conn, nil
}
func TestSameSessionLayersAndIndependentSplit(t *testing.T) {
	_, s := testSession(t)
	for _, n := range []uint32{3, 8} {
		base := &recorder{}
		split, e := s.NewStreamDialer("stream.split", n, "", fakeDialer{base})
		if e != nil {
			t.Fatal(e)
		}
		outer, e := s.NewStreamDialer("stream.identity", 0, "", split)
		if e != nil {
			t.Fatal(e)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		c, e := outer.DialStream(ctx, "example.test:80")
		cancel()
		if e != nil {
			t.Fatal(e)
		}
		outer.Close()
		split.Close() // already created children remain valid
		if _, e = c.Write([]byte("0123456789")); e != nil {
			t.Fatal(e)
		}
		c.Close()
		if base.String() != "0123456789" || len(base.chunks) != 2 || base.chunks[0] != int(n) {
			t.Fatal(base.String(), base.chunks)
		}
	}
}
func TestStreamDuplexDeadlinesHalfClose(t *testing.T) {
	_, s := testSession(t)
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := ln.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		io.Copy(c, c)
	}()
	d, e := s.NewStreamDialer("stream.identity", 0, "", &transport.TCPDialer{})
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, e := d.DialStream(ctx, ln.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	if _, e = c.Read(make([]byte, 1)); !errors.Is(e, os.ErrDeadlineExceeded) {
		t.Fatal(e)
	}
	c.SetReadDeadline(time.Time{})
	payload := bytes.Repeat([]byte("duplex"), 20000)
	got := make([]byte, len(payload))
	readDone := make(chan error, 1)
	go func() { _, e := io.ReadFull(c, got); readDone <- e }()
	if _, e = c.Write(payload); e != nil {
		t.Fatal(e)
	}
	if e = <-readDone; e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(payload, got) {
		t.Fatal("changed stream")
	}
	if e = c.CloseWrite(); e != nil {
		t.Fatal(e)
	}
	if _, e = c.Read(make([]byte, 1)); e != io.EOF {
		t.Fatal(e)
	}
	<-done
}
func TestHandshakeCancellation(t *testing.T) {
	_, s := testSession(t)
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := ln.Accept()
		if e == nil {
			defer c.Close()
			io.Copy(io.Discard, c)
		}
	}()
	d, _ := s.NewStreamDialer("stream.xor", 37, "", &transport.TCPDialer{})
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if c, e := d.DialStream(ctx, ln.Addr().String()); e == nil {
		c.Close()
		t.Fatal("handshake did not cancel")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("leaked handshake socket")
	}
	if _, e = s.Profile("packet.identity"); e != nil {
		t.Fatal("dial cancellation killed shared session", e)
	}
}
func udpEcho(t *testing.T) *net.UDPConn {
	t.Helper()
	c, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		p := make([]byte, 65536)
		for {
			n, a, e := c.ReadFromUDP(p)
			if e != nil {
				return
			}
			c.WriteToUDP(p[:n], a)
		}
	}()
	return c
}
func TestPacketsMultiPeerEmptyTruncationAndLifetime(t *testing.T) {
	_, s := testSession(t)
	a, b := udpEcho(t), udpEcho(t)
	l, e := s.NewPacketListener("packet.xor", 37, &transport.UDPListener{Address: "127.0.0.1:0"})
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	p, e := l.ListenPacket(ctx)
	cancel()
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	p2, e := l.ListenPacket(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer p2.Close()
	l.Close()
	p.SetDeadline(time.Now().Add(time.Second))
	for _, peer := range []*net.UDPConn{a, b} {
		for _, data := range [][]byte{nil, []byte("packet")} {
			n, e := p.WriteTo(data, peer.LocalAddr())
			if e != nil || n != len(data) {
				t.Fatal(n, e)
			}
			buf := make([]byte, 100)
			n, src, e := p.ReadFrom(buf)
			if e != nil || src.String() != peer.LocalAddr().String() || !bytes.Equal(buf[:n], data) {
				t.Fatal(n, src, e)
			}
		}
	}
	p.WriteTo([]byte("truncated"), a.LocalAddr())
	buf := make([]byte, 2)
	n, _, e := p.ReadFrom(buf)
	if e != nil || n != 2 || string(buf) != "tr" {
		t.Fatal(n, e)
	}
	p.WriteTo([]byte("new"), a.LocalAddr())
	buf = make([]byte, 10)
	n, _, e = p.ReadFrom(buf)
	if e != nil || string(buf[:n]) != "new" {
		t.Fatal("datagram remainder leaked", e)
	}
	p.SetReadDeadline(time.Now())
	if _, _, e = p.ReadFrom(buf); !errors.Is(e, os.ErrDeadlineExceeded) {
		t.Fatal(e)
	}
	p.SetReadDeadline(time.Time{})
	blocked := make(chan error, 1)
	go func() { _, _, e := p.ReadFrom(buf); blocked <- e }()
	p.Close()
	select {
	case e := <-blocked:
		if e == nil {
			t.Fatal("close did not interrupt read")
		}
	case <-time.After(time.Second):
		t.Fatal("read stuck")
	}
	p2.SetDeadline(time.Now().Add(time.Second))
	if _, e = p2.WriteTo([]byte("sibling"), b.LocalAddr()); e != nil {
		t.Fatal(e)
	}
	if _, _, e = p2.ReadFrom(buf); e != nil {
		t.Fatal("closing sibling affected connection", e)
	}
}
func TestConcurrentConstructors(t *testing.T) {
	_, s := testSession(t)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(key uint32) {
			defer wg.Done()
			f, e := s.create("packet.xor", key, "")
			if e != nil {
				t.Error(e)
				return
			}
			defer s.release(f)
			h, e := s.open(f)
			if e != nil {
				t.Error(e)
				return
			}
			defer s.release(h)
			out, e := s.transform(h, true, []byte("hello"))
			if e != nil {
				t.Error(e)
				return
			}
			out, e = s.transform(h, false, out)
			if e != nil || string(out) != "hello" {
				t.Error(out, e)
			}
		}(uint32(i))
	}
	wg.Wait()
}

func TestGuestFailureIsSessionScoped(t *testing.T) {
	for _, file := range []string{"testdata/loop.wasm", "testdata/trap.wasm"} {
		t.Run(file, func(t *testing.T) {
			m, good := testSession(t)
			data, e := os.ReadFile(file)
			if e != nil {
				t.Fatal(e)
			}
			bad, e := m.NewSession(context.Background(), data)
			if e != nil {
				t.Fatal(e)
			}
			f, e := bad.create("stream.identity", 0, "")
			if e != nil {
				t.Fatal(e)
			}
			h, e := bad.open(f)
			if e != nil {
				t.Fatal(e)
			}
			start := time.Now()
			if _, e = bad.transform(h, true, []byte("x")); e == nil {
				t.Fatal("expected trap or budget failure")
			}
			if time.Since(start) > 5*time.Second {
				t.Fatal("guest was not bounded")
			}
			if _, e = bad.Profile("packet.identity"); e == nil {
				t.Fatal("failed session still usable")
			}
			if _, e = good.Profile("packet.identity"); e != nil {
				t.Fatal("independent session affected", e)
			}
		})
	}
}

func TestObjectCapacityAndRecovery(t *testing.T) {
	_, s := testSession(t)
	var handles []uint32
	for i := 0; i < 256; i++ {
		h, e := s.create("stream.identity", 0, "")
		if e != nil {
			t.Fatal(e)
		}
		handles = append(handles, h)
	}
	if _, e := s.create("stream.identity", 0, ""); e == nil {
		t.Fatal("unbounded object allocation")
	}
	s.release(handles[0])
	if _, e := s.create("stream.identity", 0, ""); e != nil {
		t.Fatal("slot not released", e)
	}
}

type waitingBase struct{ started chan struct{} }

func (b waitingBase) DialStream(ctx context.Context, _ string) (transport.StreamConn, error) {
	close(b.started)
	<-ctx.Done()
	return nil, ctx.Err()
}
func (b waitingBase) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	close(b.started)
	<-ctx.Done()
	return nil, ctx.Err()
}
func TestSessionCloseCancelsSetup(t *testing.T) {
	for _, packet := range []bool{false, true} {
		t.Run(fmt.Sprint(packet), func(t *testing.T) {
			_, s := testSession(t)
			b := waitingBase{make(chan struct{})}
			done := make(chan error, 1)
			if packet {
				l, e := s.NewPacketListener("packet.identity", 0, b)
				if e != nil {
					t.Fatal(e)
				}
				go func() { _, e := l.ListenPacket(context.Background()); done <- e }()
			} else {
				d, e := s.NewStreamDialer("stream.identity", 0, "", b)
				if e != nil {
					t.Fatal(e)
				}
				go func() { _, e := d.DialStream(context.Background(), "example.test:80"); done <- e }()
			}
			<-b.started
			s.Close()
			select {
			case e := <-done:
				if !errors.Is(e, context.Canceled) {
					t.Fatal(e)
				}
			case <-time.After(time.Second):
				t.Fatal("session close left setup blocked")
			}
		})
	}
}
