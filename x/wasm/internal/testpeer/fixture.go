// Copyright 2026 The Outline Authors. SPDX-License-Identifier: Apache-2.0
// Package testpeer contains loopback-only test peers. The XOR protocol is not
// encryption and these relays must never be used as production proxies.
package testpeer

import (
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/http3"
)

const Body = "Outline Wasm fetch spike\n"

func Payload() string { return strings.Repeat(Body, 9000) }

type Fixture struct {
	Origin                                       *httptest.Server
	HTTP3URL, StreamRelay, TLSRelay, PacketRelay string
	Certificate                                  []byte
	StreamVersion, PacketVersion                 atomic.Uint32
	mu                                           sync.Mutex
	closed                                       bool
	closers                                      []io.Closer
	workers                                      sync.WaitGroup
	h3                                           *http3.Server
}

func Start() (*Fixture, error) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, Payload())
	})
	origin := httptest.NewUnstartedServer(handler)
	origin.EnableHTTP2 = true
	origin.StartTLS()
	f := &Fixture{Origin: origin, Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.Certificate().Raw})}
	fail := func(e error) (*Fixture, error) { f.Close(); return nil, e }
	packet, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		return fail(e)
	}
	f.own(packet)
	f.h3 = &http3.Server{Handler: handler, TLSConfig: origin.TLS.Clone()}
	f.HTTP3URL = "https://" + packet.LocalAddr().String()
	f.work(func() { _ = f.h3.Serve(packet) })
	target := origin.Listener.Addr().String()
	for _, encrypted := range []bool{false, true} {
		ln, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			return fail(e)
		}
		if encrypted {
			ln = tls.NewListener(ln, &tls.Config{Certificates: origin.TLS.Certificates})
			f.TLSRelay = ln.Addr().String()
		} else {
			f.StreamRelay = ln.Addr().String()
		}
		f.own(ln)
		f.work(func() {
			for {
				c, e := ln.Accept()
				if e != nil {
					return
				}
				if !f.own(c) {
					return
				}
				f.work(func() { defer c.Close(); f.stream(c, target) })
			}
		})
	}
	relay, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		return fail(e)
	}
	f.own(relay)
	f.PacketRelay = relay.LocalAddr().String()
	f.work(func() { f.packets(relay, packet.LocalAddr().(*net.UDPAddr)) })
	return f, nil
}
func (f *Fixture) own(c io.Closer) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		c.Close()
		return false
	}
	f.closers = append(f.closers, c)
	return true
}
func (f *Fixture) work(fn func()) {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	f.workers.Add(1)
	f.mu.Unlock()
	go func() { defer f.workers.Done(); fn() }()
}
func (f *Fixture) Close() {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	f.closed = true
	cs := append([]io.Closer(nil), f.closers...)
	f.mu.Unlock()
	for _, c := range cs {
		c.Close()
	}
	if f.h3 != nil {
		f.h3.Close()
	}
	f.Origin.Close()
	f.workers.Wait()
}

type xorReader struct {
	io.Reader
	key byte
}

func (r xorReader) Read(p []byte) (int, error) {
	n, e := r.Reader.Read(p)
	for i := 0; i < n; i++ {
		p[i] ^= r.key
	}
	return n, e
}
func (f *Fixture) stream(c net.Conn, target string) {
	c.SetDeadline(time.Now().Add(5 * time.Second))
	var h [4]byte
	if _, e := io.ReadFull(c, h[:]); e != nil || h[0] != 'O' || h[1] != 'W' || (h[2] != 1 && h[2] != 2) {
		return
	}
	f.StreamVersion.Store(uint32(h[2]))
	up, e := net.DialTimeout("tcp", target, time.Second)
	if e != nil {
		return
	}
	if !f.own(up) {
		return
	}
	defer up.Close()
	ack := h
	ack[1] = 'K'
	if _, e = c.Write(ack[:]); e != nil {
		return
	}
	c.SetDeadline(time.Time{})
	done := make(chan struct{})
	key := h[3] ^ (h[2] - 1)
	go func() {
		defer close(done)
		io.Copy(up, xorReader{c, key})
		if cw, ok := up.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	}()
	io.Copy(c, xorReader{up, key})
	c.Close()
	up.Close()
	<-done
}

type udpPeer struct {
	conn   *net.UDPConn
	header [4]byte
}

func (f *Fixture) packets(relay *net.UDPConn, target *net.UDPAddr) {
	peers := make(map[string]*udpPeer)
	buf := make([]byte, 65536)
	for {
		n, addr, e := relay.ReadFromUDP(buf)
		if e != nil {
			return
		}
		if n < 4 || buf[0] != 'W' || buf[1] != 'P' || (buf[2] != 1 && buf[2] != 2) {
			continue
		}
		h := [4]byte{buf[0], buf[1], buf[2], buf[3]}
		f.PacketVersion.Store(uint32(h[2]))
		key := addr.String()
		p := peers[key]
		if p == nil {
			if len(peers) >= 64 {
				continue
			}
			up, e := net.DialUDP("udp", nil, target)
			if e != nil {
				continue
			}
			if !f.own(up) {
				return
			}
			p = &udpPeer{up, h}
			peers[key] = p
			f.work(func() {
				wire := make([]byte, 65536)
				for {
					n, e := up.Read(wire[4:])
					if e != nil {
						return
					}
					copy(wire, h[:])
					for i := 4; i < n+4; i++ {
						wire[i] ^= h[3] ^ (h[2] - 1)
					}
					if _, e = relay.WriteToUDP(wire[:n+4], addr); e != nil {
						return
					}
				}
			})
		}
		if p.header != h {
			continue
		}
		for i := 4; i < n; i++ {
			buf[i] ^= h[3] ^ (h[2] - 1)
		}
		p.conn.Write(buf[4:n])
	}
}
