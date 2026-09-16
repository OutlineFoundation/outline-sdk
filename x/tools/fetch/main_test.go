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
	"bytes"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

type recordingPacketConn struct {
	packets [][]byte
	addrs   []net.Addr
}

func (c *recordingPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, errors.New("not implemented")
}

func (c *recordingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.packets = append(c.packets, bytes.Clone(p))
	c.addrs = append(c.addrs, addr)
	return len(p), nil
}

func (*recordingPacketConn) Close() error                     { return nil }
func (*recordingPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*recordingPacketConn) SetDeadline(time.Time) error      { return nil }
func (*recordingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*recordingPacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestParseQUICVersions(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    []quic.Version
		wantErr bool
	}{
		{name: "v1", value: "1", want: []quic.Version{quic.Version1}},
		{name: "v2", value: "2", want: []quic.Version{quic.Version2}},
		{name: "ordered", value: "2,1", want: []quic.Version{quic.Version2, quic.Version1}},
		{name: "spaces", value: " 2, 1 ", want: []quic.Version{quic.Version2, quic.Version1}},
		{name: "empty", value: "", wantErr: true},
		{name: "version name", value: "v1", wantErr: true},
		{name: "unknown", value: "3", wantErr: true},
		{name: "duplicate", value: "2,2", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseQUICVersions(tt.value)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseQUICVersions(%q) error = %v, wantErr %v", tt.value, err, tt.wantErr)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("parseQUICVersions(%q) = %v, want %v", tt.value, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("parseQUICVersions(%q) = %v, want %v", tt.value, got, tt.want)
				}
			}
		})
	}
}

func TestQUICPreludeConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  quicPreludeConfig
		wantErr bool
	}{
		{name: "disabled", config: quicPreludeConfig{count: 0}},
		{name: "negative count", config: quicPreludeConfig{count: -1}, wantErr: true},
		{name: "random", config: quicPreludeConfig{count: 1, mode: quicPreludeRandom, size: 1}},
		{name: "random empty", config: quicPreludeConfig{count: 1, mode: quicPreludeRandom}, wantErr: true},
		{name: "v1 shaped", config: quicPreludeConfig{count: 1, mode: quicPreludeV1Invalid, size: 1200}},
		{name: "v2 shaped", config: quicPreludeConfig{count: 1, mode: quicPreludeV2Invalid, size: 1200}},
		{name: "shaped too short", config: quicPreludeConfig{count: 1, mode: quicPreludeV2Invalid, size: 1199}, wantErr: true},
		{name: "valid v2", config: quicPreludeConfig{count: 1, mode: quicPreludeValidV2, sni: "www.google.com", attemptTimeout: time.Second}},
		{name: "valid v2 missing sni", config: quicPreludeConfig{count: 1, mode: quicPreludeValidV2, attemptTimeout: time.Second}, wantErr: true},
		{name: "valid v2 missing timeout", config: quicPreludeConfig{count: 1, mode: quicPreludeValidV2, sni: "www.google.com"}, wantErr: true},
		{name: "unknown mode", config: quicPreludeConfig{count: 1, mode: "unknown", size: 1200}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.config.validate(); (err != nil) != tt.wantErr {
				t.Fatalf("validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestQUICPreludeConfigBudget(t *testing.T) {
	tests := []struct {
		name   string
		config quicPreludeConfig
		want   time.Duration
	}{
		{name: "disabled", config: quicPreludeConfig{count: 0, mode: quicPreludeValidV2, attemptTimeout: 3 * time.Second}},
		{name: "raw modes are immediate", config: quicPreludeConfig{count: 4, mode: quicPreludeV2Invalid, size: 1200, attemptTimeout: 3 * time.Second}},
		{name: "valid v2 reserves every attempt", config: quicPreludeConfig{count: 2, mode: quicPreludeValidV2, sni: "www.google.com", attemptTimeout: 3 * time.Second}, want: 6 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.config.budget(); got != tt.want {
				t.Fatalf("budget() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestQUICShapedInvalidInitial(t *testing.T) {
	tests := []struct {
		name          string
		version       quic.Version
		initialType   byte
		versionNumber uint32
	}{
		{name: "v1", version: quic.Version1, initialType: 0x00, versionNumber: uint32(quic.Version1)},
		{name: "v2", version: quic.Version2, initialType: 0x10, versionNumber: uint32(quic.Version2)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet, err := quicShapedInvalidInitial(tt.version, 1200)
			if err != nil {
				t.Fatal(err)
			}
			if len(packet) != 1200 {
				t.Fatalf("length = %d, want 1200", len(packet))
			}
			if packet[0]&0xc0 != 0xc0 {
				t.Fatalf("first byte %#x does not set long-header and fixed bits", packet[0])
			}
			if got := packet[0] & 0x30; got != tt.initialType {
				t.Fatalf("long packet type = %#x, want %#x", got, tt.initialType)
			}
			gotVersion := uint32(packet[1])<<24 | uint32(packet[2])<<16 | uint32(packet[3])<<8 | uint32(packet[4])
			if gotVersion != tt.versionNumber {
				t.Fatalf("version = %#x, want %#x", gotVersion, tt.versionNumber)
			}
			if packet[5] != 8 || packet[14] != 8 || packet[23] != 0 {
				t.Fatalf("unexpected connection ID or token lengths: dcid=%d scid=%d token=%d", packet[5], packet[14], packet[23])
			}
			gotLength := int(packet[24]&0x3f)<<8 | int(packet[25])
			if want := len(packet) - 26; gotLength != want {
				t.Fatalf("protected length = %d, want %d", gotLength, want)
			}
		})
	}
}

func TestSendDatagramPreludes(t *testing.T) {
	destination := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443}
	conn := &recordingPacketConn{}
	config := quicPreludeConfig{count: 4, mode: quicPreludeV2Invalid, size: 1200}
	if err := sendDatagramPreludes(conn, destination, config); err != nil {
		t.Fatal(err)
	}
	if len(conn.packets) != config.count {
		t.Fatalf("sent %d datagrams, want %d", len(conn.packets), config.count)
	}
	for i, packet := range conn.packets {
		if len(packet) != config.size {
			t.Errorf("datagram %d length = %d, want %d", i+1, len(packet), config.size)
		}
		if conn.addrs[i] != destination {
			t.Errorf("datagram %d destination = %v, want %v", i+1, conn.addrs[i], destination)
		}
	}
}
