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
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

type quicPreludeMode string

const (
	quicPreludeRandom     quicPreludeMode = "random"
	quicPreludeV1Invalid  quicPreludeMode = "quic-v1-invalid"
	quicPreludeV2Invalid  quicPreludeMode = "quic-v2-invalid"
	quicPreludeVerInvalid quicPreludeMode = "quic-version-invalid"
	quicPreludeValidV2    quicPreludeMode = "valid-v2"
	// minimumQUICPreludeLength is the smallest datagram RFC 9000 allows a client
	// to carry an Initial packet in.
	minimumQUICPreludeLength = 1200
	// defaultQUICPreludeLength matches the datagram size QUIC-Go uses for its own
	// Initials, so a prelude is not distinguishable from the measured connection
	// by datagram size alone.
	defaultQUICPreludeLength = 1280
)

type quicPreludeConfig struct {
	count int
	mode  quicPreludeMode
	size  int
	sni   string
	// version is the wire codepoint used by the quic-version-invalid mode. It may
	// be any 32-bit value, including versions no implementation supports, which
	// lets a measurement distinguish recognition of a specific version from
	// recognition of the version-invariant long-header structure.
	version uint32
	// attemptTimeout bounds each valid-v2 handshake attempt. It is unused by the
	// raw datagram modes, which return as soon as the datagrams are written.
	attemptTimeout time.Duration
}

// budget reports how long the preludes may take. The preludes run inside the
// HTTP/3 dial, so the caller must add this to the request timeout; otherwise the
// preludes consume the budget meant for the measured connection and the request
// fails before a genuine Initial is ever sent.
func (c quicPreludeConfig) budget() time.Duration {
	if c.count <= 0 || c.mode != quicPreludeValidV2 {
		return 0
	}
	return time.Duration(c.count) * c.attemptTimeout
}

func (c quicPreludeConfig) validate() error {
	if c.count < 0 {
		return fmt.Errorf("prelude count must not be negative")
	}
	if c.count == 0 {
		return nil
	}
	switch c.mode {
	case quicPreludeRandom:
		if c.size <= 0 {
			return fmt.Errorf("random prelude size must be positive")
		}
	case quicPreludeV1Invalid, quicPreludeV2Invalid, quicPreludeVerInvalid:
		if c.size < minimumQUICPreludeLength {
			return fmt.Errorf("QUIC-shaped prelude size must be at least %d bytes", minimumQUICPreludeLength)
		}
		if c.mode == quicPreludeVerInvalid && c.version == 0 {
			return fmt.Errorf("quic-version-invalid prelude requires a non-zero version (0 means Version Negotiation)")
		}
	case quicPreludeValidV2:
		if c.sni == "" {
			return fmt.Errorf("valid-v2 prelude requires a non-empty SNI")
		}
		if c.attemptTimeout <= 0 {
			return fmt.Errorf("valid-v2 prelude attempt timeout must be positive")
		}
	default:
		return fmt.Errorf("unknown QUIC prelude mode %q", c.mode)
	}
	return nil
}

func randomDatagram(size int) ([]byte, error) {
	p := make([]byte, size)
	if _, err := rand.Read(p); err != nil {
		return nil, fmt.Errorf("generate random prelude: %w", err)
	}
	return p, nil
}

// quicShapedInvalidInitial returns a syntactically Initial-shaped datagram with
// random protected bytes and an intentionally invalid authentication tag. It is
// useful for distinguishing recognition of the invariant/long-header structure
// from successful Initial decryption. It is not a valid QUIC packet.
func quicShapedInvalidInitial(version quic.Version, size int) ([]byte, error) {
	// Known versions carry their own Initial type encoding; anything else is
	// treated as an unknown version, where RFC 8999 defines only the header form
	// and the version field, so the remaining bits are left as the v1 layout.
	typeBits := byte(0xc0)
	switch version {
	case quic.Version1:
		typeBits = 0xc0
	case quic.Version2:
		typeBits = 0xd0
	}
	return quicShapedInvalidInitialWithBits(uint32(version), typeBits, size)
}

func quicShapedInvalidInitialWithBits(version uint32, typeBits byte, size int) ([]byte, error) {
	if size < minimumQUICPreludeLength {
		return nil, fmt.Errorf("QUIC-shaped prelude size must be at least %d bytes", minimumQUICPreludeLength)
	}
	p, err := randomDatagram(size)
	if err != nil {
		return nil, err
	}

	// Header Form and Fixed Bit are set. QUIC v1 encodes Initial as type 0b00;
	// QUIC v2 encodes Initial as type 0b01. The protected low nibble and packet
	// number bytes remain random, mimicking header protection without producing a
	// valid AEAD tag.
	p[0] = typeBits | (p[0] & 0x0f)
	binary.BigEndian.PutUint32(p[1:5], version)

	const connectionIDLength = 8
	p[5] = connectionIDLength
	// p[6:14] is the random Destination Connection ID.
	p[14] = connectionIDLength
	// p[15:23] is the random Source Connection ID.
	p[23] = 0 // zero-length token

	// Use a two-byte QUIC varint for the protected payload length.
	protectedLength := size - 26
	if protectedLength <= 0 || protectedLength >= 1<<14 {
		return nil, fmt.Errorf("unsupported QUIC-shaped prelude size %d", size)
	}
	binary.BigEndian.PutUint16(p[24:26], uint16(protectedLength)|(1<<14))
	return p, nil
}

func sendDatagramPreludes(conn net.PacketConn, addr net.Addr, config quicPreludeConfig) error {
	for i := 0; i < config.count; i++ {
		var (
			payload []byte
			err     error
		)
		switch config.mode {
		case quicPreludeRandom:
			payload, err = randomDatagram(config.size)
		case quicPreludeV1Invalid:
			payload, err = quicShapedInvalidInitial(quic.Version1, config.size)
		case quicPreludeV2Invalid:
			payload, err = quicShapedInvalidInitial(quic.Version2, config.size)
		case quicPreludeVerInvalid:
			payload, err = quicShapedInvalidInitialWithBits(config.version, 0xc0, config.size)
		default:
			return fmt.Errorf("prelude mode %q does not produce raw datagrams", config.mode)
		}
		if err != nil {
			return err
		}
		if _, err := conn.WriteTo(payload, addr); err != nil {
			return fmt.Errorf("send prelude datagram %d: %w", i+1, err)
		}
	}
	return nil
}
