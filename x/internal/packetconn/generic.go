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

// Package packetconn contains packet I/O adapters shared by QUIC callers.
package packetconn

import (
	"errors"
	"net"
)

// Generic keeps QUIC-Go on ReadFrom/WriteTo, so the underlying
// transport receives domain addresses unchanged. Exposing the UDP OOB methods
// would let QUIC-Go bypass WriteTo and assert that every address is a *net.UDPAddr.
// Buffer sizing is independent of that optimized path and can still be forwarded.
type Generic struct {
	net.PacketConn
}

func (c Generic) SetReadBuffer(size int) error {
	if conn, ok := c.PacketConn.(interface{ SetReadBuffer(int) error }); ok {
		return conn.SetReadBuffer(size)
	}
	return errors.ErrUnsupported
}

func (c Generic) SetWriteBuffer(size int) error {
	if conn, ok := c.PacketConn.(interface{ SetWriteBuffer(int) error }); ok {
		return conn.SetWriteBuffer(size)
	}
	return errors.ErrUnsupported
}
