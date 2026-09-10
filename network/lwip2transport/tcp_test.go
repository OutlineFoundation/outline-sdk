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

package lwip2transport

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type testStreamConn struct {
	net.Conn
	closeCount atomic.Int32
}

func (c *testStreamConn) CloseRead() error  { return nil }
func (c *testStreamConn) CloseWrite() error { return nil }

func (c *testStreamConn) Close() error {
	c.closeCount.Add(1)
	return c.Conn.Close()
}

func TestRelayClosesStalledHalfClosedConnections(t *testing.T) {
	left, leftPeer := net.Pipe()
	leftPeer.Close()
	right, rightPeer := net.Pipe()
	defer rightPeer.Close()
	leftConn := &testStreamConn{Conn: left}
	rightConn := &testStreamConn{Conn: right}
	start := time.Now()

	relayWithHalfCloseTimeout(leftConn, rightConn, 10*time.Millisecond)

	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("relay took %v after a stalled half-close", elapsed)
	}
	if got := leftConn.closeCount.Load(); got != 1 {
		t.Errorf("left connection close count = %d, want 1", got)
	}
	if got := rightConn.closeCount.Load(); got != 1 {
		t.Errorf("right connection close count = %d, want 1", got)
	}
}
