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

package lwip2transport

import (
	"context"
	"io"
	"net"

	"golang.getoutline.org/sdk/transport"
	lwip "github.com/OutlineFoundation/go-tun2socks/core"
)

// Compilation guard against interface implementation
var _ lwip.TCPConnHandler = (*tcpHandler)(nil)

type tcpHandler struct {
	dialer transport.StreamDialer
}

// newTCPHandler returns a Shadowsocks lwIP connection handler.
func newTCPHandler(client transport.StreamDialer) *tcpHandler {
	return &tcpHandler{client}
}

func (h *tcpHandler) Handle(conn net.Conn, target *net.TCPAddr) error {
	proxyConn, err := h.dialer.DialStream(context.Background(), target.String())
	if err != nil {
		return err
	}
	// TODO: Request upstream to make `conn` a `core.TCPConn` so we can avoid this type assertion.
	go relay(conn.(lwip.TCPConn), proxyConn)
	return nil
}

// copyOneWay copies from rightConn to leftConn until either EOF is reached on rightConn or an error occurs.
//
// If rightConn implements io.WriterTo, or if leftConn implements io.ReaderFrom, copyOneWay will leverage these
// interfaces to do the copy as a performance improvement method.
//
// rightConn's read end and leftConn's write end will be closed after copyOneWay returns.
func copyOneWay(leftConn, rightConn transport.StreamConn) (int64, error) {
	n, err := io.Copy(leftConn, rightConn)
	// Send FIN to indicate EOF
	leftConn.CloseWrite()
	// Release reader resources
	rightConn.CloseRead()
	return n, err
}

// relay copies between left and right bidirectionally. Returns number of
// bytes copied from right to left, from left to right, and any error occurred.
// Relay allows for half-closed connections: if one side is done writing, it can
// still read all remaining data from its peer.
func relay(leftConn, rightConn transport.StreamConn) (int64, int64, error) {
	type res struct {
		N   int64
		Err error
	}
	ch := make(chan res)

	go func() {
		n, err := copyOneWay(rightConn, leftConn)
		ch <- res{n, err}
	}()

	n, err := copyOneWay(leftConn, rightConn)
	rs := <-ch

	if err == nil {
		err = rs.Err
	}
	return n, rs.N, err
}
