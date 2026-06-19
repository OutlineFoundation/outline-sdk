// Copyright 2024 The Outline Authors
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

package wait_stream

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

type waitStreamWriter struct {
	conn *net.TCPConn

	waitingTimeout time.Duration
	waitingDelay   time.Duration
}

var _ io.Writer = (*waitStreamWriter)(nil)

func NewWriter(conn *net.TCPConn, waitingTimeout time.Duration, waitingDelay time.Duration) io.Writer {
	return &waitStreamWriter{
		conn:           conn,
		waitingTimeout: waitingTimeout,
		waitingDelay:   waitingDelay,
	}
}

func isConnectionSendingBytes(conn *net.TCPConn) (result bool, err error) {
	syscallConn, err := conn.SyscallConn()
	if err != nil {
		return false, err
	}
	syscallConn.Control(func(fd uintptr) {
		result, err = isSocketFdSendingBytes(int(fd))
	})
	return
}

func waitUntilBytesAreSent(conn *net.TCPConn, waitingTimeout time.Duration, waitingDelay time.Duration) error {
	startTime := time.Now()
	for time.Since(startTime) < waitingTimeout {
		isSendingBytes, err := isConnectionSendingBytes(conn)
		if err != nil {
			return err
		}
		if !isSendingBytes {
			return nil
		}

		time.Sleep(waitingDelay)
	}
	// not sure about the right behaviour here: fail or give up waiting?
	// giving up feels safer, and matches byeDPI behavior
	return nil
}

func (w *waitStreamWriter) Write(data []byte) (written int, err error) {
	// This may not be implemented, so it's best effort really.
	waitUntilBytesAreSentErr := waitUntilBytesAreSent(w.conn, w.waitingTimeout, w.waitingDelay)
	if waitUntilBytesAreSentErr != nil && !errors.Is(waitUntilBytesAreSentErr, errors.ErrUnsupported) {
		return 0, fmt.Errorf("error when waiting for stream to send all bytes: %w", waitUntilBytesAreSentErr)
	}

	return w.conn.Write(data)
}
