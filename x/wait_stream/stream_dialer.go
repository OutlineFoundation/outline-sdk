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
	"context"
	"errors"
	"net"
	"time"

	"github.com/Jigsaw-Code/outline-sdk/transport"
)

type WaitStreamDialer struct {
	dialer transport.StreamDialer

	// Stop waiting on a packet after this timeout
	waitingTimeout time.Duration
	// Check if socket is sending bytes that often
	waitingDelay time.Duration
}

var _ transport.StreamDialer = (*WaitStreamDialer)(nil)

// byeDPI uses a default delay of 500ms with 1ms sleep
// We might reconsider the defaults later, if needed.
// https://github.com/hufrea/byedpi/blob/main/desync.c#L90
var defaultTimeout = time.Millisecond * 10
var defaultDelay = time.Microsecond * 1

func NewStreamDialer(dialer transport.StreamDialer) (*WaitStreamDialer, error) {
	if dialer == nil {
		return nil, errors.New("argument dialer must not be nil")
	}
	return &WaitStreamDialer{
		dialer:         dialer,
		waitingTimeout: defaultTimeout,
		waitingDelay:   defaultDelay,
	}, nil
}

func (d *WaitStreamDialer) SetWaitingTimeout(timeout time.Duration) {
	d.waitingTimeout = timeout
}

func (d *WaitStreamDialer) SetWaitingDelay(timeout time.Duration) {
	d.waitingDelay = timeout
}

func (d *WaitStreamDialer) DialStream(ctx context.Context, remoteAddr string) (transport.StreamConn, error) {
	innerConn, err := d.dialer.DialStream(ctx, remoteAddr)
	if err != nil {
		return nil, err
	}

	tcpInnerConn, ok := innerConn.(*net.TCPConn)
	if !ok {
		return nil, errors.New("wait_stream strategy: expected base dialer to return TCPConn")
	}

	dw := NewWriter(tcpInnerConn, d.waitingTimeout, d.waitingDelay)

	return transport.WrapConn(innerConn, innerConn, dw), nil
}
