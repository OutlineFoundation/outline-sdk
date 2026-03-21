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

package connectivity

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"time"

	"golang.getoutline.org/sdk/dns"
	"golang.org/x/net/dns/dnsmessage"
)

// ConnectivityError captures the observed error of the connectivity test.
type ConnectivityError struct {
	// Which operation in the test that failed: "connect", "send" or "receive"
	Op string
	// The POSIX error, when available
	PosixError string
	// The error observed for the action
	Err error
}

var _ error = (*ConnectivityError)(nil)

func (err *ConnectivityError) Error() string {
	return fmt.Sprintf("%v: %v", err.Op, err.Err)
}

func (err *ConnectivityError) Unwrap() error {
	return err.Err
}

func isTimeout(err error) bool {
	var timeErr interface{ Timeout() bool }
	return errors.As(err, &timeErr) && timeErr.Timeout()
}

func makeConnectivityError(op string, err error) *ConnectivityError {
	// An early close on the connection may cause an "unexpected EOF" error. That's an application-layer error,
	// not triggered by a syscall error so we don't capture an error code.
	// TODO: figure out how to standardize on those errors.
	var code string
	var errno syscall.Errno
	if errors.As(err, &errno) {
		code = errnoName(errno)
	} else if isTimeout(err) {
		code = "ETIMEDOUT"
	}
	return &ConnectivityError{Op: op, PosixError: code, Err: err}
}

// TestConnectivityWithResolver tests weather we can get a response from the given [Resolver]. It can be used
// to test connectivity of its underlying [transport.StreamDialer] or [transport.PacketDialer].
// Invalid tests that cannot assert connectivity will return (nil, error).
// Valid tests will return (*ConnectivityError, nil), where *ConnectivityError will be nil if there's connectivity or
// a structure with details of the error found.
func TestConnectivityWithResolver(ctx context.Context, resolver dns.Resolver, testDomain string) (*ConnectivityError, error) {
	if _, ok := ctx.Deadline(); !ok {
		// Default deadline is 5 seconds.
		deadline := time.Now().Add(5 * time.Second)
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		// Releases the timer.
		defer cancel()
	}
	q, err := dns.NewQuestion(testDomain, dnsmessage.TypeA)
	if err != nil {
		return nil, fmt.Errorf("question creation failed: %w", err)
	}

	_, err = resolver.Query(ctx, q)

	if errors.Is(err, dns.ErrBadRequest) {
		return nil, err
	}
	if errors.Is(err, dns.ErrDial) {
		return makeConnectivityError("connect", err), nil
	} else if errors.Is(err, dns.ErrSend) {
		return makeConnectivityError("send", err), nil
	} else if errors.Is(err, dns.ErrReceive) {
		return makeConnectivityError("receive", err), nil
	}
	return nil, nil
}
