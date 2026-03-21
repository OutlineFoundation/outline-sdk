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

//go:build android && cgo

// Uses android_res_nquery from the Android NDK to query the system resolver.
// This leverages the system's DNS cache and respects per-network DNS settings.
// See https://developer.android.com/ndk/reference/group/networking

package sysresolver

/*
#include <stdlib.h>
#include <android/multinetwork.h>
*/
import "C"

import (
	"context"
	"time"
	"unsafe"

	"golang.getoutline.org/sdk/dns"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
)

// NewResolver returns a [dns.Resolver] that uses the Android system resolver
// via android_res_nquery, supporting arbitrary DNS record types.
func NewResolver() dns.Resolver {
	return dns.FuncResolver(func(ctx context.Context, q dnsmessage.Question) (*dnsmessage.Message, error) {
		qname := q.Name.String()
		cQname := C.CString(qname)
		defer C.free(unsafe.Pointer(cQname))

		// android_res_nquery returns a file descriptor for the pending query.
		// https://developer.android.com/ndk/reference/group/networking#android_res_nquery
		fd := C.android_res_nquery(0, cQname, C.int(dnsmessage.ClassINET), C.int(q.Type), 0)
		if fd < 0 {
			return nil, unix.Errno(-fd)
		}
		// Close the fd on all paths. android_res_nresult reads but does not
		// close the fd, so we must always close it ourselves.
		defer unix.Close(int(fd))

		// Cap at 100ms so a cancelled context with no deadline is detected
		// promptly. The loop re-checks ctx.Done() after each Poll timeout.
		const maxPollMs = 100
		for {
			pollTimeout := maxPollMs
			if deadline, ok := ctx.Deadline(); ok {
				if ms := int(time.Until(deadline).Milliseconds()); ms < pollTimeout {
					if ms < 0 {
						ms = 0 // deadline already passed; let Poll return immediately
					}
					pollTimeout = ms
				}
			}
			// Use poll(2) constants (POLLIN/POLLERR/POLLHUP), not epoll constants.
			nReady, err := unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN | unix.POLLERR | unix.POLLHUP}}, pollTimeout)
			if err != nil {
				return nil, err
			}
			if nReady > 0 {
				break
			}
			// Poll timed out; check context before looping.
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
		}

		// 4096 bytes covers the vast majority of real-world DNS responses,
		// including DNSSEC and large TXT records.
		answer := make([]byte, 4096)
		// rcode is a required output parameter of android_res_nresult; the
		// DNS RCODE is already encoded in the wire-format message we unpack.
		var rcode C.int
		// android_res_nresult copies the DNS response into answer.
		// https://developer.android.com/ndk/reference/group/networking#android_res_nresult
		n := C.android_res_nresult(fd, &rcode, (*C.uint8_t)(&answer[0]), C.size_t(len(answer)))
		if n < 0 {
			return nil, unix.Errno(-n)
		}

		var msg dnsmessage.Message
		if err := msg.Unpack(answer[:n]); err != nil {
			return nil, err
		}
		return &msg, nil
	})
}
