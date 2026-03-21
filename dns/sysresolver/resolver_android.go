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

//go:build android

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

		timeout := -1
		if deadline, ok := ctx.Deadline(); ok {
			timeout = int(time.Until(deadline).Milliseconds())
		}
		nReady, err := unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.EPOLLIN | unix.EPOLLERR}}, timeout)
		if err != nil {
			return nil, err
		}
		if nReady == 0 {
			return nil, context.DeadlineExceeded
		}

		answer := make([]byte, 1500)
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
