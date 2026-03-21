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

//go:build cgo && !android && !darwin && (linux || freebsd || openbsd || netbsd || dragonfly || solaris)

// Uses libresolv to query the system resolver. libresolv returns a full DNS
// wire-format response, so all record types are accessible.
//
// Limitations:
//   - The underlying res_query call is blocking. Context cancellation is
//     detected after the call returns, not during it.
//   - May not leverage the system DNS cache on all distributions.

package sysresolver

/*
#cgo LDFLAGS: -lresolv
#include <stdlib.h>
#include <resolv.h>
*/
import "C"

import (
	"context"
	"fmt"
	"unsafe"

	"golang.getoutline.org/sdk/dns"
	"golang.org/x/net/dns/dnsmessage"
)

// NewResolver returns a [dns.Resolver] that uses libresolv's res_query,
// supporting arbitrary DNS record types.
func NewResolver() dns.Resolver {
	return dns.FuncResolver(func(ctx context.Context, q dnsmessage.Question) (*dnsmessage.Message, error) {
		type result struct {
			msg *dnsmessage.Message
			err error
		}
		ch := make(chan result, 1)

		go func() {
			qname := q.Name.String()
			cQname := C.CString(qname)
			defer C.free(unsafe.Pointer(cQname))

			// 4096 bytes covers the vast majority of real-world DNS responses,
			// including DNSSEC and large TXT records.
			answer := make([]byte, 4096)
			// res_query is blocking and returns -1 on error.
			n := C.res_query(
				cQname,
				C.int(q.Class),
				C.int(q.Type),
				(*C.uchar)(unsafe.Pointer(&answer[0])),
				C.int(len(answer)),
			)
			if n < 0 {
				ch <- result{nil, fmt.Errorf("res_query failed: %v", n)}
				return
			}
			var msg dnsmessage.Message
			if err := msg.Unpack(answer[:n]); err != nil {
				ch <- result{nil, err}
				return
			}
			ch <- result{&msg, nil}
		}()

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case res := <-ch:
			return res.msg, res.err
		}
	})
}
