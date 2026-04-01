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
)

// NewRawResolver returns a [dns.RawResolver] that uses libresolv's res_query,
// returning raw DNS wire-format bytes for any record type.
// Callers can parse the response with any DNS library.
func NewRawResolver() dns.RawResolver {
	return dns.FuncRawResolver(func(ctx context.Context, name string, qtype uint16) ([]byte, error) {
		type result struct {
			data []byte
			err  error
		}
		ch := make(chan result, 1)

		go func() {
			cQname := C.CString(name)
			defer C.free(unsafe.Pointer(cQname))

			// 4096 bytes covers the vast majority of real-world DNS responses,
			// including DNSSEC and large TXT records.
			answer := make([]byte, 4096)
			// res_query is blocking and returns -1 on error.
			// Class 1 = ClassINET (RFC 1035).
			n := C.res_query(
				cQname,
				C.int(1),
				C.int(qtype),
				(*C.uchar)(unsafe.Pointer(&answer[0])),
				C.int(len(answer)),
			)
			if n < 0 {
				ch <- result{nil, fmt.Errorf("res_query failed: %v", n)}
				return
			}
			ch <- result{answer[:n], nil}
		}()

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case res := <-ch:
			return res.data, res.err
		}
	})
}
