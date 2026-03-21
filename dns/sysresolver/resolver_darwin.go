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

//go:build darwin && cgo

// Uses the dns_sd (DNS Service Discovery) API to query the system resolver on
// Darwin (macOS/iOS). This leverages the system's DNS cache and respects
// per-network DNS configuration via mDNSResponder.
// See https://developer.apple.com/documentation/dnssd

package sysresolver

/*
#include <stdlib.h>
#include <dns_sd.h>

extern void goDNSServiceQueryRecordReply(
	DNSServiceRef sdRef, DNSServiceFlags flags, uint32_t interfaceIndex,
	DNSServiceErrorType errorCode, char* fullname, uint16_t rrtype, uint16_t rrclass,
	uint16_t rdlen, void* rdata, uint32_t ttl, void* context);
*/
import "C"

import (
	"context"
	"fmt"
	"runtime/cgo"
	"time"
	"unsafe"

	"golang.getoutline.org/sdk/dns"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
)

// callbackState is shared between the CGO callback and the Go query goroutine.
type callbackState struct {
	response dnsmessage.Message
	// done is closed when the final answer for the queried type has arrived.
	done chan struct{}
}

//export goDNSServiceQueryRecordReply
func goDNSServiceQueryRecordReply(
	sdRef C.DNSServiceRef, flags C.DNSServiceFlags, interfaceIndex C.uint32_t,
	errorCode C.DNSServiceErrorType, fullname *C.char,
	rrtype C.uint16_t, rrclass C.uint16_t,
	rdlen C.uint16_t, rdata unsafe.Pointer,
	ttl C.uint32_t, context unsafe.Pointer,
) {
	h := *(*cgo.Handle)(context)
	state := h.Value().(*callbackState)

	if errorCode != C.kDNSServiceErr_NoError {
		switch errorCode {
		case C.kDNSServiceErr_NoSuchRecord:
			// NOERROR with no answers; nothing to add.
		case C.kDNSServiceErr_NoSuchName:
			state.response.RCode = dnsmessage.RCodeNameError
		}
		// Signal done on any error that terminates the query.
		select {
		case state.done <- struct{}{}:
		default:
		}
		return
	}

	goRRType := dnsmessage.Type(rrtype)
	goRRClass := dnsmessage.Class(rrclass)
	goRData := C.GoBytes(rdata, C.int(rdlen))

	parsedName, err := dnsmessage.NewName(C.GoString(fullname))
	if err != nil {
		return
	}

	resource := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  parsedName,
			Type:  goRRType,
			Class: goRRClass,
			TTL:   uint32(ttl),
		},
		Body: resourceBodyFromRData(goRRType, goRData),
	}
	state.response.Answers = append(state.response.Answers, resource)

	// kDNSServiceFlagsMoreComing indicates that more records follow immediately.
	// Only signal done when there are no more pending records for this query.
	// We also wait until we have received at least one record of the requested type
	// (CNAME chains may arrive first with MoreComing=0 before the actual answer).
	if flags&C.kDNSServiceFlagsMoreComing == 0 {
		// Check if we have a record of the queried type (not just CNAME intermediates).
		qtype := dnsmessage.Type(state.response.Questions[0].Type)
		for _, ans := range state.response.Answers {
			if ans.Header.Type == qtype {
				select {
				case state.done <- struct{}{}:
				default:
				}
				return
			}
		}
	}
}

// NewResolver returns a [dns.Resolver] that uses the macOS/iOS dns_sd API,
// supporting arbitrary DNS record types and leveraging the system DNS cache.
func NewResolver() dns.Resolver {
	return dns.FuncResolver(func(ctx context.Context, q dnsmessage.Question) (*dnsmessage.Message, error) {
		state := &callbackState{
			done: make(chan struct{}, 1),
		}
		state.response.Header.Response = true
		state.response.Questions = []dnsmessage.Question{q}

		cQname := C.CString(q.Name.String())
		defer C.free(unsafe.Pointer(cQname))

		handle := cgo.NewHandle(state)
		defer handle.Delete()

		var sdRef C.DNSServiceRef
		// kDNSServiceFlagsReturnIntermediates: return intermediate CNAME records.
		// https://developer.apple.com/documentation/dnssd/1823436-anonymous/kdnsserviceflagsreturnintermediates
		serviceErr := C.DNSServiceQueryRecord(
			&sdRef,
			C.kDNSServiceFlagsReturnIntermediates,
			0,
			cQname,
			C.uint16_t(q.Type),
			C.uint16_t(q.Class),
			C.DNSServiceQueryRecordReply(C.goDNSServiceQueryRecordReply),
			unsafe.Pointer(&handle),
		)
		if serviceErr != C.kDNSServiceErr_NoError {
			return nil, fmt.Errorf("DNSServiceQueryRecord failed: %v", serviceErr)
		}
		defer C.DNSServiceRefDeallocate(sdRef)

		fd := C.DNSServiceRefSockFD(sdRef)
		if fd < 0 {
			return nil, fmt.Errorf("DNSServiceRefSockFD failed")
		}

		for {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-state.done:
				return &state.response, nil
			default:
			}

			pollTimeout := -1
			if deadline, ok := ctx.Deadline(); ok {
				pollTimeout = int(time.Until(deadline).Milliseconds())
			}
			nReady, err := unix.Poll(
				[]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN | unix.POLLERR | unix.POLLHUP}},
				pollTimeout,
			)
			if err != nil {
				return nil, err
			}
			if nReady == 0 {
				return nil, context.DeadlineExceeded
			}

			// Process the pending result; this invokes goDNSServiceQueryRecordReply.
			// https://developer.apple.com/documentation/dnssd/1804696-dnsserviceprocessresult
			if serviceErr = C.DNSServiceProcessResult(sdRef); serviceErr != C.kDNSServiceErr_NoError {
				return nil, fmt.Errorf("DNSServiceProcessResult failed: %v", serviceErr)
			}
		}
	})
}
