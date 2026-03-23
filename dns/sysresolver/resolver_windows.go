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

//go:build windows

// Uses DnsQueryEx from dnsapi.dll to query the Windows system resolver.
//
// The query is issued asynchronously: Windows dispatches the completion
// callback on its own thread-pool thread. The calling goroutine waits on a
// Windows event object whose timeout is derived from the context deadline.
// When the context is cancelled before the reply arrives, DnsCancelQuery
// is called; the callback still fires (with a cancellation status) before
// we return, so DNS_QUERY_CANCEL and DNS_QUERY_RESULT remain valid for
// their entire required lifetimes.
//
// References:
//   - https://learn.microsoft.com/en-us/windows/win32/api/windns/nf-windns-dnsqueryex
//   - https://learn.microsoft.com/en-us/windows/win32/api/windnsdef/ns-windnsdef-dns_recordw

package sysresolver

import (
	"context"
	"fmt"
	"syscall"
	"time"
	"unsafe"

	"golang.getoutline.org/sdk/dns"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/windows"
)

var (
	modDNSAPI             = windows.MustLoadDLL("dnsapi.dll")
	procDnsQueryEx        = modDNSAPI.MustFindProc("DnsQueryEx")
	procDnsCancelQuery    = modDNSAPI.MustFindProc("DnsCancelQuery")
	procDnsRecordListFree = modDNSAPI.MustFindProc("DnsRecordListFree")
)

const (
	dnsQueryRequestVersion1 uint32 = 1
	dnsQueryResultsVersion1 uint32 = 1
	dnsQueryStandard        uint64 = 0
	dnsRequestPending              = 9506 // DNS_REQUEST_PENDING
	dnsFreeRecordList              = 1    // DnsFreeRecordList
)

// dnsQueryRequest matches DNS_QUERY_REQUEST (Version 1) from windns.h.
// Field alignment matches both 64-bit and 32-bit Windows because Go uses
// the same natural alignment rules as MSVC for these types.
// https://learn.microsoft.com/en-us/windows/win32/api/windns/ns-windns-dns_query_request
type dnsQueryRequest struct {
	version      uint32
	queryName    *uint16 // PCWSTR
	queryType    uint16  // WORD
	queryOptions uint64  // ULONG64; Go inserts the same padding as MSVC
	serverList   uintptr // PDNS_ADDR_ARRAY; 0 = system-configured servers
	ifaceIndex   uint32  // ULONG; 0 = all interfaces
	callback     uintptr // PDNS_QUERY_COMPLETION_ROUTINE
	queryContext uintptr // PVOID passed to callback
}

// dnsQueryResult matches DNS_QUERY_RESULT from windns.h.
// https://learn.microsoft.com/en-us/windows/win32/api/windns/ns-windns-dns_query_result
type dnsQueryResult struct {
	version       uint32
	queryStatus   int32   // DNS_STATUS; 0 = ERROR_SUCCESS
	queryOptions  uint64
	pQueryRecords uintptr // PDNS_RECORD linked list head; may be NULL
	reserved      uintptr
}

// dnsQueryCancel is an opaque 32-byte handle used to cancel a pending query.
// https://learn.microsoft.com/en-us/windows/win32/api/windns/ns-windns-dns_query_cancel
type dnsQueryCancel struct{ _ [32]byte }

// dnsRecord matches DNS_RECORDW from windnsdef.h.
// The variable-length Data union immediately follows this struct in memory;
// its offset is unsafe.Sizeof(*dnsRecord).
// https://learn.microsoft.com/en-us/windows/win32/api/windnsdef/ns-windnsdef-dns_recordw
type dnsRecord struct {
	pNext       *dnsRecord
	pName       *uint16 // PWSTR — record owner name (FQDN)
	wType       uint16
	wDataLength uint16
	flags       uint32
	ttl         uint32
	reserved    uint32
}

// _txtDataLayout mirrors DNS_TXT_DATAW so unsafe.Offsetof can compute the
// correct start of pStringArray on both 32-bit and 64-bit Windows.
type _txtDataLayout struct {
	count uint32
	first *uint16
}

var _txtFirstOffset = unsafe.Offsetof(_txtDataLayout{}.first)

// queryState holds the per-query resources that must remain alive until the
// completion callback returns. All fields are written once before DnsQueryEx
// is called (or in the callback), then read by the other side.
type queryState struct {
	event  windows.Handle   // manual-reset event, signalled by callback
	result dnsQueryResult   // filled by DnsQueryEx / callback
	cancel dnsQueryCancel   // opaque cancel token returned by DnsQueryEx
}

// dnsQueryCallback is the callback invoked by Windows when the query completes.
// It must be a stdcall function: (pQueryContext uintptr, pQueryResults uintptr) uintptr.
// The callback signals the event so the waiting goroutine can proceed.
var dnsQueryCallback = syscall.NewCallback(func(pQueryContext, _ uintptr) uintptr {
	state := (*queryState)(unsafe.Pointer(pQueryContext))
	windows.SetEvent(state.event)
	return 0
})

// NewRawResolver returns a [dns.RawResolver] that queries the Windows system resolver
// via DnsQueryEx, returning raw DNS wire-format bytes for any record type.
// Callers can parse the response with any DNS library.
func NewRawResolver() dns.RawResolver {
	return dns.FuncRawResolver(func(ctx context.Context, name string, qtype uint16) ([]byte, error) {
		nameUTF16, err := windows.UTF16PtrFromString(name)
		if err != nil {
			return nil, fmt.Errorf("invalid DNS name: %w", err)
		}

		state := &queryState{}
		state.event, err = windows.CreateEvent(nil, 1, 0, nil) // manual-reset, initially unset
		if err != nil {
			return nil, fmt.Errorf("CreateEvent: %w", err)
		}
		defer windows.CloseHandle(state.event)

		state.result.version = dnsQueryResultsVersion1

		req := dnsQueryRequest{
			version:      dnsQueryRequestVersion1,
			queryName:    nameUTF16,
			queryType:    qtype,
			queryOptions: dnsQueryStandard,
			callback:     dnsQueryCallback,
			queryContext: uintptr(unsafe.Pointer(state)),
		}

		// DnsQueryEx returns DNS_REQUEST_PENDING when running asynchronously,
		// or a final status when it completes inline (cache hit).
		status, _, _ := procDnsQueryEx.Call(
			uintptr(unsafe.Pointer(&req)),
			uintptr(unsafe.Pointer(&state.result)),
			uintptr(unsafe.Pointer(&state.cancel)),
		)

		if status != dnsRequestPending {
			// Completed inline: callback will NOT be called. state.result is final.
			return dnsStatusToRaw(name, qtype, int32(status), state.result.pQueryRecords)
		}

		// Query is pending: wait for the callback to signal the event.
		waitMs := uint32(windows.INFINITE)
		if deadline, ok := ctx.Deadline(); ok {
			if ms := time.Until(deadline).Milliseconds(); ms <= 0 {
				// Already expired; cancel immediately.
				procDnsCancelQuery.Call(uintptr(unsafe.Pointer(&state.cancel)))
			} else {
				waitMs = uint32(ms)
			}
		}

		waitResult, _ := windows.WaitForSingleObject(state.event, waitMs)
		if waitResult != windows.WAIT_OBJECT_0 {
			// Timeout or error: request cancellation. The callback will still
			// fire, signalling the event, so we wait once more with no timeout.
			procDnsCancelQuery.Call(uintptr(unsafe.Pointer(&state.cancel)))
			windows.WaitForSingleObject(state.event, windows.INFINITE) //nolint:errcheck

			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, context.DeadlineExceeded
		}

		return dnsStatusToRaw(name, qtype, state.result.queryStatus, state.result.pQueryRecords)
	})
}

// dnsStatusToRaw turns a final DNS_STATUS and record list into raw wire-format bytes.
func dnsStatusToRaw(name string, qtype uint16, status int32, records uintptr) ([]byte, error) {
	if records != 0 {
		defer procDnsRecordListFree.Call(records, dnsFreeRecordList)
	}
	if status != 0 {
		return nil, fmt.Errorf("DnsQueryEx: status %d", status)
	}
	q, err := dns.NewQuestion(name, dnsmessage.Type(qtype))
	if err != nil {
		return nil, fmt.Errorf("invalid DNS name: %w", err)
	}
	return dnsRecordsToMessage(*q, records).Pack()
}

// dnsRecordsToMessage walks the DNS_RECORD linked list and builds a message.
func dnsRecordsToMessage(q dnsmessage.Question, first uintptr) *dnsmessage.Message {
	msg := &dnsmessage.Message{
		Header:    dnsmessage.Header{Response: true},
		Questions: []dnsmessage.Question{q},
	}
	for rec := (*dnsRecord)(unsafe.Pointer(first)); rec != nil; rec = rec.pNext {
		if resource, ok := winRecordToResource(rec); ok {
			msg.Answers = append(msg.Answers, resource)
		}
	}
	return msg
}

// winRecordToResource converts a single DNS_RECORDW to a dnsmessage.Resource.
func winRecordToResource(rec *dnsRecord) (dnsmessage.Resource, bool) {
	name, err := winUTF16ToName(rec.pName)
	if err != nil {
		return dnsmessage.Resource{}, false
	}
	rrtype := dnsmessage.Type(rec.wType)
	// Windows-allocated memory is not moved by the Go GC, so holding the
	// data pointer as a uintptr across these calls is safe.
	dataPtr := uintptr(unsafe.Pointer(rec)) + unsafe.Sizeof(*rec)
	body := winDataToBody(rrtype, dataPtr, rec.wDataLength)
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  name,
			Type:  rrtype,
			Class: dnsmessage.ClassINET,
			TTL:   rec.ttl,
		},
		Body: body,
	}, true
}

// winDataToBody parses the Data union of a DNS_RECORDW.
// dataPtr is the address of the first byte of the union; dataLen is wDataLength.
func winDataToBody(rrtype dnsmessage.Type, dataPtr uintptr, dataLen uint16) dnsmessage.ResourceBody {
	ptrSize := unsafe.Sizeof(uintptr(0))

	switch rrtype {
	case dnsmessage.TypeA:
		// DNS_A_DATA: { IP4_ADDRESS IpAddress } — network byte order DWORD.
		return &dnsmessage.AResource{A: *(*[4]byte)(unsafe.Pointer(dataPtr))}

	case dnsmessage.TypeAAAA:
		// DNS_AAAA_DATA: { IP6_ADDRESS Ip6Address } — 16 bytes, network order.
		return &dnsmessage.AAAAResource{AAAA: *(*[16]byte)(unsafe.Pointer(dataPtr))}

	case dnsmessage.TypeCNAME:
		// DNS_PTR_DATAW: { PWSTR pNameHost }
		if name, err := winUTF16ToName(winReadPWSTR(dataPtr)); err == nil {
			return &dnsmessage.CNAMEResource{CNAME: name}
		}

	case dnsmessage.TypeNS:
		if name, err := winUTF16ToName(winReadPWSTR(dataPtr)); err == nil {
			return &dnsmessage.NSResource{NS: name}
		}

	case dnsmessage.TypePTR:
		if name, err := winUTF16ToName(winReadPWSTR(dataPtr)); err == nil {
			return &dnsmessage.PTRResource{PTR: name}
		}

	case dnsmessage.TypeMX:
		// DNS_MX_DATAW: { PWSTR pNameExchange; WORD wPreference; WORD Pad }
		if exchange, err := winUTF16ToName(winReadPWSTR(dataPtr)); err == nil {
			pref := *(*uint16)(unsafe.Pointer(dataPtr + ptrSize))
			return &dnsmessage.MXResource{Pref: pref, MX: exchange}
		}

	case dnsmessage.TypeTXT:
		// DNS_TXT_DATAW: { DWORD dwStringCount; PWSTR pStringArray[count] }
		// _txtFirstOffset accounts for padding before pStringArray (0 on 32-bit, 4 on 64-bit).
		count := *(*uint32)(unsafe.Pointer(dataPtr))
		txts := make([]string, count)
		for i := uint32(0); i < count; i++ {
			p := winReadPWSTR(dataPtr + _txtFirstOffset + uintptr(i)*ptrSize)
			txts[i] = windows.UTF16PtrToString(p)
		}
		return &dnsmessage.TXTResource{TXT: txts}

	case dnsmessage.TypeSRV:
		// DNS_SRV_DATAW: { PWSTR pNameTarget; WORD wPriority; WORD wWeight; WORD wPort; WORD Pad }
		if target, err := winUTF16ToName(winReadPWSTR(dataPtr)); err == nil {
			priority := *(*uint16)(unsafe.Pointer(dataPtr + ptrSize))
			weight := *(*uint16)(unsafe.Pointer(dataPtr + ptrSize + 2))
			port := *(*uint16)(unsafe.Pointer(dataPtr + ptrSize + 4))
			return &dnsmessage.SRVResource{Priority: priority, Weight: weight, Port: port, Target: target}
		}
	}

	// Unknown or malformed record: preserve raw bytes so callers can inspect them.
	raw := make([]byte, dataLen)
	copy(raw, unsafe.Slice((*byte)(unsafe.Pointer(dataPtr)), dataLen))
	return &dnsmessage.UnknownResource{Type: rrtype, Data: raw}
}

// winReadPWSTR reads the PWSTR (pointer to UTF-16) stored at address p.
func winReadPWSTR(p uintptr) *uint16 {
	return (*uint16)(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(p))))
}

// winUTF16ToName converts a Windows PWSTR to a dnsmessage.Name, appending a
// trailing dot if absent to make it a valid fully-qualified domain name.
func winUTF16ToName(p *uint16) (dnsmessage.Name, error) {
	if p == nil {
		return dnsmessage.MustNewName("."), nil
	}
	s := windows.UTF16PtrToString(p)
	if len(s) == 0 || s[len(s)-1] != '.' {
		s += "."
	}
	return dnsmessage.NewName(s)
}
