// Copyright 2024 Jigsaw Operations LLC
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

package main

/*
#include <stdint.h>  // uintptr_t

typedef uintptr_t StreamDialer;
typedef uintptr_t Proxy;
*/
import "C"

import (
	"runtime/cgo"

	"github.com/Jigsaw-Code/outline-sdk/x/mobileproxy"
)

const nullptr = C.uintptr_t(0)

func marshalStreamDialer(dialer *mobileproxy.StreamDialer) C.StreamDialer {
	return C.StreamDialer(cgo.NewHandle(dialer))
}

func unmarshalStreamDialer(dialerHandle C.StreamDialer) *mobileproxy.StreamDialer {
	return cgo.Handle(dialerHandle).Value().(*mobileproxy.StreamDialer)
}

//export NewStreamDialerFromConfig
func NewStreamDialerFromConfig(config *C.char) C.StreamDialer {
	sd, err := mobileproxy.NewStreamDialerFromConfig(C.GoString(config))

	if err != nil {
		// TODO: return error
		return nullptr
	}

	return marshalStreamDialer(sd)
}

//export ReleaseStreamDialer
func ReleaseStreamDialer(dialerHandle C.StreamDialer) {
	cgo.Handle(dialerHandle).Delete()
}

func marshalProxy(proxy *mobileproxy.Proxy) C.Proxy {
	return C.Proxy(cgo.NewHandle(proxy))
}

func unmarshalProxy(proxyHandle C.Proxy) *mobileproxy.Proxy {
	return cgo.Handle(proxyHandle).Value().(*mobileproxy.Proxy)
}

//export RunProxy
func RunProxy(address *C.char, dialerHandle C.StreamDialer) C.Proxy {
	dialer := unmarshalStreamDialer(dialerHandle)

	proxy, err := mobileproxy.RunProxy(C.GoString(address), dialer)

	if err != nil {
		// TODO: return error
		return nullptr
	}

	return marshalProxy(proxy)
}

//export AddURLProxy
func AddURLProxy(proxyHandle C.Proxy, url *C.char, dialerHandle C.StreamDialer) {
	proxy := unmarshalProxy(proxyHandle)
	dialer := unmarshalStreamDialer(dialerHandle)

	proxy.AddURLProxy(C.GoString(url), dialer)
}

//export StopProxy
func StopProxy(proxyHandle C.Proxy, timeoutSeconds C.uint) {
	proxy := unmarshalProxy(proxyHandle)
	proxy.Stop(int(timeoutSeconds))
}

//export ReleaseProxy
func ReleaseProxy(proxyHandle C.Proxy) {
	cgo.Handle(proxyHandle).Delete()
}

func main() {
	// We need the main function to make possible
	// CGO compiler to compile the package as C shared library
}
