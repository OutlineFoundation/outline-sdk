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

package main

import (
	"context"
	"fmt"

	"golang.getoutline.org/sdk/dns"
	"golang.getoutline.org/sdk/network"
	"golang.getoutline.org/sdk/network/dnstruncate"
	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/x/configurl"
	"golang.getoutline.org/sdk/x/connectivity"
)

type outlinePacketProxy struct {
	network.DelegatePacketProxy

	remote, fallback network.PacketProxy
	remotePl         transport.PacketListener
}

func newOutlinePacketProxy(transportConfig string) (opp *outlinePacketProxy, err error) {
	opp = &outlinePacketProxy{}

	if opp.remotePl, err = configurl.New[transport.PacketListener](context.TODO(), configurl.NewDefaultRegistry(), transportConfig); err != nil {
		return nil, fmt.Errorf("failed to create UDP packet listener: %w", err)
	}
	if opp.remote, err = network.NewPacketProxyFromPacketListener(opp.remotePl); err != nil {
		return nil, fmt.Errorf("failed to create UDP packet proxy: %w", err)
	}
	if opp.fallback, err = dnstruncate.NewPacketProxy(); err != nil {
		return nil, fmt.Errorf("failed to create DNS truncate packet proxy: %w", err)
	}
	if opp.DelegatePacketProxy, err = network.NewDelegatePacketProxy(opp.fallback); err != nil {
		return nil, fmt.Errorf("failed to create delegate UDP proxy: %w", err)
	}

	return
}

func (proxy *outlinePacketProxy) testConnectivityAndRefresh(resolverAddr, domain string) error {
	dialer := transport.PacketListenerDialer{Listener: proxy.remotePl}
	dnsResolver := dns.NewUDPResolver(dialer, resolverAddr)
	result, err := connectivity.TestConnectivityWithResolver(context.Background(), dnsResolver, domain)
	if err != nil {
		logging.Info.Printf("connectivity test failed. Refresh skipped. Error: %v\n", err)
		return err
	}
	if result != nil {
		logging.Info.Println("remote server cannot handle UDP traffic, switch to DNS truncate mode.")
		return proxy.SetProxy(proxy.fallback)
	} else {
		logging.Info.Println("remote server supports UDP, we will delegate all UDP packets to it")
		return proxy.SetProxy(proxy.remote)
	}
}
