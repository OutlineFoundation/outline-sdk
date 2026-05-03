// Copyright 2026 The Outline Authors
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
	"time"

	"golang.getoutline.org/sdk/dns"
	"golang.getoutline.org/sdk/network/dnstruncate"
	"golang.getoutline.org/sdk/network/packetrelay"
	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/x/configurl"
	"golang.getoutline.org/sdk/x/connectivity"
)

type outlinePacketRelay struct {
	packetrelay.DelegatePacketRelay

	remote, fallback packetrelay.PacketRelay
	remotePl         transport.PacketListener
}

func newOutlinePacketRelay(transportConfig string) (opp *outlinePacketRelay, err error) {
	opp = &outlinePacketRelay{}

	if opp.remotePl, err = configurl.NewDefaultProviders().NewPacketListener(context.TODO(), transportConfig); err != nil {
		return nil, fmt.Errorf("failed to create UDP packet listener: %w", err)
	}
	
	// Create the underlying base relay
	baseRemote, err := packetrelay.NewPacketRelayFromPacketListener(opp.remotePl)
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP packet relay: %w", err)
	}
	
	// Layer the 30s timeout explicitly
	opp.remote, err = packetrelay.NewTimeoutPacketRelay(baseRemote, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to layer timeout on remote UDP relay: %w", err)
	}

	if opp.fallback, err = dnstruncate.NewPacketRelay(); err != nil {
		return nil, fmt.Errorf("failed to create DNS truncate packet relay: %w", err)
	}
	if opp.DelegatePacketRelay, err = packetrelay.NewDelegatePacketRelay(opp.fallback); err != nil {
		return nil, fmt.Errorf("failed to create delegate UDP relay: %w", err)
	}

	return
}

func (proxy *outlinePacketRelay) testConnectivityAndRefresh(resolverAddr, domain string) error {
	dialer := transport.PacketListenerDialer{Listener: proxy.remotePl}
	dnsResolver := dns.NewUDPResolver(dialer, resolverAddr)
	result, err := connectivity.TestConnectivityWithResolver(context.Background(), dnsResolver, domain)
	if err != nil {
		logging.Info.Printf("connectivity test failed. Refresh skipped. Error: %v\n", err)
		return err
	}
	if result != nil {
		logging.Info.Println("remote server cannot handle UDP traffic, switch to DNS truncate mode.")
		return proxy.SetRelay(proxy.fallback)
	} else {
		logging.Info.Println("remote server supports UDP, we will delegate all UDP packets to it")
		return proxy.SetRelay(proxy.remote)
	}
}
