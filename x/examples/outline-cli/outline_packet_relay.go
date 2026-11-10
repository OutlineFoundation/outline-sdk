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
	"time"

	"golang.getoutline.org/sdk/dns"
	"golang.getoutline.org/sdk/network/dnstruncate"
	"golang.getoutline.org/sdk/network/packetrelay"
	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/x/configurl"
	"golang.getoutline.org/sdk/x/connectivity"
)

// udpWriteIdleTimeout ends a UDP association when nothing has been sent on it for this long.
const udpWriteIdleTimeout = 30 * time.Second

type outlinePacketRelay struct {
	packetrelay.DelegatePacketRelay

	remote, fallback packetrelay.PacketRelay
	remotePl         transport.PacketListener
}

func newOutlinePacketRelay(transportConfig string) (opr *outlinePacketRelay, err error) {
	opr = &outlinePacketRelay{}

	if opr.remotePl, err = configurl.New[transport.PacketListener](context.TODO(), configurl.NewDefaultRegistry(), transportConfig); err != nil {
		return nil, fmt.Errorf("failed to create UDP packet listener: %w", err)
	}
	if opr.remote, err = packetrelay.NewPacketRelayFromPacketListener(opr.remotePl, udpWriteIdleTimeout); err != nil {
		return nil, fmt.Errorf("failed to create UDP packet relay: %w", err)
	}
	if opr.fallback, err = dnstruncate.NewPacketRelay(); err != nil {
		return nil, fmt.Errorf("failed to create DNS truncate packet relay: %w", err)
	}
	if opr.DelegatePacketRelay, err = packetrelay.NewDelegatePacketRelay(opr.fallback); err != nil {
		return nil, fmt.Errorf("failed to create delegate UDP relay: %w", err)
	}

	return
}

func (relay *outlinePacketRelay) testConnectivityAndRefresh(resolverAddr, domain string) error {
	dialer := transport.PacketListenerDialer{Listener: relay.remotePl}
	dnsResolver := dns.NewUDPResolver(dialer, resolverAddr)
	result, err := connectivity.TestConnectivityWithResolver(context.Background(), dnsResolver, domain)
	if err != nil {
		logging.Info.Printf("connectivity test failed. Refresh skipped. Error: %v\n", err)
		return err
	}
	if result != nil {
		logging.Info.Println("remote server cannot handle UDP traffic, switch to DNS truncate mode.")
		relay.SetRelay(relay.fallback)
	} else {
		logging.Info.Println("remote server supports UDP, we will delegate all UDP packets to it")
		relay.SetRelay(relay.remote)
	}
	return nil
}
