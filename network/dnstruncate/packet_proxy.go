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

package dnstruncate

import (
	"golang.getoutline.org/sdk/network"
)

// NewPacketProxy creates a new [network.PacketProxy] that can be used to handle DNS requests if the remote proxy
// doesn't support UDP traffic. It sets the TC (truncated) bit in the DNS response header to tell the caller to resend
// the DNS request over TCP.
//
// Deprecated: Use [NewPacketRelay] instead.
func NewPacketProxy() (network.PacketProxy, error) {
	relay, err := NewPacketRelay()
	if err != nil {
		return nil, err
	}
	return network.NewPacketProxyFromPacketRelay(relay), nil
}
