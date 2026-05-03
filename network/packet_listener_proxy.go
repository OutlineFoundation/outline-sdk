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

package network

import (
	"errors"
	"time"

	"golang.getoutline.org/sdk/network/packetrelay"
	"golang.getoutline.org/sdk/transport"
)

// Compilation guard against interface implementation
var _ PacketProxy = (*PacketListenerProxy)(nil)

// PacketListenerProxy creates a new [PacketProxy] that uses the existing [transport.PacketListener] to
// create connections to a proxy.
//
// Deprecated: Use [packetrelay.PacketListenerRelay] instead.
type PacketListenerProxy struct {
	relay            packetrelay.PacketRelay
	baseRelay        *packetrelay.PacketListenerRelay
	writeIdleTimeout time.Duration
}

// NewPacketProxyFromPacketListener creates a new [PacketProxy] that uses the existing [transport.PacketListener] to
// create connections to a proxy. You can also specify additional options.
//
// Deprecated: Use [packetrelay.NewPacketRelayFromPacketListener] instead.
func NewPacketProxyFromPacketListener(pl transport.PacketListener, options ...func(*PacketListenerProxy) error) (*PacketListenerProxy, error) {
	// Create the underlying base relay
	baseRelay, err := packetrelay.NewPacketRelayFromPacketListener(pl)
	if err != nil {
		return nil, err
	}

	p := &PacketListenerProxy{
		baseRelay:        baseRelay,
		writeIdleTimeout: 30 * time.Second, // Default timeout
	}

	// Apply options
	for _, opt := range options {
		if err := opt(p); err != nil {
			return nil, err
		}
	}

	// Build the final relay chain: TimeoutPacketRelay(PacketListenerRelay)
	timeoutRelay, err := packetrelay.NewTimeoutPacketRelay(p.baseRelay, p.writeIdleTimeout)
	if err != nil {
		return nil, err
	}
	p.relay = timeoutRelay

	return p, nil
}

// WithPacketListenerWriteIdleTimeout sets the write idle timeout of the [PacketListenerProxy].
// This means that if there are no WriteTo operations on the UDP session created by NewSession for the specified amount
// of time, the proxy will end this session.
//
// Deprecated: Use [packetrelay.NewTimeoutPacketRelay] to decorate the underlying [packetrelay.PacketRelay] instead.
func WithPacketListenerWriteIdleTimeout(timeout time.Duration) func(*PacketListenerProxy) error {
	return func(p *PacketListenerProxy) error {
		if timeout <= 0 {
			return errors.New("timeout must be greater than 0")
		}
		p.writeIdleTimeout = timeout
		return nil
	}
}

// NewSession implements [PacketProxy].NewSession. It uses the adapter pattern to wrap the underlying relay.
func (p *PacketListenerProxy) NewSession(respReceiver PacketResponseReceiver) (PacketRequestSender, error) {
	adapter := NewPacketProxyFromPacketRelay(p.relay)
	return adapter.NewSession(respReceiver)
}
