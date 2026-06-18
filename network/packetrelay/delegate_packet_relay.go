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

package packetrelay

import (
	"errors"
	"sync/atomic"
)

// DelegatePacketRelay is a [PacketRelay] that forwards calls (like NewAssociation) to another [PacketRelay],
// so that the caller can replace the underlying [PacketRelay] without changing the original reference.
// To create a DelegatePacketRelay with the default PacketRelay, use [NewDelegatePacketRelay]. To change
// the underlying [PacketRelay], use SetRelay.
//
// Note: After the underlying [PacketRelay] is changed, only new NewAssociation calls will be routed to the new
// [PacketRelay]. Existing associations will not be affected.
//
// Multiple goroutines can simultaneously invoke methods on a DelegatePacketRelay.
type DelegatePacketRelay interface {
	PacketRelay

	// SetRelay updates the underlying PacketRelay to `relay`; `relay` must not be nil. After this function
	// returns, all new PacketRelay calls will be forwarded to the `relay`. Existing associations will not be affected.
	SetRelay(relay PacketRelay)
}

var errNoRelay = errors.New("no relay configured")

// Compilation guard against interface implementation
var _ DelegatePacketRelay = (*delegatePacketRelay)(nil)

type delegatePacketRelay struct {
	// The underlying PacketRelay when creating NewAssociation.
	// Note that we must not use atomic.Value; otherwise TestSetRelayOfDifferentTypes will panic with
	// "store inconsistently typed value".
	relay atomic.Pointer[PacketRelay]
}

// NewDelegatePacketRelay creates a new [DelegatePacketRelay] that forwards calls to the `relay` [PacketRelay].
// The `relay` must not be nil.
func NewDelegatePacketRelay(relay PacketRelay) (DelegatePacketRelay, error) {
	dr := delegatePacketRelay{}
	dr.relay.Store(&relay)
	return &dr, nil
}

// NewAssociation implements PacketRelay.NewAssociation, and it will forward the call to the underlying PacketRelay.
// Returns an error if the underlying relay is nil.
func (p *delegatePacketRelay) NewAssociation() (PacketSender, PacketReceiver, error) {
	relayPtr := p.relay.Load()
	if relayPtr == nil || *relayPtr == nil {
		return nil, nil, errNoRelay
	}
	return (*relayPtr).NewAssociation()
}

// SetRelay implements DelegatePacketRelay.SetRelay.
func (p *delegatePacketRelay) SetRelay(relay PacketRelay) {
	p.relay.Store(&relay)
}
