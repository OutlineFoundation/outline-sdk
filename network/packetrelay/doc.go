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

/*
Package packetrelay provides a blocking, flow-based UDP traffic routing API.

It defines the core [PacketRelay], [PacketSender], [PacketReceiver], and [PacketHandler] interfaces
which allow for clean, zero-buffering UDP traffic adapters and decorators.

### Architecture: Flow-Based Push-Pull

Unlike traditional callback-heavy UDP designs, the [PacketRelay] architecture separates
the send and receive paths explicitly, giving the caller complete control over goroutine
and concurrency lifecycles:

  - [PacketSender]: A simple, synchronous send path ([PacketSender.SendPacket]) to push packets to the relay.
  - [PacketReceiver]: A blocking receive path ([PacketReceiver.ReceivePackets]) that processes packets using the caller's own goroutine loop.

### Lifecycle & Cleanup Contract

To prevent goroutine leaks and ensure robust lifecycle synchronization without extra Go-level buffering,
the interfaces enforce a strict cleanup contract:
  - Calling `Close` on a [PacketSender] MUST cause any active blocking `ReceivePackets` call
    on the associated [PacketReceiver] to return immediately and release its network resources.

### Layered Behaviors (Decorators)

Because the API cleanly separates concerns, developers can safely wrap (decorate) any [PacketRelay]
implementation on the side to add orthogonal behaviors (e.g. timeouts). 

The included [TimeoutPacketRelay] uses a high-performance, race-free timestamp timer to manage idle
timeouts safely. To prevent Denial-of-Service (DoS) vulnerabilities, it implements unidirectional mapping
refreshes (only resetting the timeout on outgoing writes, as recommended by RFC 4787 Section 4.3).
*/
package packetrelay
