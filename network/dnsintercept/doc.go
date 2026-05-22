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
Package dnsintercept provides a specialized PacketRelay that transparently intercepts
and routes UDP DNS queries to a dedicated upstream DNS relay, while forwarding all
other UDP traffic to a default relay.

The primary use case is in environments where local DNS traffic (e.g., directed at
a local stub resolver or gateway address) needs to be routed over a distinct transport
mechanism (like a proxy or a secure tunnel) to a remote DNS server, while non-DNS UDP
traffic follows a different path.

# Traffic Routing and Interception

The [InterceptDNSPacketRelay] makes routing decisions based strictly on the destination
address of outgoing packets:

 1. Intercepted DNS Traffic: If a packet is destined for the configured `dnsLocalResolver`
    address, it is treated as an intercepted DNS query. The packet's destination is
    rewritten to the configured `dnsRemoteResolver`, and it is forwarded through the
    `dnsRelay`.

 2. Default Traffic: Any packet not destined for the `dnsLocalResolver` is passed
    unmodified to the `defaultRelay`.

# Association Lifecycle and Resource Management

To handle the stateless nature of UDP DNS queries effectively, the intercept relay
employs distinct lifecycle strategies for its sub-associations:

  - Short-lived DNS Associations: For every intercepted DNS query, a brand new,
    ephemeral association is spun up on the `dnsRelay`. A background goroutine
    listens for a single corresponding response. Once the response is received and
    forwarded back to the caller (with its source address rewritten back to the
    `dnsLocalResolver`), this short-lived sub-association is immediately closed.
    This prevents port exhaustion and aligns with standard DNS proxy behaviors.

  - Lazy Default Association: For all other traffic, a single long-lived association
    is lazily created on the `defaultRelay` the first time a non-DNS packet is sent.
    All subsequent non-DNS traffic is multiplexed over this single association.

  - Auto-Termination: The parent association tracks the active sub-associations using
    an internal acquire/release reference counting mechanism. Once all activity has
    ceased—meaning the default association has been closed and all pending DNS queries
    have either completed or timed out—the parent association automatically closes
    itself, safely releasing all internal resources and goroutines.

# Important Considerations

Timeout Protection: Because DNS queries use UDP, they may silently drop. If an upstream
resolver or the network drops a DNS query, the short-lived DNS sub-association will wait
indefinitely for a response. Callers MUST ensure that the `dnsRelay` provided to the
constructor is wrapped with a mechanism (such as the `packetrelay.TimeoutPacketRelay`)
that enforces a strict deadline, forcing the underlying association to close if a
response is not received in a timely manner.
*/
package dnsintercept
