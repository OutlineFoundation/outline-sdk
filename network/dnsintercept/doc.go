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
Package dnsintercept provides a [packetrelay.PacketRelay] decorator that intercepts the UDP
DNS queries addressed to a given resolver address and answers them with a [dns.Exchanger],
forwarding all other UDP traffic to a default relay.

The typical setup is a VPN or a TUN device that advertises a resolver address to the system
(a gateway or a stub resolver address that doesn't really exist on the network), and must
answer the queries sent to it. Who answers, and how, is the caller's choice: an app tunneling
everything to a proxy forwards the queries to a remote resolver, while an app that encrypts
DNS answers them in-process over DNS-over-HTTPS. Both get the same interception machinery,
because both are just a [dns.Exchanger].

# Traffic Routing and Interception

Routing decisions are made strictly on the destination address of outgoing packets:

 1. Intercepted DNS traffic: a packet addressed to localResolver is handed to the
    [dns.Exchanger] as a wire-format DNS query. Addresses are compared with IPv4 and
    IPv4-mapped IPv6 forms treated as equal, because some network stacks surface IPv4 UDP
    destinations in mapped form.

 2. Default traffic: any other packet is passed unmodified to the default relay.

The response returned by the Exchanger is delivered to the handler of the association that
sent the query, with localResolver as the source address. The client therefore sees an answer
coming from the resolver it queried, and never learns that the query was intercepted. The
response bytes are delivered as the Exchanger returned them: matching the response to the
query is up to whoever produced the query.

# Exchange Lifecycle

Queries are dispatched to the Exchanger on their own goroutine, so sending a packet never
blocks on a resolution:

  - [packetrelay.PacketSender.SendPacket] returns as soon as the query is dispatched, and
    cannot report a failed exchange. Failures (including an empty response, which is dropped
    rather than delivered) are reported to the function installed with [WithErrorHandler], to
    be logged or counted. The default handler does nothing.

  - Each exchange gets a context that is canceled when the association closes, so closing the
    association cancels the queries still in flight.

  - Timeouts belong to the Exchanger. This package imposes none: a query with no answer ends
    when the Exchanger gives up. [NewPacketRelayExchanger] inherits the idle timeout of the
    relay it is given (see [packetrelay.NewPacketRelayFromPacketListener]), and the exchangers
    built on HTTP or TLS have timeouts of their own.

# Association Lifecycle and Resource Management

  - Lazy default association: a single association is created on the default relay the first
    time a non-DNS packet is sent, and all subsequent non-DNS traffic is multiplexed over it.
    It is never created for an association that only carries DNS.

  - Auto-termination: the parent association reference-counts its activity — the default
    sub-association and each in-flight exchange. Once all of it has ceased, the parent closes
    itself, releasing its resources and goroutines. This matters because the OS typically
    opens a fresh ephemeral UDP source port per DNS query: those associations exist only for
    as long as the query they carry.

  - Closing the parent association (with [packetrelay.PacketSender.Close]) closes the default
    sub-association and cancels the in-flight exchanges. Closing it twice, or using it after
    it is closed, returns [packetrelay.ErrClosed].

# Forwarding to a Remote Resolver

[NewPacketRelayExchanger] is the Exchanger that forwards queries to a remote resolver over
another [packetrelay.PacketRelay] — the behavior this package used to hardcode. It uses one
short-lived sub-association per query, closed as soon as the answer arrives, which keeps the
upstream association lifetime in step with the OS-side socket lifetime. That relay is usually
configured with a much shorter idle timeout (seconds) than the default relay (minutes).
*/
package dnsintercept
