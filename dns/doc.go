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

/*
Package dns provides utilities to interact with the Domain Name System (DNS).

The [Domain Name System] (DNS) is responsible for mapping domain names to IP addresses.
Because domain resolution gatekeeps connections and is predominantly done in plaintext, it is [commonly used
for network-level filtering].

# Transports

The main concept in this library is that of a [Resolver], which allows code to query the DNS. Different implementations are provided
to perform DNS resolution over different transports:

  - [DNS-over-UDP]: the standard mechanism of querying resolvers. Communication is done in plaintext, using port 53.
  - [DNS-over-TCP]: alternative to UDP that allows for more reliable delivery and larger responses, but requires establishing a connection. Communication is done in plaintext, using port 53.
  - [DNS-over-TLS] (DoT): uses the TCP protocol, but over a connection encrypted with TLS. Is uses port 853, which
    makes it very easy to block using the port number, as no other protocol is assigned to that port.
  - [DNS-over-HTTPS] (DoH): uses HTTP exchanges for querying the resolver and communicates over a connection encrypted with TLS. It uses
    port 443. That makes the DoH traffic undistinguishable from web traffic, making it harder to block.

# Establishing Stream Connections

Typically you will want to use custom DNS resolution to establish connections to a destination.
[NewStreamDialer] will create a [transport.StreamDialer] that uses the given resolver to resolve host names
and the given dialer to establish connections. The dialer efficiently performs resolutions and connection attempts
in parallel, as per the [Happy Eyeballs v2] algorithm.

[Domain Name System]: https://datatracker.ietf.org/doc/html/rfc1034
[commonly used for network-level filtering]: https://datatracker.ietf.org/doc/html/rfc9505#section-5.1.1
[DNS-over-UDP]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.2.1
[DNS-over-TCP]: https://datatracker.ietf.org/doc/html/rfc7766
[DNS-over-TLS]: https://datatracker.ietf.org/doc/html/rfc7858
[DNS-over-HTTPS]: https://datatracker.ietf.org/doc/html/rfc8484
[Happy Eyeballs v2]: https://datatracker.ietf.org/doc/html/rfc8305

# RawResolver

The [RawResolver] interface provides a lower-level primitive operating directly on wire-format byte arrays and primitive types (domain name, query type, and an output buffer). This design serves three main purposes:

 1. Zero-dependency footprint: Bypassing rigid DNS parsing libraries allows Outline to pack esoteric labels natively natively (e.g. obscure DNS tunneling headers).
 2. Future-proof compatibility: Callers can inject or parse the raw responses using any external library, including those supporting newer record types.
 3. Zero-allocation cycles: Providing a reusable `buf []byte` hands memory management to the caller, removing slice allocations in the hot path.
*/
package dns
