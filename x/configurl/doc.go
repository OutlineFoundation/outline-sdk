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
Package configurl constructs [transport.StreamDialer], [transport.PacketDialer],
and [transport.PacketListener] components from composable config URL strings.

Create a [MutableRegistry] with [NewDefaultRegistry] to use the SDK's built-in
components, then call [New] with the type of component to construct:

	registry := configurl.NewDefaultRegistry()
	dialer, err := configurl.New[transport.StreamDialer](ctx, registry, "tlsfrag:1|split:2")

[Register] adds custom component types to a MutableRegistry. Pass the read-only
[Registry] interface to code that only needs to construct components. For a parsed
[Config], use [NewFromConfig]. The section on defining custom strategies shows how
to publish reusable component registration helpers.

# Configuration Format

The configuration string is a pipe-separated (|) sequence of transport definitions. The order of transports indicates nesting, where the output of the first transport is used as the input to the next.

Example: A|B|C

In this example:

 1. Transport A is the base transport.
 2. Transport B wraps transport A.
 3. Transport C wraps transport B.

An empty string ("") represents the default TCP/UDP dialer.

Each transport definition follows a URL-like format, where the scheme identifies the transport type, and the opaque part (after the scheme) contains options specific to the transport.

The following sections list transport types are currently supported, along with their configuration options.

# Proxy Protocols

Shadowsocks proxy (compatible with Outline's access keys, package [golang.getoutline.org/sdk/transport/shadowsocks])

	ss://[USERINFO]@[HOST]:[PORT]?prefix=[PREFIX]

SOCKS5 proxy (works with both stream and packet dialers, package [golang.getoutline.org/sdk/transport/socks5])

	socks5://[USERINFO]@[HOST]:[PORT]

USERINFO field is optional and only required if username and password authentication is used. It is in the format of username:password.

HTTP CONNECT proxy (streams only, package [golang.getoutline.org/sdk/x/httpconnect])

Three variants are available:

  - httpconnect: HTTP/1.1, or HTTP/2 if negotiated via TLS ALPN. When H2 is negotiated, CONNECT streams are multiplexed over a single TCP connection.
  - h2connect: Pure HTTP/2. Always multiplexed. Supports h2c (cleartext H2) via plain=true.
  - h3connect: HTTP/3 over QUIC. Always multiplexed. QUIC runs over the packet listener from the element on its left, which defaults to a new UDP socket.

The sni parameter sets the TLS SNI. The certname parameter sets the name to validate against the server certificate.
For h2connect, plain=true enables h2c (cleartext HTTP/2 without TLS).

Proxy authentication is supported in two ways:

  - URL userinfo (user:password@host) generates a Proxy-Authorization: Basic header.

  - For other schemes such as Bearer the auth parameter sets the Proxy-Authorization header value directly.

The config formats are:

	httpconnect://[USER:PASS@][HOST]:[PORT][?sni=SNI][&certname=CERTNAME][&auth=TOKEN]
	h2connect://[USER:PASS@][HOST]:[PORT][?sni=SNI][&certname=CERTNAME][&auth=TOKEN][&plain=true]
	h3connect://[USER:PASS@][HOST]:[PORT][?sni=SNI][&certname=CERTNAME][&auth=TOKEN]

# Transports

TLS transport (currently streams only, package [golang.getoutline.org/sdk/transport/tls])

The sni parameter defines the name to be sent in the TLS SNI. It can be empty.
The certname parameter defines what name to validate against the server certificate.

	tls:sni=[SNI]&certname=[CERT_NAME]

WebSockets

	ws:tcp_path=[PATH]&udp_path=[PATH]

# DNS Protection

DNS resolution (streams only, package [golang.getoutline.org/sdk/dns])

It takes a host:port address. If the port is missing, it will use 53. The resulting dialer will use the input dialer with
Happy Eyeballs to connect to the destination.

	do53:address=[ADDRESS]

DNS-over-HTTPS resolution (streams only, package [golang.getoutline.org/sdk/dns])

It takes a host name and a host:port address. The name will be used in the SNI and Host header, while the address is used to connect
to the DoH server. The address is optional, and will default to "[NAME]:443". The resulting dialer will use the input dialer with
Happy Eyeballs to connect to the destination.

	doh:name=[NAME]&address=[ADDRESS]

Address override.

This dialer configuration is helpful for testing and development or if you need to fix the domain
resolution.
The host parameter, if not empty, specifies the host to dial instead of the original host.
The port parameter, if not empty, specifies the port to dial instead of the original port.

	override:host=[HOST]&port=[PORT]

# Packet manipulation

These strategies manipulate packets to bypass SNI-based blocking.

Stream split transport (streams only, package [golang.getoutline.org/sdk/transport/split])

It takes a list of count*length pairs meaning splitting the sequence in count segments of the given length. If you omit "[COUNT]*", it's assumed to be 1.

	split:[COUNT1]*[LENGTH1],[COUNT2]*[LENGTH2],...

TLS fragmentation (streams only, package [golang.getoutline.org/sdk/transport/tlsfrag]).

The Client Hello record payload will be split into two fragments of size LENGTH and len(payload)-LENGTH if LENGTH>0.
If LENGTH<0, the two fragments will be of size len(payload)-LENGTH and LENGTH respectively.
For more details, refer to [golang.getoutline.org/sdk/transport/tlsfrag].

	tlsfrag:[LENGTH]

QUIC prelude (packet listeners only, package [golang.getoutline.org/sdk/x/quicprelude])

Sends datagrams ahead of every packet that may carry a QUIC ClientHello, on the
same socket and therefore the same four-tuple. Other traffic passes unchanged. A
middlebox that reads the TLS Server Name Indication from the first QUIC Initial
it can parse on a flow, and caches that verdict for the flow, finds no name in
an Initial it cannot decrypt.

	quicprelude:count=[COUNT]&mode=[MODE]&length=[LENGTH]&version=[VERSION]

Every option may be omitted, and the defaults are the ones to reach for first:
one Initial-shaped datagram carrying a reserved version codepoint, sized to
match the packet it precedes.

	count    number of datagrams, at most 16; 0 disables the prelude (default 1)
	mode     invalid-initial or random (default invalid-initial)
	length   match, or a byte count (default match)
	version  reserved, draft, v1, v2, or a 32-bit hex codepoint (default reserved)

length=match sizes each datagram like the packet it precedes, so the prelude is
not separable from it by size. Only datagrams of at least 1200 bytes, the
smallest RFC 9000 allows a client to send an Initial in, get a prelude, so a
matched prelude is always a valid Initial size.

version names a range to draw a fresh codepoint from for every datagram, so no
single constant identifies the prelude. reserved uses 0x?a?a?a?a, which RFC 9000
sets aside for forcing version negotiation; draft uses the IETF draft range
above the draft numbers that were ever assigned.

The range matters: measurements found that a codepoint no implementation would
recognize is ignored rather than acted on, which defeats the technique. An
assigned draft such as draft-29 is worse still, being dropped outright on the
Iranian paths measured, which is why draft selection stays above them.

Packet reordering (streams only, package [golang.getoutline.org/sdk/x/disorder])

The disorder strategy sends TCP packets out of order by manipulating the
socket's Time To Live (TTL) or Hop Limit. It temporarily sets the TTL to a low
value, causing specific packets to be dropped early in the network (like at the
first router). These dropped packets are then re-transmitted later by the TCP
stack, resulting in the receiver getting packets out of order. This can help
bypass network filters that rely on inspecting the initial packets of a TCP
connection.

	disorder:[PACKET_NUMBER]

PACKET_NUMBER: The number of writes before the disorder action occurs. The
disorder action triggers when the number of writes equals PACKET_NUMBER. If set
to 0 (default), the disorder happens on the first write. If set to 1, it happens
on the second write, and so on.

# Examples

Packet splitting - To split outgoing streams on bytes 2 and 123, you can use:

	split:2|split:123

Disorder transport - Send some of the packets out of order:

	disorder:0|split:123

Split at position 123, then send packet 0 of 123 bytes (from splitting) out of order. The network filter will first receive packet 1, only then packet 0. This
is done by setting the hop limit for the write to 1, and then restoring it. It will be sent with its original hop limit on retransmission.

Evading DNS and SNI blocking - You can use Cloudflare's DNS-over-HTTPS to protect against DNS disruption.
The DoH resolver cloudflare-dns.com is accessible from any cloudflare.net IP, so you can specify the address to avoid blocking
of the resolver itself. This can be combines with a TCP split or TLS Record Fragmentation to bypass SNI-based blocking:

	doh:name=cloudflare-dns.com.&address=cloudflare.net.:443|split:2

SOCKS5-over-TLS, with domain-fronting - To tunnel SOCKS5 over TLS, and set the SNI to decoy.example.com, while still validating against your host name, use:

	tls:sni=decoy.example.com&certname=[HOST]|socks5:[HOST]:[PORT]

Onion Routing with Shadowsocks - To route your traffic through three Shadowsocks servers, similar to [Onion Routing], use:

	ss://[USERINFO1]@[HOST1]:[PORT1]|ss://[USERINFO2]@[HOST2]:[PORT2]|ss://[USERINFO3]@[HOST3]:[PORT3]

In that case, HOST1 will be your entry node, and HOST3 will be your exit node.

DPI Evasion - To add packet splitting to a Shadowsocks server for enhanced DPI evasion, use:

	split:2|ss://[USERINFO]@[HOST]:[PORT]

# Defining custom strategies

A [Registry] looks up parsers by their Go result type and config URL scheme.
A [MutableRegistry] also supports registration. Use [Register] to add a typed
[Constructor], [New] to construct an object from a config URL string, or [NewFromConfig]
to construct it from a parsed [Config]. Constructors receive the registry used for
construction and use it to construct their dependencies. This allows a registry
wrapper to override dependencies throughout a component chain.

For example, this component delegates to the configuration on its left:

	func newCustomDialer(ctx context.Context, registry configurl.Registry, config *configurl.Config) (transport.StreamDialer, error) {
		return configurl.NewFromConfig[transport.StreamDialer](ctx, registry, config.BaseConfig)
	}

The app creates a registry, registers the component, and constructs a dialer:

	registry := configurl.NewDefaultRegistry()
	configurl.Register(registry, "custom", newCustomDialer)
	dialer, err := configurl.New[transport.StreamDialer](context.Background(), registry, "custom|tlsfrag:1")

Constructors forward both the context and the supplied registry when calling
NewFromConfig for dependencies. Do not capture the registration registry instead:
doing so would bypass wrappers used during construction. NewFromConfig looks up
the current registration on each call and passes that registry to the constructor.
Returned objects should use the context of each later dial or listen operation,
rather than retain the construction context.

[NewRegistry] initializes the base [transport.StreamDialer],
[transport.PacketDialer], and [transport.PacketListener].
[NewDefaultRegistry] also registers the SDK's built-in configuration types.
A nil Config invokes the default base parser, registered under the empty name.
Use [RegisterBase] for a custom base parser. To reuse an existing dialer, register
a parser that returns it.

The registry supports arbitrary Go result types, including interfaces and slices.
Types are matched exactly: registering a Constructor[transport.StreamDialer] uses
transport.StreamDialer as the result type.
[Lookup] retrieves an existing typed parser, for example to wrap its behavior.
External registries can implement [Registry.Lookup] and
[MutableRegistry.Register] without exposing their storage. Both methods use
any to hold Constructor[T] values unchanged. [Register] checks parser signatures at
compile time. Direct callers of [MutableRegistry.Register] must supply a
Constructor[T], converting ordinary functions explicitly. Registration checks the function
signature; [Lookup] checks the exact Constructor[T] type before returning it.
No parser normalization or result conversion is needed. A nil parser disables an entry.

Component libraries can expose Register* helpers accepting a MutableRegistry
and type name, alongside direct constructors for callers that do not need config URLs.
Complete registration before using the constructed components.

[Onion Routing]: https://en.wikipedia.org/wiki/Onion_routing
*/
package configurl
