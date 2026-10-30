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
Package configurl provides a flexible and extensible framework for constructing a network of components from textual configurations.
This enables dynamic, composable, and easily shared transport configurations, making it ideal for complex networking scenarios.

This package is currently experimental and primarily serves as a demonstration of its capabilities and potential use cases.

Key Features:

  - Ease of Use: Define and create complex transport stacks using simple, human-readable text strings.
  - Serialization: Easily share and persist configurations between different components or users.
  - Dynamic Configuration: Modify an application's transport behavior at runtime.
  - Composability: Nest and combine various transport strategies to create sophisticated configurations.
  - DPI Evasion: Implement advanced strategies like packet splitting and TLS fragmentation to evade Deep Packet Inspection (DPI).
  - Extensibility: Define custom transport strategies and integrate them seamlessly.

# Usage

Create a registry with [NewDefaultRegistry], then call [New] with the Go type of
component you need. For example, this function creates a [transport.StreamDialer]
that fragments the TLS ClientHello and splits the resulting stream:

	import (
		"context"

		"golang.getoutline.org/sdk/transport"
		"golang.getoutline.org/sdk/x/configurl"
	)

	func newDialer(ctx context.Context) (transport.StreamDialer, error) {
		registry := configurl.NewDefaultRegistry()
		return configurl.New[transport.StreamDialer](ctx, registry, "split:2|tlsfrag:1")
	}

After checking the error, use the returned dialer like any other SDK dialer.
The registry associates a config URL scheme, such as split, with a [Parser]
for a particular Go result type. New uses those parsers to construct the
configured components and their dependencies.

# Configuration format

A configuration is a pipe-separated sequence of component definitions. A
component can use the configuration on its left to construct its dependencies.
For wrapping components, A|B|C means A wraps the default base, B wraps A, and C
wraps B. New returns C.

For example, split:2|tlsfrag:1 builds these layers:

	application → TLS fragmentation → stream splitting → TCP

Outgoing data passes through TLS fragmentation first, then stream splitting.
The first component, split:2, uses the default base [transport.StreamDialer].
An empty configuration selects the default base for the requested Go type.
[NewRegistry] supplies a TCP StreamDialer, a UDP [transport.PacketDialer], and a
UDP [transport.PacketListener]. [NewDefaultRegistry] adds the built-in component
parsers listed in the reference sections below.

Each component definition is a URL. Its scheme selects the component's parser;
the remaining fields carry that component's options. There are two common forms:

  - Opaque URLs, such as split:2 or tls:sni=example.com, put options after the colon.
  - URLs such as socks5://proxy.example:1080 use a host, optional user information,
    and, where supported, query parameters after a question mark.

A scheme with no options can omit the colon. Escape a literal pipe in an option
as %7C so it is not treated as a component separator.

The requested Go type also matters. For example, socks5 can produce a StreamDialer,
PacketDialer, or PacketListener, while tlsfrag produces only a StreamDialer.
A parser can request dependencies of a different type: h3connect returns a
StreamDialer but uses a PacketListener for its QUIC transport. Not every sequence
is valid; each dependency needs a registration for both its scheme and its Go type.

# Composing configurations

The following strings can be passed to New[transport.StreamDialer]. Replace
bracketed placeholders with your own values.

Split outgoing streams at bytes 2 and 123:

	split:2|split:123

Split at byte 123, then apply disorder to the first write to help bypass filters
that inspect the initial packets:

	disorder:0|split:123

Use DNS-over-HTTPS for destination resolution, then split outgoing streams.
Specifying the resolver's IP address avoids needing DNS to locate the resolver:

	doh:name=[RESOLVER_NAME]&address=[RESOLVER_IP]:443|split:2

Tunnel SOCKS5 over TLS, sending decoy.example.com as SNI while validating the
server certificate against HOST:

	tls:sni=decoy.example.com&certname=[HOST]|socks5://[HOST]:[PORT]

Route traffic through three Shadowsocks servers, similar to [Onion Routing].
HOST1 is the entry node and HOST3 is the exit node:

	ss://[USERINFO1]@[HOST1]:[PORT1]|ss://[USERINFO2]@[HOST2]:[PORT2]|ss://[USERINFO3]@[HOST3]:[PORT3]

Split the encrypted traffic sent to a Shadowsocks server:

	split:2|ss://[USERINFO]@[HOST]:[PORT]

# Defining custom strategies

To make a component available through a config URL, provide a [Parser] and
register it with [Register]. A parser interprets its component's options,
constructs its dependencies, and calls the component's ordinary Go constructor.
The component itself does not need to know about config URLs.

[ParseConfig] handles the shared URL-chain syntax and returns a [Config]:
URL contains the current component's URL, and BaseConfig describes the entire
configuration to its left. [NewFromConfig] constructs a dependency from that
BaseConfig. For the leftmost component, BaseConfig is nil, so NewFromConfig
invokes the default base parser for the requested type.

The example below registers fragment:<length> using the SDK's existing TLS
fragmentation component. This duplicates the built-in tlsfrag behavior to show
how a config parser connects to an ordinary component constructor. In your own
library, call your component's constructor in the same way.

	import (
		"context"
		"fmt"
		"strconv"

		"golang.getoutline.org/sdk/transport"
		"golang.getoutline.org/sdk/transport/tlsfrag"
		"golang.getoutline.org/sdk/x/configurl"
	)

	func parseFragmentDialer(ctx context.Context, registry configurl.Registry, config *configurl.Config) (transport.StreamDialer, error) {
		length, err := strconv.Atoi(config.URL.Opaque)
		if err != nil {
			return nil, fmt.Errorf("fragment: invalid length: %w", err)
		}
		base, err := configurl.NewFromConfig[transport.StreamDialer](ctx, registry, config.BaseConfig)
		if err != nil {
			return nil, err
		}
		return tlsfrag.NewFixedLenStreamDialer(base, length)
	}

	// RegisterFragment registers the fragment parser under name.
	func RegisterFragment(registry configurl.MutableRegistry, name string) {
		configurl.Register(registry, name, parseFragmentDialer)
	}

A component library can publish a Register* helper like this from its own package.
Apps import the library and call its helper on their registry. Keep direct
constructors available too, for apps that do not need config URLs. Here,
[golang.getoutline.org/sdk/transport/tlsfrag.NewFixedLenStreamDialer] is that direct
constructor.

An app using RegisterFragment can then construct the component:

	func newFragmentDialer(ctx context.Context) (transport.StreamDialer, error) {
		registry := configurl.NewDefaultRegistry()
		RegisterFragment(registry, "fragment")
		return configurl.New[transport.StreamDialer](ctx, registry, "split:2|fragment:5")
	}

The fragment parser reads 5 from config.URL.Opaque and asks NewFromConfig to
construct split:2 as its base. Register infers the result type transport.StreamDialer
from the parser's signature. Registrations match Go types exactly: a parser returning
*MyDialer must instead return transport.StreamDialer if it is to be used by
New[transport.StreamDialer].

Always forward the supplied registry and ctx when constructing dependencies.
The registry used for construction may wrap the one used for registration to
override a dependency. Capturing the registration registry would bypass that
override. The context controls construction; returned components should use the
context of each later dial or listen operation instead of retaining it.

# Custom base components

Use [RegisterBase] to change the component returned for an empty configuration
or when a parser reaches the left end of a chain. For example, if base is an
existing transport.StreamDialer, register a parser that returns it:

	parseBase := func(context.Context, configurl.Registry, *configurl.Config) (transport.StreamDialer, error) {
		return base, nil
	}
	configurl.RegisterBase(registry, parseBase)

Now split:2 and split:2|fragment:5 both build on that dialer. Packet bases are
unchanged because registrations are specific to a Go result type.
RegisterBase is a convenience for Register with an empty name. A base parser
receives a nil Config; it can return an existing instance, as above, or create one.

Complete registration before constructing and using components. Replacing a
registration affects subsequent construction, not objects already created.

# Registry interfaces

Use [MutableRegistry] in registration helpers and the read-only [Registry]
interface in code that only constructs components. The registry supports
arbitrary Go result types, beyond the built-in transport interfaces. A custom
result type needs a base registration only if its parser requests the default
base for that type.
[Lookup] retrieves a typed parser without invoking it, which is useful when
wrapping an existing registration.

For custom registry implementations, [Registry.Lookup] and [MutableRegistry.Register]
use any to store Parser[T] values unchanged. Prefer the generic Register and
Lookup helpers in application code: Register checks the signature at compile
time, and Lookup checks the exact Parser[T] type when retrieving it. Direct
callers of MutableRegistry.Register must explicitly convert ordinary functions
to Parser[T]. A registered nil parser disables an entry.

# Built-in components

[NewDefaultRegistry] registers the following config URL schemes. To add them
to another MutableRegistry without changing its bases, use [RegisterDefaultTypes].
The sections below describe their options and supported transport types.

# Proxy protocols

Shadowsocks proxy (stream dialers, packet dialers, and packet listeners; compatible with Outline's access keys; package [golang.getoutline.org/sdk/transport/shadowsocks])

	ss://[USERINFO]@[HOST]:[PORT]?prefix=[PREFIX]

SOCKS5 proxy (stream dialers, packet dialers, and packet listeners; package [golang.getoutline.org/sdk/transport/socks5])

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

  - For other schemes such as Bearer the auth parameter sets the full Proxy-Authorization header value, for example ?auth=Bearer%20TOKEN.

The config formats are shown below. All query parameters are optional; the first
parameter supplied must start with ?, and subsequent parameters with &.

	httpconnect://[USER:PASS@][HOST]:[PORT][?sni=SNI][&certname=CERTNAME][&auth=TOKEN]
	h2connect://[USER:PASS@][HOST]:[PORT][?sni=SNI][&certname=CERTNAME][&auth=TOKEN][&plain=true]
	h3connect://[USER:PASS@][HOST]:[PORT][?sni=SNI][&certname=CERTNAME][&auth=TOKEN]

# Transports

TLS transport (currently streams only, package [golang.getoutline.org/sdk/transport/tls])

The sni parameter defines the name to be sent in the TLS SNI. It can be empty.
The certname parameter defines what name to validate against the server certificate.

	tls:sni=[SNI]&certname=[CERT_NAME]

WebSockets (stream and packet dialers)

	ws:tcp_path=[PATH]&udp_path=[PATH]

# DNS protection

DNS resolution (streams only, package [golang.getoutline.org/sdk/dns])

It takes a host:port address. If the port is missing, it will use 53. The resulting dialer will use the input dialer with
Happy Eyeballs to connect to the destination.

	do53:address=[ADDRESS]

DNS-over-HTTPS resolution (streams only, package [golang.getoutline.org/sdk/dns])

It takes a host name and a host:port address. The name will be used in the SNI and Host header, while the address is used to connect
to the DoH server. The address is optional, and will default to "[NAME]:443". The resulting dialer will use the input dialer with
Happy Eyeballs to connect to the destination.

	doh:name=[NAME]&address=[ADDRESS]

Address override (stream and packet dialers).

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

A positive LENGTH specifies the number of leading payload bytes in the first
fragment of the TLS ClientHello record. A negative LENGTH specifies the number
of trailing payload bytes in the second fragment (using its absolute value).
A zero LENGTH disables fragmentation.
For more details, refer to [golang.getoutline.org/sdk/transport/tlsfrag].

	tlsfrag:[LENGTH]

QUIC prelude (packet listeners only, package [golang.getoutline.org/sdk/x/quicprelude])

Sends prelude datagrams before packets that may carry a QUIC ClientHello, using
the same socket. Other traffic passes unchanged. See [golang.getoutline.org/sdk/x/quicprelude]
for the mechanism and guidance on choosing a version.

	quicprelude:count=[COUNT]&mode=[MODE]&length=[LENGTH]&version=[VERSION]

All options are optional. By default, one Initial-shaped datagram with a reserved
version precedes each eligible packet and matches its size.

	count    number of datagrams, at most 16; 0 disables the prelude (default 1)
	mode     invalid-initial or random (default invalid-initial)
	length   match, or a byte count (default match)
	version  reserved, draft, v1, v2, or a 32-bit hex codepoint (default reserved)

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
to 0, the disorder happens on the first write. If set to 1, it happens
on the second write, and so on.

[Onion Routing]: https://en.wikipedia.org/wiki/Onion_routing
*/
package configurl
