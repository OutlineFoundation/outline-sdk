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
Package configurl provides a flexible and extensible framework for creating network objects based on textual configurations.
This enables dynamic, composable, and easily shared transport configurations, making it ideal for complex networking scenarios.

This package is currently experimental and primarily serves as a demonstration of its capabilities and potential use cases.

Key Features:

  - Ease of Use: Define and create complex transport stacks using simple, human-readable text strings.
  - Serialization: Easily share and persist configurations between different components or users.
  - Dynamic Configuration: Modify an application's transport behavior at runtime.
  - Composability: Nest and combine various transport strategies to create sophisticated configurations.
  - DPI Evasion: Implement advanced strategies like packet splitting and TLS fragmentation to evade Deep Packet Inspection (DPI).
  - Extensibility: Define custom transport strategies and integrate them seamlessly.

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
  - h3connect: HTTP/3 over QUIC. Always multiplexed. Creates its own UDP socket.

The sni parameter sets the TLS SNI. The certname parameter sets the name to validate against the server certificate.
For h2connect, plain=true enables h2c (cleartext HTTP/2 without TLS).

	httpconnect://[HOST]:[PORT][?sni=SNI][&certname=CERTNAME]
	h2connect://[HOST]:[PORT][?sni=SNI][&certname=CERTNAME][&plain=true]
	h3connect://[HOST]:[PORT][?sni=SNI][&certname=CERTNAME]

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

Core Concepts:

  - [ProviderContainer]: A central registry for managing different types of network object builders (StreamDialers, PacketDialers, PacketListeners).
  - [ExtensibleProvider]: A type that provides a mechanism to register and retrieve builders for specific subtypes of network objects.
  - [BuildFunc]: A function that creates an instance of a network object from a parsed configuration.
  - [Config]: A parsed representation of the configuration string.
  - [TypeRegistry]: An interface for registering new transport types.

You can define your custom strategy by implementing and registering [BuildFunc[ObjectType]] functions:

	// Create new config parser.
	// p := configurl.NewProviderContainer()
	// or
	p := configurl.NewDefaultProviders()
	// Register your custom dialer.
	p.StreamDialers.RegisterType("custom", func(ctx context.Context, config *Config) (transport.StreamDialer, error) {
	  // Build logic
	  // ...
	})
	p.PacketDialers.RegisterType("custom", func(ctx context.Context, config *Config) (transport.PacketDialer, error) {
	  // Build logic
	  // ...
	})
	// Then use it
	dialer, err := p.NewStreamDialer(context.Background(), "custom://config")

[Onion Routing]: https://en.wikipedia.org/wiki/Onion_routing
*/
package configurl
