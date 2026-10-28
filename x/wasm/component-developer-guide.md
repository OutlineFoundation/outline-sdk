# Writing and building Outline Wasm components

**Design-level guide for the broader ABI.** For the implemented spike, use the [actual component authoring/build guide](docs/components.md) and [ABI reference](docs/abi.md). The spike uses freestanding C with Clang/LLD 19.1.7; Rust bindings and the general event/action API described below are not implemented.

## What you build

An Outline component is a named constructor plus implementations of transport object interfaces. Link several components and their common dependencies into one core WebAssembly `.wasm` artifact. Its catalog declares the `outline_transport_v1` ABI, each constructor's output interface and parameter schema. Each constructor can create multiple independently configured factories; each factory can create multiple connections. See [object-model.md](object-model.md) for the object/session distinction and alternatives. The proposed artifact format does not require a WebAssembly Component Model binary, WIT bindings, browser JavaScript, or a WASI command-line program.

Stream components implement connection setup and bidirectional byte processing. Packet components implement address-aware datagram processing on one listener shared by multiple peers. Go owns actual networking and calls the component through the Outline ABI. The component has no ambient socket, filesystem, or environment access.

## Write a component

1. Start from a complete identity example for the desired profile. Use the package's guest bindings and pinned toolchain rather than hand-coding offsets in every component.
2. Define a named constructor, its interface and a bounded parameter schema. Store configuration and the injected base capability in the returned factory object. Keep provider secrets out of source, command-line URLs, and logs.
3. Implement factory methods that create independent connection objects. StreamDialer creates StreamConn children; PacketListener creates PacketConn children with bounded per-peer state. Several factories/children may share an execution session; no mutable singleton config, connection or active dialer is allowed.
4. Process object-addressed events and emit actions carrying object/request IDs. Return promptly whenever you need network data, write credit, or a timer. Waiting happens in Go; do not busy-loop or call into a nested guest synchronously.
5. Handle completion, cancellation, malformed input, and cleanup explicitly. Use request IDs so delayed completions cannot be mistaken for another operation.

Conceptual stream identity handler (pseudocode, not an ABI declaration):

```text
constructor(params, base)      -> new_dialer_object(params, base)
dial(self, destination)        -> new_stream_child(self), request_base_dial(destination)
base_dial_ready                -> ready
application_bytes(id, bytes)   -> send_base(id, bytes)
base_send_complete(id, result) -> acknowledge_application_write(id, result)
base_bytes(bytes)              -> deliver_application_bytes(bytes)
application_close_write       -> finish_framing_then_close_base_write
base_eof                      -> finish_decoding_then_application_eof
```

A real protocol adds its handshake before `ready`, encodes outgoing bytes, and decodes incoming bytes. Preserve partial progress and stream half-close. Application byte counts and encoded byte counts are different.

Conceptual packet identity handler:

```text
constructor(params, base)             -> new_listener_object(params, base)
listen(self)                          -> new_packet_child(self), request_base_listener()
base_listener_ready                   -> ready
application_packet(id, dst, bytes)     -> send_base_packet(id, dst, bytes)
base_send_complete(id, result)         -> complete_application_packet(id, result)
base_packet(src, bytes)                -> deliver_application_packet(src, bytes)
```

A packet encapsulation component sends to a relay and carries the logical destination in its protocol. On receipt it validates and decodes the logical source before delivery. A prelude and its payload use the same base packet connection. Preserve empty datagrams and boundaries; never treat datagrams as chunks of a byte stream. If your protocol fragments datagrams, bound reassembly and only deliver complete logical datagrams.

For both profiles, copy or retain bytes only according to the binding's ownership rules. Guest linear-memory views cannot survive arbitrary host calls or memory growth. Separate operation errors from a fatal instance error. A bad packet from one peer need not terminate every peer using the listener. Ask the host for randomness and monotonic timers through the declared capabilities.

Ordinary connection close releases that child; factory release stops new operations and retains state required by existing children until they close. Explicit session close releases all objects. The bindings implement typed, generation-checked handles in a session-owned arena. Put mutable protocol state in objects and pass any intentionally shared context explicitly. Immutable constructor tables and compiler allocator/stack internals are not an ambient transport configuration. Objects sharing one session share memory and fatal runtime failures; separate sessions are the isolation mechanism.

## Build the artifact

The proposed production authoring path is a small Rust library/reactor with guest bindings; these bindings remain unimplemented. Use `wasm32-unknown-unknown` as the proposed core-Wasm target, with the exact Rust release, dependencies, feature flags and linker settings checked into each example. A reactor stays available for repeated host calls; it does not run a blocking CLI `_start` loop. Additional C/TinyGo paths require their own tested recipes before being advertised as supported.

The package must include four source-complete component examples: stream identity, stream handshake/framing, packet identity, and packet encapsulation. A shared bundle example links these constructors into one artifact with one compatible dependency graph. Include dependency locks, toolchain pins, a build script, generated constructor catalog, parameter records and local harnesses. Protocol examples include matching relays and origin setup. Optional standalone builds help compare code size but are not required for deploying several layers.

The documented build sequence must:

1. Install/select the pinned toolchain and required Wasm target.
2. Build a bundle crate/library that explicitly registers all included constructors, from the checked-in lockfile with the declared core-Wasm feature set. Link common libraries once where the toolchain/dependency graph permits; do not just archive standalone Wasm binaries. Keep constructors reachable through the generated dispatch/catalog so dead-code elimination cannot strip selected implementations.
3. Produce the final `.wasm` file at a documented path. Record any stripping/optimization steps and pin those tools too.
4. Validate the **final** artifact's format, exact fixed ABI exports/imports, constructor catalog and parameter schemas, memory requirements, start behavior and instruction features against the chosen host release.
5. Run conformance tests and the local protocol harness before packaging.
6. Hash the final bytes and create the artifact metadata expected by the module catalog. Changes after hashing require a new digest.

Do not equate a successful compiler invocation with ABI compatibility. The author guide must publish one copy-and-paste build recipe per supported example, with prerequisites, expected output and error explanations. CI must run those exact scripts from a clean environment. Exact compiler versions, exported symbol names, and executable recipes are intentionally pending the ABI implementation; do not invent a working command around absent bindings.

The same compatible core-Wasm artifact is intended for all host platforms. Verify that in the host test matrix rather than rebuilding a different guest for each operating system. Publish supported host ABI/features and memory requirements alongside each artifact.

## Test with the host and fetch

First run the package's conformance harness with fake SDK base transports. Check stream full duplex, partial writes, half-close, cancellation and deadlines. For packets, use multiple peers, IPv4/IPv6, empty datagrams, truncation, oversize datagrams, drops, short-write errors, malformed addresses, queue exhaustion and cleanup. Exercise out-of-order/lost packets where the protocol permits them.

Then run local loopback origins and protocol relays with the real host. Proposed fetch invocation shapes:

```sh
fetch -proto h1 \
  -wasm-module demo=./demo.wasm \
  -transport 'wasm:module=demo&component=stream.identity' \
  https://example.com/

fetch -proto h3 \
  -wasm-module demo=./demo.wasm \
  -transport 'wasm:module=demo&component=packet.identity' \
  https://example.com/
```

These illustrate proposed flags, not runnable examples today. Delivered recipes must use the packaged local origin/relay, explain its certificate trust and guest configuration, and work without an external service. Only an identity component can generally connect directly to an ordinary origin; a changed wire protocol needs a matching peer. Include HTTP/2 as a stream integration check. Repeat through a native wrapper to prove composition.

Also document selecting constructor parameters through the explicit build scope, creating two differently configured instances of one constructor, creating multiple connections per factory, and placing two constructors from the same artifact at different layers separated by native TLS. Test all cases in one session and separate sessions; confirm no implicit global state, dispatcher deadlocks, or sibling destruction on ordinary close.

## Debug and publish

Document errors by phase: artifact validation, initialization, base transport setup, protocol handshake, data processing, resource limit, and shutdown. Explain how to map a guest trap to source with the pinned toolchain's debug information and how to enable bounded local diagnostics. Avoid logging payloads, destination history, or credentials by default. Provide a malformed-component troubleshooting example.

For distribution, provide the immutable module bytes, digest/size, ABI and profile requirements, configuration schema/version, protocol peer requirements, and build provenance. A production provider publishes this through its authenticated catalog; the local file flag is for development. Existing stream and packet connections keep their existing module version until close.

## Documentation is part of package completion

- Package Go documentation links this guide, the normative ABI reference, version compatibility rules, guest bindings and examples.
- The ABI reference specifies binary layouts, address encoding, exports/imports, ownership, profile state machines, return codes, progress, truncation and deadlines precisely enough to implement another language binding.
- An independent developer can implement constructors, jointly build stream and packet components into one artifact, validate it, select components/parameters and manage multiple objects using only the published instructions.
- CI detects stale recipes or bindings by rebuilding and running all examples, including profile mismatch and unsupported ABI failures.
- No component language or platform is described as supported without a verified recipe and host test.
