# One artifact, named constructors, independent transport objects

Design revision, 2026-09-24. Required: several Wasm components at different layers, multiple independently configured objects, and no mutable global transport state. APIs below are conceptual proposals, not implemented interfaces.

## Recommendation

Build a **single linked core-Wasm module containing multiple named component constructors**. The host loads the artifact, selects a constructor and passes parameters plus a base-transport capability. The constructor returns an object. That object implements StreamDialer or PacketListener and creates separate connection objects on demand.

Select behavior from the loaded module; do not extract an inner Wasm file. A constructor is the discoverable entry for one component implementation. An artifact can contain many constructors and each can create many objects with independent configurations. Use interfaces and explicit ownership; object orientation does not require inheritance or exposing Rust/Go object layouts across the ABI.

Keep four concepts distinct:

| Concept | Meaning and ownership |
|---|---|
| Artifact | Immutable `.wasm` bytes, digest, ABI version and constructor catalog; verified/compiled once per compatible manager cache |
| Session | Explicit execution instance with memory, dispatcher, capability table and object arena; created and owned by the embedding application/build scope |
| Factory object | A StreamDialer or PacketListener created by a named constructor with its own parameters and injected base |
| Connection object | A StreamConn or PacketConn created by a factory call; independent protocol state and lifetime |

A session may contain several factories and their connections. There is no “current dialer,” “current config,” default active component, or package-global runtime. Reusing a digest must never implicitly merge application sessions or provider state.

## What a single file does and does not deduplicate

| Resource | Proposed sharing |
|---|---|
| Download/cache bytes | Store the artifact once by digest; all constructor references point to it |
| Dependency code | Link components and compatible shared dependencies into one module during the producer build |
| Prepared code | Reuse a compiled module within the manager's compatible runtime/cache scope |
| Runtime/linear memory | Shared by objects explicitly placed in the same session; separate sessions have separate memories |
| Protocol state | Owned by individual factories/connections; shared only through an explicit passed object when intentionally supported |

A ZIP or custom container of independently linked modules merely packages the duplication. A joint build with a shared dependency graph is the initial route to reducing it. It cannot guarantee elimination of all duplicate code/data: dependency versions, generic specialization, feature differences and compiler choices still matter. Measure final artifact size and dependency provenance. Static linking also means changing one bundled constructor normally publishes a new whole artifact.

The WebAssembly linker supports linking object files into a module and discarding unreachable functions/data. Those features support this packaging proposal; they do not imply arbitrary automatic dependency deduplication. [LLVM Wasm linker](https://lld.llvm.org/WebAssembly.html)

Separately, wazero distinguishes compiled code from instantiated execution state and permits repeated instantiation. That lets us trade memory sharing against isolation without changing the published file. [Wazero terminology](https://wazero.io/docs/)

Dynamic linking to separately delivered shared libraries is another possible architecture, but it adds dependency resolution and compatibility machinery. It is outside V1. The authoring path must build all bundled components in one supported toolchain/link graph; independently built opaque `.wasm` files cannot simply be concatenated into the desired artifact.

## Catalog and selection

Embed a bounded, versioned constructor catalog in the artifact. Each entry contains a stable name, output interface, parameter-schema version, and required base/host capabilities. For example:

```text
artifact: emergency.wasm
ABI: outline_transport_v1
constructors:
  stream.identity   -> StreamDialer
  stream.split      -> StreamDialer   parameters: {first_write_bytes: integer}
  stream.tunnel     -> StreamDialer   parameters: {relay: address, ...}
  packet.identity   -> PacketListener
  packet.encapsulate -> PacketListener parameters: {relay: address, ...}
```

Treat this catalog as part of the authenticated artifact. A custom section is a possible encoding: the host can inspect names/types before running a constructor. Cross-check catalog declarations against the fixed ABI exports and reject duplicate names, unknown interfaces and unsupported capabilities. Generate the catalog and dispatch table together to prevent drift. Catalog metadata does not itself grant capabilities or prove implementation behavior.

Use a fixed `object_create` ABI operation carrying the constructor name/ID rather than allowing configuration to invoke arbitrary Wasm exports. A generated switch/immutable table calls the component's typed constructor. Individual constructor exports could work too, but a common dispatcher keeps signatures, validation and errors uniform. Names are stable within a versioned artifact; compact IDs may be assigned when loading and are not persistent config identifiers.

Proposed URL shape:

```text
wasm:module=emergency&component=stream.split&config=split3
```

`module` resolves to exact artifact bytes; `component` selects the constructor; `config` optionally names a parameter record supplied through the explicit build context/catalog. The host validates that record against the constructor's schema and passes structured bytes to `object_create`. Programmatic callers can pass parameters directly. Configuration records containing secrets remain memory-only. No constructor executes configuration text or interprets it as source code. Missing component names are errors, including for single-constructor artifacts; make selection consistent.

## Object API and lifetimes

Conceptual Go usage (error handling elided):

```go
manager := NewManager(runtimeOptions)
artifact := manager.Load(ctx, wasmBytes, verificationPolicy)
session := artifact.NewSession(ctx, sessionOptions)

split3 := session.NewStreamDialer(ctx, "stream.split", SplitParams{3}, tcpBase)
split8 := session.NewStreamDialer(ctx, "stream.split", SplitParams{8}, tcpBase)
tunnel := session.NewStreamDialer(ctx, "stream.tunnel", relayParams, split3)
packets := session.NewPacketListener(ctx, "packet.encapsulate", packetParams, udpBase)

c1 := tunnel.DialStream(ctx, "one.example:443")
c2 := tunnel.DialStream(ctx, "two.example:443")
pc := packets.ListenPacket(ctx)
```

The two split objects coexist without overwriting configuration. One factory can create multiple concurrent connections. A PacketListener factory can create multiple PacketConn objects; each PacketConn supports multiple peers. Constructors validate parameters and store base capabilities; network setup happens on DialStream/ListenPacket rather than during arbitrary global initialization.

Conceptual ABI operations:

```text
session_new(limits) -> session_handle
object_create(session, constructor, params, base_capability) -> factory_handle
stream_dial(session, factory_handle, request_id, destination) -> pending_conn_handle
packet_listen(session, factory_handle, request_id) -> pending_packet_handle
object_step(session, object_handle, events) -> actions
object_release(session, object_handle)
session_close(session)
```

Returned connection handles are pending until their READY event; the Go interface call waits for readiness. Every method/event/action identifies its object and operation. The ABI uses scalars, bounded buffer offsets and opaque typed handles, not pointers to language objects or serialized vtables. The binding owns a session-scoped arena with generation counters; the host validates session, type, generation and permission before dispatch. Capacity exhaustion and invalid handles are explicit errors.

Factory configuration belongs to that factory object; handshake/buffer/peer state belongs to a connection object. Libraries that need mutable shared state must receive an explicit owned context, not use a module-wide active configuration. A session arena is explicit infrastructure passed on calls, not a hidden process-global registry. Compiler-generated stack/allocator machinery and immutable constructor tables are implementation details; “no globals” here prohibits mutable ambient application/transport state, not every Wasm global instruction.

Ordinary factory disposal stops new calls but does not kill already returned connections: child objects retain necessary factory state and base leases until released. Layer objects borrow injected bases through explicit leases and never unconditionally close caller-owned factories. Setup failures release partial children and capabilities. Late completions for released objects are discarded using generation/request checks. Force-closing a session aborts all its objects and owned I/O; manager close shuts down its sessions before dropping cached code. Cache eviction cannot invalidate a live session.

Because SDK factory interfaces have no Close method, expose lifecycle on concrete handles plus an explicit build/session scope that can clean up factories even after an adapter is returned as an SDK interface. Release must be idempotent at the Go wrapper; do not require callers to discover a hidden global cleanup function.

## Composition at different layers

This proposed config uses two constructors from one file with a native layer between them:

```text
wasm:module=emergency&component=stream.split&config=split3|tls:sni=relay.example|wasm:module=emergency&component=stream.tunnel&config=relayA
```

It constructs `Tunnel(TLS(Split(TCP)))`. The tunnel object dials its configured relay through its base; its application destination is separate. `split3` and `relayA` are parameter records in the build context. Repeating a constructor with other parameters creates another object. Packet constructors compose similarly in the packet-listener registry. V1 still requires matching stream/packet interfaces at each boundary.

An explicit `BuildScope` owns a mapping from artifact digest to session for one trusted strategy graph, plus constructor parameters and provider registrations. Both `wasm:` builders capture that scope. Recursively building BaseConfig creates distinct objects, while references to the same artifact in the scope reuse prepared code and the explicitly shared session. Different scopes may choose separate sessions of the same artifact. Share across several stack builds only when the caller supplies the same scope; do not use a global singleton or a digest-keyed global session cache.

The injected base is a host capability referencing the actual SDK interface. It can refer to a native layer, another Wasm object in the same session, or an object in another session. The guest emits an action and returns. Host workers call the base outside guest execution; completions are queued to the owning object. If the base ultimately reaches another object in the same session, dispatch it after the current guest call returns. Never hold the session execution lock while waiting for base I/O: native/Wasm/native nesting otherwise deadlocks. Prohibit cyclic ownership/composition graphs and bound nesting depth.

## Shared-session trade-offs

Use one dispatcher per session, serializing short guest calls and scheduling fairly across objects. Blocked network operations run outside it. Normal object errors/close stay local; runaway execution that triggers wazero instance termination destroys the shared session and all its objects. A trap is treated as session-fatal in V1 because partially mutated shared memory may be inconsistent.

Object handles provide API correctness, not memory isolation inside a module. Components jointly linked into one module share its trust boundary. Separate sessions when separate memory/failure isolation is needed; separately packaged artifacts may still be appropriate for independently trusted publishers. Do not claim independent malicious-code isolation between constructors in one file or per-object hard memory limits inside shared linear memory. Enforce session memory/CPU caps and per-object host-I/O/queue quotas, with separate sessions available for stronger isolation.

Default proposal: a caller-owned session per artifact per trusted BuildScope, with many objects. Start without transparent session pooling or automatic object migration. Measure memory/throughput and the impact of a noisy object before considering sharding. Sharing prepared code remains possible when choosing separate sessions.

## Required demonstrations

1. One source build produces one artifact with stream and packet constructors, linking a common dependency; inspect provenance and compare size with independently built artifacts without promising perfect deduplication.
2. Load/prepare it once; construct the same constructor twice with different parameters and different bases, plus different constructors in the same session.
3. Compose two Wasm layers separated by native TLS; exercise simultaneous reads/writes without dispatcher reentry or deadlock.
4. Create multiple connections from each factory, multiple PacketConns from a listener and multiple peers per PacketConn; verify state is not conflated.
5. Release one object while siblings continue; reject stale/wrong-type/cross-session handles; verify factory and base lease ownership.
6. Demonstrate explicit shared-session failure and separate-session isolation. Reusing the same artifact across independent managers/build scopes must not share mutable state.
7. The component guide teaches implementing constructors/types, assembling a multi-constructor artifact, selecting parameters and releasing objects.

## Alternatives and trade-offs to review

The required behavior is multiple independent objects and multiple component layers. The choices below are recommendations, not additional user decisions already made.

| Decision | Recommended starting point | Alternative and when it helps | Cost/trade-off |
|---|---|---|---|
| Packaging | One jointly linked artifact with several constructors | Separate artifacts when components have different publishers or update schedules; a container can deliver them together | A joint build shares dependency code more naturally, but couples versions, toolchains and update downloads. Packaging separate modules together does not itself deduplicate them |
| Dependency sharing | Build-time linking with a compatible shared dependency graph | Runtime-imported shared library modules for independent updates | Dynamic linking needs dependency resolution, ABI/version management and resource ownership; not a V1 prerequisite |
| Constructor selection | Catalog plus fixed `object_create(name, params, base)` dispatcher | One named Wasm export per constructor | Named exports are easier to inspect/call directly; the dispatcher provides uniform signatures, schema validation and generated bindings. Neither determines state ownership |
| Object interface | Explicit handles with Outline's small core-Wasm ABI | Standard Component Model/WIT resources with constructors, methods and ownership | Custom ABI fits the proposed embedding but requires maintaining bindings and handle/lifetime rules. Standard resources reduce bespoke interface conventions but require a proven runtime/toolchain/mobile integration path and do not automatically deduplicate code |
| Execution sharing | One explicitly shared session per artifact per trusted strategy scope | Separate session per factory or strategy graph | Shared memory reduces runtime duplication; calls serialize and an instance-fatal error affects every object in that session. Separate sessions reuse prepared code but duplicate linear memory and initialization |
| Stronger connection isolation | Keep children in their factory's selected session initially | A separate session per connection or bounded shards | Smaller failure domains and more execution parallelism cost memory and startup work. Per-connection sessions complicate preserving mutable factory state; do not promise transparent migration |
| Parameters | Constructor-specific typed schemas, serialized by guest bindings | Raw byte/string configuration for each constructor | Raw payloads make experimentation easy but weaken diagnostics and compatibility checks. The wire can remain a byte buffer while its schema is typed/versioned |
| I/O programming model | Event-driven guest methods and asynchronous host base calls | Blocking socket-like imports with a guest scheduler | Events make composition and budgeting explicit but require more author support. Blocking APIs can simplify protocol ports, yet introduce scheduling/reentry/cancellation complexity for shared instances |

WIT resources already express an object-like interface with constructors, methods, handles and ownership. This is a substantive alternative to the custom ABI, not an object-orientation feature we must invent. The present proposal borrows that conceptual separation without claiming Component Model binary compatibility or current support in our selected embedding. [WIT resource reference](https://component-model.bytecodealliance.org/design/wit.html#resources)

Before freezing the design, compare the multi-constructor example in one shared session against separate sessions per factory: artifact/prepared-code reuse, resident memory, cold creation time, throughput under concurrent connections, failure propagation and native/Wasm layer composition. Keep deployment packaging independent from this runtime placement choice.
