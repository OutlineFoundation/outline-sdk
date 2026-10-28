# Implementation plan

Status: a bounded local spike is implemented; see [results and remaining gaps](spike-results.md). Runtime ownership, named objects, both adapters, parser registration, fetch h1/h2/h3, author docs and artifact replacement are tested. The full event ABI, guest-visible packet addresses, general schemas, Rust bindings, mobile execution and delivery remain open. Milestones below describe the broader target, not completed acceptance criteria. Read [design.md](design.md) for architecture and limitations.

## Milestone 0 — settle the contract

- Pin the SDK and candidate runtime versions; check the current SDK API against the inspected snapshot.
- Use the Outline-specific ABI; WATER interfaces and an adoption spike are excluded by the user's decision.
- Write the shared ABI and separate stream/packet profiles: event/action layouts, typed addresses, capabilities, size limits, allocation ownership, initialization, write/datagram acknowledgements, error codes, and state transitions.
- Specify the multi-constructor catalog, parameter schemas, typed/generational object handles, explicit BuildScope/session ownership, factory-child/base leases, and normal versus session-fatal cleanup. Compare the alternatives in [object-model.md](object-model.md#alternatives-and-trade-offs-to-review) before freezing runtime placement.
- Specify the component authoring contract and select a pinned Rust core-Wasm toolchain. Documentation, guest bindings, and buildable examples are required package deliverables.
- Prepare a local SDK API-proposal draft. The inspected SDK AGENTS.md requests API proposals before implementing new features. Publishing the discussion is a separate action.

Exit: reviewable Go API/ABI proposal covering both StreamDialer and PacketListener, plus the component documentation outline and example build contract.

## Milestone 1 — runtime, stream adapter, and packet listener

Proposed additions in the SDK's `x/` module:

| Path | Work |
|---|---|
| `x/wasm/manager.go` | Runtime lifecycle, verified-module handles, bounded cache, limits |
| `x/wasm/session.go`, `x/wasm/objects.go` | Explicit sessions, fair dispatcher, constructor catalog, typed handles, child/base leases and cleanup |
| `x/wasm/dialer.go` | Named constructor creates a factory; DialStream creates independent child objects with readiness boundary |
| `x/wasm/conn.go` | Go StreamConn adapter, dispatcher, I/O completion queues, deadlines and half-close |
| `x/wasm/packet_listener.go` | Named constructor creates a factory; ListenPacket creates independent PacketConn children |
| `x/wasm/packet_conn.go` | ReadFrom/WriteTo, typed addresses, datagram completions, queues and deadlines |
| `x/wasm/abi.go` | Version/features, buffer validation, events/actions and errors |
| `x/wasm/*_test.go` | Connection contract, cancellation, memory and cleanup tests |
| `x/wasm/testdata/` | Minimal guest sources, reproducible compiler commands and small fixtures |
| `x/wasm/doc.go`, `x/wasm/README.md` | Package overview, profiles, links to the component-developer guide |
| `x/wasm/docs/components.md`, `x/wasm/docs/abi.md` | Author/build/debug guide and normative versioned ABI reference |
| `x/wasm/guest/rust/` | Proposed guest bindings, pinned compiler and dependency locks |
| `x/wasm/examples/` | Stream identity/framing and packet identity/encapsulation components jointly linked in one bundle, build scripts, local relays |
| `x/go.mod`, `x/go.sum` | Pinned runtime dependency and license verification |

Both adapters use the shared Outline ABI and runtime. No root SDK interface edits or local `replace` directives are planned. PacketDialer registration is optional follow-on work and cannot substitute for PacketListener support.

Start with identity passthrough, then a guest that creates and validates a handshake and frames every subsequent write. Pair it with a loopback relay that decodes frames, connects to a test origin, and frames replies. Keep the relay and protocol explicitly test-only; this is not an encryption or censorship-resistance claim.

Also implement a packet identity component and a component with address-aware encapsulation plus a loopback UDP relay. Exercise multiple destinations on the same packet connection. Use fake bases without native socket interfaces for both profiles, alongside real loopback integration tests.

Exit: full-duplex stream behavior and multi-peer packet behavior work; guest logic controls the protocol in both profiles; aborts leave no instances, handles, or blocked workers behind. The author guide can build and test all four examples from a clean checkout.

Additionally, one artifact must support multiple named constructors, multiple configurations of the same constructor, and multiple children per factory in the same explicitly shared session. Build the common dependency graph jointly and report artifact/code/memory sharing separately. No singleton transport initialization or process-global manager/session/registry.

## Milestone 2 — register `wasm:` and wire fetch

- Add `x/wasmconfig` with explicit registration against both stream-dialer and packet-listener registries, matching-profile recursive base construction, strict opaque-query parsing, and a prepared-module resolver.
- Add proposed local `-wasm-module ID=PATH` mappings to fetch, plus interpreter selection for experiments if useful. Hash/read each artifact once before preparing it. Reject duplicate IDs and limit input size.
- Instantiate the manager and explicit BuildScope, register both builders with that scope before stack construction, and leave strategy selection in `-transport`. Require `component`, resolve its parameter record, and validate the constructor's interface before creating its base. Unwind partial objects on build failure.
- Give preparation and request work appropriate separate deadlines and guarantee teardown on all error paths.
- Add CLI help/examples and targeted tests for h1/h2 streams and h3 packets; report unknown constructor, bad parameters and wrong-interface selections even when another constructor in the artifact supports that interface.

Proof sequence:

1. Direct native fetch to a local HTTPS origin establishes a control.
2. The same fetch through the identity guest returns identical content.
3. The framing guest plus relay returns identical content; a relay transcript verifies the handshake and framed bytes came from the guest contract.
4. Repeat with the native SOCKS5 dialer underneath Wasm and with a native wrapper above it. Assert the expected destination and layer order using recording dialers.
5. Swap to a second Wasm artifact with a different handshake/framing rule and matching relay behavior. The fetch executable hash must remain unchanged. This is the central no-new-client-release demonstration.
6. An unknown ABI, trap, unsupported import, or malformed frame yields a diagnostic failure with no direct fallback.
7. Native HTTP/3 fetch to a local QUIC origin succeeds through the packet identity component and through the packet encapsulation component plus its relay. QUIC stays in Go.
8. Repeat the packet proof with a compatible native packet wrapper underneath, verify addresses and datagram boundaries, and replace the packet component without rebuilding fetch. Include a two-peer harness because one HTTP/3 fetch does not establish multi-destination correctness.
9. Load one artifact once and select different constructors at two layers separated by native TLS. Exercise concurrent calls through that graph; no recursive guest entry or session-lock deadlock. Repeat a constructor with different parameters/bases and show independent behavior.

An optional first-write splitting guest can compare behavior with native `split`, but splitting alone is insufficient proof of a replaceable protocol and does not prove TCP segmentation on the wire.

## Milestone 3 — meaningful correctness and performance checks

| Check | Pass condition |
|---|---|
| Full duplex | A blocked read does not prevent writes; simultaneous traffic completes under backpressure |
| Partial I/O | Byte-for-byte delivery, correct counts, no duplication on short reads/writes or errors |
| Lifecycle | Dial cancellation, close during I/O, handshake failure, and shutdown drain release resources |
| Half-close | Remote sees EOF after guest trailers; reply direction remains usable |
| Datagram semantics | Preserve logical boundaries, empty packets, per-packet source/destination and IPv4/IPv6 address types; defined truncation and oversize errors |
| Multiple packet peers | One listener handles independent destinations; bounded state and no cross-peer address/data mix-ups |
| Packet completions | Logical length reported despite framing/preludes; short writes are errors; no suffix retransmission or implicit replay |
| Packet resources | Queue byte/count limits, expansion and reassembly bounds, malformed input, flooding and close during send/receive are tested |
| Deadlines | In-flight deadline updates take effect; read deadline reset works; unrecoverable frame timeout fails explicitly |
| Guest failure | Infinite loop, invalid memory, resource exhaustion, malformed actions and start-section behavior are bounded |
| Composition | Host uses only the injected base; no raw-socket assumptions or surprise local DNS/direct fallback |
| Object ownership | Distinct factories/children keep independent state; only explicitly injected contexts are shared; ordinary release leaves siblings running |
| Session isolation | Different scopes/providers do not share mutable state implicitly; session-fatal errors affect exactly that session and its objects |
| Handles/lifetimes | Reject stale, wrong-type and cross-session handles; release failed construction, late completions and factory/base leases correctly |
| Multi-layer execution | Same-session Wasm/native/Wasm calls never hold guest locks across base I/O; scheduling remains fair |
| Parser | Invalid IDs, duplicate/unknown fields, escaping, and sensitive-error redaction are covered |
| Performance | Record cold preparation, warm dial, per-connection memory, throughput, CPU, binary size, and concurrency scaling |
| Author documentation | Clean environment runs every published build recipe, ABI validation, local harness and fetch example; artifacts match declared profiles |

Compare native control, identity Wasm, and framing Wasm with identical buffers and traffic. Exercise interpreter and compiler where supported. Use bounded concurrency on the ZimaBlade; determine device-appropriate connection limits before load tests. Set numerical production thresholds after measuring and agreeing on a target workload.

Compare one jointly linked artifact with standalone artifacts for dependency/code size, and a shared session with separate sessions per factory for memory/startup/throughput and failure propagation. Distinguish code-cache reuse from linear-memory sharing. Treat placement defaults as provisional until this comparison.

For packets, measure datagrams/second, packet sizes, packet loss under load, latency/jitter, per-peer state and native QUIC on the generic PacketConn path. Do not expose optional socket interfaces that let QUIC bypass the Wasm adapter.

Run focused package tests and race checks, then the SDK-required `x/` checks (tests, staticcheck, license check) before an implementation PR. Run root-module checks if required by contribution policy; no root code change is expected. Keep external network tests behind the repository's `nettest` convention. Prefer deterministic local origins and relays.

## Milestone 4 — mobile and provider-update pilot

- Build and run bundled stream and packet guests through actual Android/iOS bindings. Start in interpreter mode; validate routing/protection, suspend/resume, resource limits and shutdown.
- Implement authenticated catalog, bounded artifact downloads/cache, compatibility checks, and atomic activation. Test corrupted bytes, unknown signer, manifest replay, expired/offline policy, and signed rollback.
- Use a long-running test host to activate artifact B while an A connection remains open. Confirm new dials use B and existing A traffic continues, with bounded retention and eventual cleanup.
- Repeat for packet listeners: existing packet connections and QUIC sessions retain A; new ListenPacket calls use B. Do not replace modules between datagrams on an existing connection.
- Existing factory references stay pinned to A; route new calls through the newly selected B stack rather than mutating a live factory. Retired factory leases drain while their child connections finish. Catalog/constructor/parameter changes are part of the versioned update.
- Demonstrate a broken strategy can be replaced through an independent update path or a pre-cached artifact.
- Resolve distribution constraints before enabling downloaded modules on each mobile channel.

Exit: technical feasibility and rollout eligibility recorded separately for every target platform. A successful desktop fetch demo is not mobile rollout approval.

## Milestone 5 — temporary Wasm to native strategy

Use the same protocol fixtures to validate a native implementation. Advertise native capability in client configuration negotiation, select native for supporting clients, retain Wasm for compatible older clients, and retire the artifact according to provider policy. Measure whether migration improves the specific CPU/memory/startup costs found in the pilot.

## Immediate next step

Specify the Outline V1 stream/packet ABI and component authoring/build contract. The first implementation increment should end at Milestones 1–2: replaceable Wasm stream and packet protocols selected through fetch's existing transport configuration, with the component-developer documentation and reproducible examples shipped alongside the package.
