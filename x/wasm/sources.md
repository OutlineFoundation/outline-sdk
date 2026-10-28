# Sources and evidence

Accessed 2026-09-24. Links to `main` are mutable. Pin exact commits/releases at implementation time.

## Outline SDK

Local source inspected read-only at SDK commit [`d901c4f1f0ccbd00a93fa07a4e325a5c02bb8ad3`](https://github.com/OutlineFoundation/outline-sdk/tree/d901c4f1f0ccbd00a93fa07a4e325a5c02bb8ad3) (2026-09-21), the base of this spike branch. No tracked working-tree changes were reported. This is an available local development snapshot, not a claim about current upstream HEAD.

- [Stream interfaces](https://github.com/OutlineFoundation/outline-sdk/blob/d901c4f1f0ccbd00a93fa07a4e325a5c02bb8ad3/transport/stream.go): `StreamDialer`, `StreamConn`, half-close.
- [Packet interfaces](https://github.com/OutlineFoundation/outline-sdk/blob/main/transport/packet.go): `PacketListener.ListenPacket` returns `net.PacketConn`; local and public raw source inspected for the packet-scope revision.
- [Go PacketConn](https://pkg.go.dev/net#PacketConn): portable packet connection methods and semantics. Adapter-specific datagram policies remain design proposals.
- [Config types and registry](https://github.com/OutlineFoundation/outline-sdk/blob/main/x/configurl/config.go): factories, registration, and pipe parsing. Public raw source also inspected.
- [Provider container](https://github.com/OutlineFoundation/outline-sdk/blob/main/x/configurl/module.go): defaults and separate stream/packet registries. Local snapshot inspected.
- [TLS config](https://github.com/OutlineFoundation/outline-sdk/blob/main/x/configurl/tls.go): existing opaque-query convention. Local snapshot inspected.
- [Fetch](https://github.com/OutlineFoundation/outline-sdk/blob/main/x/tools/fetch/main.go): stream integration for h1/h2 and packet path for h3. Public raw source and local snapshot inspected; web snapshot is older than the local checkout in unrelated QUIC functionality.
- Local SDK `AGENTS.md`: experimental code in `x/`, released root-module pin, no local replaces, permissive dependencies, tests, API-proposal workflow.

Direct shell network access could not resolve public hosts in this session. Public pages were read through web tooling; live upstream HEAD was not independently established.

## Runtime

- [wazero project](https://github.com/wazero/wazero), [documentation](https://wazero.io/docs/): Go runtime and execution model.
- [Runtime and module configuration](https://github.com/wazero/wazero/blob/main/config.go): engine selection, memory bounds, cancellation behavior, cache and module startup controls. Raw source inspected.
- [Function/memory API](https://github.com/wazero/wazero/blob/main/api/wasm.go): function-call concurrency constraints and guest-memory interface. Raw source inspected.
- [Language notes](https://wazero.io/languages/): guest execution/toolchain considerations.
- [Wasmtime Go](https://github.com/bytecodealliance/wasmtime-go): alternative runtime binding; not benchmarked.

## Multi-constructor artifact and object-model references

- [LLVM WebAssembly linker](https://lld.llvm.org/WebAssembly.html): static linking, exports and dead-code elimination; dynamic linking remains a separate mechanism. Inspected 2026-09-24. Supports build-time bundling, not a guarantee of perfect dependency deduplication.
- [Wazero terminology](https://wazero.io/docs/): binary, compiled module and module instance are distinct; repeated instantiation permits separate execution state from the same prepared code.
- [WIT resources](https://component-model.bytecodealliance.org/design/wit.html#resources): standardized object-like constructors, methods and owned/borrowed handles. A substantive alternative to a custom object ABI; no assertion that Component Model binaries run in the proposed embedding without additional integration.

## Existing WebAssembly transport work (historical)

Decision from the user, 2026-09-24: WATER interfaces are inappropriate for this project. The sources below are historical prior art only; no adoption spike or WATER interface compatibility is planned.

- [WATER current repository](https://github.com/water-transports/water-go): redirected from `refraction-networking/water`; README inspected.
- [WATER package API](https://pkg.go.dev/github.com/refraction-networking/water): inspected rendering identifies v0.6.4 (2024-03-18), explicitly not the latest package version. Shows dialer injection; insufficient to establish current implementation compatibility.
- [WATER Go overview](https://water.refraction.network/runtime/go.html), [WATM specification](https://water.refraction.network/transport-module/spec.html): discovered through indexed excerpts; direct opens failed. Do not treat these as fully reviewed ABI specifications.
- [Just add WATER paper](https://arxiv.org/abs/2312.00163): authors' abstract establishes prior art in dynamically supplied Wasm circumvention transports; full paper not reviewed in this phase.

## Mobile distribution

- [Apple App Review Guidelines](https://developer.apple.com/app-store/review/guidelines/#software-requirements), section 2.5.2: downloaded-code restrictions. This creates an unresolved rollout question, not a determination about a particular submission.
- [Google Play Developer Program Policy](https://support.google.com/googleplay/android-developer/answer/16313518?hl=en): indexed policy text includes conditions on runtime-loaded interpreted code. Revalidate applicable current policy for the chosen distribution channel before activation.

At the initial design stage, no performance, interoperability, or mobile runtime tests had been run. Subsequent local implementation and validation are recorded in [spike-results.md](spike-results.md); no mobile runtime execution or performance benchmark has been completed. The event ABI, package names, flags, limits, and rollout design are proposals derived from the requirements and inspected interfaces.
