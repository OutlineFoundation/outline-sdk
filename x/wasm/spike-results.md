# Fetch Wasm spike results

Implemented and tested locally on 2026-09-24, on Debian x86-64. The isolated [SDK checkout](../../) is on `spike/wasm-transports`, based on `d901c4f1f0ccbd00a93fa07a4e325a5c02bb8ad3`. At the time of validation, no changes were published and the original research checkout was not modified. Research documents and validation logs were consolidated into `x/wasm/` on 2026-10-28; the recorded test results below are from 2026-09-24.

## What the proof establishes

- One linked Wasm artifact exposes five named constructors: stream identity, splitting and handshake/XOR; packet identity and envelope/XOR. The provider selects a constructor through `wasm:module=demo&component=…` in the existing transport URL stack.
- Both `StreamDialer` and `PacketListener` are implemented. Objects have independent parameters and generation-checked handles. Factories can create multiple children; closing a factory preserves live children. No package-global active transport, manager or configuration is used.
- Multiple layers use the same artifact/session, including `Wasm(TLS(Wasm(TCP)))`. Compiled code is cached by digest. Guest calls are serialized, but network I/O runs outside the session lock, allowing nested composition and simultaneous stream reads/writes.
- Fetch HTTP/1, HTTP/2 and HTTP/3 complete against local peers. Native QUIC runs above the Wasm packet listener. Every integration case verifies all 225,000 response bytes and the negotiated HTTP version.
- The integration test builds fetch once, changes only the supplied Wasm artifact for stream and packet protocol version 2, verifies the new wire version, and checks that the executable hash is unchanged. This demonstrates artifact selection between invocations, not live replacement of established connections.
- Packet tests cover multiple peers, empty datagrams, truncation, deadlines and independent listener children. Stream tests cover duplex traffic, deadlines, half-close and setup cancellation. Trap/loop tests exercise session failure containment; object exhaustion and stale handles are tested.

The XOR protocols are toy encodings, not encryption. Relays have fixed local upstreams. This proves extensibility, not censorship resistance.

## Run and extend it

See the [package README](README.md) for executable fetch examples, the [component developer guide](docs/components.md) for writing and building guests, and the [implemented ABI](docs/abi.md). The [local API proposal](spike-api-proposal.md) is a review draft.

From the SDK checkout:

```sh
go test -C x -p 2 -tags nettest -run TestFetchCLI -v ./wasm
go test -C x -p 2 -race -tags nettest ./wasm ./wasmconfig ./tools/fetch
```

Go dependencies may need downloading; tests use loopback services. Generated Wasm fixtures are included. Rebuilding them uses Clang/LLD 19.1.7, with no libc or WASI, through `sh x/wasm/examples/build-all.sh`. C was chosen for a small, inspectable ABI experiment; proposed Rust bindings remain future work.

## Validation evidence

| Check | Result |
|---|---|
| Focused tests and fetch integration | Passed; [verbose log](results/fetch-spike.log) |
| Focused race tests including fetch integration | Passed; [race log](results/race.log) |
| Full `x` module regression suite with race detector | Passed; final setup-cancellation changes additionally covered by the focused race run |
| Full `x` module `go tool staticcheck ./...` | Passed with a writable temporary `XDG_CACHE_HOME` |
| Android arm64, `CGO_ENABLED=0`, build of `./wasm ./wasmconfig` | Passed; library cross-compilation only |
| iOS, gomobile embedding and physical mobile execution | Not tested |
| License checker | The broad check rejected existing `gorilla/websocket` BSD-2-Clause because the repository command omits that license from its allowlist. No blanket license-check pass is claimed; new wazero and updated x/sys source licenses are Apache-2.0 and BSD-3-Clause. |

Tests used Go 1.25.5 and wazero 1.12.0. The interpreter is the default; the compiler engine also passed the HTTP/2 integration case. Initial failures caused by an incomplete reused dependency cache were resolved with a fresh cache before recording the successful runs. Local HTTP/3 emitted a UDP receive-buffer-size warning; this did not prevent correctness tests. No benchmark or runtime ranking is claimed.

Artifacts rebuilt from the included source:

| Artifact | Bytes | SHA256 |
|---|---:|---|
| `bundle.wasm` | 2158 | `225871394aa896b1b385b856303ed8c8cb93f2cafca6d5242976c6622de77c23` |
| `bundle-v2.wasm` | 2167 | `b0bbfb49deb275d431ece1cc49198a7834d13b34fd53f0315930e96c2432e395` |

The final integration log records unchanged fetch SHA256 `61bd60f4ed40d3c546bfd14217f8434b784f0db83f85884d625a766e5b6a15c4` across artifact versions. Hashes are evidence for this local build, not a reproducible-Go-binary guarantee.

## Trade-offs and next design decisions

| Spike choice | Benefit | Cost / alternative |
|---|---|---|
| Single core-Wasm module, named object constructors | Shared linked helpers and compiled code; multiple layers and objects | Shared memory/fatal-failure domain within a session. Separate sessions isolate state at additional memory cost. Large third-party dependency deduplication remains unmeasured. |
| Explicit session and object arena | No mutable global transport state; predictable ownership | Fixed 256-object capacity in the example; production allocation policy remains open. |
| Short synchronous guest calls, Go-owned I/O | Straightforward SDK composition, no blocking guest socket imports | Current transforms cannot buffer arbitrary stream frames. A richer event/action ABI is needed for general protocols. |
| wazero interpreter by default | Pure-Go embedding and no JIT assumption | Performance needs measurement; optional compiler passed locally. Runtime version raises the x module Go minimum to 1.25 and updates x/sys. |
| Freestanding C guest | Tiny buildable proof with visible object layout | Manual ABI bindings; Rust bindings or a standardized resource interface may offer better author ergonomics at additional integration cost. |

The runtime enforces a 16 MiB memory ceiling and two-second guest-call fuse. The sample starts at 128 KiB and the host adds three pages for arena/scratch, totaling 320 KiB of linear memory per session. These are experimental limits, not a production resource policy. A timeout/trap kills all objects sharing that session.

The implemented ABI is deliberately smaller than the design proposal:

1. Streams support bounded handshake actions, write splitting and length-preserving transforms. Add buffered framing, I/O completions, timers and backpressure before treating it as a general protocol engine.
2. Packet addresses are preserved by Go but are not visible to the guest. Add typed source/destination addresses and rewrite actions for arbitrary proxy encapsulation. Packet-listener support exists today; address-aware guest protocols do not.
3. Constructor configuration currently supports one integer plus a relay string. Add versioned parameter schemas and a typed catalog instead of extending a hard-coded parser indefinitely.
4. Artifacts are explicitly supplied trusted local files. Remote retrieval, authentication, rollback, activation of new strategies and retention of old sessions are not implemented.
5. Validate actual Android/iOS embedding and distribution constraints independently. Android cross-compilation is not proof of mobile runtime behavior.

Next recommended step: use these tests and examples to review the full event/action ABI, implementing guest-visible packet addresses and one length-changing stream protocol before freezing an SDK API.
