# Outline Wasm transport spike

Local proof of concept, not a released API. One **2.2 KiB freestanding C/Wasm artifact** exposes five named constructors. Explicit sessions contain multiple factory and connection objects. The host uses wazero v1.12.0 (Go 1.25 minimum), defaulting to its interpreter.

| Constructor | Interface | Parameters | Behavior implemented in Wasm |
|---|---|---|---|
| `stream.identity` | StreamDialer | none | Stream identity |
| `stream.split` | StreamDialer | `split=3` | Splits the first nonempty write into separate base writes |
| `stream.xor` | StreamDialer | `key=37`, optional `relay=HOST:PORT` | Selects dial target, performs request/ack handshake, XORs subsequent bytes |
| `packet.identity` | PacketListener | none | Datagram identity |
| `packet.xor` | PacketListener | `key=37` | Adds/checks a four-byte envelope and XORs each datagram |

**XOR is a test encoding, not encryption.** The relays are loopback-only fixtures with fixed upstream targets. No censorship-effectiveness claim is made.

See [component authoring/build guide](docs/components.md) and [ABI reference](docs/abi.md). Guest sources and small generated artifacts are included so Go tests do not require a C compiler. No WATER interface/runtime is used. The existing SDK dependency named `songgao/water` is an unrelated native TUN/TAP package.

## Findings and research

This branch includes the implementation, research, authoring documentation, examples and recorded validation logs. Start with [spike results](spike-results.md) for what was demonstrated and what remains untested, then use the reproduction commands below.

| Resource | Purpose |
|---|---|
| [Spike results](spike-results.md) | Implemented behavior, validation evidence, limitations and next decisions; [original logs](results/) are from 2026-09-24. |
| [Component authoring guide](docs/components.md) and [implemented ABI](docs/abi.md) | Build and extend the working C/Wasm examples; these describe the executable contract. |
| [Architecture design](design.md) | Broader proposed stream/packet ABI, composition, runtime and delivery design. |
| [Object model](object-model.md) | Constructors, factories, connections, explicit ownership and session isolation trade-offs. |
| [API-proposal draft](spike-api-proposal.md) | Experimental API scope and questions for upstream review. |
| [Implementation plan](implementation-plan.md) | Broader milestones, including work beyond the implemented spike. |
| [Design-level developer guide](component-developer-guide.md) | Proposed authoring workflow and acceptance criteria for the broader ABI; use the component authoring guide above for runnable instructions. |
| [Sources](sources.md) | Inspected versions, primary references and evidence boundaries. |

The design documents describe a broader target than the implemented spike. They are proposals, not released APIs or promises of mobile support.

## Run by branch name

The branch is named `wasm-research` so it can be used directly in Go version queries. Run fetch from the upstream Outline SDK branch with Go 1.25 or later:

```sh
go run golang.getoutline.org/sdk/x/tools/fetch@wasm-research -h
```

This command downloads and runs fetch from the branch; it does not copy example Wasm artifacts into your working directory. For the examples below, obtain the artifacts from the same branch and supply their local paths with `-wasm-module`. To use the local SDK checkout instead, run `go run -C x ./tools/fetch -h` from its root.

## Reproduce the fetch proof

From the SDK repository root, using Go 1.25 or later:

```sh
go test -C x -p 2 -tags nettest -run TestFetchCLI -v ./wasm
go test -C x -p 2 -race -tags nettest ./wasm ./wasmconfig ./tools/fetch
```

The integration test builds fetch once, starts loopback HTTPS/HTTP2/HTTP3 origins and matching protocol relays, trusts only the public fixture certificate through `SSL_CERT_FILE`, and verifies the entire 225,000-byte response. It checks negotiated HTTP versions, same-session Wasm/native TLS/Wasm composition, packet nesting, interpreter/compiler execution, and replacement of stream and packet protocol versions with an unchanged fetch executable hash. No Internet origin is required. The first Go build may download dependencies.

For manual exploration:

```sh
mkdir -p bin
go build -C x -o ../bin/fetch ./tools/fetch
go build -C x -o ../bin/wasm-fixture ./wasm/cmd/fixture
./bin/wasm-fixture -cert /tmp/outline-wasm-ca.pem
```

Leave the fixture running. It prints JSON containing `https`, `h3`, `stream_relay`, `tls_relay`, and `packet_relay` endpoints. In another terminal, set `ORIGIN` to `https` and `TLS_RELAY` to `tls_relay` from that output, then run:

```sh
SSL_CERT_FILE=/tmp/outline-wasm-ca.pem ./bin/fetch -v -proto h2 \
  -wasm-module demo=./x/wasm/examples/bundle.wasm \
  -transport "wasm:module=demo&component=stream.split&split=3|tls:sni=example.com&certname=127.0.0.1|wasm:module=demo&component=stream.xor&key=37&relay=$TLS_RELAY" \
  "$ORIGIN"
```

For HTTP/3, set `H3_ORIGIN` and `PACKET_RELAY` from the fixture output:

```sh
SSL_CERT_FILE=/tmp/outline-wasm-ca.pem ./bin/fetch -v -proto h3 \
  -wasm-module demo=./x/wasm/examples/bundle.wasm \
  -transport 'wasm:module=demo&component=packet.xor&key=37' \
  -address "$PACKET_RELAY" "$H3_ORIGIN"
```

Change only `bundle.wasm` to `bundle-v2.wasm` to exercise a different handshake/envelope version and byte encoding. Add `-wasm-compiler` to compare wazero's compiler with its default interpreter. Stop the fixture with Ctrl-C. Its private TLS key exists only in memory; the written certificate is public test data.

## Ownership and composition

`Manager` owns prepared code and sessions. `Manager.NewSession` reuses compilation by artifact SHA256 but creates distinct guest memory. `wasmconfig.Scope` explicitly shares a session between aliases/layers of the same artifact within that scope. Registration is per provider container, with no package-global runtime, registry, active dialer or configuration.

`Session.NewStreamDialer` and `Session.NewPacketListener` invoke named guest constructors. Each creates a distinct factory handle. Factory methods create generation-checked connection handles, copying immutable factory parameters into child objects. Closing a factory prevents new children and leaves existing ones usable. Closing a connection leaves siblings usable. Session closure aborts its pending setups and established base connections. Scope/manager closure is explicit; injected base factories remain caller-owned.

Only short guest calls hold the session mutex. Base dial/read/write/listen operations run outside it, so a nested native layer may call another object in the same session without deadlock. Go runs blocking I/O on caller goroutines; this spike does not yet have a general event dispatcher or guest scheduler.

## Scope and limitations

- This is ABI **spike version 1**, not the complete proposed `outline_transport_v1` contract. It implements a bounded send/read/ready handshake and synchronous buffer transforms. Stream transforms must preserve length; arbitrary buffered framing, timers, multiple outstanding guest actions and general asynchronous protocol state machines are follow-on work.
- Packet boundaries, empty packets, per-packet Go addresses, multiple peers, deadlines and close are preserved. Guest functions currently see payload bytes only; address-aware encapsulation/rewriting in the guest is not implemented. The test packet relay has a fixed upstream. No guest-side DNS, QUIC implementation, cross-profile transport or optional raw socket interfaces.
- The constructor ABI accepts one integer plus an optional stream relay address. `wasmconfig` validates the sample constructors' options; generic schema/parameter records and a machine-readable typed constructor catalog remain design work.
- One session has 256 guest object slots and initially 320 KiB linear memory (including scratch space). Every guest call has a two-second termination fuse; guest memory is capped at 16 MiB and local artifact reads at 4 MiB. Trap/timeout kills the session and all of its objects. Per-object memory isolation, fair scheduling, aggregate resource budgets, authenticated downloads and hot activation are not implemented.
- Load only explicitly trusted local artifacts. Signature verification and full adversarial ABI validation are not provided. The host rejects imports and validates required signatures, but this is not a production sandbox review.
- Linux x86-64 interpreter and compiler were exercised. Physical Android/iOS behavior, store distribution and realistic throughput/battery costs remain unvalidated. The guest has no dependencies beyond its own shared code; large-library deduplication has not been measured.

Status and measurements for this checkout are recorded in [spike results](spike-results.md). Next implementation decision: retain this small transform API as a useful subset, or expand it into object-addressed events/actions for protocols needing buffered stream output and packet-address control.
