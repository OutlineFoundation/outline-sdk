# Write and build a component for the spike

This is documentation for the code in this checkout. It intentionally describes the smaller implemented ABI, not the broader draft design.

## Build prerequisites

Tested: Debian clang/lld **19.1.7**, target `wasm32-unknown-unknown`, and Go **1.25.5**. The guest needs no libc, WASI, Rust, JavaScript, or system socket imports. Install `clang-19` and `lld-19` through your normal development-tool setup, or point `CLANG` and `WASM_LD` at those executables.

From the SDK repository root:

```sh
sh x/wasm/examples/build-all.sh
go test -C x -p 2 -tags nettest -run TestFetchCLI -v ./wasm
```

`build-all.sh` creates `examples/bundle.wasm`, `examples/bundle-v2.wasm`, and two deliberately failing fixtures in `testdata/`. It prints their SHA256 values. The loop/trap fixtures are only for containment tests. To build one artifact:

```sh
VARIANT=1 OUT=my-bundle.wasm sh x/wasm/examples/build.sh
```

Output paths are relative to `x/wasm/examples/`. Changing `VARIANT=2` changes the stream handshake version, packet envelope version, and XOR byte encoding, without modifying fetch. Generated `.wasm` files in this checkout correspond to their checked-in C source and build commands.

## Add a named constructor

Read [bundle.c](../examples/bundle.c) and the [ABI reference](abi.md). The small example keeps all constructors in one translation unit; a larger implementation can compile multiple C objects and link them into the same module using the same build entrypoint.

1. Add a stable constructor name to the immutable catalog and `describe` interface lookup.
2. Dispatch it from `object_create`. Validate its integer/relay parameters and allocate a **factory object in the supplied Session**. Store no active constructor/configuration in a mutable global.
3. Make `object_open` create an independent child object from the factory. Do not reuse one child for every connection. Store per-connection state, such as handshake progress, in that child. Object handles combine slot index and generation; release clears the slot and a reused slot gets a new generation.
4. Implement the relevant child operations. Stream constructors may choose a target, run handshake steps, choose write chunk sizes and transform bytes. Packet constructors transform complete datagrams.
5. Keep all guest calls bounded. Return a handshake action when I/O is needed; Go performs it after releasing the session lock. Never poll or wait inside Wasm for network data.
6. Add conformance tests, rebuild the artifact, and run fetch against a compatible local peer. A new wire protocol needs a matching peer; an ordinary HTTPS server only understands the identity/splitting variants.

The common object arena and helper functions are linked in the same file as all five implementations. This proves multi-constructor packaging and runtime reuse; it is not evidence of automatic deduplication across independently compiled third-party libraries.

## Writing a stream implementation

`dial_target` receives the requested destination in a scratch buffer and can replace it with the configured relay address. The Go host still uses the factory's injected SDK base dialer. There is no direct socket import.

For `stream.xor`, child handshake state emits a four-byte `OW` request, requests four response bytes, validates an `OK` acknowledgment, and reports ready. The host only interprets generic send/read/ready actions; the request bytes and protocol validation live in Wasm. The peer accepts the two fixture protocol versions.

After readiness, `transform` encodes/decodes stream buffers in place. This spike requires equal input/output lengths. `stream.split` uses `write_limit` and its child's first-write state to request a small first base write. This does not promise TCP packet segmentation.

Test full-duplex reads/writes, partial I/O, deadline reset, canceled setup, closing a write half, and ordinary object close. Changes in one factory's parameters must not affect other factories. The host releases the guest lock before base I/O, allowing `Wasm(TLS(Wasm(TCP)))` inside one session.

## Writing a packet implementation

`transform` sees one datagram and an encode/decode flag. `packet.xor` adds or removes a four-byte header and XORs the remaining bytes. The Go adapter retains each packet's source/destination and reports the original logical write length. Empty datagrams are supported. An undersized caller read buffer discards that datagram's remainder; the next read receives the next datagram.

The current guest does not receive addresses, so it cannot implement arbitrary address-aware proxy envelopes yet. Test multiple peers through one PacketConn and several PacketConns from the same listener. Oversize data or failed transformations return errors; malformed input currently fails that read operation rather than implementing a silent drop/retry policy.

## Debugging and distribution

Run tests with `-v`, and fetch with `-v` for HTTP negotiation and compiled-artifact count. The fixture records stream/packet protocol versions so the integration test verifies wire behavior as well as the response. Host errors name the failed guest export. For richer guest traces, build without `--strip-all` and add compiler debug information; this has not been turned into a supported source-level debugger workflow.

Use `Session.Catalog`, `Session.Calls`, and `Manager.CompiledCount` in a harness. The same numeric handle has meaning only with its owning session; use typed Go wrappers rather than passing handles between sessions. Factory close preserves children; session failure does not.

Distribute sample artifacts only as trusted local test inputs through `-wasm-module ID=PATH`. Remote delivery, signing, generalized parameter schemas, typed catalogs, and mobile rollout require further implementation. See the [package README](../README.md) for executable CLI examples and boundaries.
