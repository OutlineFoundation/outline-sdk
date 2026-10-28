# Implemented spike ABI v1

Core Wasm module with exported linear `memory`, no imported functions/memory, and the functions below. All parameters and results are `i32`; pointers are wasm32 offsets. Operations returning lengths/actions use `0xffffffff` as failure. Factory/child handles use zero as failure, low 16 bits for slot+1 and high 16 bits for generation. A slot retires before generation wrap. The host checks required export signatures.

| Export | Arguments | Result |
|---|---|---|
| `abi_version` | — | `1` |
| `catalog_ptr`, `catalog_len` | — | Pointer/length of immutable newline-delimited names |
| `session_size` | — | Arena bytes; at most 1 MiB accepted by host |
| `session_init` | arena | Initialize a freshly zeroed host-allocated arena |
| `describe` | name pointer, length | 1 = stream factory, 2 = packet factory, 0 = unknown |
| `object_create` | arena, name pointer, length, integer parameter, relay pointer, relay length | New factory handle |
| `object_open` | arena, factory handle | New connection handle with independent state |
| `object_release` | arena, handle | 1 = released, 0 = invalid/stale |
| `dial_target` | arena, child, buffer, input length | Output address length |
| `handshake` | arena, child, buffer, input length | Ready/send/read action or failure |
| `write_limit` | arena, child, proposed write length | Next stream write length (1..proposed) |
| `transform` | arena, child, encode flag, buffer, input length | Output length or failure |

Handshake result `0` means ready. `(1 << 16) | n` requests writing `n` bytes from the buffer; the next call receives zero input bytes. `(2 << 16) | n` requests reading exactly `n` bytes into the buffer before the next call. The host caps a handshake at 16 actions and the caller's setup context bounds network waiting. In V1, handshake errors are fatal to that connection.

The host grows memory to append an arena and 65,536-byte scratch region; the guest uses no allocator/heap. All mutable protocol state is in the passed arena. Constructor names occupy at most 256 bytes and relay addresses at most 255 bytes. `object_open` copies configuration into a child, so releasing its factory does not invalidate it. There is no shared mutable factory state in this example.

Guest buffer contents are borrowed only during a serialized call. The host copies outputs before unlocking or doing I/O. A host application write is split into chunks of at most 65,528 bytes. Stream transforms must preserve length. Packet transforms can expand within the scratch limit; the host limits encoded reads to 65,532 bytes. Raw UDP may impose a smaller payload limit. Zero-length datagrams are valid.

Host methods preserve Go addresses and deadlines outside this ABI. Stream and packet factories hold injected base interfaces; guest target/handshake/transform functions cannot select a different host capability. Session setup, close and cancellation are host-owned. Instantiation is bounded by the preparation context; each exported call has a two-second fuse. A trap or call timeout cancels the session and closes its established/pending I/O. Normal connection or factory errors do not affect other objects.

This is a spike contract. General events/actions, timers, address marshaling, structured parameters, a typed catalog, multi-buffer ownership, buffered stream framing, hot activation and capability negotiation have not been implemented. Do not treat ABI version 1 as a published compatibility promise.
