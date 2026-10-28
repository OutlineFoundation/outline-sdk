# Local API-proposal draft: Wasm transport objects

Status: experimental code and supporting research are included in this SDK checkout on branch `spike-wasm-transports`. This is a local review draft, not an accepted upstream API proposal.

Problem: test whether provider-delivered protocol artifacts can add behavior to Outline SDK stream and packet transports while retaining composition and explicit object ownership.

The spike adds `x/wasm` and `x/wasmconfig`, plus opt-in local artifact flags in fetch. One artifact contains several constructors. An explicit Manager owns compiled code; a Session owns guest memory and object handles; Scope controls configuration registration and artifact sharing. Factories create independent StreamConn/PacketConn children. All network access uses injected SDK interfaces. The stable root module is unchanged and remains pinned to a release.

The implemented contract is deliberately narrower than the design: bounded handshake actions plus byte transforms, with packet addresses managed in Go. The result should inform the final asynchronous object ABI rather than freeze this spike interface.

Questions for upstream review: custom core-Wasm ABI versus Component Model resources; minimum Go/runtime versions; structured constructor parameters and typed catalog; object/event scheduling; address-aware packet operations; per-session versus per-factory isolation; and whether a small transform interface is useful independently of the general protocol ABI.
