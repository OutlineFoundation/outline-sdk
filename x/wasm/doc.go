// Copyright 2026 The Outline Authors. SPDX-License-Identifier: Apache-2.0

// Package wasm is a local experimental spike for object-based Wasm Outline
// transports. A Manager caches prepared artifacts; explicit Sessions own guest
// memory and independent stream/packet factories and connections. Guest calls
// are short and serialized; no session lock is held across base network I/O.
//
// This is a deliberately small transform/handshake ABI, not the complete
// proposed asynchronous protocol ABI or an untrusted-code distribution system.
// See README.md and docs/components.md for executable examples and limitations.
package wasm
