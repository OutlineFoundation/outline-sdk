// Copyright 2024 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package sysresolver provides a [dns.Resolver] backed by the system's native
// DNS resolution APIs, leveraging the system's configured resolvers and cache.
//
// Platform support:
//   - Android: uses android_res_nquery (NDK), requires CGO
//   - macOS/iOS: uses dns_sd (DNS Service Discovery), requires CGO
//   - Linux and other Unix with CGO: uses libresolv
//   - Windows: uses DnsQueryEx from dnsapi.dll (no CGO required)
//   - Other: uses [net.DefaultResolver] (A and AAAA records only)
//
// All implementations return the full [dnsmessage.Message], so callers can
// inspect any record type even if sysresolver does not have a dedicated parser
// for it. Unknown record types appear as [dnsmessage.UnknownResource].
package sysresolver
