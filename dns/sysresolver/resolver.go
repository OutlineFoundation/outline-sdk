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

package sysresolver

import "golang.getoutline.org/sdk/dns"

// NewResolver returns a [dns.Resolver] backed by the platform's native system DNS API.
// It wraps [NewRawResolver] and parses the wire-format response using
// golang.org/x/net/dns/dnsmessage. Use [NewRawResolver] directly to parse
// the response with a different library.
func NewResolver() dns.Resolver {
	return dns.RawToResolver(NewRawResolver())
}
