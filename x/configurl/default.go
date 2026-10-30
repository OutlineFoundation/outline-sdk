// Copyright 2026 The Outline Authors
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

package configurl

// NewDefaultRegistry creates a registry with default bases and built-in parsers.
func NewDefaultRegistry() MutableRegistry { return RegisterDefaultTypes(NewRegistry()) }

// RegisterDefaultTypes registers the built-in config URL parsers, preserving bases.
func RegisterDefaultTypes(registry MutableRegistry) MutableRegistry {
	// Please keep the list in alphabetical order.
	Register(registry, "disorder", parseDisorderDialer)
	Register(registry, "do53", parseDO53StreamDialer)
	Register(registry, "doh", parseDOHStreamDialer)

	Register(registry, "h2connect", parseH2ConnectStreamDialer)
	Register(registry, "h3connect", parseH3ConnectStreamDialer)
	Register(registry, "httpconnect", parseHTTPConnectStreamDialer)

	Register(registry, "override", parseOverrideStreamDialer)
	Register(registry, "override", parseOverridePacketDialer)

	Register(registry, "quicprelude", parseQUICPreludePacketListener)

	Register(registry, "socks5", parseSOCKS5StreamDialer)
	Register(registry, "socks5", parseSOCKS5PacketDialer)
	Register(registry, "socks5", parseSOCKS5PacketListener)

	Register(registry, "split", parseSplitStreamDialer)

	Register(registry, "ss", parseShadowsocksStreamDialer)
	Register(registry, "ss", parseShadowsocksPacketDialer)
	Register(registry, "ss", parseShadowsocksPacketListener)

	Register(registry, "tls", parseTLSStreamDialer)

	Register(registry, "tlsfrag", parseTLSFragStreamDialer)

	Register(registry, "ws", parseWebsocketStreamDialer)
	Register(registry, "ws", parseWebsocketPacketDialer)
	return registry
}
