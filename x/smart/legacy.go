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

package smart

import (
	"context"
	"io"
	"maps"
	"reflect"
	"sync"
	"time"

	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/x/configurl"
)

// StrategyFinder searches for working DNS, TLS, and fallback strategies.
// Each NewDialer call copies the fields and fallback registrations when it starts.
// Do not change them concurrently with NewDialer calls.
//
// Deprecated: Use [NewFinderConfig] to create a [Finder] instead.
type StrategyFinder struct {
	// TestTimeout is the timeout for each connectivity test.
	TestTimeout time.Duration
	// LogWriter receives strategy selection logs; nil disables logging.
	LogWriter io.Writer
	// Cache stores successful strategies for later searches; nil disables caching.
	Cache StrategyResultCache

	// StreamDialer is the stream base. Nil uses a [transport.TCPDialer].
	//
	// Deprecated: Use configurl.RegisterBase[transport.StreamDialer] on the registry
	// passed to FinderConfig.SetConfigURLRegistry instead.
	StreamDialer transport.StreamDialer
	// PacketDialer is the packet base. Nil uses a [transport.UDPDialer].
	//
	// Deprecated: Use configurl.RegisterBase[transport.PacketDialer] on the registry
	// passed to FinderConfig.SetConfigURLRegistry instead.
	PacketDialer transport.PacketDialer

	fallbackParsers map[string]FallbackParser
}

// legacyDefaultRegistry is shared by all legacy searches and never modified, so
// concurrent searches can read it. Its stream and packet bases are the stable
// defaults used when the legacy dialer fields are nil.
var legacyDefaultRegistry = sync.OnceValue(func() configurl.Registry {
	return configurl.NewDefaultRegistry()
})

// RegisterFallbackParser registers or replaces the parser for a YAML fallback type.
// Finish registrations before calling NewDialer.
func (f *StrategyFinder) RegisterFallbackParser(name string, parser FallbackParser) {
	if f.fallbackParsers == nil {
		f.fallbackParsers = make(map[string]FallbackParser)
	}
	f.fallbackParsers[name] = parser
}

// newFinder copies the legacy configuration for one search. The registry
// overrides only the bases whose legacy fields are set; nil fields fall through
// to the shared defaults. Do not apply FinderConfig validation here: legacy
// callers may use zero-valued fields.
func (f *StrategyFinder) newFinder() *finder {
	bases := registryMap{}
	if streamDialer := f.StreamDialer; streamDialer != nil {
		parseStreamDialer := func(context.Context, configurl.Registry, *configurl.Config) (transport.StreamDialer, error) {
			return streamDialer, nil
		}
		bases[reflect.TypeFor[transport.StreamDialer]()] = map[string]any{
			"": configurl.Parser[transport.StreamDialer](parseStreamDialer),
		}
	}
	if packetDialer := f.PacketDialer; packetDialer != nil {
		parsePacketDialer := func(context.Context, configurl.Registry, *configurl.Config) (transport.PacketDialer, error) {
			return packetDialer, nil
		}
		bases[reflect.TypeFor[transport.PacketDialer]()] = map[string]any{
			"": configurl.Parser[transport.PacketDialer](parsePacketDialer),
		}
	}
	return &finder{
		registry:        overlayRegistry{top: bases, bottom: legacyDefaultRegistry()},
		testTimeout:     f.TestTimeout,
		logWriter:       f.LogWriter,
		cache:           f.Cache,
		fallbackParsers: maps.Clone(f.fallbackParsers),
	}
}

// NewDialer implements [Finder]. Changes to fields and fallback registrations
// between calls affect subsequent searches. Previously returned dialers retain
// their original bases.
func (f *StrategyFinder) NewDialer(ctx context.Context, testDomains []string, config []byte) (transport.StreamDialer, error) {
	return f.newFinder().NewDialer(ctx, testDomains, config)
}
