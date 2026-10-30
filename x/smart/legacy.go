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
	"sync"
	"time"

	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/x/configurl"
)

// StrategyFinder searches for working DNS, TLS, and fallback strategies.
// Do not change its fields or fallback registrations while NewDialer is running,
// or copy it after its first use.
//
// Deprecated: Use [NewFinderOptions] to create a [Finder] instead.
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
	// passed to FinderOptions.SetConfigURLRegistry instead.
	StreamDialer transport.StreamDialer
	// PacketDialer is the packet base. Nil uses a [transport.UDPDialer].
	//
	// Deprecated: Use configurl.RegisterBase[transport.PacketDialer] on the registry
	// passed to FinderOptions.SetConfigURLRegistry instead.
	PacketDialer transport.PacketDialer

	// registryOnce initializes the legacy base constructors before concurrent searches.
	registryOnce    sync.Once
	registry        configurl.Registry
	fallbackParsers map[string]FallbackParser
}

// initLegacyRegistry registers base constructors that read the current legacy
// dialer fields. Changes between searches affect new dialers, while previously
// constructed dialers keep their original bases.
func (f *StrategyFinder) initLegacyRegistry() {
	registry := configurl.NewDefaultRegistry()
	defaultSD := &transport.TCPDialer{}
	newStreamDialer := func(context.Context, configurl.Registry, *configurl.Config) (transport.StreamDialer, error) {
		if streamDialer := f.StreamDialer; streamDialer != nil {
			return streamDialer, nil
		}
		return defaultSD, nil
	}
	configurl.RegisterBase(registry, newStreamDialer)
	defaultPD := &transport.UDPDialer{}
	newPacketDialer := func(context.Context, configurl.Registry, *configurl.Config) (transport.PacketDialer, error) {
		if packetDialer := f.PacketDialer; packetDialer != nil {
			return packetDialer, nil
		}
		return defaultPD, nil
	}
	configurl.RegisterBase(registry, newPacketDialer)
	f.registry = registry
}

// RegisterFallbackParser registers or replaces the parser for a YAML fallback type.
// Finish registrations before calling NewDialer.
func (f *StrategyFinder) RegisterFallbackParser(name string, parser FallbackParser) {
	if f.fallbackParsers == nil {
		f.fallbackParsers = make(map[string]FallbackParser)
	}
	f.fallbackParsers[name] = parser
}

// NewDialer implements [Finder]. Changes to fields and fallback registrations
// between calls affect subsequent searches. Previously returned dialers retain
// their original bases.
func (f *StrategyFinder) NewDialer(ctx context.Context, testDomains []string, config []byte) (transport.StreamDialer, error) {
	f.registryOnce.Do(f.initLegacyRegistry)
	// Snapshot the mutable legacy configuration for this search. Do not apply the
	// new options validation here: legacy callers may use zero-valued options.
	delegate := &finder{
		registry:        f.registry,
		testTimeout:     f.TestTimeout,
		logWriter:       f.LogWriter,
		cache:           f.Cache,
		fallbackParsers: maps.Clone(f.fallbackParsers),
	}
	return delegate.NewDialer(ctx, testDomains, config)
}
