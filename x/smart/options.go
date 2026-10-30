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
	"errors"
	"fmt"
	"io"
	"maps"
	"time"

	"golang.getoutline.org/sdk/x/configurl"
)

// FinderOptions configures a [Finder]. Setters collect options;
// [FinderOptions.New] validates them. Finish all configuration, including
// registry and fallback registrations, before calling New. Concurrent New calls
// are supported after setup.
type FinderOptions struct {
	// testTimeout is the positive timeout for each connectivity test.
	testTimeout time.Duration
	// logWriter receives strategy selection logs; nil disables logging.
	logWriter io.Writer
	// cache stores successful strategies for later searches; nil disables caching.
	cache StrategyResultCache
	// configURLRegistry is shared by the finders created from these options.
	// If nil, each New call creates a fresh default registry.
	configURLRegistry configurl.Registry
	// fallbackParsers maps YAML fallback type names to parsers. New copies this map
	// into each finder so later changes to the options do not affect existing finders.
	fallbackParsers map[string]FallbackParser
}

// NewFinderOptions creates options with a five-second test timeout.
func NewFinderOptions() *FinderOptions {
	return &FinderOptions{testTimeout: 5 * time.Second}
}

// SetConfigURLRegistry shares registry with the finders created by New. A nil
// registry selects a fresh default registry for each New call. Complete
// registrations before New. Finders only look up parsers in this registry;
// each TLS search uses a separate wrapper to supply its selected DNS dialer.
func (o *FinderOptions) SetConfigURLRegistry(registry configurl.Registry) *FinderOptions {
	o.configURLRegistry = registry
	return o
}

// SetTestTimeout sets the positive timeout for each connectivity test.
func (o *FinderOptions) SetTestTimeout(timeout time.Duration) *FinderOptions {
	o.testTimeout = timeout
	return o
}

// SetLogWriter sets the optional destination for strategy selection logs.
func (o *FinderOptions) SetLogWriter(writer io.Writer) *FinderOptions {
	o.logWriter = writer
	return o
}

// SetCache sets the optional cache of successful strategies.
func (o *FinderOptions) SetCache(cache StrategyResultCache) *FinderOptions {
	o.cache = cache
	return o
}

// RegisterFallbackParser registers or replaces a parser for a YAML fallback type.
// A parser can capture the registry passed to SetConfigURLRegistry to construct
// nested config URLs using the same component registrations and base instances.
func (o *FinderOptions) RegisterFallbackParser(name string, parser FallbackParser) *FinderOptions {
	if o.fallbackParsers == nil {
		o.fallbackParsers = make(map[string]FallbackParser)
	}
	o.fallbackParsers[name] = parser
	return o
}

// New validates the options and creates a finder without performing network I/O.
// It snapshots the options and fallback registrations, sharing the registry, cache,
// and log writer by reference. The returned finder is ready to search.
func (o *FinderOptions) New() (Finder, error) {
	if o.testTimeout <= 0 {
		return nil, errors.New("test timeout must be positive")
	}
	for name, parser := range o.fallbackParsers {
		if parser == nil {
			return nil, fmt.Errorf("fallback parser %q must not be nil", name)
		}
	}
	registry := o.configURLRegistry
	if registry == nil {
		registry = configurl.NewDefaultRegistry()
	}
	return &finder{
		testTimeout:     o.testTimeout,
		logWriter:       o.logWriter,
		cache:           o.cache,
		registry:        registry,
		fallbackParsers: maps.Clone(o.fallbackParsers),
	}, nil
}
