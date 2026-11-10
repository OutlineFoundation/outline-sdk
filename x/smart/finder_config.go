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

// FinderConfig configures a [Finder]: its registry, timeouts, logging, cache, and
// fallback parsers. The strategies to search are passed to [Finder.NewDialer].
// Setters collect settings; [FinderConfig.New] validates them. Finish all
// configuration, including registry and fallback registrations, before calling
// New. Concurrent New calls are supported after setup.
type FinderConfig struct {
	// testTimeout is the positive timeout for each connectivity test.
	testTimeout time.Duration
	// logWriter receives strategy selection logs; nil disables logging.
	logWriter io.Writer
	// cache stores successful strategies for later searches; nil disables caching.
	cache StrategyResultCache
	// configURLRegistry is shared by the finders created from this config.
	// If nil, each New call creates a fresh default registry.
	configURLRegistry configurl.Registry
	// fallbackParsers maps YAML fallback type names to parsers. New copies this map
	// into each finder so later changes to the config do not affect existing finders.
	fallbackParsers map[string]FallbackParser
}

// NewFinderConfig creates a config with a five-second test timeout.
func NewFinderConfig() *FinderConfig {
	return &FinderConfig{testTimeout: 5 * time.Second}
}

// SetConfigURLRegistry shares registry with the finders created by New. A nil
// registry selects a fresh default registry for each New call. Complete
// registrations before New. Finders only look up parsers in this registry;
// each TLS search uses a separate wrapper to supply its selected DNS dialer.
func (c *FinderConfig) SetConfigURLRegistry(registry configurl.Registry) *FinderConfig {
	c.configURLRegistry = registry
	return c
}

// SetTestTimeout sets the positive timeout for each connectivity test.
func (c *FinderConfig) SetTestTimeout(timeout time.Duration) *FinderConfig {
	c.testTimeout = timeout
	return c
}

// SetLogWriter sets the optional destination for strategy selection logs.
func (c *FinderConfig) SetLogWriter(writer io.Writer) *FinderConfig {
	c.logWriter = writer
	return c
}

// SetCache sets the optional cache of successful strategies.
func (c *FinderConfig) SetCache(cache StrategyResultCache) *FinderConfig {
	c.cache = cache
	return c
}

// RegisterFallbackParser registers or replaces a parser for a YAML fallback type.
// A parser can capture the registry passed to SetConfigURLRegistry to construct
// nested config URLs using the same component registrations and base instances.
func (c *FinderConfig) RegisterFallbackParser(name string, parser FallbackParser) *FinderConfig {
	if c.fallbackParsers == nil {
		c.fallbackParsers = make(map[string]FallbackParser)
	}
	c.fallbackParsers[name] = parser
	return c
}

// New validates the config and creates a finder without performing network I/O.
// It snapshots the settings and fallback registrations, sharing the registry, cache,
// and log writer by reference. The returned finder is ready to search.
func (c *FinderConfig) New() (Finder, error) {
	if c.testTimeout <= 0 {
		return nil, errors.New("test timeout must be positive")
	}
	for name, parser := range c.fallbackParsers {
		if parser == nil {
			return nil, fmt.Errorf("fallback parser %q must not be nil", name)
		}
	}
	registry := c.configURLRegistry
	if registry == nil {
		registry = configurl.NewDefaultRegistry()
	}
	return &finder{
		testTimeout:     c.testTimeout,
		logWriter:       c.logWriter,
		cache:           c.cache,
		registry:        registry,
		fallbackParsers: maps.Clone(c.fallbackParsers),
	}, nil
}
