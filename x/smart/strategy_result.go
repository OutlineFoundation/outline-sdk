// Copyright 2025 The Outline Authors
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
	"reflect"
	"slices"

	"github.com/goccy/go-yaml"
)

// StrategyResultCache is a cache of strategy results that can be used by [Finder]
// to resume a strategy efficiently.
// Implementations are expected to be called concurrently from different goroutines.
type StrategyResultCache interface {
	// Get retrieves a strategy result value associated with the given key.
	// It returns the value text encoded in UTF-8 and true if found.
	Get(key string) (value []byte, ok bool)

	// Put adds the strategy result value encoded in UTF-8 to the cache with the given key.
	// If called with nil value, it should remove the cache entry.
	Put(key string, value []byte)
}

// winningStrategyCacheKey is the key for storing the winning strategy in the
// [StrategyResultCache] each time [Finder.NewDialer] is invoked.
const winningStrategyCacheKey = "winning_strategy"

// winningConfig holds the configuration of a successful strategy.
// It contains either one entry of proxyless or one entry of fallback.
type winningConfig configConfig

func newProxylessWinningConfig(dns *dnsEntryConfig, tls string) winningConfig {
	w := winningConfig{}
	if dns != nil {
		w.DNS = []dnsEntryConfig{*dns}
	}
	if tls != "" {
		w.TLS = []string{tls}
	}
	return w
}

func newFallbackWinningConfig(fallback fallbackEntryConfig) winningConfig {
	w := winningConfig{}
	if fallback != nil {
		w.Fallback = []fallbackEntryConfig{fallback}
	}
	return w
}

// getFallbackIfExclusive checks if the winningConfig is a fallback strategy.
// It returns the fallback entry and true if there is only one exclusive fallback entry
// in the config; otherwise it returns nil and false.
func (w winningConfig) getFallbackIfExclusive(cfg *configConfig) (fallbackEntryConfig, bool) {
	if len(w.Fallback) != 1 || len(w.DNS) != 0 || len(w.TLS) != 0 {
		return nil, false
	}
	if !slices.ContainsFunc(cfg.Fallback, func(e fallbackEntryConfig) bool {
		return reflect.DeepEqual(e, w.Fallback[0])
	}) {
		return nil, false
	}
	return w.Fallback[0], true
}

// promoteProxylessToFront reorders the DNS and TLS configs within the provided configConfig
// to move the entries matching the winning strategy to the front.
func (w winningConfig) promoteProxylessToFront(cfg *configConfig) {
	if len(w.DNS) == 1 {
		// If not found, IndexFunc will return -1, and moveToFront will ignore
		moveToFront(cfg.DNS, slices.IndexFunc(cfg.DNS, func(e dnsEntryConfig) bool {
			return reflect.DeepEqual(e, w.DNS[0])
		}))
	}
	if len(w.TLS) == 1 {
		// If not found, Index will return -1, and moveToFront will ignore
		moveToFront(cfg.TLS, slices.Index(cfg.TLS, w.TLS[0]))
	}
}

func (w winningConfig) toYAML() ([]byte, error) {
	return yaml.MarshalWithOptions(w, yaml.Flow(true))
}
