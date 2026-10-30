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
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/x/configurl"
)

type namedDialer string

func (d namedDialer) DialStream(ctx context.Context, addr string) (transport.StreamConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("%s@%s", d, addr)
}

func TestFinderOptions(t *testing.T) {
	registry := configurl.NewDefaultRegistry()
	var logs bytes.Buffer
	parser := func(context.Context, YAMLNode) (transport.StreamDialer, string, error) {
		return namedDialer("custom"), "custom", nil
	}
	opts := NewFinderOptions()
	require.Same(t, opts, opts.SetTestTimeout(0).SetLogWriter(&logs).SetCache(nil).
		SetConfigURLRegistry(registry).RegisterFallbackParser("custom", nil))
	_, err := opts.New()
	require.ErrorContains(t, err, "timeout must be positive")
	opts.SetTestTimeout(time.Second)
	_, err = opts.New()
	require.ErrorContains(t, err, `fallback parser "custom" must not be nil`)
	result, err := opts.RegisterFallbackParser("custom", parser).New()
	require.NoError(t, err)
	f := result.(*finder)
	require.Same(t, registry, f.registry)
	require.Same(t, &logs, f.logWriter)
	require.Equal(t, time.Second, f.testTimeout)

	// Scalar options and the parser map are snapshots, not live builder state.
	opts.SetTestTimeout(2*time.Second).SetLogWriter(nil).RegisterFallbackParser("custom", nil)
	dialer, _, err := f.makeDialerFromConfig(context.Background(), registry, map[string]any{"custom": ""})
	require.NoError(t, err)
	require.Equal(t, namedDialer("custom"), dialer)
	require.Equal(t, time.Second, f.testTimeout)
	require.Same(t, &logs, f.logWriter)
}

func TestFinderOptionsDefaultRegistries(t *testing.T) {
	opts := NewFinderOptions().SetConfigURLRegistry(nil)
	first, err := opts.New()
	require.NoError(t, err)
	second, err := opts.New()
	require.NoError(t, err)
	require.NotSame(t, first.(*finder).registry, second.(*finder).registry)
	require.Equal(t, 5*time.Second, first.(*finder).testTimeout)
	_, err = configurl.New[transport.StreamDialer](context.Background(), first.(*finder).registry, "tlsfrag:1")
	require.NoError(t, err)
}

type memoryStrategyCache struct {
	mu   sync.Mutex
	data []byte
	gets atomic.Int32
	puts atomic.Int32
}

func (c *memoryStrategyCache) Get(string) ([]byte, bool) {
	c.gets.Add(1)
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.data, c.data != nil
}

func (c *memoryStrategyCache) Put(_ string, data []byte) {
	c.puts.Add(1)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data = data
}

func TestFallbackRegistryAndCache(t *testing.T) {
	for _, config := range []string{`fallback: ["injected|tlsfrag:1"]`, `fallback: [{nested: "injected|tlsfrag:1"}]`} {
		t.Run(config, func(t *testing.T) {
			registry := configurl.NewDefaultRegistry()
			configurl.RegisterBase[transport.StreamDialer](registry, nil) // The injected component needs no default base.
			var builds atomic.Int32
			newInstance := func(ctx context.Context, registry configurl.Registry, cfg *configurl.Config) (transport.StreamDialer, error) {
				if cfg.BaseConfig != nil {
					return nil, errors.New("unexpected base config in fallback")
				}
				builds.Add(1)
				return namedDialer("injected"), nil
			}
			configurl.Register[transport.StreamDialer](registry, "injected", newInstance)
			parser := func(ctx context.Context, node YAMLNode) (transport.StreamDialer, string, error) {
				text, ok := node.(string)
				if !ok {
					return nil, "", errors.New("expected string")
				}
				dialer, err := configurl.New[transport.StreamDialer](ctx, registry, text)
				return dialer, text, err
			}
			cache := &memoryStrategyCache{}
			var logs bytes.Buffer
			finder, err := NewFinderOptions().SetConfigURLRegistry(registry).
				RegisterFallbackParser("nested", parser).SetCache(cache).SetLogWriter(&logs).New()
			require.NoError(t, err)
			for range 2 {
				dialer, err := finder.NewDialer(context.Background(), nil, []byte(config))
				require.NoError(t, err)
				_, err = dialer.DialStream(context.Background(), "target.invalid:443")
				require.EqualError(t, err, "injected@target.invalid:443")
			}
			require.EqualValues(t, 2, builds.Load())
			require.EqualValues(t, 2, cache.gets.Load())
			require.EqualValues(t, 1, cache.puts.Load(), "second search resumes the cached fallback")
			require.Contains(t, logs.String(), "resume strategy from cache")
		})
	}
}

func TestDNSMissingRegistryBases(t *testing.T) {
	registry := configurl.NewDefaultRegistry()
	configurl.RegisterBase[transport.StreamDialer](registry, nil)
	configurl.RegisterBase[transport.PacketDialer](registry, nil)
	finder, err := NewFinderOptions().SetConfigURLRegistry(registry).New()
	require.NoError(t, err)
	for _, config := range []string{
		`dns: [{udp: {address: resolver.invalid}}]`,
		`dns: [{tcp: {address: resolver.invalid}}]`,
		`dns: [{tls: {name: resolver.invalid}}]`,
		`dns: [{https: {name: resolver.invalid}}]`,
		`dns: [{system: {}}]`,
	} {
		_, err := finder.NewDialer(context.Background(), nil, []byte(config))
		require.Error(t, err, config)
	}
}
