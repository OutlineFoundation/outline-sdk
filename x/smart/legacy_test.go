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
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/x/configurl"
)

var _ Finder = (*StrategyFinder)(nil)
var _ Finder = (*finder)(nil)

func TestLegacyFinderConfigurationUpdates(t *testing.T) {
	f := &StrategyFinder{}
	// Legacy registrations are checked when used, not when a finder is created.
	f.RegisterFallbackParser("unused", nil)
	for i, timeout := range []time.Duration{0, time.Minute} {
		var logs bytes.Buffer
		cache := &memoryStrategyCache{}
		f.TestTimeout = timeout
		f.LogWriter = &logs
		f.Cache = cache

		observed := make(chan error, 1)
		dialStream := func(ctx context.Context, _ string) (transport.StreamConn, error) {
			observed <- ctx.Err()
			return nil, errors.New("probe dial")
		}
		name := fmt.Sprintf("parser-%d", i)
		parser := func(context.Context, YAMLNode) (transport.StreamDialer, string, error) {
			return transport.FuncStreamDialer(dialStream), name, nil
		}
		f.RegisterFallbackParser("custom", parser)
		_, err := f.NewDialer(context.Background(), []string{"target.invalid"}, []byte(`fallback: [{custom: ""}]`))
		require.ErrorContains(t, err, "could not find a working fallback")
		var dialContextErr error
		select {
		case dialContextErr = <-observed:
		default:
			t.Fatal("fallback connectivity test did not dial")
		}
		if timeout == 0 {
			require.ErrorIs(t, dialContextErr, context.DeadlineExceeded, "preserve the legacy zero timeout")
		} else {
			require.NoError(t, dialContextErr, "use the updated timeout on the next search")
		}
		require.Contains(t, logs.String(), "custom:"+name, "use the current parser and log writer")
		require.Contains(t, logs.String(), "probe dial")
		require.EqualValues(t, 1, cache.gets.Load())
		require.EqualValues(t, 1, cache.puts.Load(), "use the current cache")
	}
}

func TestLegacyFinderRegistry(t *testing.T) {
	for _, mode := range []string{"none", "stream", "packet", "both"} {
		t.Run(mode, func(t *testing.T) {
			finder := &StrategyFinder{TestTimeout: time.Second}
			if mode == "stream" || mode == "both" {
				finder.StreamDialer = namedDialer("legacy")
			}
			pd := &transport.UDPDialer{}
			if mode == "packet" || mode == "both" {
				finder.PacketDialer = pd
			}
			streamDialer, packetDialer := finder.StreamDialer, finder.PacketDialer
			// Invalid YAML still initializes the registry. A later call can retry.
			_, err := finder.NewDialer(context.Background(), nil, []byte("["))
			require.Error(t, err)
			registry := finder.registry
			require.NotNil(t, registry)
			require.Equal(t, streamDialer, finder.StreamDialer)
			require.Equal(t, packetDialer, finder.PacketDialer)
			packetBase, err := configurl.NewFromConfig[transport.PacketDialer](context.Background(), registry, nil)
			require.NoError(t, err)
			listenerBase, err := configurl.NewFromConfig[transport.PacketListener](context.Background(), registry, nil)
			require.NoError(t, err)
			if mode == "packet" || mode == "both" {
				require.Same(t, pd, packetBase)
			} else {
				require.IsType(t, &transport.UDPDialer{}, packetBase)
			}
			require.IsType(t, &transport.UDPListener{}, listenerBase)
			for range 2 {
				dialer, err := finder.NewDialer(context.Background(), nil, []byte(`fallback: [""]`))
				require.NoError(t, err)
				require.Same(t, registry, finder.registry)
				if mode == "stream" || mode == "both" {
					// Legacy bases now apply to fallback configs as well as DNS/TLS.
					require.Equal(t, namedDialer("legacy"), dialer)
				} else {
					require.IsType(t, &transport.TCPDialer{}, dialer)
				}
			}
		})
	}
}

func TestLegacyFinderDialerUpdates(t *testing.T) {
	ctx := context.Background()
	finder := &StrategyFinder{}
	fallbackConfig := []byte(`fallback: [""]`)
	defaultSD, err := finder.NewDialer(ctx, nil, fallbackConfig)
	require.NoError(t, err)
	registry := finder.registry
	defaultPD, err := configurl.NewFromConfig[transport.PacketDialer](ctx, registry, nil)
	require.NoError(t, err)
	listener, err := configurl.NewFromConfig[transport.PacketListener](ctx, registry, nil)
	require.NoError(t, err)

	type result struct {
		name   string
		dialer transport.StreamDialer
		packet *countingDNSDialer
	}
	var results []result
	for _, name := range []string{"first", "second"} {
		pd := &countingDNSDialer{}
		finder.StreamDialer = namedDialer(name)
		finder.PacketDialer = pd
		fallback, err := finder.NewDialer(ctx, nil, fallbackConfig)
		require.NoError(t, err)
		require.Equal(t, namedDialer(name), fallback)

		// Exercise both fields through DNS selection and TLS construction.
		dialer, err := finder.NewDialer(ctx, nil, []byte(`
dns: [{udp: {address: resolver.invalid}}]
tls: ["tlsfrag:1"]
`))
		require.NoError(t, err)
		_, err = dialer.DialStream(ctx, "target.invalid:443")
		require.EqualError(t, err, name+"@192.0.2.42:443")
		require.EqualValues(t, 2, pd.queries.Load(), "DNS uses the current packet dialer")
		require.Same(t, registry, finder.registry, "field updates reuse the registry")
		results = append(results, result{name, dialer, pd})
	}

	// Clearing the fields restores the same defaults without replacing the registry.
	finder.StreamDialer = nil
	finder.PacketDialer = nil
	sd, err := finder.NewDialer(ctx, nil, fallbackConfig)
	require.NoError(t, err)
	require.Same(t, defaultSD, sd)
	pd, err := configurl.NewFromConfig[transport.PacketDialer](ctx, registry, nil)
	require.NoError(t, err)
	require.Same(t, defaultPD, pd)
	pl, err := configurl.NewFromConfig[transport.PacketListener](ctx, registry, nil)
	require.NoError(t, err)
	require.Same(t, listener, pl, "legacy fields do not affect the packet listener")
	require.Same(t, registry, finder.registry)

	// Previously returned dialers retain both bases, even for an uncached name.
	for _, result := range results {
		_, err := result.dialer.DialStream(ctx, "uncached.invalid:443")
		require.EqualError(t, err, result.name+"@192.0.2.42:443")
		require.EqualValues(t, 4, result.packet.queries.Load())
	}
}

func TestLegacyFinderConcurrentFirstUse(t *testing.T) {
	finder := &StrategyFinder{}
	var wg sync.WaitGroup
	for _, name := range []string{"first", "second"} {
		finder.StreamDialer = namedDialer(name)
		for range 16 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				dialer, err := finder.NewDialer(context.Background(), nil, []byte(`fallback: [""]`))
				if err != nil || dialer != namedDialer(name) {
					t.Errorf("NewDialer = %v, %v", dialer, err)
				}
			}()
		}
		wg.Wait()
	}
}
