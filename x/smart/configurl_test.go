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
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/x/configurl"
	"golang.org/x/net/dns/dnsmessage"
)

func TestTLSSearchUsesRegistryAndKeepsBasesSeparate(t *testing.T) {
	registry := configurl.NewDefaultRegistry()
	configurl.RegisterBase(registry, func(context.Context, configurl.Registry, *configurl.Config) (transport.StreamDialer, error) {
		return namedDialer("fallback"), nil
	})
	parse := func(ctx context.Context, registry configurl.Registry, cfg *configurl.Config) (transport.StreamDialer, error) {
		return configurl.NewFromConfig[transport.StreamDialer](ctx, registry, cfg.BaseConfig)
	}
	configurl.Register[transport.StreamDialer](registry, "custom", parse)
	// Independently parsed nested configs must receive the same registry base.
	parseNested := func(ctx context.Context, registry configurl.Registry, cfg *configurl.Config) (transport.StreamDialer, error) {
		return configurl.New[transport.StreamDialer](ctx, registry, cfg.URL.Opaque)
	}
	configurl.Register(registry, "nested", parseNested)
	opts := NewFinderOptions().SetConfigURLRegistry(registry)
	sharedFinder, err := opts.New()
	require.NoError(t, err)
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f, err := opts.New() // Concurrent construction only reads the options and registry.
			if err != nil {
				t.Error(err)
				return
			}
			if i%2 == 0 {
				f = sharedFinder
			}
			selected := namedDialer(fmt.Sprintf("selected-%d", i))
			for _, config := range []string{"", "custom|tlsfrag:1", "custom|override:host=front.invalid|split:1", "nested:tlsfrag:1", "custom|disorder:1"} {
				ctx, cancel := context.WithCancel(context.Background())
				dialer, gotConfig, err := f.(*finder).findTLS(ctx, nil, selected, []string{config})
				cancel()
				if err != nil {
					t.Error(err)
					return
				}
				if gotConfig != config {
					t.Errorf("config = %q, want %q", gotConfig, config)
				}
				for _, port := range []string{"443", "853", "80"} {
					host := "target.invalid"
					if config == "custom|override:host=front.invalid|split:1" && port != "80" {
						host = "front.invalid"
					}
					_, err = dialer.DialStream(context.Background(), "target.invalid:"+port)
					want := fmt.Sprintf("%s@%s:%s", selected, host, port)
					if err == nil || err.Error() != want {
						t.Errorf("DialStream = %v, want %s", err, want)
					}
				}
			}
			fallback, _, err := f.(*finder).findFallback(context.Background(), nil, []fallbackEntryConfig{"custom|tlsfrag:1"})
			if err != nil {
				t.Error(err)
				return
			}
			_, err = fallback.DialStream(context.Background(), "target.invalid:443")
			if err == nil || err.Error() != "fallback@target.invalid:443" {
				t.Errorf("fallback: %v", err)
			}
		}()
	}
	wg.Wait()
}

// countingDNSDialer answers DNS messages over in-memory connections, exercising
// the real UDP resolver without external DNS or network dependencies.
type countingDNSDialer struct{ queries atomic.Int32 }

func (d *countingDNSDialer) DialPacket(ctx context.Context, _ string) (net.Conn, error) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		server.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 1500)
		n, err := server.Read(buf)
		if err != nil {
			return
		}
		var msg dnsmessage.Message
		if msg.Unpack(buf[:n]) != nil || len(msg.Questions) != 1 {
			return
		}
		d.queries.Add(1)
		msg.Response = true
		q := msg.Questions[0]
		if q.Type == dnsmessage.TypeA {
			msg.Answers = []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: q.Class},
				Body:   &dnsmessage.AResource{A: [4]byte{192, 0, 2, 42}},
			}}
		}
		response, err := msg.Pack()
		if err == nil {
			server.Write(response)
		}
	}()
	return client, nil
}

func TestTLSAttemptsReuseDNSDialerAndCache(t *testing.T) {
	registry := configurl.NewDefaultRegistry()
	configurl.RegisterBase(registry, func(context.Context, configurl.Registry, *configurl.Config) (transport.StreamDialer, error) {
		return namedDialer("selected"), nil
	})
	pd := &countingDNSDialer{}
	configurl.RegisterBase(registry, func(context.Context, configurl.Registry, *configurl.Config) (transport.PacketDialer, error) {
		return pd, nil
	})
	var mu sync.Mutex
	var bases []transport.StreamDialer
	parse := func(ctx context.Context, registry configurl.Registry, cfg *configurl.Config) (transport.StreamDialer, error) {
		base, err := configurl.NewFromConfig[transport.StreamDialer](ctx, registry, cfg.BaseConfig)
		if err != nil {
			return nil, err
		}
		mu.Lock()
		bases = append(bases, base)
		mu.Unlock()
		// Complete both lookups before letting the next candidate start. Cache
		// sharing should avoid repeating them for the next attempt and winner.
		_, err = base.DialStream(ctx, "target.invalid:443")
		if err == nil || err.Error() != "selected@192.0.2.42:443" {
			return nil, fmt.Errorf("selected DNS dial: %v", err)
		}
		if cfg.URL.Opaque == "fail" {
			return nil, errors.New("try the next candidate")
		}
		return base, nil
	}
	configurl.Register[transport.StreamDialer](registry, "probe", parse)
	cache := &memoryStrategyCache{}
	f, err := NewFinderOptions().SetConfigURLRegistry(registry).SetCache(cache).New()
	require.NoError(t, err)
	dialer, err := f.NewDialer(context.Background(), nil, []byte(`
dns: [{udp: {address: resolver.invalid}}]
tls: ["probe:fail", "probe:win|tlsfrag:1"]
`))
	require.NoError(t, err)
	mu.Lock()
	require.Len(t, bases, 2)
	require.Same(t, bases[0], bases[1])
	mu.Unlock()
	require.EqualValues(t, 2, pd.queries.Load(), "one A and one AAAA query across all attempts")
	for _, port := range []string{"443", "853", "80"} {
		_, err = dialer.DialStream(context.Background(), "target.invalid:"+port)
		require.EqualError(t, err, "selected@192.0.2.42:"+port)
	}
	require.EqualValues(t, 2, pd.queries.Load(), "winner and non-TLS dialer reuse the warmed resolver cache")
	data, _ := cache.Get(winningStrategyCacheKey)
	require.Contains(t, string(data), "probe:win|tlsfrag:1")
	require.NotContains(t, string(data), "selected-dns")
}

type failingPacketListener struct {
	err   error
	calls atomic.Int32
}

func (l *failingPacketListener) ListenPacket(context.Context) (net.PacketConn, error) {
	l.calls.Add(1)
	return nil, l.err
}

func TestTLSKeepsPacketBases(t *testing.T) {
	listenErr := errors.New("injected packet listener")
	pd := &countingDNSDialer{}
	listener := &failingPacketListener{err: listenErr}
	registry := configurl.NewDefaultRegistry()
	configurl.RegisterBase(registry, func(context.Context, configurl.Registry, *configurl.Config) (transport.StreamDialer, error) {
		return namedDialer("fallback"), nil
	})
	configurl.RegisterBase(registry, func(context.Context, configurl.Registry, *configurl.Config) (transport.PacketDialer, error) {
		return pd, nil
	})
	configurl.RegisterBase(registry, func(context.Context, configurl.Registry, *configurl.Config) (transport.PacketListener, error) {
		return listener, nil
	})
	f, err := NewFinderOptions().SetConfigURLRegistry(registry).New()
	require.NoError(t, err)
	dialer, _, err := f.(*finder).findTLS(context.Background(), nil, namedDialer("selected"), []string{"do53:address=192.0.2.53"})
	require.NoError(t, err)
	_, err = dialer.DialStream(context.Background(), "target.invalid:443")
	require.EqualError(t, err, "selected@192.0.2.42:443")
	require.EqualValues(t, 2, pd.queries.Load(), "do53 uses the original packet base")
	_, _, err = f.(*finder).findTLS(context.Background(), nil, namedDialer("selected"), []string{"h3connect://proxy.invalid:443"})
	require.Error(t, err)
	require.EqualValues(t, 1, listener.calls.Load(), "h3connect uses the original packet listener")
}

func TestTLSRejectsMalformedConfigs(t *testing.T) {
	f, err := NewFinderOptions().New()
	require.NoError(t, err)
	for _, config := range []string{"|tlsfrag:1", "tlsfrag:1|", "split:1||tlsfrag:1"} {
		_, _, err := f.(*finder).findTLS(context.Background(), nil, namedDialer("selected"), []string{config})
		require.Error(t, err, config)
	}
}

type readOnlyRegistry struct{ configurl.Registry }

func TestTLSRegistryOverrideLeavesOriginalBaseUntouched(t *testing.T) {
	type traceKey struct{}
	registry := configurl.NewDefaultRegistry()
	var originalCalls atomic.Int32
	originalErr := errors.New("original base error")
	parseOriginal := func(ctx context.Context, _ configurl.Registry, cfg *configurl.Config) (transport.StreamDialer, error) {
		originalCalls.Add(1)
		if cfg != nil {
			return nil, errors.New("base received non-nil config")
		}
		if ctx.Value(traceKey{}) != "trace" {
			return nil, errors.New("lost construction context")
		}
		return nil, originalErr
	}
	configurl.RegisterBase(registry, parseOriginal)
	readOnly := readOnlyRegistry{registry}
	opts := NewFinderOptions().SetConfigURLRegistry(readOnly)
	ctx := context.WithValue(context.Background(), traceKey{}, "trace")
	for i := range 2 {
		f, err := opts.New()
		require.NoError(t, err)
		selected := namedDialer("selected")
		base, _, err := f.(*finder).findTLS(ctx, nil, selected, []string{""})
		require.NoError(t, err)
		_, err = base.DialStream(ctx, "target.invalid:443")
		require.EqualError(t, err, "selected@target.invalid:443")
		require.EqualValues(t, i, originalCalls.Load(), "TLS must not invoke the original base")
		_, err = configurl.NewFromConfig[transport.StreamDialer](ctx, f.(*finder).registry, nil)
		require.ErrorIs(t, err, originalErr, "the finder retains the original registry")
		require.EqualValues(t, i+1, originalCalls.Load())
	}
}

func TestFailedTLSSearchFallsBackToOriginalBase(t *testing.T) {
	registry := configurl.NewDefaultRegistry()
	configurl.RegisterBase(registry, func(context.Context, configurl.Registry, *configurl.Config) (transport.StreamDialer, error) {
		return namedDialer("original"), nil
	})
	pd := &countingDNSDialer{}
	configurl.RegisterBase(registry, func(context.Context, configurl.Registry, *configurl.Config) (transport.PacketDialer, error) {
		return pd, nil
	})
	var observed transport.StreamDialer
	fail := func(ctx context.Context, registry configurl.Registry, cfg *configurl.Config) (transport.StreamDialer, error) {
		var err error
		observed, err = configurl.NewFromConfig[transport.StreamDialer](ctx, registry, cfg.BaseConfig)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("TLS construction failed")
	}
	configurl.Register(registry, "fail", fail)
	fallback := func(ctx context.Context, _ YAMLNode) (transport.StreamDialer, string, error) {
		base, err := configurl.NewFromConfig[transport.StreamDialer](ctx, registry, nil)
		return base, "nested", err
	}
	f, err := NewFinderOptions().SetConfigURLRegistry(registry).
		RegisterFallbackParser("nested", fallback).New()
	require.NoError(t, err)
	dialer, err := f.NewDialer(context.Background(), nil, []byte(`
dns: [{udp: {address: resolver.invalid}}]
tls: [fail]
fallback: [{nested: ""}]
`))
	require.NoError(t, err)
	require.NotNil(t, observed)
	require.NotEqual(t, namedDialer("original"), observed, "TLS used the DNS-wrapped base")
	require.Equal(t, namedDialer("original"), dialer, "fallback did not inherit the TLS context")
}
