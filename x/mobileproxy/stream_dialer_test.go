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

package mobileproxy_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/x/configurl"
	"golang.getoutline.org/sdk/x/mobileproxy"
	"golang.getoutline.org/sdk/x/mobileproxy/testdata/registryextension"
)

func TestSmartDialerRegistryExtensions(t *testing.T) {
	for _, config := range []string{
		`fallback: ["custom|tlsfrag:1"]`,
		`fallback: [{nested: "custom|tlsfrag:1"}]`,
		`dns: [{system: {}}]
tls: ["custom|tlsfrag:1"]`,
	} {
		t.Run(config, func(t *testing.T) {
			opts := mobileproxy.NewSmartDialerOptions(&mobileproxy.StringList{}, config)
			registry := opts.ConfigURLRegistry()
			registryextension.RegisterCustomComponent(opts, "custom")
			require.Same(t, registry, opts.ConfigURLRegistry())
			// Clearing an optional adapter must not leave a typed-nil interface.
			opts.SetStrategyCache(nil)
			opts.SetLogWriter(nil)
			var wg sync.WaitGroup
			for range 16 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					dialer, err := opts.NewStreamDialer()
					if err != nil {
						t.Error(err)
						return
					}
					_, err = dialer.DialStream(context.Background(), "target.invalid:443")
					if err == nil || err.Error() != "custom@target.invalid:443" {
						t.Errorf("DialStream: %v", err)
					}
				}()
			}
			wg.Wait()
		})
	}
}

func TestSmartDialerRegistriesAreIsolated(t *testing.T) {
	one := mobileproxy.NewSmartDialerOptions(&mobileproxy.StringList{}, `fallback: ["custom"]`)
	two := mobileproxy.NewSmartDialerOptions(&mobileproxy.StringList{}, `fallback: ["custom"]`)
	registryextension.RegisterCustomComponent(one, "custom")
	require.NotSame(t, one.ConfigURLRegistry(), two.ConfigURLRegistry())
	_, err := one.NewStreamDialer()
	require.NoError(t, err)
	_, err = two.NewStreamDialer()
	require.Error(t, err)
	_, err = mobileproxy.NewStreamDialerFromConfig("custom")
	require.Error(t, err, "per-options registrations must not leak to the static factory")
}

func TestSmartDialerInvalidParser(t *testing.T) {
	opts := mobileproxy.NewSmartDialerOptions(&mobileproxy.StringList{}, `fallback: [""]`)
	opts.RegisterFallbackParser("broken", nil)
	_, err := opts.NewStreamDialer()
	require.ErrorContains(t, err, `fallback parser "broken" must not be nil`)
}

func TestSmartDialerReplacementRegistry(t *testing.T) {
	opts := mobileproxy.NewSmartDialerOptions(&mobileproxy.StringList{}, `fallback: ["tlsfrag:1"]`)
	original := opts.ConfigURLRegistry()
	baseErr := errors.New("injected base")
	dialStream := func(context.Context, string) (transport.StreamConn, error) { return nil, baseErr }
	replacement := configurl.NewDefaultRegistry()
	baseDialer := transport.FuncStreamDialer(dialStream)
	parse := func(context.Context, configurl.Registry, *configurl.Config) (transport.StreamDialer, error) {
		return baseDialer, nil
	}
	configurl.RegisterBase(replacement, parse)
	require.Same(t, opts, opts.SetConfigURLRegistry(replacement))
	require.Same(t, replacement, opts.ConfigURLRegistry())
	dialer, err := opts.NewStreamDialer()
	require.NoError(t, err)
	_, err = dialer.DialStream(context.Background(), "target.invalid:443")
	require.ErrorIs(t, err, baseErr)
	base, err := configurl.NewFromConfig[transport.StreamDialer](context.Background(), original, nil)
	require.NoError(t, err)
	require.IsType(t, &transport.TCPDialer{}, base)
	opts.SetConfigURLRegistry(nil)
	require.NotSame(t, original, opts.ConfigURLRegistry())
	base, err = configurl.NewFromConfig[transport.StreamDialer](context.Background(), opts.ConfigURLRegistry(), nil)
	require.NoError(t, err)
	require.IsType(t, &transport.TCPDialer{}, base)
}
