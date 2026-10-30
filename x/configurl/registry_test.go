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

package configurl_test

import (
	"context"
	"errors"
	"net"
	"net/url"
	"reflect"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/x/configurl"
)

func TestRegistryDefaults(t *testing.T) {
	for _, defaults := range []bool{false, true} {
		registry := configurl.NewRegistry()
		if defaults {
			configurl.RegisterDefaultTypes(registry)
		}
		ctx := context.Background()
		sd, err := configurl.NewFromConfig[transport.StreamDialer](ctx, registry, nil)
		require.NoError(t, err)
		require.IsType(t, &transport.TCPDialer{}, sd)
		pd, err := configurl.NewFromConfig[transport.PacketDialer](ctx, registry, nil)
		require.NoError(t, err)
		require.IsType(t, &transport.UDPDialer{}, pd)
		pl, err := configurl.NewFromConfig[transport.PacketListener](ctx, registry, nil)
		require.NoError(t, err)
		require.IsType(t, &transport.UDPListener{}, pl)
		same, err := configurl.New[transport.StreamDialer](ctx, registry, "  ")
		require.NoError(t, err)
		require.Same(t, sd, same)
		_, streamErr := configurl.New[transport.StreamDialer](ctx, registry, "disorder:1|tlsfrag:1|split:1")
		_, packetErr := configurl.New[transport.PacketDialer](ctx, registry, "override:port=53")
		_, listenerErr := configurl.New[transport.PacketListener](ctx, registry, "quicprelude:count=0")
		for _, err := range []error{streamErr, packetErr, listenerErr} {
			if defaults {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, "is not registered")
			}
		}
	}
}

// A registry implemented outside configurl, including a read-only lookup wrapper.
type externalRegistry map[reflect.Type]map[string]any

// Lookup implements [configurl.Registry].
func (r externalRegistry) Lookup(resultType reflect.Type, name string) (any, bool) {
	p, ok := r[resultType][name]
	return p, ok
}

// Register implements [configurl.MutableRegistry].
func (r externalRegistry) Register(resultType reflect.Type, name string, parser any) {
	if resultType == nil {
		panic("result type is nil")
	}
	signature := reflect.TypeFor[configurl.Constructor[any]]()
	inputs := make([]reflect.Type, signature.NumIn())
	for i := range inputs {
		inputs[i] = signature.In(i)
	}
	outputs := make([]reflect.Type, signature.NumOut())
	for i := range outputs {
		outputs[i] = signature.Out(i)
	}
	outputs[0] = resultType
	parserType := reflect.FuncOf(inputs, outputs, signature.IsVariadic())
	if parser != nil {
		if !reflect.TypeOf(parser).AssignableTo(parserType) {
			panic("invalid parser type")
		}
	}
	if r[resultType] == nil {
		r[resultType] = make(map[string]any)
	}
	r[resultType][name] = parser
}

type lookupOnly struct{ configurl.Registry }

func TestRegistryArbitraryTypesAndExternalImplementation(t *testing.T) {
	for _, registry := range []configurl.MutableRegistry{configurl.NewRegistry(), externalRegistry{}} {
		// Non-comparable output types and identical scheme names work independently.
		registeredValues := []string{"hello"}
		configurl.Register(registry, "value", func(context.Context, configurl.Registry, *configurl.Config) ([]string, error) {
			return registeredValues, nil
		})
		configurl.Register(registry, "value", func(context.Context, configurl.Registry, *configurl.Config) (int, error) {
			return 42, nil
		})
		configurl.RegisterBase(registry, func(context.Context, configurl.Registry, *configurl.Config) ([]string, error) {
			return nil, nil
		})
		readOnly := lookupOnly{registry}
		_, mutable := any(readOnly).(configurl.MutableRegistry)
		require.False(t, mutable)
		values, err := configurl.New[[]string](context.Background(), readOnly, "value")
		require.NoError(t, err)
		require.Equal(t, []string{"hello"}, values)
		number, err := configurl.New[int](context.Background(), readOnly, "value")
		require.NoError(t, err)
		require.Equal(t, 42, number)
		values, err = configurl.NewFromConfig[[]string](context.Background(), readOnly, nil)
		require.NoError(t, err)
		require.Nil(t, values)
	}
}

type registryBase struct{ err error }

// DialStream implements [transport.StreamDialer].
func (b *registryBase) DialStream(context.Context, string) (transport.StreamConn, error) {
	return nil, b.err
}

// DialPacket implements [transport.PacketDialer].
func (b *registryBase) DialPacket(context.Context, string) (net.Conn, error) { return nil, b.err }

// ListenPacket implements [transport.PacketListener].
func (b *registryBase) ListenPacket(context.Context) (net.PacketConn, error) { return nil, b.err }

func registerPassThrough[T any](registry configurl.MutableRegistry, name string) {
	newInstance := func(ctx context.Context, registry configurl.Registry, cfg *configurl.Config) (T, error) {
		return configurl.NewFromConfig[T](ctx, registry, cfg.BaseConfig)
	}
	configurl.Register(registry, name, newInstance)
}

func TestParsersSeeCurrentBaseRegistrations(t *testing.T) {
	registry := configurl.NewDefaultRegistry()
	registerPassThrough[transport.StreamDialer](registry, "custom")
	registerPassThrough[transport.PacketDialer](registry, "custom")
	registerPassThrough[transport.PacketListener](registry, "custom")
	ctx := context.Background()
	for range 2 {
		base := &registryBase{errors.New("configured base")}
		configurl.RegisterBase(registry, func(context.Context, configurl.Registry, *configurl.Config) (transport.StreamDialer, error) {
			return base, nil
		})
		configurl.RegisterBase(registry, func(context.Context, configurl.Registry, *configurl.Config) (transport.PacketDialer, error) {
			return base, nil
		})
		configurl.RegisterBase(registry, func(context.Context, configurl.Registry, *configurl.Config) (transport.PacketListener, error) {
			return base, nil
		})
		sd, err := configurl.New[transport.StreamDialer](ctx, registry, "custom|custom|tlsfrag:1|split:1")
		require.NoError(t, err)
		_, err = sd.DialStream(ctx, "target.invalid:443")
		require.ErrorIs(t, err, base.err)
		pd, err := configurl.New[transport.PacketDialer](ctx, registry, "custom|override:port=53")
		require.NoError(t, err)
		_, err = pd.DialPacket(ctx, "target.invalid:443")
		require.ErrorIs(t, err, base.err)
		pl, err := configurl.New[transport.PacketListener](ctx, registry, "custom|quicprelude:count=0")
		require.NoError(t, err)
		_, err = pl.ListenPacket(ctx)
		require.ErrorIs(t, err, base.err)
	}
	base := &registryBase{}
	configurl.Register(registry, "concrete", func(context.Context, configurl.Registry, *configurl.Config) (*registryBase, error) {
		return base, nil
	})
	_, err := configurl.New[transport.StreamDialer](ctx, registry, "concrete")
	require.ErrorContains(t, err, "is not registered", "result types are matched exactly")
	configurl.Register(registry, "interface", func(context.Context, configurl.Registry, *configurl.Config) (transport.StreamDialer, error) {
		return base, nil
	})
	got, err := configurl.New[transport.StreamDialer](ctx, registry, "interface")
	require.NoError(t, err)
	require.Same(t, base, got)
}

func TestRegistryInvalidParsers(t *testing.T) {
	ctx := context.Background()
	registry := configurl.NewRegistry()
	configurl.Register[int](registry, "disabled", nil)
	for _, cfg := range []string{"", "missing", "disabled", "a||b"} {
		_, err := configurl.New[int](ctx, registry, cfg)
		require.Error(t, err, cfg)
	}
	_, err := configurl.NewFromConfig[int](ctx, nil, nil)
	require.ErrorContains(t, err, "nil registry")
	_, err = configurl.NewFromConfig[int](ctx, registry, &configurl.Config{URL: url.URL{Path: "missing-scheme"}})
	require.ErrorContains(t, err, "no scheme")
	parserErr := errors.New("parser failed")
	configurl.Register(registry, "error", func(context.Context, configurl.Registry, *configurl.Config) (int, error) { return 0, parserErr })
	_, err = configurl.New[int](ctx, registry, "error")
	require.ErrorIs(t, err, parserErr)
}

// baseOverride intercepts base lookup without modifying the wrapped registry.
type baseOverride[T any] struct {
	configurl.Registry
	base T
}

// Lookup implements [configurl.Registry].
func (r *baseOverride[T]) Lookup(resultType reflect.Type, name string) (any, bool) {
	if name == "" && resultType == reflect.TypeFor[T]() {
		newInstance := func(context.Context, configurl.Registry, *configurl.Config) (T, error) {
			return r.base, nil
		}
		return configurl.Constructor[T](newInstance), true
	}
	return r.Registry.Lookup(resultType, name)
}

func TestRegistryWrappersReachNestedDependencies(t *testing.T) {
	registry := configurl.NewDefaultRegistry()
	registerPassThrough[transport.StreamDialer](registry, "custom")
	newNested := func(ctx context.Context, registry configurl.Registry, cfg *configurl.Config) (transport.StreamDialer, error) {
		return configurl.New[transport.StreamDialer](ctx, registry, cfg.URL.Opaque)
	}
	configurl.Register(registry, "nested", newNested)
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			base := &registryBase{errors.New("own base")}
			wrapped := &baseOverride[transport.StreamDialer]{registry, base}
			ctx, cancel := context.WithCancel(context.Background())
			sd, err := configurl.New[transport.StreamDialer](ctx, wrapped, "nested:custom|disorder:1|tlsfrag:1|split:1")
			cancel()
			if err != nil {
				t.Error(err)
				return
			}
			_, err = sd.DialStream(context.Background(), "target.invalid:443")
			if !errors.Is(err, base.err) {
				t.Errorf("wrong registry base: %v", err)
			}
		}()
	}
	wg.Wait()
	sd, err := configurl.New[transport.StreamDialer](context.Background(), registry, "custom")
	require.NoError(t, err)
	require.IsType(t, &transport.TCPDialer{}, sd, "wrappers leave the original base unchanged")
}

type cancelablePacketListener struct{ observed context.Context }

// ListenPacket implements [transport.PacketListener].
func (l *cancelablePacketListener) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	l.observed = ctx
	return nil, ctx.Err()
}

func TestConstructorForwardsCancellationToInitialization(t *testing.T) {
	registry := configurl.NewDefaultRegistry()
	listener := &cancelablePacketListener{}
	newListener := func(context.Context, configurl.Registry, *configurl.Config) (transport.PacketListener, error) {
		return listener, nil
	}
	configurl.RegisterBase(registry, newListener)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := configurl.New[transport.StreamDialer](ctx, registry, "h3connect://proxy.invalid:443")
	require.ErrorIs(t, err, context.Canceled)
	require.Same(t, ctx, listener.observed, "HTTP/3 setup receives the construction context")
}

func checkNilParserResults[T any](t *testing.T) {
	t.Helper()
	registry := configurl.NewRegistry()
	var zero T
	configurl.Register(registry, "typed", func(context.Context, configurl.Registry, *configurl.Config) (T, error) {
		return zero, nil
	})
	newInstance := configurl.Constructor[T](func(context.Context, configurl.Registry, *configurl.Config) (T, error) {
		return zero, nil
	})
	registry.Register(reflect.TypeFor[T](), "raw", newInstance)
	for _, name := range []string{"typed", "raw"} {
		value, err := configurl.New[T](context.Background(), registry, name)
		require.NoError(t, err)
		require.Nil(t, value)
	}
}

func TestParserNilResults(t *testing.T) {
	t.Run("interface", checkNilParserResults[transport.StreamDialer])
	t.Run("any", checkNilParserResults[any])
	t.Run("pointer", checkNilParserResults[*registryBase])
	t.Run("slice", checkNilParserResults[[]byte])
	t.Run("map", checkNilParserResults[map[string]int])
	t.Run("function", checkNilParserResults[func()])
	t.Run("channel", checkNilParserResults[chan int])

	registry := configurl.NewRegistry()
	var base *registryBase
	configurl.Register(registry, "typed-nil", func(context.Context, configurl.Registry, *configurl.Config) (transport.StreamDialer, error) {
		return base, nil
	})
	got, err := configurl.New[transport.StreamDialer](context.Background(), registry, "typed-nil")
	require.NoError(t, err)
	require.True(t, got != nil, "a typed nil implementation must retain its dynamic type")
	require.IsType(t, base, got)
	require.Nil(t, got.(*registryBase))

	configurl.Register[transport.StreamDialer](registry, "disabled", nil)
	parser, ok := registry.Lookup(reflect.TypeFor[transport.StreamDialer](), "disabled")
	require.True(t, ok)
	require.Nil(t, parser, "disabled parsers must not become callable wrappers around nil")
	_, err = configurl.Lookup[transport.StreamDialer](registry, "disabled")
	require.ErrorContains(t, err, "parser is nil")
}

func TestParsersPreserveArgumentsAndResults(t *testing.T) {
	type contextKey struct{}
	ctx := context.WithValue(context.Background(), contextKey{}, "request")
	cfg, err := configurl.ParseConfig("value:options")
	require.NoError(t, err)
	registry := configurl.NewRegistry()
	readOnly := &lookupOnly{registry}
	parserErr := errors.New("partial result")
	calls := 0
	newInstance := func(gotCtx context.Context, gotRegistry configurl.Registry, gotConfig *configurl.Config) (int, error) {
		require.Equal(t, "request", gotCtx.Value(contextKey{}))
		require.Same(t, readOnly, gotRegistry)
		require.Same(t, cfg, gotConfig)
		calls++
		return 42, parserErr
	}
	configurl.Register(registry, "value", newInstance)
	stored, ok := registry.Lookup(reflect.TypeFor[int](), "value")
	require.True(t, ok)
	require.IsType(t, configurl.Constructor[int](nil), stored, "Register must preserve the named Constructor type")
	parser, err := configurl.Lookup[int](registry, "value")
	require.NoError(t, err)
	require.Zero(t, calls, "lookup does not construct an instance")
	value, err := configurl.NewFromConfig[int](ctx, readOnly, cfg)
	require.Equal(t, 42, value)
	require.ErrorIs(t, err, parserErr)
	require.Equal(t, 1, calls)

	// Lookup captures the existing parser; NewFromConfig performs a fresh lookup.
	configurl.Register(registry, "value", func(context.Context, configurl.Registry, *configurl.Config) (int, error) {
		return 7, nil
	})
	value, err = parser(ctx, readOnly, cfg)
	require.Equal(t, 42, value)
	require.ErrorIs(t, err, parserErr)
	value, err = configurl.NewFromConfig[int](ctx, registry, cfg)
	require.NoError(t, err)
	require.Equal(t, 7, value)

	// Interface results retain their concrete implementation.
	base := &registryBase{}
	newDialer := configurl.Constructor[transport.StreamDialer](func(context.Context, configurl.Registry, *configurl.Config) (transport.StreamDialer, error) {
		return base, nil
	})
	registry.Register(reflect.TypeFor[transport.StreamDialer](), "raw", newDialer)
	dialer, err := configurl.New[transport.StreamDialer](ctx, registry, "raw")
	require.NoError(t, err)
	require.Same(t, base, dialer)

	// Nil interface results and errors are preserved together.
	newError := configurl.Constructor[transport.StreamDialer](func(context.Context, configurl.Registry, *configurl.Config) (transport.StreamDialer, error) {
		return nil, parserErr
	})
	registry.Register(reflect.TypeFor[transport.StreamDialer](), "error", newError)
	dialer, err = configurl.New[transport.StreamDialer](ctx, registry, "error")
	require.Nil(t, dialer)
	require.ErrorIs(t, err, parserErr)
}

type constantConstructor int

// NewInstance constructs the configured value.
func (c constantConstructor) NewInstance(context.Context, configurl.Registry, *configurl.Config) (int, error) {
	return int(c), nil
}

func TestRegisterPreservesNamedType(t *testing.T) {
	type customParser func(context.Context, configurl.Registry, *configurl.Config) (int, error)
	calls := 0
	newInstance := func(context.Context, configurl.Registry, *configurl.Config) (int, error) {
		calls++
		return 42, nil
	}
	provider := constantConstructor(42)
	for name, candidate := range map[string]any{
		"function": configurl.Constructor[int](newInstance),
		"custom":   configurl.Constructor[int](customParser(newInstance)),
		"method":   configurl.Constructor[int](provider.NewInstance),
	} {
		t.Run(name, func(t *testing.T) {
			registry := configurl.NewRegistry()
			calls = 0
			registry.Register(reflect.TypeFor[int](), "value", candidate)
			stored, ok := registry.Lookup(reflect.TypeFor[int](), "value")
			require.True(t, ok)
			require.IsType(t, configurl.Constructor[int](nil), stored)
			parser, err := configurl.Lookup[int](registry, "value")
			require.NoError(t, err)
			require.Zero(t, calls, "registration and lookup must not invoke the parser")
			value, err := parser(context.Background(), registry, nil)
			require.NoError(t, err)
			require.Equal(t, 42, value)
		})
	}
}

func TestRegisterRejectsInvalidSignatures(t *testing.T) {
	resultType := reflect.TypeFor[int]()
	registry := configurl.NewRegistry()
	configurl.Register(registry, "value", func(context.Context, configurl.Registry, *configurl.Config) (int, error) { return 42, nil })
	for name, candidate := range map[string]any{
		"non-function":   42,
		"legacy":         configurl.BuildFunc[int](func(context.Context, *configurl.Config) (int, error) { return 0, nil }),
		"wrong-argument": func(context.Context, string) (int, error) { return 0, nil },
		"wrong-result":   func(context.Context, configurl.Registry, *configurl.Config) (string, error) { return "", nil },
		"any-result":     func(context.Context, configurl.Registry, *configurl.Config) (any, error) { return 42, nil },
		"missing-error":  func(context.Context, configurl.Registry, *configurl.Config) int { return 0 },
		"wrong-error":    func(context.Context, configurl.Registry, *configurl.Config) (int, string) { return 0, "" },
		"variadic":       func(context.Context, ...*configurl.Config) (int, error) { return 0, nil },
		"wrong-nil":      configurl.Constructor[string](nil),
	} {
		t.Run(name, func(t *testing.T) {
			require.Panics(t, func() { registry.Register(resultType, "value", candidate) })
			value, err := configurl.New[int](context.Background(), registry, "value")
			require.NoError(t, err)
			require.Equal(t, 42, value, "invalid registration must preserve the existing parser")
		})
	}
	require.PanicsWithValue(t, "configurl: parser result type is nil", func() {
		registry.Register(nil, "value", nil)
	})
	// A function returning a concrete implementation cannot be registered as an interface parser.
	require.Panics(t, func() {
		registry.Register(reflect.TypeFor[transport.StreamDialer](), "concrete", func(context.Context, configurl.Registry, *configurl.Config) (*registryBase, error) {
			return &registryBase{}, nil
		})
	})
	// Even convertible result types must match exactly, including struct tags.
	type tagged = struct {
		Value int `json:"value"`
	}
	type otherTagged = struct {
		Value int `json:"other"`
	}
	require.Panics(t, func() {
		registry.Register(reflect.TypeFor[tagged](), "tags", func(context.Context, configurl.Registry, *configurl.Config) (otherTagged, error) {
			return otherTagged{}, nil
		})
	})
}

func TestRegisterDisablesEntries(t *testing.T) {
	for name, candidate := range map[string]any{
		"nil":   nil,
		"typed": configurl.Constructor[int](nil),
	} {
		t.Run(name, func(t *testing.T) {
			registry := configurl.NewRegistry()
			registry.Register(reflect.TypeFor[int](), name, candidate)
			_, err := configurl.Lookup[int](registry, name)
			require.ErrorContains(t, err, "parser is nil")
		})
	}
}

func TestLookupRejectsInvalidExternalParsers(t *testing.T) {
	type customParser func(context.Context, configurl.Registry, *configurl.Config) (int, error)
	// Bypass registration to simulate a registry violating the lookup contract.
	registry := externalRegistry{reflect.TypeFor[int](): {
		"non-function": 42,
		"wrong-result": func(context.Context, configurl.Registry, *configurl.Config) (string, error) {
			t.Fatal("lookup must not invoke an incompatible parser")
			return "", nil
		},
		"wrong-parser": configurl.Constructor[string](func(context.Context, configurl.Registry, *configurl.Config) (string, error) { return "", nil }),
		"ordinary":     func(context.Context, configurl.Registry, *configurl.Config) (int, error) { return 42, nil },
		"custom":       customParser(func(context.Context, configurl.Registry, *configurl.Config) (int, error) { return 42, nil }),
	}}
	for name := range registry[reflect.TypeFor[int]()] {
		_, err := configurl.Lookup[int](registry, name)
		require.ErrorContains(t, err, "incompatible parser type")
	}
	registry.Register(reflect.TypeFor[int](), "disabled", configurl.Constructor[int](nil))
	_, err := configurl.Lookup[int](registry, "disabled")
	require.ErrorContains(t, err, "parser is nil")
}
