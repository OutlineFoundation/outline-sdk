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

package configurl

import (
	"context"
	"fmt"
	"reflect"
	"sync"

	"golang.getoutline.org/sdk/transport"
)

// Constructor creates a T from config, using registry to construct dependencies.
// A nil config requests the default base. Always use the supplied registry for
// dependencies so registry wrappers apply throughout the component chain.
// Forward ctx for cancellation during construction; returned objects should use
// the context of each later operation rather than retain the construction context.
type Constructor[T any] func(ctx context.Context, registry Registry, config *Config) (T, error)

// Registry looks up parsers by their exact Go result type and config URL scheme.
// Use [Lookup], [New], or [NewFromConfig] for typed access. Implementations may store
// parsers however they choose; the interface does not expose storage or base instances.
type Registry interface {
	// Lookup returns the parser registered for resultType and name, with ok
	// reporting whether the entry exists. The empty name denotes the default base
	// parser, invoked with a nil Config. A registered nil parser disables the entry.
	// A non-nil parser must be a Constructor[T], where T is exactly resultType.
	Lookup(resultType reflect.Type, name string) (parser any, ok bool)
}

// MutableRegistry adds registration to [Registry]. Use [Register] or [RegisterBase]
// for type safety.
// Configure registries before using components built from them; changing a parser
// does not change objects already constructed. Implementations used concurrently
// must synchronize lookup and registration.
type MutableRegistry interface {
	Registry
	// Register registers parser for resultType and name, replacing any existing
	// registration. The empty name selects the default base parser; a nil parser
	// disables the entry.
	// Callers must supply a Constructor[T], where T is exactly resultType. The parser
	// is stored unchanged. Use [Register] for compile-time signature checking.
	// It panics if resultType is nil or the function signature is incompatible.
	// [Lookup] checks the exact Constructor[T] type when retrieving the registration.
	Register(resultType reflect.Type, name string, parser any)
}

type parserKey struct {
	resultType reflect.Type
	name       string
}

type registry struct {
	mu      sync.RWMutex
	parsers map[parserKey]any
}

// Lookup implements [Registry].
func (r *registry) Lookup(resultType reflect.Type, name string) (any, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	parser, ok := r.parsers[parserKey{resultType, name}]
	return parser, ok
}

// Register implements [MutableRegistry].
func (r *registry) Register(resultType reflect.Type, name string, parser any) {
	validateConstructor(resultType, parser)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.parsers[parserKey{resultType, name}] = parser
}

// Register registers a parser for a config URL scheme and exact result type T.
// Use an interface type argument when registering an implementation of it.
// The empty name registers the default base parser. A nil parser disables the entry.
func Register[T any](r MutableRegistry, name string, parser Constructor[T]) {
	r.Register(reflect.TypeFor[T](), name, parser)
}

// RegisterBase registers the parser used when a config is nil.
// It is a convenience function equivalent to calling [Register] with an empty name:
// Register(r, "", parser).
func RegisterBase[T any](r MutableRegistry, parser Constructor[T]) {
	Register(r, "", parser)
}

// Lookup returns a typed parser without invoking it. It checks that the stored
// value is a Constructor[T]. Capturing it before replacing a registration
// lets a new parser delegate to the previous parser.
func Lookup[T any](r Registry, name string) (Constructor[T], error) {
	resultType := reflect.TypeFor[T]()
	if r == nil {
		return nil, fmt.Errorf("cannot look up %v parser %q in a nil registry", resultType, name)
	}
	parser, ok := r.Lookup(resultType, name)
	if !ok {
		return nil, fmt.Errorf("%v config type %q is not registered", resultType, name)
	}
	if parser == nil {
		return nil, fmt.Errorf("%v config type %q parser is nil", resultType, name)
	}
	newInstance, ok := parser.(Constructor[T])
	if !ok {
		return nil, fmt.Errorf("%v config type %q has incompatible parser type %T", resultType, name, parser)
	}
	if newInstance == nil {
		return nil, fmt.Errorf("%v config type %q parser is nil", resultType, name)
	}
	return newInstance, nil
}

// NewFromConfig constructs a T from a parsed config. A nil config invokes the base parser.
// The constructor receives r so it can use the same registry for dependencies.
func NewFromConfig[T any](ctx context.Context, r Registry, config *Config) (T, error) {
	name := ""
	if config != nil {
		name = config.URL.Scheme
		if name == "" {
			var zero T
			return zero, fmt.Errorf("config URL has no scheme")
		}
	}
	parser, err := Lookup[T](r, name)
	if err != nil {
		var zero T
		return zero, err
	}
	return parser(ctx, r, config)
}

// New constructs a T from a config URL string. An empty or whitespace-only string
// invokes the base parser. Use NewFromConfig when the config is already parsed.
func New[T any](ctx context.Context, r Registry, configText string) (T, error) {
	config, err := ParseConfig(configText)
	if err != nil {
		var zero T
		return zero, err
	}
	return NewFromConfig[T](ctx, r, config)
}

// NewRegistry creates a registry with default base implementations of
// [transport.StreamDialer], [transport.PacketDialer], and [transport.PacketListener].
// Other result types and config URL schemes can be added with Register.
func NewRegistry() MutableRegistry {
	r := &registry{parsers: make(map[parserKey]any)}
	streamDialer := &transport.TCPDialer{}
	newStreamDialer := func(context.Context, Registry, *Config) (transport.StreamDialer, error) {
		return streamDialer, nil
	}
	RegisterBase(r, newStreamDialer)
	packetDialer := &transport.UDPDialer{}
	newPacketDialer := func(context.Context, Registry, *Config) (transport.PacketDialer, error) {
		return packetDialer, nil
	}
	RegisterBase(r, newPacketDialer)
	packetListener := &transport.UDPListener{}
	newPacketListener := func(context.Context, Registry, *Config) (transport.PacketListener, error) {
		return packetListener, nil
	}
	RegisterBase(r, newPacketListener)
	return r
}

// NewDefaultRegistry creates a registry with default bases and built-in parsers.
func NewDefaultRegistry() MutableRegistry { return RegisterDefaultTypes(NewRegistry()) }

// RegisterDefaultTypes registers the built-in config URL parsers, preserving bases.
func RegisterDefaultTypes(registry MutableRegistry) MutableRegistry {
	// Please keep the list in alphabetical order.
	Register(registry, "disorder", newDisorderDialer)
	Register(registry, "do53", newDO53StreamDialer)
	Register(registry, "doh", newDOHStreamDialer)

	Register(registry, "h2connect", newH2ConnectStreamDialer)
	Register(registry, "h3connect", newH3ConnectStreamDialer)
	Register(registry, "httpconnect", newHTTPConnectStreamDialer)

	Register(registry, "override", newOverrideStreamDialer)
	Register(registry, "override", newOverridePacketDialer)

	Register(registry, "quicprelude", newQUICPreludePacketListener)

	Register(registry, "socks5", newSOCKS5StreamDialer)
	Register(registry, "socks5", newSOCKS5PacketDialer)
	Register(registry, "socks5", newSOCKS5PacketListener)

	Register(registry, "split", newSplitStreamDialer)

	Register(registry, "ss", newShadowsocksStreamDialer)
	Register(registry, "ss", newShadowsocksPacketDialer)
	Register(registry, "ss", newShadowsocksPacketListener)

	Register(registry, "tls", newTLSStreamDialer)

	Register(registry, "tlsfrag", newTLSFragStreamDialer)

	Register(registry, "ws", newWebsocketStreamDialer)
	Register(registry, "ws", newWebsocketPacketDialer)
	return registry
}

// validateConstructor checks the signature without changing or invoking the parser.
// Lookup verifies the exact Constructor[T] type when T is known.
func validateConstructor(resultType reflect.Type, parser any) {
	if resultType == nil {
		panic("configurl: parser result type is nil")
	}
	if parser == nil {
		return
	}
	// Derive the signature from Constructor, replacing only its component result T.
	signature := reflect.TypeFor[Constructor[any]]()
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
	if !reflect.TypeOf(parser).AssignableTo(parserType) {
		panic(fmt.Sprintf("configurl: parser for %v has type %T, want %v", resultType, parser, parserType))
	}
}
