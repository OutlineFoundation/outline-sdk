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
	"reflect"

	"golang.getoutline.org/sdk/transport"
)

// providerContainerRegistry lets the released provider API use the same component
// registration helpers. Lookups read the providers themselves so later changes
// to their registrations or BaseInstance fields remain visible to dependencies.
// This adapter is private and is used only to register the built-in named types.
type providerContainerRegistry struct{ *ProviderContainer }

// Lookup implements [Registry].
func (r providerContainerRegistry) Lookup(resultType reflect.Type, name string) (any, bool) {
	switch resultType {
	case reflect.TypeFor[transport.StreamDialer]():
		return lookupProviderConstructor(&r.StreamDialers, name)
	case reflect.TypeFor[transport.PacketDialer]():
		return lookupProviderConstructor(&r.PacketDialers, name)
	case reflect.TypeFor[transport.PacketListener]():
		return lookupProviderConstructor(&r.PacketListeners, name)
	default:
		return nil, false
	}
}

// Register implements [MutableRegistry].
func (r providerContainerRegistry) Register(resultType reflect.Type, name string, parser any) {
	validateConstructor(resultType, parser)
	switch resultType {
	case reflect.TypeFor[transport.StreamDialer]():
		registerProviderConstructor(r, &r.StreamDialers, name, parser)
	case reflect.TypeFor[transport.PacketDialer]():
		registerProviderConstructor(r, &r.PacketDialers, name, parser)
	case reflect.TypeFor[transport.PacketListener]():
		registerProviderConstructor(r, &r.PacketListeners, name, parser)
	default:
		panic("unsupported built-in configurl result type: " + resultType.String())
	}
}

// lookupProviderConstructor adapts the released two-argument builder signature.
func lookupProviderConstructor[T comparable](provider *ExtensibleProvider[T], name string) (any, bool) {
	var builder BuildFunc[T]
	if name == "" {
		builder = provider.NewInstance
	} else {
		var ok bool
		builder, ok = provider.builders[name]
		if !ok {
			return nil, false
		}
	}
	if builder == nil {
		return Constructor[T](nil), true
	}
	newInstance := func(ctx context.Context, _ Registry, config *Config) (T, error) {
		return builder(ctx, config)
	}
	return Constructor[T](newInstance), true
}

// registerProviderConstructor binds built-in dependencies to the legacy providers.
func registerProviderConstructor[T comparable](registry Registry, provider *ExtensibleProvider[T], name string, parser any) {
	var newInstance BuildFunc[T]
	if parser != nil {
		constructor := parser.(Constructor[T])
		if constructor != nil {
			newInstance = func(ctx context.Context, config *Config) (T, error) {
				return constructor(ctx, registry, config)
			}
		}
	}
	provider.RegisterType(name, newInstance)
}
