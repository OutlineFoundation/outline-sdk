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
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.getoutline.org/sdk/x/configurl"
)

func TestOverlayRegistryConstruction(t *testing.T) {
	bottom := configurl.NewRegistry()
	configurl.Register(bottom, "value", func(context.Context, configurl.Registry, *configurl.Config) (int, error) {
		return 1, nil
	})
	configurl.Register(bottom, "value", func(context.Context, configurl.Registry, *configurl.Config) (string, error) {
		return "bottom", nil
	})
	newNested := func(ctx context.Context, registry configurl.Registry, _ *configurl.Config) (int, error) {
		return configurl.New[int](ctx, registry, "value")
	}
	configurl.Register(bottom, "nested", newNested)
	newValue := func(context.Context, configurl.Registry, *configurl.Config) (int, error) {
		return 2, nil
	}
	registry := overlayRegistry{
		top: registryMap{
			reflect.TypeFor[int](): {"value": configurl.Constructor[int](newValue)},
		},
		bottom: bottom,
	}
	ctx := context.Background()
	for _, name := range []string{"value", "nested"} {
		value, err := configurl.New[int](ctx, registry, name)
		require.NoError(t, err)
		require.Equal(t, 2, value, "constructors from either layer use the overlay for dependencies")
	}
	text, err := configurl.New[string](ctx, registry, "value")
	require.NoError(t, err)
	require.Equal(t, "bottom", text, "a different result type falls through to the bottom registry")
	_, err = configurl.New[int](ctx, registry, "missing")
	require.ErrorContains(t, err, "is not registered")
	value, err := configurl.New[int](ctx, bottom, "value")
	require.NoError(t, err)
	require.Equal(t, 1, value, "the bottom registry remains unchanged")
}

func TestOverlayRegistryDisabledEntries(t *testing.T) {
	bottom := configurl.NewRegistry()
	configurl.Register(bottom, "value", func(context.Context, configurl.Registry, *configurl.Config) (int, error) {
		t.Fatal("a disabled top entry must not use the bottom constructor")
		return 0, nil
	})
	for name, constructor := range map[string]any{
		"nil":   nil,
		"typed": configurl.Constructor[int](nil),
	} {
		t.Run(name, func(t *testing.T) {
			registry := overlayRegistry{
				top:    registryMap{reflect.TypeFor[int](): {"value": constructor}},
				bottom: bottom,
			}
			_, err := configurl.New[int](context.Background(), registry, "value")
			require.ErrorContains(t, err, "parser is nil")
		})
	}
}
