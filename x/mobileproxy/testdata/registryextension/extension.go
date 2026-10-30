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

// Package registryextension is a test component library that can be bound with mobileproxy.
package registryextension

import (
	"context"
	"errors"
	"fmt"

	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/x/configurl"
	"golang.getoutline.org/sdk/x/mobileproxy"
	"golang.getoutline.org/sdk/x/smart"
)

// A component library can expose this helper from a gomobile wrapper package.
func RegisterCustomComponent(opts *mobileproxy.SmartDialerOptions, name string) {
	registry := opts.ConfigURLRegistry()
	newInstance := func(ctx context.Context, registry configurl.Registry, cfg *configurl.Config) (transport.StreamDialer, error) {
		dialStream := func(ctx context.Context, addr string) (transport.StreamConn, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("%s@%s", name, addr)
		}
		return transport.FuncStreamDialer(dialStream), nil
	}
	configurl.Register[transport.StreamDialer](registry, name, newInstance)
	parser := func(ctx context.Context, node smart.YAMLNode) (transport.StreamDialer, string, error) {
		text, ok := node.(string)
		if !ok {
			return nil, "", errors.New("expected a config URL string")
		}
		dialer, err := configurl.New[transport.StreamDialer](ctx, registry, text)
		return dialer, text, err
	}
	opts.RegisterFallbackParser("nested", parser)
}
