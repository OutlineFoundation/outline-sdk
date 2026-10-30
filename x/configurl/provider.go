// Copyright 2024 The Outline Authors
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
	"errors"
	"fmt"
	"net/url"
	"strings"

	"golang.getoutline.org/sdk/transport"
)

// BuildFunc creates an instance of ObjectType for the legacy [TypeRegistry] API.
// Use [Parser] with the registry API to receive the registry for dependencies.
// A nil config requests the default base. Forward ctx when constructing dependencies;
// returned objects should use the context of each later operation rather than retain
// the construction context.
type BuildFunc[ObjectType any] func(ctx context.Context, config *Config) (ObjectType, error)

// TypeRegistry registers config types.
//
// Deprecated: Use [MutableRegistry] and [Register] instead.
type TypeRegistry[ObjectType any] interface {
	// RegisterType registers a factory for the given subtype, replacing any existing one.
	//
	// Deprecated: Use [Register] with a [MutableRegistry] instead.
	RegisterType(subtype string, newInstance BuildFunc[ObjectType])
}

// ExtensibleProvider creates instances of ObjectType in a way that can be extended via its [TypeRegistry] interface.
//
// Deprecated: Use [MutableRegistry] with [Register] and [NewFromConfig] instead.
type ExtensibleProvider[ObjectType comparable] struct {
	// Instance to return when config is nil.
	//
	// Deprecated: Use [RegisterBase] with a function that returns the base instance.
	BaseInstance ObjectType
	builders     map[string]BuildFunc[ObjectType]
}

var (
	_ BuildFunc[any]    = (*ExtensibleProvider[any])(nil).NewInstance
	_ TypeRegistry[any] = (*ExtensibleProvider[any])(nil)
)

// NewExtensibleProvider creates an [ExtensibleProvider] with the given base instance.
//
// Deprecated: Use [NewRegistry] and [RegisterBase] instead.
func NewExtensibleProvider[ObjectType comparable](baseInstance ObjectType) ExtensibleProvider[ObjectType] {
	return ExtensibleProvider[ObjectType]{
		BaseInstance: baseInstance,
		builders:     make(map[string]BuildFunc[ObjectType]),
	}
}

func (p *ExtensibleProvider[ObjectType]) ensureBuildersMap() map[string]BuildFunc[ObjectType] {
	if p.builders == nil {
		p.builders = make(map[string]BuildFunc[ObjectType])
	}
	return p.builders
}

// RegisterType implements [TypeRegistry].
//
// Deprecated: Use [Register] with a [MutableRegistry] instead.
func (p *ExtensibleProvider[ObjectType]) RegisterType(subtype string, newInstance BuildFunc[ObjectType]) {
	p.ensureBuildersMap()[subtype] = newInstance
}

// NewInstance creates a new instance of ObjectType according to the config.
// Missing base instances, missing registrations, and nil registered functions
// return errors wrapping [errors.ErrUnsupported]. Parser errors are returned unchanged.
//
// Deprecated: Use [NewFromConfig] with a [Registry] instead.
func (p *ExtensibleProvider[ObjectType]) NewInstance(ctx context.Context, config *Config) (ObjectType, error) {
	var zero ObjectType
	if config == nil {
		if p.BaseInstance == zero {
			return zero, fmt.Errorf("%.0wbase instance is not configured", errors.ErrUnsupported)
		}
		return p.BaseInstance, nil
	}

	newInstance, ok := p.ensureBuildersMap()[config.URL.Scheme]
	if !ok {
		return zero, fmt.Errorf("%.0wconfig type '%v' is not registered", errors.ErrUnsupported, config.URL.Scheme)
	}
	if newInstance == nil {
		return zero, fmt.Errorf("%.0wconfig type %q parser is nil", errors.ErrUnsupported, config.URL.Scheme)
	}
	return newInstance(ctx, config)
}

// ProviderContainer contains providers for the creation of network objects based on a config. The config is
// extensible by registering providers for different config subtypes.
//
// Deprecated: Use [MutableRegistry], created with [NewRegistry] or [NewDefaultRegistry].
type ProviderContainer struct {
	// StreamDialers creates stream dialers.
	//
	// Deprecated: Use [Register] and [New] with [transport.StreamDialer].
	StreamDialers ExtensibleProvider[transport.StreamDialer]
	// PacketDialers creates packet dialers.
	//
	// Deprecated: Use [Register] and [New] with [transport.PacketDialer].
	PacketDialers ExtensibleProvider[transport.PacketDialer]
	// PacketListeners creates packet listeners.
	//
	// Deprecated: Use [Register] and [New] with [transport.PacketListener].
	PacketListeners ExtensibleProvider[transport.PacketListener]
}

// NewProviderContainer creates a [ProviderContainer] with the base instances properly initialized.
//
// Deprecated: Use [NewRegistry] instead.
func NewProviderContainer() *ProviderContainer {
	return &ProviderContainer{
		StreamDialers:   NewExtensibleProvider[transport.StreamDialer](&transport.TCPDialer{}),
		PacketDialers:   NewExtensibleProvider[transport.PacketDialer](&transport.UDPDialer{}),
		PacketListeners: NewExtensibleProvider[transport.PacketListener](&transport.UDPListener{}),
	}
}

// RegisterDefaultProviders registers a set of default providers with the providers in [ProviderContainer].
//
// Deprecated: Use [RegisterDefaultTypes] instead.
func RegisterDefaultProviders(c *ProviderContainer) *ProviderContainer {
	RegisterDefaultTypes(providerContainerRegistry{c})

	return c
}

// NewDefaultProviders creates a [ProviderContainer] with a set of default providers already registered.
//
// Deprecated: Use [NewDefaultRegistry] instead.
func NewDefaultProviders() *ProviderContainer {
	return RegisterDefaultProviders(NewProviderContainer())
}

// NewStreamDialer creates a [transport.StreamDialer] according to the config text.
//
// Deprecated: Use [New] with [transport.StreamDialer] as its type argument.
func (p *ProviderContainer) NewStreamDialer(ctx context.Context, configText string) (transport.StreamDialer, error) {
	config, err := ParseConfig(configText)
	if err != nil {
		return nil, err
	}
	return p.StreamDialers.NewInstance(ctx, config)
}

// NewPacketDialer creates a [transport.PacketDialer] according to the config text.
//
// Deprecated: Use [New] with [transport.PacketDialer] as its type argument.
func (p *ProviderContainer) NewPacketDialer(ctx context.Context, configText string) (transport.PacketDialer, error) {
	config, err := ParseConfig(configText)
	if err != nil {
		return nil, err
	}
	return p.PacketDialers.NewInstance(ctx, config)
}

// NewPacketListener creates a [transport.PacketListener] according to the config text.
//
// Deprecated: Use [New] with [transport.PacketListener] as its type argument.
func (p *ProviderContainer) NewPacketListener(ctx context.Context, configText string) (transport.PacketListener, error) {
	config, err := ParseConfig(configText)
	if err != nil {
		return nil, err
	}
	return p.PacketListeners.NewInstance(ctx, config)
}

// SanitizeConfig removes sensitive information from the given config so it can be safely be used in logging and debugging.
func SanitizeConfig(configStr string) (string, error) {
	config, err := ParseConfig(configStr)
	if err != nil {
		return "", err
	}

	// Do nothing if the config is empty
	if config == nil {
		return "", nil
	}

	var sanitized string
	for config != nil {
		var part string
		scheme := strings.ToLower(config.URL.Scheme)
		switch scheme {
		case "ss":
			part, err = sanitizeShadowsocksURL(config.URL)
			if err != nil {
				return "", err
			}
		case "socks5":
			part, err = sanitizeSOCKS5URL(&config.URL)
			if err != nil {
				return "", err
			}
		case "h2connect", "h3connect", "httpconnect":
			part, err = sanitizeConnectURL(config.URL)
			if err != nil {
				return "", err
			}
		case "override", "quicprelude", "split", "tls", "tlsfrag":
			// No sanitization needed
			part = config.URL.String()
		default:
			part = scheme + "://UNKNOWN"
		}
		if sanitized == "" {
			sanitized = part
		} else {
			sanitized = part + "|" + sanitized
		}
		config = config.BaseConfig
	}
	return sanitized, nil
}

func sanitizeSOCKS5URL(u *url.URL) (string, error) {
	const redactedPlaceholder = "REDACTED"
	if u.User != nil {
		u.User = url.User(redactedPlaceholder)
		return u.String(), nil
	}
	return u.String(), nil
}
