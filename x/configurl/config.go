// Copyright 2023 The Outline Authors
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
)

// Config is a pre-parsed generic config created from pipe-separated URLs.
type Config struct {
	URL        url.URL
	BaseConfig *Config
}

// BuildFunc creates an instance of ObjectType for the legacy [TypeRegistry] API.
// Use [Constructor] with the registry API to receive the registry for dependencies.
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
//
// Deprecated: Use [NewFromConfig] with a [Registry] instead.
func (p *ExtensibleProvider[ObjectType]) NewInstance(ctx context.Context, config *Config) (ObjectType, error) {
	var zero ObjectType
	if config == nil {
		if p.BaseInstance == zero {
			return zero, errors.New("base instance is not configured")
		}
		return p.BaseInstance, nil
	}

	newInstance, ok := p.ensureBuildersMap()[config.URL.Scheme]
	if !ok {
		return zero, fmt.Errorf("config type '%v' is not registered", config.URL.Scheme)
	}
	return newInstance(ctx, config)
}

// ParseConfig will parse a config given as a string and return the structured [Config].
func ParseConfig(configText string) (*Config, error) {
	parts := strings.Split(strings.TrimSpace(configText), "|")
	if len(parts) == 1 && parts[0] == "" {
		return nil, nil
	}

	var config *Config = nil
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, errors.New("empty config part")
		}
		// Make it "<scheme>:" if it's only "<scheme>" to parse as a URL.
		if !strings.Contains(part, ":") {
			part += ":"
		}
		url, err := url.Parse(part)
		if err != nil {
			return nil, fmt.Errorf("part is not a valid URL: %w", err)
		}
		config = &Config{URL: *url, BaseConfig: config}
	}
	return config, nil
}
