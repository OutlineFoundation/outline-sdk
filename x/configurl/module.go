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
	"net/url"
	"strings"

	"golang.getoutline.org/sdk/transport"
)

// ProviderContainer contains providers for the creation of network objects based on a config. The config is
// extensible by registering providers for different config subtypes.
type ProviderContainer struct {
	StreamDialers   ExtensibleProvider[transport.StreamDialer]
	PacketDialers   ExtensibleProvider[transport.PacketDialer]
	PacketListeners ExtensibleProvider[transport.PacketListener]
}

// NewProviderContainer creates a [ProviderContainer] with the base instances properly initialized.
func NewProviderContainer() *ProviderContainer {
	return &ProviderContainer{
		StreamDialers:   NewExtensibleProvider[transport.StreamDialer](&transport.TCPDialer{}),
		PacketDialers:   NewExtensibleProvider[transport.PacketDialer](&transport.UDPDialer{}),
		PacketListeners: NewExtensibleProvider[transport.PacketListener](&transport.UDPListener{}),
	}
}

// RegisterDefaultProviders registers a set of default providers with the providers in [ProviderContainer].
func RegisterDefaultProviders(c *ProviderContainer) *ProviderContainer {
	// Please keep the list in alphabetical order.
	registerDisorderDialer(&c.StreamDialers, "disorder", c.StreamDialers.NewInstance)
	registerDO53StreamDialer(&c.StreamDialers, "do53", c.StreamDialers.NewInstance, c.PacketDialers.NewInstance)
	registerDOHStreamDialer(&c.StreamDialers, "doh", c.StreamDialers.NewInstance)

	registerOverrideStreamDialer(&c.StreamDialers, "override", c.StreamDialers.NewInstance)
	registerOverridePacketDialer(&c.PacketDialers, "override", c.PacketDialers.NewInstance)

	registerSOCKS5StreamDialer(&c.StreamDialers, "socks5", c.StreamDialers.NewInstance)
	registerSOCKS5PacketDialer(&c.PacketDialers, "socks5", c.StreamDialers.NewInstance, c.PacketDialers.NewInstance)
	registerSOCKS5PacketListener(&c.PacketListeners, "socks5", c.StreamDialers.NewInstance, c.PacketDialers.NewInstance)

	registerSplitStreamDialer(&c.StreamDialers, "split", c.StreamDialers.NewInstance)

	registerShadowsocksStreamDialer(&c.StreamDialers, "ss", c.StreamDialers.NewInstance)
	registerShadowsocksPacketDialer(&c.PacketDialers, "ss", c.PacketDialers.NewInstance)
	registerShadowsocksPacketListener(&c.PacketListeners, "ss", c.PacketDialers.NewInstance)

	registerTLSStreamDialer(&c.StreamDialers, "tls", c.StreamDialers.NewInstance)

	registerTLSFragStreamDialer(&c.StreamDialers, "tlsfrag", c.StreamDialers.NewInstance)

	registerWebsocketStreamDialer(&c.StreamDialers, "ws", c.StreamDialers.NewInstance)
	registerWebsocketPacketDialer(&c.PacketDialers, "ws", c.StreamDialers.NewInstance)

	registerWaitStreamDialer(&c.StreamDialers, "waitstream", c.StreamDialers.NewInstance)

	return c
}

// NewDefaultProviders creates a [ProviderContainer] with a set of default providers already registered.
func NewDefaultProviders() *ProviderContainer {
	return RegisterDefaultProviders(NewProviderContainer())
}

// NewStreamDialer creates a [transport.StreamDialer] according to the config text.
func (p *ProviderContainer) NewStreamDialer(ctx context.Context, configText string) (transport.StreamDialer, error) {
	config, err := ParseConfig(configText)
	if err != nil {
		return nil, err
	}
	return p.StreamDialers.NewInstance(ctx, config)
}

// NewPacketDialer creates a [transport.PacketDialer] according to the config text.
func (p *ProviderContainer) NewPacketDialer(ctx context.Context, configText string) (transport.PacketDialer, error) {
	config, err := ParseConfig(configText)
	if err != nil {
		return nil, err
	}
	return p.PacketDialers.NewInstance(ctx, config)
}

// NewPacketListner creates a [transport.PacketListener] according to the config text.
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
		case "override", "split", "tls", "tlsfrag":
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
