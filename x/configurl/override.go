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
	"fmt"
	"net"
	"net/url"
	"strings"

	"golang.getoutline.org/sdk/transport"
)

func parseOverrideStreamDialer(ctx context.Context, registry Registry, config *Config) (transport.StreamDialer, error) {
	sd, err := NewFromConfig[transport.StreamDialer](ctx, registry, config.BaseConfig)
	if err != nil {
		return nil, err
	}
	override, err := newOverrideFromURL(config.URL)
	if err != nil {
		return nil, err
	}
	return transport.FuncStreamDialer(func(ctx context.Context, addr string) (transport.StreamConn, error) {
		addr, err := override(addr)
		if err != nil {
			return nil, err
		}
		return sd.DialStream(ctx, addr)
	}), nil
}

func parseOverridePacketDialer(ctx context.Context, registry Registry, config *Config) (transport.PacketDialer, error) {
	pd, err := NewFromConfig[transport.PacketDialer](ctx, registry, config.BaseConfig)
	if err != nil {
		return nil, err
	}
	override, err := newOverrideFromURL(config.URL)
	if err != nil {
		return nil, err
	}
	return transport.FuncPacketDialer(func(ctx context.Context, addr string) (net.Conn, error) {
		addr, err := override(addr)
		if err != nil {
			return nil, err
		}
		return pd.DialPacket(ctx, addr)
	}), nil
}

func newOverrideFromURL(configURL url.URL) (func(string) (string, error), error) {
	query := configURL.Opaque
	values, err := url.ParseQuery(query)
	if err != nil {
		return nil, err
	}
	hostOverride, portOverride := "", ""
	for key, values := range values {
		switch strings.ToLower(key) {
		case "host":
			if len(values) != 1 {
				return nil, fmt.Errorf("host option must has one value, found %v", len(values))
			}
			hostOverride = values[0]
		case "port":
			if len(values) != 1 {
				return nil, fmt.Errorf("port option must has one value, found %v", len(values))
			}
			portOverride = values[0]
		default:
			return nil, fmt.Errorf("unsupported option %v", key)
		}
	}
	return func(address string) (string, error) {
		// Optimization when we fully override the address.
		if hostOverride != "" && portOverride != "" {
			return net.JoinHostPort(hostOverride, portOverride), nil
		}
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return "", fmt.Errorf("address is not valid host:port: %w", err)
		}
		if hostOverride != "" {
			host = hostOverride
		}
		if portOverride != "" {
			port = portOverride
		}
		return net.JoinHostPort(host, port), nil
	}, nil
}
