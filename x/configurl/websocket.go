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
	"net"
	"net/url"
	"strings"

	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/x/websocket"
)

type wsConfig struct {
	tcpPath string
	udpPath string
}

func parseWSConfig(configURL url.URL) (*wsConfig, error) {
	query := configURL.Opaque
	values, err := url.ParseQuery(query)
	if err != nil {
		return nil, err
	}
	var cfg wsConfig
	for key, values := range values {
		switch strings.ToLower(key) {
		case "tcp_path":
			if len(values) != 1 {
				return nil, fmt.Errorf("udp_path option must has one value, found %v", len(values))
			}
			cfg.tcpPath = values[0]
		case "udp_path":
			if len(values) != 1 {
				return nil, fmt.Errorf("tcp_path option must has one value, found %v", len(values))
			}
			cfg.udpPath = values[0]
		default:
			return nil, fmt.Errorf("unsupported option %v", key)
		}
	}
	return &cfg, nil
}

func parseWebsocketStreamDialer(ctx context.Context, registry Registry, config *Config) (transport.StreamDialer, error) {
	sd, err := NewFromConfig[transport.StreamDialer](ctx, registry, config.BaseConfig)
	if err != nil {
		return nil, err
	}
	wsConfig, err := parseWSConfig(config.URL)
	if err != nil {
		return nil, err
	}
	if wsConfig.tcpPath == "" {
		return nil, errors.New("must specify tcp_path")
	}
	return transport.FuncStreamDialer(func(ctx context.Context, addr string) (transport.StreamConn, error) {
		wsURL := url.URL{Scheme: "ws", Host: addr, Path: wsConfig.tcpPath}
		connect, err := websocket.NewStreamEndpoint(wsURL.String(), &transport.StreamDialerEndpoint{Address: addr, Dialer: sd})
		if err != nil {
			return nil, fmt.Errorf("failed to create websocket stream endpoint: %w", err)
		}
		return connect(ctx)
	}), nil
}

func parseWebsocketPacketDialer(ctx context.Context, registry Registry, config *Config) (transport.PacketDialer, error) {
	sd, err := NewFromConfig[transport.StreamDialer](ctx, registry, config.BaseConfig)
	if err != nil {
		return nil, err
	}
	wsConfig, err := parseWSConfig(config.URL)
	if err != nil {
		return nil, err
	}
	if wsConfig.udpPath == "" {
		return nil, errors.New("must specify udp_path")
	}
	return transport.FuncPacketDialer(func(ctx context.Context, addr string) (net.Conn, error) {
		wsURL := url.URL{Scheme: "ws", Host: addr, Path: wsConfig.udpPath}
		connect, err := websocket.NewPacketEndpoint(wsURL.String(), &transport.StreamDialerEndpoint{Address: addr, Dialer: sd})
		if err != nil {
			return nil, fmt.Errorf("failed to create websocket stream endpoint: %w", err)
		}
		return connect(ctx)
	}), nil
}
