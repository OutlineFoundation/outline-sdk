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
	"testing"

	"github.com/stretchr/testify/require"
	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/x/configurl"
)

// Verify the legacy signatures, including composite literals and method expressions.
var (
	_ = configurl.ProviderContainer{
		StreamDialers:   configurl.ExtensibleProvider[transport.StreamDialer]{BaseInstance: &transport.TCPDialer{}},
		PacketDialers:   configurl.ExtensibleProvider[transport.PacketDialer]{BaseInstance: &transport.UDPDialer{}},
		PacketListeners: configurl.ExtensibleProvider[transport.PacketListener]{BaseInstance: &transport.UDPListener{}},
	}
	_ func() *configurl.ProviderContainer                                                           = configurl.NewProviderContainer
	_ func() *configurl.ProviderContainer                                                           = configurl.NewDefaultProviders
	_ func(*configurl.ProviderContainer) *configurl.ProviderContainer                               = configurl.RegisterDefaultProviders
	_ func(*configurl.ProviderContainer, context.Context, string) (transport.StreamDialer, error)   = (*configurl.ProviderContainer).NewStreamDialer
	_ func(*configurl.ProviderContainer, context.Context, string) (transport.PacketDialer, error)   = (*configurl.ProviderContainer).NewPacketDialer
	_ func(*configurl.ProviderContainer, context.Context, string) (transport.PacketListener, error) = (*configurl.ProviderContainer).NewPacketListener
)

func TestLegacyProviderConstructors(t *testing.T) {
	for _, defaults := range []bool{false, true} {
		providers := configurl.NewProviderContainer()
		if defaults {
			providers = configurl.NewDefaultProviders()
		}
		ctx := context.Background()
		sd, err := providers.NewStreamDialer(ctx, "")
		require.NoError(t, err)
		require.Same(t, providers.StreamDialers.BaseInstance, sd)
		pd, err := providers.NewPacketDialer(ctx, "")
		require.NoError(t, err)
		require.Same(t, providers.PacketDialers.BaseInstance, pd)
		pl, err := providers.NewPacketListener(ctx, "")
		require.NoError(t, err)
		require.Same(t, providers.PacketListeners.BaseInstance, pl)
		_, streamErr := providers.NewStreamDialer(ctx, "split:1")
		_, packetErr := providers.NewPacketDialer(ctx, "override:port=53")
		_, listenerErr := providers.NewPacketListener(ctx, "quicprelude:count=0")
		for _, err := range []error{streamErr, packetErr, listenerErr} {
			if defaults {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, "is not registered")
			}
		}
	}
}

func TestLegacyRegistrationUsesCurrentProviders(t *testing.T) {
	providers := configurl.NewProviderContainer()
	require.Same(t, providers, configurl.RegisterDefaultProviders(providers))
	newInstance := func(ctx context.Context, config *configurl.Config) (transport.StreamDialer, error) {
		return providers.StreamDialers.NewInstance(ctx, config.BaseConfig)
	}
	providers.StreamDialers.RegisterType("custom", newInstance)
	// Assign the base after registering both built-in and custom constructors.
	baseErr := errors.New("configured base")
	dialStream := func(context.Context, string) (transport.StreamConn, error) { return nil, baseErr }
	providers.StreamDialers.BaseInstance = transport.FuncStreamDialer(dialStream)
	for _, config := range []string{"split:1", "custom|split:1"} {
		dialer, err := providers.NewStreamDialer(context.Background(), config)
		require.NoError(t, err)
		_, err = dialer.DialStream(context.Background(), "unused.invalid:443")
		require.ErrorIs(t, err, baseErr)
	}
}

func TestLegacyPacketDependenciesRemainLive(t *testing.T) {
	providers := configurl.NewDefaultProviders()
	base := &registryBase{errors.New("late packet base")}
	providers.PacketDialers.BaseInstance = base
	providers.PacketListeners.BaseInstance = base
	packet, err := providers.NewPacketDialer(context.Background(), "override:port=53")
	require.NoError(t, err)
	_, err = packet.DialPacket(context.Background(), "unused.invalid:443")
	require.ErrorIs(t, err, base.err)
	listener, err := providers.NewPacketListener(context.Background(), "quicprelude:count=0")
	require.NoError(t, err)
	_, err = listener.ListenPacket(context.Background())
	require.ErrorIs(t, err, base.err)
}

func TestLegacyConfigErrorClassification(t *testing.T) {
	ctx := context.Background()
	providers := configurl.NewDefaultProviders()
	providers.StreamDialers.RegisterType("disabled", nil)
	for _, cfg := range []string{"unknown", "disabled", "unknown|split:2", "disabled|split:2"} {
		_, err := providers.NewStreamDialer(ctx, cfg)
		require.ErrorIs(t, err, errors.ErrUnsupported, cfg)
	}
	for _, cfg := range []string{"split:invalid", "split:invalid|tlsfrag:1", "split:2||tlsfrag:1", "socks5://%zz"} {
		_, err := providers.NewStreamDialer(ctx, cfg)
		require.Error(t, err, cfg)
		require.NotErrorIs(t, err, errors.ErrUnsupported, cfg)
	}
	providers.StreamDialers.BaseInstance = nil
	for _, cfg := range []string{"", "split:2"} {
		_, err := providers.NewStreamDialer(ctx, cfg)
		require.ErrorIs(t, err, errors.ErrUnsupported, cfg)
	}
}
