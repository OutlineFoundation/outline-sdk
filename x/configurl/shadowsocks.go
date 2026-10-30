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
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/transport/shadowsocks"
)

func newShadowsocksStreamDialer(ctx context.Context, registry Registry, config *Config) (transport.StreamDialer, error) {
	sd, err := NewFromConfig[transport.StreamDialer](ctx, registry, config.BaseConfig)
	if err != nil {
		return nil, err
	}
	ssConfig, err := parseShadowsocksURL(config.URL)
	if err != nil {
		return nil, err
	}
	endpoint := &transport.StreamDialerEndpoint{Dialer: sd, Address: ssConfig.serverAddress}
	dialer, err := shadowsocks.NewStreamDialer(endpoint, ssConfig.cryptoKey)
	if err != nil {
		return nil, err
	}
	if len(ssConfig.prefix) > 0 {
		dialer.SaltGenerator = shadowsocks.NewPrefixSaltGenerator(ssConfig.prefix)
	}
	return dialer, nil
}

func newShadowsocksPacketDialer(ctx context.Context, registry Registry, config *Config) (transport.PacketDialer, error) {
	pd, err := NewFromConfig[transport.PacketDialer](ctx, registry, config.BaseConfig)
	if err != nil {
		return nil, err
	}
	ssConfig, err := parseShadowsocksURL(config.URL)
	if err != nil {
		return nil, err
	}
	endpoint := &transport.PacketDialerEndpoint{Dialer: pd, Address: ssConfig.serverAddress}
	pl, err := shadowsocks.NewPacketListener(endpoint, ssConfig.cryptoKey)
	if err != nil {
		return nil, err
	}
	// TODO: support UDP prefix.
	return transport.PacketListenerDialer{Listener: pl}, nil
}

func newShadowsocksPacketListener(ctx context.Context, registry Registry, config *Config) (transport.PacketListener, error) {
	pd, err := NewFromConfig[transport.PacketDialer](ctx, registry, config.BaseConfig)
	if err != nil {
		return nil, err
	}
	ssConfig, err := parseShadowsocksURL(config.URL)
	if err != nil {
		return nil, err
	}
	endpoint := &transport.PacketDialerEndpoint{Dialer: pd, Address: ssConfig.serverAddress}
	return shadowsocks.NewPacketListener(endpoint, ssConfig.cryptoKey)
}

type shadowsocksConfig struct {
	serverAddress string
	cryptoKey     *shadowsocks.EncryptionKey
	prefix        []byte
}

func parseShadowsocksURL(url url.URL) (*shadowsocksConfig, error) {
	// attempt to decode as SIP002 URI format and
	// fall back to legacy base64 format if decoding fails
	config, err := parseShadowsocksSIP002URL(url)
	if err == nil {
		return config, nil
	}
	return parseShadowsocksLegacyBase64URL(url)
}

// parseShadowsocksLegacyBase64URL parses URL based on legacy base64 format:
// https://shadowsocks.org/doc/configs.html#uri-and-qr-code
func parseShadowsocksLegacyBase64URL(url url.URL) (*shadowsocksConfig, error) {
	config := &shadowsocksConfig{}
	if url.Host == "" {
		return nil, errors.New("host not specified")
	}
	decoded, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(url.Host)
	if err != nil {
		// If decoding fails, return the original url with error
		return nil, fmt.Errorf("failed to decode host string [%v]: %w", url.String(), err)
	}
	var fragment string
	if url.Fragment != "" {
		fragment = "#" + url.Fragment
	} else {
		fragment = ""
	}
	newURL, err := url.Parse(strings.ToLower(url.Scheme) + "://" + string(decoded) + fragment)
	if err != nil {
		// if parsing fails, return the original url with error
		return nil, fmt.Errorf("failed to parse config part: %w", err)
	}
	// extend this check to see if decoded string contains contains other valid fields
	if newURL.User == nil {
		return nil, fmt.Errorf("invalid user info: %w", err)
	}
	cipherInfoBytes := newURL.User.String()
	cipherName, secret, found := strings.Cut(string(cipherInfoBytes), ":")
	if !found {
		return nil, errors.New("invalid cipher info: no ':' separator")
	}
	config.serverAddress = newURL.Host
	config.cryptoKey, err = shadowsocks.NewEncryptionKey(cipherName, secret)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	prefixStr := newURL.Query().Get("prefix")
	if len(prefixStr) > 0 {
		config.prefix, err = parseStringPrefix(prefixStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse prefix: %w", err)
		}
	}
	return config, nil
}

// parseShadowsocksSIP002URL parses URL based on SIP002 format:
// https://shadowsocks.org/doc/sip002.html
func parseShadowsocksSIP002URL(url url.URL) (*shadowsocksConfig, error) {
	config := &shadowsocksConfig{}
	if url.Host == "" {
		return nil, errors.New("host not specified")
	}
	config.serverAddress = url.Host
	userInfo := url.User.String()
	// Cipher info can be optionally encoded with Base64URL.
	encoding := base64.URLEncoding.WithPadding(base64.NoPadding)
	decodedUserInfo, err := encoding.DecodeString(userInfo)
	if err != nil {
		// Try base64 decoding in legacy mode
		decodedUserInfo, err = base64.StdEncoding.DecodeString(userInfo)
	}
	var cipherInfo string
	if err == nil {
		cipherInfo = string(decodedUserInfo)
	} else {
		cipherInfo = userInfo
	}
	cipherName, secret, found := strings.Cut(cipherInfo, ":")
	if !found {
		return nil, errors.New("invalid cipher info: no ':' separator")
	}
	config.cryptoKey, err = shadowsocks.NewEncryptionKey(cipherName, secret)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	prefixStr := url.Query().Get("prefix")
	if len(prefixStr) > 0 {
		config.prefix, err = parseStringPrefix(prefixStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse prefix: %w", err)
		}
	}
	return config, nil
}

func parseStringPrefix(utf8Str string) ([]byte, error) {
	runes := []rune(utf8Str)
	rawBytes := make([]byte, len(runes))
	for i, r := range runes {
		if (r & 0xFF) != r {
			return nil, fmt.Errorf("character out of range: %d", r)
		}
		rawBytes[i] = byte(r)
	}
	return rawBytes, nil
}

func sanitizeShadowsocksURL(u url.URL) (string, error) {
	config, err := parseShadowsocksURL(u)
	if err != nil {
		return "", err
	}
	values := make(url.Values)
	if prefix := u.Query().Get("prefix"); prefix != "" {
		values.Add("prefix", prefix)
	}
	cleanURL := url.URL{
		Scheme:   "ss",
		User:     url.User("REDACTED"),
		Host:     config.serverAddress,
		RawQuery: values.Encode(),
	}
	return cleanURL.String(), nil
}
