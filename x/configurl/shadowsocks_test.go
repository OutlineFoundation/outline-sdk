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
	"encoding/base64"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.getoutline.org/sdk/transport/shadowsocks"
)

func Test_sanitizeShadowsocksURL(t *testing.T) {
	ssURL, err := url.Parse("ss://YWVzLTEyOC1nY206dGVzdA@192.168.100.1:8888")
	require.NoError(t, err)
	sanitized, err := sanitizeShadowsocksURL(*ssURL)
	require.NoError(t, err)
	require.Equal(t, "ss://REDACTED@192.168.100.1:8888", sanitized)
}

func Test_sanitizeShadowsocksURL_withPrefix(t *testing.T) {
	ssURL, err := url.Parse("ss://YWVzLTEyOC1nY206dGVzdA@192.168.100.1:8888?prefix=foo")
	require.NoError(t, err)
	sanitized, err := sanitizeShadowsocksURL(*ssURL)
	require.NoError(t, err)
	require.Equal(t, "ss://REDACTED@192.168.100.1:8888?prefix=foo", sanitized)
}

func TestParseShadowsocksURLFullyEncoded(t *testing.T) {
	encoded := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString([]byte("aes-256-gcm:1234567@example.com:1234?prefix=HTTP%2F1.1%20"))
	config, err := ParseConfig("ss://" + string(encoded) + "#outline-123")
	require.NoError(t, err)
	require.Nil(t, config.BaseConfig)

	ssConfig, err := parseShadowsocksURL(config.URL)

	require.NoError(t, err)
	require.Equal(t, "example.com:1234", ssConfig.serverAddress)
	require.Equal(t, "HTTP/1.1 ", string(ssConfig.prefix))
}

func TestParseShadowsocksURLUserInfoEncoded(t *testing.T) {
	encoded := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString([]byte("aes-256-gcm:1234567"))
	config, err := ParseConfig("ss://" + string(encoded) + "@example.com:1234?prefix=HTTP%2F1.1%20" + "#outline-123")
	require.NoError(t, err)
	require.Nil(t, config.BaseConfig)

	ssConfig, err := parseShadowsocksURL(config.URL)

	require.NoError(t, err)
	require.Equal(t, "example.com:1234", ssConfig.serverAddress)
	require.Equal(t, "HTTP/1.1 ", string(ssConfig.prefix))
}

func TestParseShadowsocksURLUserInfoLegacyEncoded(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:shadowsocks"))
	config, err := ParseConfig("ss://" + string(encoded) + "@example.com:1234?prefix=HTTP%2F1.1%20" + "#outline-123")
	require.NoError(t, err)
	require.Nil(t, config.BaseConfig)

	ssConfig, err := parseShadowsocksURL(config.URL)

	require.NoError(t, err)
	require.Equal(t, "example.com:1234", ssConfig.serverAddress)
	require.Equal(t, "HTTP/1.1 ", string(ssConfig.prefix))
}

func TestLegacyEncodedShadowsocksURL(t *testing.T) {
	configString := "ss://YWVzLTEyOC1nY206c2hhZG93c29ja3M=@example.com:1234"
	config, err := ParseConfig(configString)
	require.NoError(t, err)
	require.Nil(t, config.BaseConfig)

	ssConfig, err := parseShadowsocksURL(config.URL)

	require.NoError(t, err)
	require.Equal(t, "example.com:1234", ssConfig.serverAddress)
}

func TestParseShadowsocksURLNoEncoding(t *testing.T) {
	configString := "ss://aes-256-gcm:1234567@example.com:1234"
	config, err := ParseConfig(configString)
	require.NoError(t, err)
	require.Nil(t, config.BaseConfig)

	ssConfig, err := parseShadowsocksURL(config.URL)

	require.NoError(t, err)
	require.Equal(t, "example.com:1234", ssConfig.serverAddress)
}

func TestParseShadowsocksURLNoEncodingPercentEncodedPassword(t *testing.T) {
	// SIP002 requires the password in a plain user info to be percent-encoded.
	configString := "ss://chacha20-ietf-poly1305:pass%2Fw%3Fo%40r%7Cd%20%25@example.com:1234"
	config, err := ParseConfig(configString)
	require.NoError(t, err)
	require.Nil(t, config.BaseConfig)

	ssConfig, err := parseShadowsocksURL(config.URL)

	require.NoError(t, err)
	require.Equal(t, "example.com:1234", ssConfig.serverAddress)
	expectedKey, err := shadowsocks.NewEncryptionKey("chacha20-ietf-poly1305", "pass/w?o@r|d %")
	require.NoError(t, err)
	require.Equal(t, expectedKey, ssConfig.cryptoKey)
}

func TestParseShadowsocksURLInvalidCipherInfoFails(t *testing.T) {
	configString := "ss://aes-256-gcm1234567@example.com:1234"
	config, err := ParseConfig(configString)
	require.NoError(t, err)
	require.Nil(t, config.BaseConfig)

	_, err = parseShadowsocksURL(config.URL)

	require.Error(t, err)
}

func TestParseShadowsocksURLUnsupportedCypherFails(t *testing.T) {
	configString := "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwnTpLeTUyN2duU3FEVFB3R0JpQ1RxUnlT@example.com:1234"
	config, err := ParseConfig(configString)
	require.NoError(t, err)
	require.Nil(t, config.BaseConfig)

	_, err = parseShadowsocksURL(config.URL)

	require.Error(t, err)
}

func TestParseShadowsocksLegacyBase64URL(t *testing.T) {
	encoded := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString([]byte("aes-256-gcm:1234567@example.com:1234?prefix=HTTP%2F1.1%20"))
	config, err := ParseConfig("ss://" + string(encoded) + "#outline-123")
	require.NoError(t, err)
	require.Nil(t, config.BaseConfig)

	ssConfig, err := parseShadowsocksLegacyBase64URL(config.URL)

	require.NoError(t, err)
	require.Equal(t, "example.com:1234", ssConfig.serverAddress)
	require.Equal(t, "HTTP/1.1 ", string(ssConfig.prefix))
}

func TestParseShadowsocksLegacyBase64URLPasswordWithAt(t *testing.T) {
	encoded := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString([]byte("aes-256-gcm:p@ss@example.com:1234"))
	config, err := ParseConfig("ss://" + string(encoded))
	require.NoError(t, err)

	ssConfig, err := parseShadowsocksLegacyBase64URL(config.URL)

	require.NoError(t, err)
	require.Equal(t, "example.com:1234", ssConfig.serverAddress)
	expectedKey, err := shadowsocks.NewEncryptionKey("aes-256-gcm", "p@ss")
	require.NoError(t, err)
	require.Equal(t, expectedKey, ssConfig.cryptoKey)
}

func TestParseShadowsocksSIP002URLUnsuccessful(t *testing.T) {
	encoded := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString([]byte("aes-256-gcm:1234567@example.com:1234?prefix=HTTP%2F1.1%20"))
	config, err := ParseConfig("ss://" + string(encoded) + "#outline-123")
	require.NoError(t, err)
	require.Nil(t, config.BaseConfig)

	_, err = parseShadowsocksSIP002URL(config.URL)
	require.Error(t, err, "URL is %v", config.URL.String())
}
