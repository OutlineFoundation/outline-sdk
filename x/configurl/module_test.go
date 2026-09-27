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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSanitizeConfig(t *testing.T) {
	// Test that empty config is accepted.
	_, err := SanitizeConfig("")
	require.NoError(t, err)

	// Test that a invalid cypher is rejected.
	_, err = SanitizeConfig("split:5|ss://jhvdsjkfhvkhsadvf@example.com:1234?prefix=HTTP%2F1.1%20")
	require.Error(t, err)

	// Test that a valid config is accepted and user info is redacted.
	sanitizedConfig, err := SanitizeConfig("split:5|ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpLeTUyN2duU3FEVFB3R0JpQ1RxUnlT@example.com:1234?prefix=HTTP%2F1.1%20")
	require.NoError(t, err)
	require.Equal(t, "split:5|ss://REDACTED@example.com:1234?prefix=HTTP%2F1.1+", sanitizedConfig)

	// Test sanitizer with unknown transport.
	sanitizedConfig, err = SanitizeConfig("split:5|vless://ac08785d-203d-4db4-915c-eb4e23435fd62@example.com:443?path=%2Fvless&security=tls&encryption=none&alpn=h2&host=sub.hello.com&fp=chrome&type=ws&sni=sub.hello.com#vless-ws-tls-cdn")
	require.NoError(t, err)
	require.Equal(t, "split:5|vless://UNKNOWN", sanitizedConfig)

	// Test sanitizer with transport that don't have user info.
	sanitizedConfig, err = SanitizeConfig("split:5|quicprelude:count=3&mode=random")
	require.NoError(t, err)
	require.Equal(t, "split:5|quicprelude:count=3&mode=random", sanitizedConfig)

	sanitizedConfig, err = SanitizeConfig("split:5|tlsfrag:5")
	require.NoError(t, err)
	require.Equal(t, "split:5|tlsfrag:5", sanitizedConfig)

	// Test sanitization on an unknown transport.
	sanitizedConfig, err = SanitizeConfig("transport://hjdbfjhbqfjheqrf")
	require.NoError(t, err)
	require.Equal(t, "transport://UNKNOWN", sanitizedConfig)

	// Test that an invalid config is rejected.
	_, err = SanitizeConfig("::hghg")
	require.Error(t, err)
}

func TestSocks5URLSanitization(t *testing.T) {
	configString := "socks5://myuser:mypassword@192.168.1.100:1080"
	sanitizedConfig, err := SanitizeConfig(configString)
	require.NoError(t, err)
	require.Equal(t, "socks5://REDACTED@192.168.1.100:1080", sanitizedConfig)
}
