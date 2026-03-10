// Copyright 2025 The Outline Authors
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

package soax

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.getoutline.org/sdk/transport"
)

const checkerURL = "https://checker.soax.com/api/ipinfo"

type ipInfoResponse struct {
	Status bool   `json:"status"`
	Reason string `json:"reason"`
	Data   struct {
		CountryCode string `json:"country_code"`
		IP          string `json:"ip"`
		ISP         string `json:"isp"`
		Carrier     string `json:"carrier"`
		Region      string `json:"region"`
		City        string `json:"city"`
	} `json:"data"`
}

func newLiveProxyConfig(t *testing.T) ProxySessionConfig {
	t.Helper()
	packageIDStr := os.Getenv("SOAX_PACKAGE_ID")
	packageKey := os.Getenv("SOAX_PACKAGE_KEY")
	if packageIDStr == "" || packageKey == "" {
		t.Skip("SOAX_PACKAGE_ID and SOAX_PACKAGE_KEY must be set to run live proxy tests")
	}
	packageID, err := strconv.Atoi(packageIDStr)
	require.NoError(t, err)
	return ProxySessionConfig{
		Auth: ProxyAuthConfig{
			PackageID:  packageID,
			PackageKey: packageKey,
		},
		Node: ProxyNodeConfig{
			CountryCode: "US",
		},
	}
}

func fetchIPInfo(t *testing.T, dialer transport.StreamDialer) *ipInfoResponse {
	t.Helper()
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.DialStream(ctx, addr)
			},
		},
	}
	resp, err := httpClient.Get(checkerURL)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var info ipInfoResponse
	require.NoError(t, json.Unmarshal(body, &info))
	require.True(t, info.Status, "checker returned status=false: %s", info.Reason)
	return &info
}

func TestLiveProxy_SOCKS5(t *testing.T) {
	config := newLiveProxyConfig(t)
	session := config.NewSession()
	client, err := session.NewSOCKS5Client()
	require.NoError(t, err)

	info := fetchIPInfo(t, client)
	require.Equal(t, "US", info.Data.CountryCode)
	t.Logf("SOCKS5: ip=%s isp=%s city=%s region=%s", info.Data.IP, info.Data.ISP, info.Data.City, info.Data.Region)
}

func TestLiveProxy_HTTPConnect(t *testing.T) {
	config := newLiveProxyConfig(t)
	session := config.NewSession()
	dialer, err := session.NewWebProxyStreamDialer()
	require.NoError(t, err)

	info := fetchIPInfo(t, dialer)
	require.Equal(t, "US", info.Data.CountryCode)
	t.Logf("HTTP CONNECT: ip=%s isp=%s city=%s region=%s", info.Data.IP, info.Data.ISP, info.Data.City, info.Data.Region)
}