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
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func newLiveClient(t *testing.T) *Client {
	t.Helper()
	apiKey := os.Getenv("SOAX_API_KEY")
	packageKey := os.Getenv("SOAX_PACKAGE_KEY")
	if apiKey == "" || packageKey == "" {
		t.Skip("SOAX_API_KEY and SOAX_PACKAGE_KEY must be set to run live API tests")
	}
	return &Client{
		APIKey:     apiKey,
		PackageKey: packageKey,
	}
}

func TestLiveAPI_GetResidentialISPs(t *testing.T) {
	client := newLiveClient(t)
	isps, err := client.GetResidentialISPs(context.Background(), "US", "", "")
	require.NoError(t, err)
	require.NotEmpty(t, isps)
	t.Logf("Residential ISPs in US (%v): %v", len(isps), isps)
}

func TestLiveAPI_GetMobileISPs(t *testing.T) {
	client := newLiveClient(t)
	isps, err := client.GetMobileISPs(context.Background(), "US", "", "")
	require.NoError(t, err)
	require.NotEmpty(t, isps)
	t.Logf("Mobile ISPs in US (%v): %v", len(isps), isps)
}

func TestLiveAPI_GetRegions(t *testing.T) {
	client := newLiveClient(t)
	regions, err := client.GetRegions(context.Background(), ConnTypeMobile, "US", "")
	require.NoError(t, err)
	require.NotEmpty(t, regions)
	t.Logf("Mobile regions in US (%v): %v", len(regions), regions)
}

func TestLiveAPI_GetCities(t *testing.T) {
	client := newLiveClient(t)
	cities, err := client.GetCities(context.Background(), ConnTypeMobile, "US", "", "")
	require.NoError(t, err)
	require.NotEmpty(t, cities)
	t.Logf("Mobile cities in US (%v): %v", len(cities), cities)
}