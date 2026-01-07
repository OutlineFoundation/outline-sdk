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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClient(t *testing.T) {
	const (
		testAPIKey     = "test_api_key"
		testPackageKey = "test_package_key"
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		q := r.URL.Query()
		require.Equal(t, testAPIKey, q.Get("api_key"))
		require.Equal(t, testPackageKey, q.Get("package_key"))

		var responseData any
		switch r.URL.Path {
		case "/api/get-country-isp":
			require.Equal(t, "us", q.Get("country_iso"))
			require.Equal(t, "ny", q.Get("region"))
			require.Equal(t, "nyc", q.Get("city"))
			responseData = []string{"isp1", "isp2"}
		case "/api/get-country-operators":
			require.Equal(t, "de", q.Get("country_iso"))
			require.Equal(t, "be", q.Get("region"))
			require.Equal(t, "ber", q.Get("city"))
			responseData = []string{"op1", "op2"}
		case "/api/get-country-regions":
			require.Equal(t, "fr", q.Get("country_iso"))
			require.Equal(t, "mobile", q.Get("conn_type"))
			require.Equal(t, "orange", q.Get("provider"))
			responseData = []string{"region1", "region2"}
		case "/api/get-country-cities":
			require.Equal(t, "es", q.Get("country_iso"))
			require.Equal(t, "wifi", q.Get("conn_type"))
			require.Equal(t, "movistar", q.Get("provider"))
			require.Equal(t, "md", q.Get("region"))
			responseData = []string{"city1", "city2"}
		default:
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(responseData)
		require.NoError(t, err)
	}))
	defer server.Close()

	client := &Client{
		APIKey:     testAPIKey,
		PackageKey: testPackageKey,
		HTTPClient: server.Client(),
		BaseURL:    server.URL,
	}

	ctx := context.Background()

	t.Run("GetResidentialISPs", func(t *testing.T) {
		isps, err := client.GetResidentialISPs(ctx, "US", "ny", "nyc")
		require.NoError(t, err)
		require.Equal(t, []string{"isp1", "isp2"}, isps)
	})

	t.Run("GetMobileISPs", func(t *testing.T) {
		isps, err := client.GetMobileISPs(ctx, "DE", "be", "ber")
		require.NoError(t, err)
		require.Equal(t, []string{"op1", "op2"}, isps)
	})

	t.Run("GetRegions", func(t *testing.T) {
		client.ConnType = ConnTypeMobile
		regions, err := client.GetRegions(ctx, "FR", "orange")
		require.NoError(t, err)
		require.Equal(t, []string{"region1", "region2"}, regions)
	})

	t.Run("GetCities", func(t *testing.T) {
		client.ConnType = ConnTypeResidential
		cities, err := client.GetCities(ctx, "ES", "movistar", "md")
		require.NoError(t, err)
		require.Equal(t, []string{"city1", "city2"}, cities)
	})

	t.Run("Error", func(t *testing.T) {
		errorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}))
		defer errorServer.Close()
		errorClient := &Client{
			APIKey:     testAPIKey,
			PackageKey: testPackageKey,
			HTTPClient: errorServer.Client(),
			BaseURL:    errorServer.URL,
		}
		_, err := errorClient.GetResidentialISPs(ctx, "us", "ny", "nyc")
		require.Error(t, err)
		require.Contains(t, err.Error(), "request failed with status 500 Internal Server Error")
		require.Contains(t, err.Error(), "internal server error")
	})

	t.Run("BadJSON", func(t *testing.T) {
		badJSONServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, err := w.Write([]byte(`{"bad json`))
			require.NoError(t, err)
		}))
		defer badJSONServer.Close()
		badJSONClient := &Client{
			APIKey:     testAPIKey,
			PackageKey: testPackageKey,
			HTTPClient: badJSONServer.Client(),
			BaseURL:    badJSONServer.URL,
		}
		_, err := badJSONClient.GetResidentialISPs(ctx, "us", "ny", "nyc")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to decode response")
	})
}
