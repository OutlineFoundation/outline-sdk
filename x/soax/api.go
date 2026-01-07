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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	apiHost = "api.soax.com"
)

// ConnType specifies the connection type for SOAX API calls.
type ConnType string

const (
	// ConnTypeResidential is for residential proxies, referred to as "wifi" by the API.
	ConnTypeResidential ConnType = "wifi"
	// ConnTypeMobile is for mobile proxies.
	ConnTypeMobile ConnType = "mobile"
)

// Client allows you to access the SOAX REST API.
type Client struct {
	APIKey     string
	PackageKey string
	// ConnType is the connection type.
	ConnType ConnType
	// HTTPClient is the client to use for API calls. If nil, a default client will be used.
	HTTPClient *http.Client
	// BaseURL for testing. If empty, "https://api.soax.com" is used. This can be a plain URL, or one
	// with a path.
	BaseURL string
}

func (c *Client) httpClient() *http.Client {
	if c.HTTPClient == nil {
		return http.DefaultClient
	}
	return c.HTTPClient
}

func (c *Client) newRequest(ctx context.Context, apiPath string, queryParams map[string]string) (*http.Request, error) {
	var baseURL *url.URL
	var err error
	if c.BaseURL != "" {
		baseURL, err = url.Parse(c.BaseURL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse BaseURL: %w", err)
		}
	} else {
		baseURL = &url.URL{
			Scheme: "https",
			Host:   apiHost,
		}
	}
	pathURL := &url.URL{Path: apiPath}
	apiURL := baseURL.ResolveReference(pathURL)

	q := apiURL.Query()
	q.Set("api_key", c.APIKey)
	q.Set("package_key", c.PackageKey)
	for k, v := range queryParams {
		if v != "" {
			q.Set(k, v)
		}
	}
	apiURL.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	return req, nil
}

func (c *Client) doAndDecode(req *http.Request, result any) error {
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("request failed with status %v: %v", resp.Status, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}
	if err := json.Unmarshal(body, result); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}
	return nil
}

// GetResidentialISPs returns the available ISPs for the given location.
// This is for Residential packages only. The official documentation refers to them as "WiFi ISPS".
// API reference: https://helpcenter.soax.com/en/articles/6228391-getting-a-list-of-wifi-isps
func (c *Client) GetResidentialISPs(ctx context.Context, countryCode, regionID, cityID string) ([]string, error) {
	req, err := c.newRequest(ctx, "/api/get-country-isp", map[string]string{
		"country_iso": strings.ToLower(countryCode),
		"region":      regionID,
		"city":        cityID,
	})
	if err != nil {
		return nil, err
	}
	var isps []string
	if err := c.doAndDecode(req, &isps); err != nil {
		return nil, err
	}
	return isps, nil
}

// GetMobileISPs returns the available mobile carriers for the given location.
// This is for Mobile packages only.
// API reference: https://helpcenter.soax.com/en/articles/6228381-getting-a-list-of-mobile-carriers
func (c *Client) GetMobileISPs(ctx context.Context, countryCode, regionID, cityID string) ([]string, error) {
	req, err := c.newRequest(ctx, "/api/get-country-operators", map[string]string{
		"country_iso": strings.ToLower(countryCode),
		"region":      regionID,
		"city":        cityID,
	})
	if err != nil {
		return nil, err
	}
	var isps []string
	if err := c.doAndDecode(req, &isps); err != nil {
		return nil, err
	}
	return isps, nil
}

// GetRegions returns the available regions for the given country and ISP.
// API reference: https://helpcenter.soax.com/en/articles/6227864-getting-a-list-of-regions
func (c *Client) GetRegions(ctx context.Context, countryCode, isp string) ([]string, error) {
	req, err := c.newRequest(ctx, "/api/get-country-regions", map[string]string{
		"country_iso": strings.ToLower(countryCode),
		"conn_type":   string(c.ConnType),
		"provider":    isp,
	})
	if err != nil {
		return nil, err
	}
	var regions []string
	if err := c.doAndDecode(req, &regions); err != nil {
		return nil, err
	}
	return regions, nil
}

// GetCities returns the available cities for the given country, ISP, and region.
// API reference: https://helpcenter.soax.com/en/articles/6228092-getting-a-list-of-cities
func (c *Client) GetCities(ctx context.Context, countryCode, isp, regionID string) ([]string, error) {
	req, err := c.newRequest(ctx, "/api/get-country-cities", map[string]string{
		"country_iso": strings.ToLower(countryCode),
		"conn_type":   string(c.ConnType),
		"provider":    isp,
		"region":      regionID,
	})
	if err != nil {
		return nil, err
	}
	var cities []string
	if err := c.doAndDecode(req, &cities); err != nil {
		return nil, err
	}
	return cities, nil
}
