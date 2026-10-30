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
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Config is a pre-parsed generic config created from pipe-separated URLs.
type Config struct {
	URL        url.URL
	BaseConfig *Config
}

// ParseConfig will parse a config given as a string and return the structured [Config].
func ParseConfig(configText string) (*Config, error) {
	parts := strings.Split(strings.TrimSpace(configText), "|")
	if len(parts) == 1 && parts[0] == "" {
		return nil, nil
	}

	var config *Config = nil
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, errors.New("empty config part")
		}
		// Make it "<scheme>:" if it's only "<scheme>" to parse as a URL.
		if !strings.Contains(part, ":") {
			part += ":"
		}
		url, err := url.Parse(part)
		if err != nil {
			return nil, fmt.Errorf("part is not a valid URL: %w", err)
		}
		config = &Config{URL: *url, BaseConfig: config}
	}
	return config, nil
}
