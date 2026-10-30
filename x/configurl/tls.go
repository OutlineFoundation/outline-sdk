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
	"fmt"
	"net/url"
	"strings"

	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/transport/tls"
)

func newTLSStreamDialer(ctx context.Context, registry Registry, config *Config) (transport.StreamDialer, error) {
	sd, err := NewFromConfig[transport.StreamDialer](ctx, registry, config.BaseConfig)
	if err != nil {
		return nil, err
	}
	options, err := parseOptions(config.URL)
	if err != nil {
		return nil, err
	}
	return tls.NewStreamDialer(sd, options...)
}

func parseOptions(configURL url.URL) ([]tls.ClientOption, error) {
	query := configURL.Opaque
	values, err := url.ParseQuery(query)
	if err != nil {
		return nil, err
	}
	options := []tls.ClientOption{}
	for key, values := range values {
		switch strings.ToLower(key) {
		case "sni":
			if len(values) != 1 {
				return nil, fmt.Errorf("sni option must has one value, found %v", len(values))
			}
			options = append(options, tls.WithSNI(values[0]))
		case "certname":
			if len(values) != 1 {
				return nil, fmt.Errorf("certName option must has one value, found %v", len(values))
			}
			options = append(options, tls.WithCertVerifier(&tls.StandardCertVerifier{CertificateName: values[0]}))
		default:
			return nil, fmt.Errorf("unsupported option %v", key)

		}
	}
	return options, nil
}
