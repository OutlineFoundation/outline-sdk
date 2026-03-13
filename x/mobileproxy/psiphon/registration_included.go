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

//go:build psiphon

package psiphon

import (
	"context"
	"encoding/json"
	"fmt"

	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/x/psiphon"
	"golang.getoutline.org/sdk/x/smart"
)

func parsePsiphon(ctx context.Context, psiphonCfg smart.YAMLNode) (transport.StreamDialer, error) {
	psiphonJSON, err := json.Marshal(psiphonCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal to JSON: %v, %v", psiphonCfg, err)
	}
	config := &psiphon.DialerConfig{ProviderConfig: psiphonJSON}

	config.DataRootDirectory, err = getUserCacheDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get cache directory: %w", err)
	}

	dialer := psiphon.GetSingletonDialer()
	if err := dialer.Start(ctx, config); err != nil {
		return nil, fmt.Errorf("failed to start psiphon dialer: %w", err)
	}

	return dialer, nil
}
