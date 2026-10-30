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
	"context"
	"fmt"
	"strconv"

	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/x/disorder"
)

func parseDisorderDialer(ctx context.Context, registry Registry, config *Config) (transport.StreamDialer, error) {
	sd, err := NewFromConfig[transport.StreamDialer](ctx, registry, config.BaseConfig)
	if err != nil {
		return nil, err
	}
	disorderPacketNStr := config.URL.Opaque
	disorderPacketN, err := strconv.Atoi(disorderPacketNStr)
	if err != nil {
		return nil, fmt.Errorf("disoder: could not parse splice position: %v", err)
	}
	return disorder.NewStreamDialer(sd, disorderPacketN)
}
