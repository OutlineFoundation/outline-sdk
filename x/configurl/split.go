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
	"strings"

	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/transport/split"
)

func newSplitStreamDialer(ctx context.Context, registry Registry, config *Config) (transport.StreamDialer, error) {
	sd, err := NewFromConfig[transport.StreamDialer](ctx, registry, config.BaseConfig)
	if err != nil {
		return nil, err
	}
	configText := config.URL.Opaque
	splits := make([]split.RepeatedSplit, 0)
	for _, part := range strings.Split(configText, ",") {
		var count int
		var bytes int64
		subparts := strings.Split(strings.TrimSpace(part), "*")
		switch len(subparts) {
		case 1:
			count = 1
			bytes, err = strconv.ParseInt(subparts[0], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("bytes is not a number: %v", subparts[0])
			}
		case 2:
			count, err = strconv.Atoi(subparts[0])
			if err != nil {
				return nil, fmt.Errorf("count is not a number: %v", subparts[0])
			}
			bytes, err = strconv.ParseInt(subparts[1], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("bytes is not a number: %v", subparts[1])
			}
		default:
			return nil, fmt.Errorf("split format must be a comma-separated list of '[$COUNT*]$BYTES' (e.g. '100,5*2'). Got %v", part)
		}
		splits = append(splits, split.RepeatedSplit{Count: count, Bytes: bytes})
	}
	return split.NewStreamDialer(sd, split.NewRepeatedSplitIterator(splits...))
}
