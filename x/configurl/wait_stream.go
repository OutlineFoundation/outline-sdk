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
	"net/url"
	"time"

	"github.com/Jigsaw-Code/outline-sdk/transport"
	"github.com/Jigsaw-Code/outline-sdk/x/wait_stream"
)

func registerWaitStreamDialer(r TypeRegistry[transport.StreamDialer], typeID string, newSD BuildFunc[transport.StreamDialer]) {
	r.RegisterType(typeID, func(ctx context.Context, config *Config) (transport.StreamDialer, error) {
		sd, err := newSD(ctx, config.BaseConfig)
		if err != nil {
			return nil, err
		}

		queryUrlParameters, err := url.ParseQuery(config.URL.Opaque)
		if err != nil {
			return nil, fmt.Errorf("waitstream: failed to parse URL parameters: %w", err)
		}

		resultStreamDialer, err := wait_stream.NewStreamDialer(sd)
		if err != nil {
			return nil, err
		}

		if queryUrlParameters.Has("timeout") {
			timeout, err := time.ParseDuration(queryUrlParameters.Get("timeout"))
			if err != nil {
				return nil, fmt.Errorf("waitstream: failed to parse timeout parameter: %w", err)
			}
			resultStreamDialer.SetWaitingTimeout(timeout)
		}

		if queryUrlParameters.Has("delay") {
			delay, err := time.ParseDuration(queryUrlParameters.Get("delay"))
			if err != nil {
				return nil, fmt.Errorf("waitstream: failed to parse delay parameter: %w", err)
			}
			resultStreamDialer.SetWaitingDelay(delay)
		}

		return resultStreamDialer, err
	})
}
