// Copyright 2026 The Outline Authors
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
	"strconv"
	"strings"

	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/x/quicprelude"
)

func registerQUICPreludePacketListener(r TypeRegistry[transport.PacketListener], typeID string, newPL BuildFunc[transport.PacketListener]) {
	r.RegisterType(typeID, func(ctx context.Context, config *Config) (transport.PacketListener, error) {
		inner, err := newPL(ctx, config.BaseConfig)
		if err != nil {
			return nil, err
		}
		preludeConfig, err := newQUICPreludeConfigFromURL(config.URL)
		if err != nil {
			return nil, err
		}
		return preludeConfig.NewPacketListener(inner)
	})
}

// quicPreludeOptions holds the options as written in the config string, before
// they are turned into a generator.
type quicPreludeOptions struct {
	count   int
	mode    string
	length  int
	version quicprelude.VersionSource
}

func newQUICPreludeConfigFromURL(configURL url.URL) (*quicprelude.Config, error) {
	options := quicPreludeOptions{
		count:   1,
		mode:    "invalid-initial",
		length:  quicprelude.MatchPacketLength,
		version: quicprelude.RandomReservedVersion(),
	}

	values, err := url.ParseQuery(configURL.Opaque)
	if err != nil {
		return nil, fmt.Errorf("invalid quicprelude options: %w", err)
	}
	for key, vs := range values {
		if len(vs) != 1 {
			return nil, fmt.Errorf("option %v must have exactly one value, found %v", key, len(vs))
		}
		value := vs[0]
		switch strings.ToLower(key) {
		case "count":
			if options.count, err = strconv.Atoi(value); err != nil {
				return nil, fmt.Errorf("invalid count %q: %w", value, err)
			}
		case "mode":
			options.mode = strings.ToLower(value)
		case "length":
			if options.length, err = parseQUICPreludeLength(value); err != nil {
				return nil, err
			}
		case "version":
			if options.version, err = parseQUICVersionSource(value); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unsupported option %v", key)
		}
	}
	generator, err := newQUICPreludeGenerator(options)
	if err != nil {
		return nil, fmt.Errorf("invalid quicprelude options: %w", err)
	}
	// count is applied by repeating the generator, so count=0 disables the
	// prelude without needing a separate switch.
	generator, err = quicprelude.Repeat(options.count, generator)
	if err != nil {
		return nil, fmt.Errorf("invalid quicprelude options: %w", err)
	}
	return quicprelude.NewConfig().WithGenerator(generator), nil
}

func newQUICPreludeGenerator(options quicPreludeOptions) (quicprelude.Generator, error) {
	switch options.mode {
	case "invalid-initial":
		return quicprelude.InvalidInitial(options.version, options.length)
	case "random":
		return quicprelude.Random(options.length)
	default:
		return nil, fmt.Errorf("unknown mode %q, want invalid-initial or random", options.mode)
	}
}

// parseQUICPreludeLength accepts "match", the default, which sizes each
// datagram to the packet it precedes, or a byte count.
func parseQUICPreludeLength(value string) (int, error) {
	if strings.EqualFold(value, "match") {
		return quicprelude.MatchPacketLength, nil
	}
	length, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("invalid length %q: want \"match\" or a byte count", value)
	}
	if length <= 0 {
		return 0, fmt.Errorf("invalid length %d: want \"match\" or a positive byte count", length)
	}
	return length, nil
}

// parseQUICVersionSource accepts the name of a range to draw a fresh codepoint
// from for every datagram, "reserved" (the default) or "draft"; the names "v1"
// and "v2"; or a 32-bit hex codepoint to use verbatim.
func parseQUICVersionSource(value string) (quicprelude.VersionSource, error) {
	switch strings.ToLower(value) {
	case "reserved":
		return quicprelude.RandomReservedVersion(), nil
	case "draft":
		return quicprelude.RandomDraftVersion(), nil
	case "v1":
		return quicprelude.FixedVersion(quicprelude.Version1)
	case "v2":
		return quicprelude.FixedVersion(quicprelude.Version2)
	}
	trimmed := strings.TrimPrefix(strings.TrimPrefix(value, "0x"), "0X")
	v, err := strconv.ParseUint(trimmed, 16, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid version %q: want \"reserved\", \"draft\", v1, v2, or a 32-bit hex codepoint", value)
	}
	if v == 0 {
		return nil, fmt.Errorf("invalid version 0x0, which denotes Version Negotiation: use \"reserved\" for a fresh codepoint per datagram")
	}
	return quicprelude.FixedVersion(uint32(v))
}
