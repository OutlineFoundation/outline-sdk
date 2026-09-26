//go:build linux

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

package quicprelude

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"
)

// parseUDPSegmentation finds per-message GSO sizing. Other control messages
// (including source routing and ECN) retain their exact bytes; the caller's
// oob buffer is never modified.
func parseUDPSegmentation(oob []byte) (udpSegmentation, error) {
	var result udpSegmentation
	for rest := oob; len(rest) > 0; {
		// ParseOneSocketControlMessage assumes space for the header.
		if len(rest) < unix.CmsgLen(0) {
			return result, fmt.Errorf("quicprelude: truncated UDP control message")
		}
		header, data, next, err := unix.ParseOneSocketControlMessage(rest)
		if err != nil {
			return result, fmt.Errorf("quicprelude: UDP control message: %w", err)
		}
		if header.Level == unix.IPPROTO_UDP && header.Type == unix.UDP_SEGMENT {
			if result.end != 0 || len(data) != 2 {
				return result, fmt.Errorf("quicprelude: invalid UDP_SEGMENT control message")
			}
			result = udpSegmentation{
				size:  int(binary.NativeEndian.Uint16(data)),
				start: len(oob) - len(rest),
				end:   len(oob) - len(next),
			}
		}
		rest = next
	}
	return result, nil
}
