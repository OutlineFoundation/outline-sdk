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

package main

import (
	"testing"

	"github.com/quic-go/quic-go"
)

func TestParseQUICVersions(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    []quic.Version
		wantErr bool
	}{
		{name: "v1", value: "1", want: []quic.Version{quic.Version1}},
		{name: "v2", value: "2", want: []quic.Version{quic.Version2}},
		{name: "ordered", value: "2,1", want: []quic.Version{quic.Version2, quic.Version1}},
		{name: "spaces", value: " 2, 1 ", want: []quic.Version{quic.Version2, quic.Version1}},
		{name: "empty", value: "", wantErr: true},
		{name: "version name", value: "v1", wantErr: true},
		{name: "unknown", value: "3", wantErr: true},
		{name: "duplicate", value: "2,2", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseQUICVersions(tt.value)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseQUICVersions(%q) error = %v, wantErr %v", tt.value, err, tt.wantErr)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("parseQUICVersions(%q) = %v, want %v", tt.value, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("parseQUICVersions(%q) = %v, want %v", tt.value, got, tt.want)
				}
			}
		})
	}
}
