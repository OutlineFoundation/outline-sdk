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

//go:build nettest

package sysresolver_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.getoutline.org/sdk/dns"
	"golang.getoutline.org/sdk/dns/sysresolver"
	"golang.org/x/net/dns/dnsmessage"
)

func TestNewResolver_A(t *testing.T) {
	resolver := sysresolver.NewResolver()
	q, err := dns.NewQuestion("dns.google.", dnsmessage.TypeA)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	msg, err := resolver.Query(ctx, *q)
	require.NoError(t, err)
	require.NotNil(t, msg)
	require.NotEmpty(t, msg.Answers)
	for _, ans := range msg.Answers {
		t.Logf("Answer: %v %v %v", ans.Header.Name, ans.Header.Type, ans.Body)
	}
}

func TestNewResolver_AAAA(t *testing.T) {
	resolver := sysresolver.NewResolver()
	q, err := dns.NewQuestion("dns.google.", dnsmessage.TypeAAAA)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	msg, err := resolver.Query(ctx, *q)
	require.NoError(t, err)
	require.NotNil(t, msg)
	require.NotEmpty(t, msg.Answers)
}

func TestNewResolver_TXT(t *testing.T) {
	resolver := sysresolver.NewResolver()
	q, err := dns.NewQuestion("dns.google.", dnsmessage.TypeTXT)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// TXT is not supported on all fallback platforms; skip if unsupported.
	msg, err := resolver.Query(ctx, *q)
	if err != nil {
		t.Skipf("TXT not supported on this platform: %v", err)
	}
	require.NotNil(t, msg)
	for _, ans := range msg.Answers {
		t.Logf("TXT Answer: %v", ans.Body)
	}
}
