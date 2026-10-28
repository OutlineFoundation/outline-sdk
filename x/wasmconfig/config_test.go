// Copyright 2026 The Outline Authors. SPDX-License-Identifier: Apache-2.0
package wasmconfig

import (
	"context"
	"golang.getoutline.org/sdk/x/configurl"
	"golang.getoutline.org/sdk/x/wasm"
	"net/url"
	"os"
	"testing"
)

func TestRegisterBothProfilesAndRejectInvalid(t *testing.T) {
	ctx := context.Background()
	m := wasm.NewManager(ctx, false)
	defer m.Close()
	s := NewScope(m)
	defer s.Close()
	data, e := os.ReadFile("../wasm/examples/bundle.wasm")
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Load(ctx, "demo", data); e != nil {
		t.Fatal(e)
	}
	if e = s.Load(ctx, "alias", data); e != nil {
		t.Fatal(e)
	}
	if m.CompiledCount() != 1 || s.modules["demo"] != s.modules["alias"] {
		t.Fatal("artifact/session not deduplicated in scope")
	}
	p := configurl.NewDefaultProviders()
	s.Register(p)
	if _, e = p.NewStreamDialer(ctx, "wasm:module=demo&component=stream.split&split=3|wasm:module=alias&component=stream.identity"); e != nil {
		t.Fatal(e)
	}
	if _, e = p.NewPacketListener(ctx, "wasm:module=demo&component=packet.xor&key=9"); e != nil {
		t.Fatal(e)
	}
	for _, value := range []string{"wasm:module=demo", "wasm:module=demo&component=packet.identity", "wasm:module=absent&component=stream.identity", "wasm:module=demo&component=stream.identity&key=1", "wasm:module=demo&component=stream.split&split=0", "wasm:module=demo&component=stream.identity&module=demo", "wasm:module=demo&component=stream.xor&key=256"} {
		if _, e = p.NewStreamDialer(ctx, value); e == nil {
			t.Errorf("accepted %s", value)
		}
	}
	if _, e = p.NewPacketListener(ctx, "wasm:module=demo&component=stream.identity"); e == nil {
		t.Fatal("accepted stream for packet")
	}
}
func TestParseRejectsUnexpectedSyntax(t *testing.T) {
	for _, value := range []string{"wasm://x", "wasm:module=x&component=y?bad=1", "wasm:module=x&component=y&unknown=1"} {
		u, e := url.Parse(value)
		if e == nil {
			_, e = parse(*u)
		}
		if e == nil {
			t.Fatal(value)
		}
	}
}
