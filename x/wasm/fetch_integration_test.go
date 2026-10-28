//go:build nettest

// Copyright 2026 The Outline Authors. SPDX-License-Identifier: Apache-2.0
package wasm_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"golang.getoutline.org/sdk/x/wasm/internal/testpeer"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFetchCLI(t *testing.T) {
	fixture, e := testpeer.Start()
	if e != nil {
		t.Fatal(e)
	}
	defer fixture.Close()
	tmp := t.TempDir()
	ca := filepath.Join(tmp, "ca.pem")
	if e = os.WriteFile(ca, fixture.Certificate, 0600); e != nil {
		t.Fatal(e)
	}
	binary := filepath.Join(tmp, "fetch")
	build := exec.Command("go", "build", "-p", "2", "-o", binary, "../tools/fetch")
	if output, e := build.CombinedOutput(); e != nil {
		t.Fatalf("build: %v\n%s", e, output)
	}
	exe, _ := os.ReadFile(binary)
	before := sha256.Sum256(exe)
	type testCase struct {
		name, proto, config, url, address, artifact string
		compiler                                    bool
		stream, packet                              uint32
	}
	cases := []testCase{
		{name: "native-h1", proto: "h1", url: fixture.Origin.URL},
		{name: "identity-h1", proto: "h1", config: "wasm:module=demo&component=stream.identity", url: fixture.Origin.URL},
		{name: "guest-handshake-h1", proto: "h1", config: "wasm:module=demo&component=stream.xor&key=37&relay=" + fixture.StreamRelay, url: fixture.Origin.URL, stream: 1},
		{name: "wasm-native-tls-wasm-h2", proto: "h2", config: "wasm:module=demo&component=stream.split&split=3|tls:sni=example.com&certname=127.0.0.1|wasm:module=demo&component=stream.xor&key=37&relay=" + fixture.TLSRelay, url: fixture.Origin.URL, stream: 1},
		{name: "identity-h3", proto: "h3", config: "wasm:module=demo&component=packet.identity", url: fixture.HTTP3URL},
		{name: "guest-packets-h3", proto: "h3", config: "wasm:module=demo&component=packet.identity|wasm:module=demo&component=packet.xor&key=37", url: fixture.HTTP3URL, address: fixture.PacketRelay, packet: 1},
		{name: "compiler-h2", proto: "h2", config: "wasm:module=demo&component=stream.xor&key=37&relay=" + fixture.StreamRelay, url: fixture.Origin.URL, compiler: true, stream: 1},
		{name: "updated-artifact-stream", proto: "h2", config: "wasm:module=demo&component=stream.xor&key=37&relay=" + fixture.StreamRelay, url: fixture.Origin.URL, artifact: "examples/bundle-v2.wasm", stream: 2},
		{name: "updated-artifact-packets", proto: "h3", config: "wasm:module=demo&component=packet.xor&key=37", url: fixture.HTTP3URL, address: fixture.PacketRelay, artifact: "examples/bundle-v2.wasm", packet: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			artifact := tc.artifact
			if artifact == "" {
				artifact = "examples/bundle.wasm"
			}
			args := []string{"-v", "-timeout", "20", "-proto", tc.proto}
			if tc.config != "" {
				args = append(args, "-wasm-module", "demo="+artifact, "-transport", tc.config)
			}
			if tc.address != "" {
				args = append(args, "-address", tc.address)
			}
			if tc.compiler {
				args = append(args, "-wasm-compiler")
			}
			args = append(args, tc.url)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, args...)
			cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+ca, "SSL_CERT_DIR="+tmp)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			start := time.Now()
			e := cmd.Run()
			if e != nil {
				t.Fatalf("%v\n%s", e, stderr.String())
			}
			if stdout.String() != testpeer.Payload()+"\n" {
				t.Fatalf("incorrect body length %d", stdout.Len())
			}
			proto := map[string]string{"h1": "HTTP/1.1", "h2": "HTTP/2.0", "h3": "HTTP/3.0"}[tc.proto]
			if !strings.Contains(stderr.String(), proto) {
				t.Fatalf("protocol not negotiated: %s", stderr.String())
			}
			if tc.stream > 0 && fixture.StreamVersion.Load() != tc.stream {
				t.Fatal("wrong guest stream wire version")
			}
			if tc.packet > 0 && fixture.PacketVersion.Load() != tc.packet {
				t.Fatal("wrong guest packet wire version")
			}
			if tc.config != "" && !strings.Contains(stderr.String(), "count=1") {
				t.Fatalf("artifact not compiled once: %s", stderr.String())
			}
			t.Logf("%s: %d bytes in %s", proto, stdout.Len(), time.Since(start))
		})
	}
	exe, _ = os.ReadFile(binary)
	if sha256.Sum256(exe) != before {
		t.Fatal("fetch binary changed")
	}
	t.Logf("unchanged fetch SHA256 %x", before)
}
