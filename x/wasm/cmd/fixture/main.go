// Copyright 2026 The Outline Authors. SPDX-License-Identifier: Apache-2.0
// Loopback-only fixture for manual fetch experiments.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"golang.getoutline.org/sdk/x/wasm/internal/testpeer"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	cert := flag.String("cert", "", "Path to write the public test CA certificate")
	flag.Parse()
	if *cert == "" {
		fmt.Fprintln(os.Stderr, "-cert is required")
		os.Exit(1)
	}
	f, e := testpeer.Start()
	if e != nil {
		panic(e)
	}
	defer f.Close()
	if e = os.WriteFile(*cert, f.Certificate, 0600); e != nil {
		panic(e)
	}
	json.NewEncoder(os.Stdout).Encode(map[string]string{"https": f.Origin.URL, "h3": f.HTTP3URL, "stream_relay": f.StreamRelay, "tls_relay": f.TLSRelay, "packet_relay": f.PacketRelay, "ca": *cert})
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
}
