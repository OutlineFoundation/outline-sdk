// Copyright 2023 The Outline Authors
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
	"context"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/x/configurl"
	"golang.getoutline.org/sdk/x/httpproxy"
)

func main() {
	transportFlag := flag.String("transport", "", "Transport config")
	addrFlag := flag.String("localAddr", "localhost:1080", "Local proxy address")
	urlProxyPrefixFlag := flag.String("urlProxyPrefix", "/proxy", "Path where to run the URL proxy. Set to empty (\"\") to disable it.")
	flag.Parse()

	dialer, err := configurl.New[transport.StreamDialer](context.Background(), configurl.NewDefaultRegistry(), *transportFlag)

	if err != nil {
		log.Fatalf("Could not create dialer: %v", err)
	}

	listener, err := net.Listen("tcp", *addrFlag)
	if err != nil {
		log.Fatalf("Could not listen on address %v: %v", *addrFlag, err)
	}
	defer listener.Close()
	log.Printf("Proxy listening on %v", listener.Addr().String())

	proxyHandler := httpproxy.NewProxyHandler(dialer)
	if *urlProxyPrefixFlag != "" {
		proxyHandler.FallbackHandler = http.StripPrefix(*urlProxyPrefixFlag, httpproxy.NewPathHandler(dialer))
	}
	server := http.Server{Handler: proxyHandler}
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Error running web server: %v", err)
		}
	}()

	// Wait for interrupt signal to stop the proxy.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
	log.Print("Shutting down")
	// Gracefully shut down the server, with a 5s timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Failed to shutdown gracefully: %v", err)
	}
}
