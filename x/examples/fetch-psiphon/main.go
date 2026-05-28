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

//go:build psiphon

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"time"

	"golang.getoutline.org/sdk/x/psiphon"
)

var debugLog *log.Logger = log.New(io.Discard, "", 0)

func init() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [flags...] <url>\n", path.Base(os.Args[0]))
		flag.PrintDefaults()
	}
}

func main() {
	verboseFlag := flag.Bool("v", false, "Enable debug output")
	configFlag := flag.String("config", "", "A Psiphon JSON config file")
	methodFlag := flag.String("method", "GET", "The HTTP method to use")

	flag.Parse()

	if *verboseFlag {
		debugLog = log.New(os.Stderr, "[DEBUG] ", log.LstdFlags|log.Lmicroseconds|log.Lshortfile)
	}

	url := flag.Arg(0)
	if url == "" {
		log.Println("Need to pass the URL to fetch in the command-line")
		flag.Usage()
		os.Exit(1)
	}

	if *configFlag == "" {
		log.Println("Need to pass config file in the command-line")
		flag.Usage()
		os.Exit(1)
	}

	// Read and process Psiphon config.
	configJSON, err := os.ReadFile(*configFlag)
	if err != nil {
		log.Fatalf("Could not read config file: %v\n", err)
	}
	config := &psiphon.DialerConfig{ProviderConfig: configJSON}
	cacheBaseDir, err := os.UserCacheDir()
	if err != nil {
		log.Fatalf("Failed to get the user cache directory: %v", err)
	}
	config.DataRootDirectory = path.Join(cacheBaseDir, "fetch-psiphon")
	if err := os.MkdirAll(config.DataRootDirectory, 0700); err != nil {
		log.Fatalf("Failed to create storage directory: %v", err)
	}
	debugLog.Printf("Using data store in %v\n", config.DataRootDirectory)

	// Start the Psiphon dialer.
	dialer := psiphon.GetSingletonDialer()
	ctx, cancel := context.WithTimeout(context.Background(), 30 * time.Second)
	defer cancel()
	if err := dialer.Start(ctx, config); err != nil {
		log.Fatalf("Could not start dialer: %v\n", err)
	}
	defer dialer.Stop()

	// Set up HTTP client.
	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.DialStream(ctx, addr)
	}
	httpClient := &http.Client{Transport: &http.Transport{DialContext: dialContext}, Timeout: 5 * time.Second}

	// Issue HTTP request.
	req, err := http.NewRequest(*methodFlag, url, nil)
	if err != nil {
		log.Fatalln("Failed to create request:", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		log.Fatalf("HTTP request failed: %v\n", err)
	}
	defer resp.Body.Close()

	// Output response.
	if *verboseFlag {
		for k, v := range resp.Header {
			debugLog.Printf("%v: %v", k, v)
		}
	}
	_, err = io.Copy(os.Stdout, resp.Body)
	fmt.Println()
	if err != nil {
		log.Fatalf("Read of page body failed: %v\n", err)
	}
}
