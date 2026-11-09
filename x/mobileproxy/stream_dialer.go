// Copyright 2025 The Outline Authors
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

package mobileproxy

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/x/configurl"
	"golang.getoutline.org/sdk/x/smart"
)

// StreamDialer encapsulates the logic to create stream connections (like TCP).
type StreamDialer struct {
	transport.StreamDialer
}

var configRegistry = configurl.NewDefaultRegistry()

// NewStreamDialerFromConfig creates a [StreamDialer] based on the given config.
// The config format is specified in https://pkg.go.dev/golang.getoutline.org/sdk/x/configurl#hdr-Config_Format.
func NewStreamDialerFromConfig(transportConfig string) (*StreamDialer, error) {
	dialer, err := configurl.New[transport.StreamDialer](context.Background(), configRegistry, transportConfig)
	if err != nil {
		return nil, err
	}
	return &StreamDialer{dialer}, nil
}

// SmartDialerOptions specifies the options for creating a "Smart Dialer".
// A "Smart Dialer" automatically selects the best DNS/TLS strategy to connect to the internet.
type SmartDialerOptions struct {
	testDomains []string
	config      []byte
	testTimeout time.Duration

	baseSD transport.StreamDialer
	basePD transport.PacketDialer

	fallbackParsers map[string]smart.FallbackParser

	logWriter io.Writer
	cache     *strategyCacheAdapter
}

// NewSmartDialerOptions initializes the required options for creating a "Smart Dialer".
//
// `testDomains` are used to test connectivity for each DNS/TLS strategy.
// `config` defines the strategies to test. For an example, see:
// https://golang.getoutline.org/sdk/blob/main/x/examples/smart-proxy/config.yaml
func NewSmartDialerOptions(testDomains *StringList, config string) *SmartDialerOptions {
	return &SmartDialerOptions{
		testDomains: testDomains.list,
		config:      []byte(config),
		testTimeout: 5 * time.Second,
		baseSD:      &transport.TCPDialer{},
		basePD:      &transport.UDPDialer{},
	}
}

func (opt *SmartDialerOptions) ensureFallbackParsers() map[string]smart.FallbackParser {
	if opt.fallbackParsers == nil {
		opt.fallbackParsers = make(map[string]smart.FallbackParser)
	}
	return opt.fallbackParsers
}

// SetLogWriter configures an optional LogWriter for logging the strategy selection process.
func (opt *SmartDialerOptions) SetLogWriter(logw LogWriter) {
	if logw == nil {
		opt.logWriter = nil
	} else {
		opt.logWriter = toWriter(logw)
	}
}

// SetStrategyCache configures an optional StrategyCache to store successful strategies,
// speeding up NewDialer calls.
func (opt *SmartDialerOptions) SetStrategyCache(cache StrategyCache) {
	if cache == nil {
		opt.cache = nil
	} else {
		opt.cache = &strategyCacheAdapter{cache}
	}
}

func (opt *SmartDialerOptions) RegisterFallbackParser(name string, parser smart.FallbackParser) {
	opt.ensureFallbackParsers()[name] = parser
}

// NewStreamDialer creates a new "Smart" StreamDialer using the configured options.
// It finds the best-performing DNS/TLS strategy and returns a StreamDialer that uses this strategy.
func (opt *SmartDialerOptions) NewStreamDialer() (*StreamDialer, error) {
	// TODO: inject the base dialer for tests.
	finder := smart.StrategyFinder{
		LogWriter:    opt.logWriter,
		TestTimeout:  opt.testTimeout,
		StreamDialer: opt.baseSD,
		PacketDialer: opt.basePD,
	}
	for name, parser := range opt.ensureFallbackParsers() {
		finder.RegisterFallbackParser(name, parser)
	}
	// When assigning a nil concrete value to an interface, the interface is not nil
	// but contains a nil value. The `if` check is necessary to avoid a panic.
	if opt.cache != nil {
		finder.Cache = opt.cache
	}

	dialer, err := finder.NewDialer(context.Background(), opt.testDomains, opt.config)
	if err != nil {
		return nil, fmt.Errorf("failed to find dialer: %w", err)
	}
	return &StreamDialer{dialer}, nil
}

// NewSmartStreamDialer automatically selects a DNS and TLS strategy to use, and returns a [StreamDialer]
// that will use the selected strategy.
// It uses testDomains to find a strategy that works when accessing those domains.
// The strategies to search are given in the searchConfig. An example can be found in
// https://golang.getoutline.org/sdk/x/examples/smart-proxy/config.yaml
//
// Deprecated: Use [SmartDialerOptions] NewStreamDialer instead.
func NewSmartStreamDialer(testDomains *StringList, searchConfig string, logWriter LogWriter) (*StreamDialer, error) {
	opt := NewSmartDialerOptions(testDomains, searchConfig)
	opt.SetLogWriter(logWriter)
	return opt.NewStreamDialer()
}

// StringList allows us to pass a list of strings to the Go Mobile functions, since Go Mobile doesn't
// support slices as parameters.
type StringList struct {
	list []string
}

// Append adds the string value to the end of the list.
func (l *StringList) Append(value string) {
	l.list = append(l.list, value)
}

// NewListFromLines creates a StringList by splitting the input string on new lines.
func NewListFromLines(lines string) *StringList {
	return &StringList{list: strings.Split(lines, "\n")}
}

// LogWriter is used as a sink for logging.
type LogWriter io.StringWriter

// NewStderrLogWriter creates a [LogWriter] that writes to the standard error output.
func NewStderrLogWriter() LogWriter {
	return &stringToBytesWriter{os.Stderr}
}

// Adaptor to convert an [io.StringWriter] to a [io.Writer].
type stringToBytesWriter struct {
	w io.Writer
}

// WriteString implements [io.StringWriter].
func (w *stringToBytesWriter) WriteString(logText string) (int, error) {
	return io.WriteString(w.w, logText)
}

// Adaptor to convert an [io.Writer] to a [io.StringWriter].
type bytestoStringWriter struct {
	sw io.StringWriter
}

// Write implements [io.Writer].
func (w *bytestoStringWriter) Write(b []byte) (int, error) {
	return w.sw.WriteString(string(b))
}

func toWriter(logWriter LogWriter) io.Writer {
	if logWriter == nil {
		return nil
	}
	if w, ok := logWriter.(io.Writer); ok {
		return w
	}
	return &bytestoStringWriter{logWriter}
}

// StrategyCache enables storing and retrieving successful strategies.
// Clients are required to provide a platform-specific implementation of this interface.
type StrategyCache interface {
	// Get retrieves the string value associated with the given key.
	// It should return an empty (or `null`) string if the key is not found.
	Get(key string) string

	// Put adds the string value with the given key to the cache.
	// If called with empty (or `null`) value, it should remove the cache entry.
	Put(key string, value string)
}

// strategyCacheAdapter adapts a [StrategyCache] to the [smart.StrategyResultCache].
// This is required because [smart.StrategyResultCache]'s Get returns multiple values,
// which is not supported by gomobile.
// This adapter also converts between []byte and string.
type strategyCacheAdapter struct {
	impl StrategyCache
}

func (sc *strategyCacheAdapter) Get(key string) (value []byte, ok bool) {
	v := sc.impl.Get(key)
	if v == "" {
		return nil, false
	}
	return []byte(v), true
}

func (sc *strategyCacheAdapter) Put(key string, value []byte) {
	sc.impl.Put(key, string(value))
}
