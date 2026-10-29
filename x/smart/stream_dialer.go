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

package smart

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/goccy/go-yaml"
	"golang.getoutline.org/sdk/dns"
	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/x/configurl"
)

// To test one strategy:
// go run -C ./x/examples/smart-proxy/ . -v -localAddr=localhost:1080 --transport="" --domain www.rferl.org  --config=<(echo '{"dns": [{"https": {"name": "doh.sb"}}]}')

// YAMLNode represents a parsed YAML node.
type YAMLNode any

// FallbackParser goes from a YAML node to a [transport.StreamDialer] and strategy key. In case of error,
// the dialer is nil, and the configSignature is empty.
type FallbackParser func(context.Context, YAMLNode) (dialer transport.StreamDialer, configSignature string, err error)

// Finder searches for a working connection strategy and constructs its dialer.
// Use [NewFinderOptions] to configure a finder. A finder supports concurrent
// searches; its configured registry, cache, and log writer must support that use.
type Finder interface {
	// NewDialer searches the YAML config for a DNS/TLS or fallback strategy that
	// reaches every test domain, returning a dialer that uses the selected strategy.
	// Test domains must have a TLS service on port 443. It returns an error if no
	// strategy succeeds. The returned dialer remains usable after ctx is canceled;
	// each connection uses the context passed to its DialStream call.
	NewDialer(ctx context.Context, testDomains []string, config []byte) (transport.StreamDialer, error)
}

// finder holds the configuration prepared by FinderOptions.New. All search state
// is local to NewDialer; the registry, cache, and log writer are shared.
type finder struct {
	registry        configurl.Registry
	testTimeout     time.Duration
	logWriter       io.Writer
	cache           StrategyResultCache
	fallbackParsers map[string]FallbackParser
}

type httpsEntryConfig struct {
	// Domain name of the host.
	Name string `yaml:"name,omitempty"`
	// Host:port. Defaults to Name:443.
	Address string `yaml:"address,omitempty"`
}

type tlsEntryConfig struct {
	// Domain name of the host.
	Name string `yaml:"name,omitempty"`
	// Host:port. Defaults to Name:853.
	Address string `yaml:"address,omitempty"`
}

type udpEntryConfig struct {
	// Host:port.
	Address string `yaml:"address,omitempty"`
}

type tcpEntryConfig struct {
	// Host:port.
	Address string `yaml:"address,omitempty"`
}

type dnsEntryConfig struct {
	System *struct{}         `yaml:"system,omitempty"`
	HTTPS  *httpsEntryConfig `yaml:"https,omitempty"`
	TLS    *tlsEntryConfig   `yaml:"tls,omitempty"`
	UDP    *udpEntryConfig   `yaml:"udp,omitempty"`
	TCP    *tcpEntryConfig   `yaml:"tcp,omitempty"`
}

// This contains either a configURL string or a fallbackEntryStructConfig
// It is parsed into the correct type later
type fallbackEntryConfig any

type configConfig struct {
	DNS      []dnsEntryConfig      `yaml:"dns,omitempty"`
	TLS      []string              `yaml:"tls,omitempty"`
	Fallback []fallbackEntryConfig `yaml:"fallback,omitempty"`
}

// mapToAny marshalls a map into a struct. It's a helper for parsers that want to
// map config maps into their config structures.
func mapToAny(in map[string]any, out any) error {
	newMap := make(map[string]any)
	for k, v := range in {
		if len(k) > 0 && k[0] == '$' {
			// Skip $ keys
			continue
		}
		newMap[k] = v
	}
	yamlText, err := yaml.Marshal(newMap)
	if err != nil {
		return fmt.Errorf("error marshaling to YAML: %w", err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(yamlText), yaml.DisallowUnknownField())
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("error decoding YAML: %w", err)
	}
	return nil
}

// newDNSResolverFromEntry creates a [dns.Resolver] based on the config, returning the resolver and
// a boolean indicating whether the resolver is secure (TLS, HTTPS) and a possible error.
func (f *finder) newDNSResolverFromEntry(ctx context.Context, entry dnsEntryConfig) (dns.Resolver, bool, error) {
	if entry.System != nil {
		return nil, false, nil
	}

	if cfg := entry.HTTPS; cfg != nil {
		baseSD, err := configurl.NewFromConfig[transport.StreamDialer](ctx, f.registry, nil)
		if err != nil {
			return nil, false, fmt.Errorf("DNS requires a stream base instance: %w", err)
		}
		if cfg.Name == "" {
			return nil, true, errors.New("https entry has empty server name")
		}
		serverAddr := cfg.Address
		if serverAddr == "" {
			serverAddr = cfg.Name
		}
		_, port, err := net.SplitHostPort(serverAddr)
		if err != nil {
			serverAddr = net.JoinHostPort(serverAddr, "443")
			port = "443"
		}
		dohURL := url.URL{Scheme: "https", Host: net.JoinHostPort(cfg.Name, port), Path: "/dns-query"}
		return dns.NewHTTPSResolver(baseSD, serverAddr, dohURL.String()), true, nil
	} else if cfg := entry.TLS; cfg != nil {
		baseSD, err := configurl.NewFromConfig[transport.StreamDialer](ctx, f.registry, nil)
		if err != nil {
			return nil, false, fmt.Errorf("DNS requires a stream base instance: %w", err)
		}
		if cfg.Name == "" {
			return nil, true, errors.New("tls entry has empty server name")
		}
		serverAddr := cfg.Address
		if serverAddr == "" {
			serverAddr = cfg.Name
		}
		_, _, err = net.SplitHostPort(serverAddr)
		if err != nil {
			serverAddr = net.JoinHostPort(serverAddr, "853")
		}
		return dns.NewTLSResolver(baseSD, serverAddr, cfg.Name), true, nil
	} else if cfg := entry.TCP; cfg != nil {
		baseSD, err := configurl.NewFromConfig[transport.StreamDialer](ctx, f.registry, nil)
		if err != nil {
			return nil, false, fmt.Errorf("DNS requires a stream base instance: %w", err)
		}
		if cfg.Address == "" {
			return nil, false, errors.New("tcp entry has empty server address")
		}
		host, port, err := net.SplitHostPort(cfg.Address)
		if err != nil {
			host = cfg.Address
			port = "53"
		}
		serverAddr := net.JoinHostPort(host, port)
		return dns.NewTCPResolver(baseSD, serverAddr), false, nil
	} else if cfg := entry.UDP; cfg != nil {
		basePD, err := configurl.NewFromConfig[transport.PacketDialer](ctx, f.registry, nil)
		if err != nil {
			return nil, false, fmt.Errorf("DNS requires a packet base instance: %w", err)
		}
		if cfg.Address == "" {
			return nil, false, errors.New("udp entry has empty server address")
		}
		host, port, err := net.SplitHostPort(cfg.Address)
		if err != nil {
			host = cfg.Address
			port = "53"
		}
		serverAddr := net.JoinHostPort(host, port)
		return dns.NewUDPResolver(basePD, serverAddr), false, nil
	} else {
		return nil, false, errors.New("invalid DNS entry")
	}
}

type smartResolver struct {
	dns.Resolver
	ID     string
	Secure bool
	Config dnsEntryConfig
}

func (f *finder) dnsConfigToResolver(ctx context.Context, dnsConfig []dnsEntryConfig) ([]*smartResolver, error) {
	if len(dnsConfig) == 0 {
		return nil, errors.New("no DNS config entry")
	}
	rts := make([]*smartResolver, 0, len(dnsConfig))
	for ei, entry := range dnsConfig {
		idBytes, err := yaml.Marshal(entry)
		if err != nil {
			return nil, fmt.Errorf("cannot serialize entry %v: %w", ei, err)
		}
		id := string(idBytes)
		resolver, isSecure, err := f.newDNSResolverFromEntry(ctx, entry)
		if err != nil {
			return nil, fmt.Errorf("failed to process entry %v: %w", ei, err)
		}
		rts = append(rts, &smartResolver{Resolver: resolver, ID: id, Secure: isSecure, Config: entry})
	}
	return rts, nil
}

// testDialerSingleDomain tests that a dialer is able to access a single test domain.
func (f *finder) testDialerSingleDomain(ctx context.Context, dialer transport.StreamDialer, testDomain, transportCfg string) error {
	startTime := time.Now()

	testAddr := net.JoinHostPort(testDomain, "443")
	logCtx(ctx, "🏃 running test: '%v' (domain: %v)\n", transportCfg, testDomain)

	testCtx, cancel := context.WithTimeout(ctx, f.testTimeout)
	defer cancel()

	// Dial

	testConn, err := dialer.DialStream(testCtx, testAddr)
	if err != nil {
		logCtx(ctx, "🏁 failed to dial: '%v' (domain: %v), duration=%v, dial_error=%v ❌\n", transportCfg, testDomain, time.Since(startTime), err)
		return err
	}

	// TLS Connection

	tlsConn := tls.Client(testConn, &tls.Config{ServerName: testDomain})
	defer tlsConn.Close()
	err = tlsConn.HandshakeContext(testCtx)
	if err != nil {
		logCtx(ctx, "🏁 failed TLS handshake: '%v' (domain: %v), duration=%v, handshake=%v ❌\n", transportCfg, testDomain, time.Since(startTime), err)
		return err
	}

	// HTTPS Get

	req, err := http.NewRequestWithContext(testCtx, http.MethodHead, "https://"+testDomain, nil)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	if err := req.Write(tlsConn); err != nil {
		logCtx(ctx, "🏁 failed to write HTTP request: '%v' (domain: %v), duration=%v, error=%v ❌\n", transportCfg, testDomain, time.Since(startTime), err)
		return err
	}

	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		logCtx(ctx, "🏁 failed to read HTTP response: '%v' (domain: %v), duration=%v, error=%v ❌\n", transportCfg, testDomain, time.Since(startTime), err)
		return err
	}
	defer resp.Body.Close()

	// Many bare domains return i.e. 301 redirects, so we don't validate anything about the response here, just that the request succeeded.

	logCtx(ctx, "🏁 success: '%v' (domain: %v), duration=%v, status=ok ✅\n", transportCfg, testDomain, time.Since(startTime))
	return nil
}

// Test that a dialer is able to access all the given test domains. Returns nil if all tests succeed
func (f *finder) testDialer(ctx context.Context, dialer transport.StreamDialer, testDomains []string, transportCfg string) error {
	// Run tests for all the testDomains in parallel
	var wg sync.WaitGroup
	errCh := make(chan error, len(testDomains))
	testCtx, cancelAll := context.WithCancel(ctx)
	defer cancelAll()

	wg.Add(len(testDomains))
	for _, testDomain := range testDomains {
		go func(testDomain string) {
			defer wg.Done()
			err := f.testDialerSingleDomain(testCtx, dialer, testDomain, transportCfg)
			if err != nil {
				cancelAll()
				errCh <- err
			}
		}(testDomain)
	}

	go func() {
		wg.Wait()
		close(errCh)
	}()

	// Return the first error we received, if any. If all tests succeed,
	// the channel will be closed and this will return nil.
	return <-errCh
}

func (f *finder) findDNS(ctx context.Context, testDomains []string, dnsConfig []dnsEntryConfig) (dns.Resolver, *dnsEntryConfig, error) {
	resolvers, err := f.dnsConfigToResolver(ctx, dnsConfig)
	if err != nil {
		return nil, nil, err
	}

	raceCtx, raceDone := context.WithCancel(ctx)
	defer raceDone()
	raceStart := time.Now()
	resolver, err := raceTests(raceCtx, 250*time.Millisecond, resolvers, func(_ int, resolver *smartResolver) (*smartResolver, error) {
		for _, testDomain := range testDomains {
			select {
			case <-raceCtx.Done():
				return nil, raceCtx.Err()
			default:
			}

			logCtx(raceCtx, "🏃 run DNS: %v (domain: %v)\n", resolver.ID, testDomain)
			startTime := time.Now()
			ips, err := testDNSResolver(raceCtx, f.testTimeout, resolver, testDomain)
			duration := time.Since(startTime)

			status := "ok ✅"
			if err != nil {
				status = fmt.Sprintf("%v ❌", err)
			}
			// Only output log if the search is not done yet.
			logCtx(raceCtx, "🏁 got DNS: %v (domain: %v), duration=%v, ips=%v, status=%v\n", resolver.ID, testDomain, duration, ips, status)

			if err != nil {
				return nil, err
			}
		}
		return resolver, nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("could not find working resolver: %w", err)
	}
	logCtx(ctx, "🏆 selected DNS resolver %v in %0.2fs\n\n", resolver.ID, time.Since(raceStart).Seconds())
	return resolver.Resolver, &resolver.Config, nil
}

// streamBaseParserKey identifies a StreamDialer constructor override in a config
// construction context. It is private so only SmartDialer can set the override.
type streamBaseParserKey struct{}

// withStreamBaseParser returns a construction context whose default StreamDialer
// is built by parser through the wrapper installed by registerContextStreamBase.
// The override applies only to the returned context and its children. A nil parser
// delegates to the original registered base.
func withStreamBaseParser(ctx context.Context, parser configurl.BuildFunc[transport.StreamDialer]) context.Context {
	return context.WithValue(ctx, streamBaseParserKey{}, parser)
}

// registerContextStreamBase wraps the registry's default StreamDialer constructor
// so findTLS can use its selected DNS dialer as the base for every TLS strategy.
// The wrapper uses the constructor supplied by withStreamBaseParser when present;
// otherwise, DNS discovery and fallback construction use the original base.
// Install it during setup, after base registrations and before searches begin.
func registerContextStreamBase(registry configurl.MutableRegistry) {
	// Capture the original constructor: looking it up after registering the wrapper
	// would recurse. A TLS override also works when the original base is unavailable.
	originalBase, originalErr := configurl.Lookup[transport.StreamDialer](registry, "")
	newBase := func(ctx context.Context, config *configurl.Config) (transport.StreamDialer, error) {
		if override, ok := ctx.Value(streamBaseParserKey{}).(configurl.BuildFunc[transport.StreamDialer]); ok && override != nil {
			return override(ctx, config)
		}
		if originalErr != nil {
			return nil, originalErr
		}
		return originalBase(ctx, config)
	}
	configurl.RegisterBase(registry, newBase)
}

func (f *finder) findTLS(
	ctx context.Context, testDomains []string, baseDialer transport.StreamDialer, tlsConfig []string,
) (transport.StreamDialer, string, error) {
	if len(tlsConfig) == 0 {
		return nil, "", errors.New("config for TLS is empty. Please specify at least one transport")
	}
	// All TLS strategies must use the selected DNS resolver. Return the same
	// prebuilt baseDialer so every attempt shares its DNS cache. The wrapper from
	// registerContextStreamBase reads this constructor from the context, including
	// when nested config components request a base. Scoping the override to this
	// search keeps concurrent searches and later fallbacks on their own bases.
	newBase := func(context.Context, *configurl.Config) (transport.StreamDialer, error) {
		return baseDialer, nil
	}
	ctx = withStreamBaseParser(ctx, newBase)

	raceCtx, raceDone := context.WithCancel(ctx)
	defer raceDone()
	raceStart := time.Now()
	type SearchResult struct {
		Dialer transport.StreamDialer
		Config string
	}
	result, err := raceTests(raceCtx, 250*time.Millisecond, tlsConfig, func(index int, transportCfg string) (*SearchResult, error) {
		tlsDialer, err := configurl.New[transport.StreamDialer](raceCtx, f.registry, transportCfg)
		if err != nil {
			logCtx(raceCtx, "❌ Failed to create tls[%d]: %v, error=%v\n", index, transportCfg, err)
			return nil, fmt.Errorf("NewStreamDialer failed: %w", err)
		}

		err = f.testDialer(raceCtx, tlsDialer, testDomains, transportCfg)
		if err != nil {
			return nil, err
		}

		return &SearchResult{tlsDialer, transportCfg}, nil
	})
	if err != nil {
		return nil, "", fmt.Errorf("could not find TLS strategy: %w", err)
	}
	logCtx(ctx, "🏆 selected TLS strategy '%v' in %0.2fs\n\n", result.Config, time.Since(raceStart).Seconds())
	tlsDialer := result.Dialer
	return transport.FuncStreamDialer(func(searchCtx context.Context, raddr string) (transport.StreamConn, error) {
		_, portStr, err := net.SplitHostPort(raddr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse address: %w", err)
		}
		portNum, err := net.DefaultResolver.LookupPort(searchCtx, "tcp", portStr)
		if err != nil {
			return nil, fmt.Errorf("could not resolve port: %w", err)
		}
		selectedDialer := baseDialer
		if portNum == 443 || portNum == 853 {
			selectedDialer = tlsDialer
		}
		return selectedDialer.DialStream(searchCtx, raddr)
	}), result.Config, nil
}

type SearchResult struct {
	Dialer          transport.StreamDialer
	Config          fallbackEntryConfig
	ConfigSignature string
}

// Make a fallback dialer (either from a configurl or a Psiphon config)
// Returns a stream dialer, config signature, error
// In case of an error the stream dialer can be nil, but the string is always set.
func (f *finder) makeDialerFromConfig(ctx context.Context, registry configurl.Registry, fallbackConfig fallbackEntryConfig) (transport.StreamDialer, string, error) {
	switch v := fallbackConfig.(type) {
	case string:
		configUrl := v
		dialer, err := configurl.New[transport.StreamDialer](ctx, registry, configUrl)
		if err != nil {
			return nil, v, fmt.Errorf("getStreamDialer failed: %w", err)
		}
		return dialer, v, nil

	case map[string]any:
		if len(v) != 1 {
			return nil, fmt.Sprint(fallbackConfig), fmt.Errorf("fallback config has too many keys")
		}
		// There should be only one entry.
		for key, config := range v {
			parser, ok := f.fallbackParsers[key]
			if !ok || parser == nil {
				return nil, fmt.Sprintf("Unknown Config: %v", fallbackConfig), fmt.Errorf("%.0wunsupported fallback type: %v", errors.ErrUnsupported, key)
			}
			dialer, signature, err := parser(ctx, config)
			fullSignature := fmt.Sprintf("%s:%s", key, signature)
			return dialer, fullSignature, err
		}
	}
	return nil, fmt.Sprintf("Invalid Config: %v", fallbackConfig), fmt.Errorf("invalid config of type %T: %v", fallbackConfig, fallbackConfig)
}

func makeConfigErrorSignature(ctx context.Context, config fallbackEntryConfig) string {
	var configSignature string
	sigBytes, marshalErr := yaml.MarshalContext(ctx, config, yaml.Flow(true))
	if marshalErr != nil {
		configSignature = fmt.Sprint(config)
	} else {
		configSignature = string(sigBytes)
	}
	configSignature = strings.TrimSpace(configSignature)
	if len(configSignature) > 80 {
		configSignature = configSignature[:79] + "…"
	}
	return configSignature
}

// Return the fastest fallback dialer that is able to access all the testDomans
func (f *finder) findFallback(
	ctx context.Context, testDomains []string, fallbackConfigs []fallbackEntryConfig,
) (transport.StreamDialer, fallbackEntryConfig, error) {
	if len(fallbackConfigs) == 0 {
		return nil, nil, errors.New("attempted to find fallback but no fallback configuration was specified")
	}

	raceCtx, raceDone := context.WithCancel(ctx)
	defer raceDone()
	raceStart := time.Now()

	fallback, err := raceTests(raceCtx, 250*time.Millisecond, fallbackConfigs, func(index int, fallbackConfig fallbackEntryConfig) (*SearchResult, error) {
		dialer, configSignature, err := f.makeDialerFromConfig(raceCtx, f.registry, fallbackConfig)
		if err != nil {
			// Make up a config signature in case of failure.
			configSignature := makeConfigErrorSignature(raceCtx, fallbackConfig)
			logCtx(raceCtx, "❌ Failed to create fallback[%d]: [%v]: %v\n", index, configSignature, err)
			return nil, err
		}

		err = f.testDialer(raceCtx, dialer, testDomains, configSignature)
		if err != nil {
			return nil, err
		}

		return &SearchResult{dialer, fallbackConfig, configSignature}, nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("could not find a working fallback: %w", err)
	}
	logCtx(ctx, "🏆 selected fallback '%v' in %0.2fs\n\n", fallback.ConfigSignature, time.Since(raceStart).Seconds())

	return fallback.Dialer, fallback.Config, nil
}

// Attempts to create a new Dialer using only proxyless (DNS and TLS) strategies
func (f *finder) newProxylessDialer(
	ctx context.Context, testDomains []string, config configConfig,
) (transport.StreamDialer, *dnsEntryConfig, string, error) {
	resolver, dnsConfig, err := f.findDNS(ctx, testDomains, config.DNS)
	if err != nil {
		return nil, nil, "", err
	}
	baseSD, err := configurl.NewFromConfig[transport.StreamDialer](ctx, f.registry, nil)
	if err != nil {
		return nil, nil, "", fmt.Errorf("DNS requires a stream base instance: %w", err)
	}
	var dnsDialer transport.StreamDialer
	if resolver == nil {
		if _, ok := baseSD.(*transport.TCPDialer); !ok {
			return nil, nil, "", fmt.Errorf("cannot use system resolver with base dialer of type %T", baseSD)
		}
		dnsDialer = baseSD
	} else {
		resolver = newSimpleLRUCacheResolver(resolver, 100)
		dnsDialer, err = dns.NewStreamDialer(resolver, baseSD)
		if err != nil {
			return nil, nil, "", fmt.Errorf("dns.NewStreamDialer failed: %w", err)
		}
	}

	if len(config.TLS) == 0 {
		return dnsDialer, dnsConfig, "", nil
	}
	sd, tlsConfig, err := f.findTLS(ctx, testDomains, dnsDialer, config.TLS)
	if err != nil {
		return nil, nil, "", err
	}
	return sd, dnsConfig, tlsConfig, err
}

func (f *finder) parseConfig(configBytes []byte) (configConfig, error) {
	var parsedConfig configConfig
	var configMap map[string]any
	err := yaml.Unmarshal(configBytes, &configMap)
	if err != nil {
		return configConfig{}, fmt.Errorf("failed to unmarshal config to map: %w", err)
	}
	err = mapToAny(configMap, &parsedConfig)
	if err != nil {
		return configConfig{}, fmt.Errorf("failed to parse config: %w", err)
	}

	// Iterate through fallback field and convert individual elements to strings or fallbackEntryStructConfig
	for i, fallbackElement := range parsedConfig.Fallback {
		switch v := fallbackElement.(type) {
		case string:
			parsedConfig.Fallback[i] = v
		case map[string]any:
			var fallbackEntry fallbackEntryConfig
			err := mapToAny(v, &fallbackEntry)
			if err != nil {
				return configConfig{}, fmt.Errorf("failed to parse fallback config: %w", err)
			}
			parsedConfig.Fallback[i] = fallbackEntry
		default:
			return configConfig{}, fmt.Errorf("unknown fallback type: %v", v)
		}
	}

	return parsedConfig, nil
}

// rankStrategiesFromCache reads a winningStrategy from the cache and adjust the input config accordingly.
// It returns the adjusted ranked config, and optionally a first2Try config that the caller should prioritize.
func (f *finder) rankStrategiesFromCache(
	logWriter io.Writer,
	input configConfig,
) (ranked configConfig, first2Try fallbackEntryConfig) {
	data, ok := f.cache.Get(winningStrategyCacheKey)
	if !ok {
		return input, nil
	}

	cachedCfg, err := f.parseConfig(data)
	if err != nil {
		return input, nil
	}

	logWriter.Write([]byte("💾 resume strategy from cache\n"))
	winner := winningConfig(cachedCfg)

	if fbCfg, ok := winner.getFallbackIfExclusive(&input); ok {
		return input, fbCfg
	}
	winner.promoteProxylessToFront(&input)
	return input, nil
}

type logWriterContextKeyType struct{}

var logWriterContextKey = logWriterContextKeyType{}

// logCtx logs to the writer in the context, if any and if the context is not done.
func logCtx(ctx context.Context, format string, a ...any) {
	// Suppress logging if the context is done.
	// There's a race condition where the context may be done after this check and before the
	// output, and the output will still proceed, but we just need to minimize spurious logging.
	select {
	case <-ctx.Done():
		return
	default:
	}
	writer, _ := ctx.Value(logWriterContextKey).(*turnOffWriter)
	if writer != nil {
		fmt.Fprintf(writer, format, a...)
	}
}

// turnOffWriter is an io.Writer that can be turned off to stop writing.
type turnOffWriter struct {
	writer io.Writer
	mu     sync.Mutex
}

// Write implements io.Writer.
func (t *turnOffWriter) Write(p []byte) (n int, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.writer == nil {
		return len(p), nil
	}
	return t.writer.Write(p)
}

// TurnOff stops the writer from writing any further.
func (t *turnOffWriter) TurnOff() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.writer = nil
}

// NewDialer implements [Finder].
func (f *finder) NewDialer(ctx context.Context, testDomains []string, configBytes []byte) (transport.StreamDialer, error) {
	// Set up logger for this session.
	logWriter := &turnOffWriter{writer: f.logWriter}
	ctx = context.WithValue(ctx, logWriterContextKey, logWriter)
	defer logWriter.TurnOff()

	// Parse the config and make sure it's valid
	inputConfig, err := f.parseConfig(configBytes)
	if err != nil {
		return nil, err
	}

	// Make domain fully-qualified to prevent confusing domain search.
	testDomains = append(make([]string, 0, len(testDomains)), testDomains...)
	for di, domain := range testDomains {
		testDomains[di] = makeFullyQualified(domain)
	}

	// Fast resume the winning strategy from the cache
	if f.cache != nil {
		rankedConfig, first2Try := f.rankStrategiesFromCache(logWriter, inputConfig)
		if first2Try != nil {
			if dialer, _, err := f.findFallback(ctx, testDomains, []fallbackEntryConfig{first2Try}); err == nil {
				return dialer, nil
			}
		}
		inputConfig = rankedConfig
	}

	// Find a working strategy and persist it to the cache
	var winner winningConfig
	dialer, dnsConf, tlsConf, err := f.newProxylessDialer(ctx, testDomains, inputConfig)
	if err == nil {
		winner = newProxylessWinningConfig(dnsConf, tlsConf)
	} else if inputConfig.Fallback != nil {
		var fbConf fallbackEntryConfig
		dialer, fbConf, err = f.findFallback(ctx, testDomains, inputConfig.Fallback)
		if err == nil {
			winner = newFallbackWinningConfig(fbConf)
		}
	}

	// Persist the potential winner to cache
	if f.cache != nil {
		var data []byte = nil
		if err == nil {
			data, err = winner.toYAML()
		}
		f.cache.Put(winningStrategyCacheKey, data)
		if data != nil {
			logWriter.Write([]byte("💾 strategy stored to cache\n"))
		} else {
			logWriter.Write([]byte("💾 strategy cache cleared\n"))
		}
	}

	return dialer, err
}
