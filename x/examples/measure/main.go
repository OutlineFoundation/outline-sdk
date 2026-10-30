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

package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
	"sync/atomic"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/lmittmann/tint"
	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/transport/tls"
	"golang.getoutline.org/sdk/x/configurl"
	"golang.org/x/term"
)

func init() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [flags...] <url>\n", path.Base(os.Args[0]))
		flag.PrintDefaults()
	}
}

type MeasurementConfig struct {
	NumAttempts *int     `yaml:"num_attempts,omitempty"`
	Proto       string   `yaml:"proto,omitempty"`
	Domains     []string `yaml:"domains,omitempty"`
	ISPProxies  []string `yaml:"isp_proxies,omitempty"`
	Strategies  []string `yaml:"strategies,omitempty"`
}

type Measurement struct {
	Time         time.Time
	Domain       string
	ISP          string
	Country      string
	Strategy     string
	Attempt      int
	Img          string
	ErrorOp      string
	ErrorMessage string
}

type ISP struct {
	Transport   string
	Name        string
	CountryCode string
}

type ISPInfo struct {
	Data struct {
		IP          string
		ISP         string
		Carrier     string
		City        string
		Region      string
		CountryName string `json:"country_name,omitempty"`
		CountryCode string `json:"country_code,omitempty"`
	}
}

var configRegistry = configurl.NewDefaultRegistry()

func makeErrorMsg(err error, domain string) string {
	return strings.ReplaceAll(err.Error(), domain, "${DOMAIN}")
}

func newISP(ispProxy string) ISP {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dialer, err := configurl.New[transport.StreamDialer](ctx, configRegistry, ispProxy)
	if err != nil {
		slog.Error("Could not create ISP dialer", "error", err)
		os.Exit(1)
	}
	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if !strings.HasPrefix(network, "tcp") {
			return nil, fmt.Errorf("protocol not supported: %v", network)
		}
		return dialer.DialStream(ctx, addr)
	}
	httpClient := &http.Client{
		Transport: &http.Transport{DialContext: dialContext},
		Timeout:   time.Duration(10) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest("GET", "https://checker.soax.com/api/ipinfo", nil)
	if err != nil {
		slog.Error("Failed to create request", "error", err)
		os.Exit(1)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		slog.Error("HTTP request failed", "error", err)
		os.Exit(1)
	}
	var ispInfo ISPInfo
	func() {
		defer resp.Body.Close()
		jsonBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			slog.Error("failed to get isp info", "error", err)
			os.Exit(1)
		}
		json.Unmarshal(jsonBytes, &ispInfo)
	}()
	return ISP{Transport: ispProxy, Name: ispInfo.Data.ISP, CountryCode: ispInfo.Data.CountryCode}
}

func main() {
	verboseFlag := flag.Bool("v", false, "Enable debug output")
	timeoutSecFlag := flag.Int("timeout", 15, "Timeout in seconds")
	configFlag := flag.String("config", "config.yml", "config to use")

	flag.Parse()

	logLevel := slog.LevelInfo
	if *verboseFlag {
		logLevel = slog.LevelDebug
	}
	slog.SetDefault(slog.New(tint.NewHandler(
		os.Stderr,
		&tint.Options{NoColor: !term.IsTerminal(int(os.Stderr.Fd())), Level: logLevel},
	)))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := MeasurementConfig{}
	configData, err := os.ReadFile(*configFlag)
	if err != nil {
		slog.Error("failed to read config", "error", err)
		os.Exit(1)
	}
	if err := yaml.Unmarshal(configData, &cfg); err != nil {
		slog.Error("Failed to parse config", "error", err)
		os.Exit(1)
	}

	// Collect ISPs
	isps := make([]ISP, 0, len(cfg.ISPProxies))
	for _, ispProxy := range cfg.ISPProxies {
		isp := newISP(ispProxy)
		slog.Debug("Loaded ISP", "name", isp.Name, "country", isp.CountryCode)
		isps = append(isps, isp)
	}

	// Collect domain IPs
	domainIP := make([]string, 0, len(cfg.Domains))
	for _, domain := range cfg.Domains {
		ip, err := net.ResolveIPAddr("ip4", domain)
		if err != nil {
			slog.Error("failed to resolve domain", "domain", domain, "error", err)
			os.Exit(1)
		}
		domainIP = append(domainIP, ip.String())
	}

	msmtCh := make(chan Measurement)
	var pending atomic.Int32
	for _, isp := range isps {
		// Make variable copies for go routine.
		isp := isp
		pending.Add(1)
		go func() {
			defer func() {
				if pending.Add(-1) == 0 {
					close(msmtCh)
				}
			}()
			numAttempts := 1
			if cfg.NumAttempts != nil {
				numAttempts = *cfg.NumAttempts
			}
			for attempt := 1; attempt <= numAttempts; attempt++ {
				for _, strategy := range cfg.Strategies {
					transportConfig := isp.Transport
					if transportConfig != "" && strategy != "" {
						transportConfig += "|" + strategy
					}
					var test func(context.Context, string, string) (string, string)
					switch cfg.Proto {
					case "":
						fallthrough
					case "tls":
						dialer, err := configurl.New[transport.StreamDialer](ctx, configRegistry, transportConfig)
						if err != nil {
							slog.Error("Could not create dialer", "error", err)
							os.Exit(1)
						}

						test = func(ctx context.Context, domain string, ip string) (string, string) {
							tcpConn, err := dialer.DialStream(ctx, net.JoinHostPort(ip, "443"))
							if err != nil {
								if err == context.Canceled {
									err = context.Cause(ctx)
								}
								return "connect", makeErrorMsg(err, domain)
							}
							tlsConn, err := tls.WrapConn(ctx, tcpConn, domain)
							if err != nil {
								if err == context.Canceled {
									err = context.Cause(ctx)
								}
								return "tls", makeErrorMsg(err, domain)
							}
							tlsConn.Close()
							return "", ""
						}
					case "quic":
						_, err := configurl.New[transport.PacketListener](ctx, configRegistry, transportConfig)
						if err != nil {
							slog.Error("Could not create dialer", "error", err)
							os.Exit(1)
						}
					default:
						slog.Error("protocol not supported", "proto", cfg.Proto)
						os.Exit(1)
					}
					for di, domain := range cfg.Domains {
						domain := domain
						ip := domainIP[di]

						m := Measurement{
							Time:     time.Now(),
							Domain:   domain,
							ISP:      isp.Name,
							Country:  isp.CountryCode,
							Strategy: strategy,
							Attempt:  attempt,
						}
						if strategy == "" {
							m.Strategy = "direct"
						}
						ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeoutSecFlag)*time.Second)
						m.ErrorOp, m.ErrorMessage = test(ctx, domain, ip)
						cancel()
						if m.ErrorOp == "" {
							m.Img = "✅"
						} else {
							m.Img = "❌"
						}
						msmtCh <- m
					}
				}
			}
		}()
	}

	w := csv.NewWriter(os.Stdout)
	w.Write([]string{"domain", "country_code", "isp", "strategy", "attempt", "img", "error_op", "error_msg"})
	for {
		m, ok := <-msmtCh
		if !ok {
			break
		}
		w.Write([]string{m.Domain, m.Country, m.ISP, m.Strategy, fmt.Sprint(m.Attempt), m.Img, m.ErrorOp, m.ErrorMessage})
		w.Flush()
	}
}
