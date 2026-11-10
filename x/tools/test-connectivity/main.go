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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/lmittmann/tint"
	"golang.getoutline.org/sdk/dns"
	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/x/configurl"
	"golang.getoutline.org/sdk/x/connectivity"
	"golang.getoutline.org/sdk/x/report"
	"golang.org/x/term"
)

type connectivityReport struct {
	Test           testReport  `json:"test"`
	DNSQueries     []dnsReport `json:"dns_queries,omitempty"`
	TCPConnections []tcpReport `json:"tcp_connections,omitempty"`
}

type testReport struct {
	// Inputs
	Resolver string `json:"resolver"`
	Proto    string `json:"proto"`
	// TODO(fortuna): add sanitized transport config.
	Transport string `json:"transport"`

	// Observations
	Time       time.Time  `json:"time"`
	DurationMs int64      `json:"duration_ms"`
	Error      *errorJSON `json:"error"`
}

type dnsReport struct {
	QueryName  string    `json:"query_name"`
	Time       time.Time `json:"time"`
	DurationMs int64     `json:"duration_ms"`
	AnswerIPs  []string  `json:"answer_ips"`
	Error      string    `json:"error"`
}

type tcpReport struct {
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
	Port     string `json:"port"`
	Error    string `json:"error"`
}

type errorJSON struct {
	// TODO: add Shadowsocks/Transport error
	Op string `json:"op,omitempty"`
	// Posix error, when available
	PosixError string `json:"posix_error,omitempty"`
	// TODO: remove IP addresses
	Msg string `json:"msg,omitempty"`
}

func makeErrorRecord(result *connectivity.ConnectivityError) *errorJSON {
	if result == nil {
		return nil
	}
	var record = new(errorJSON)
	record.Op = result.Op
	record.PosixError = result.PosixError
	record.Msg = unwrapAll(result.Err).Error()
	return record
}

func unwrapAll(err error) error {
	for {
		unwrapped := errors.Unwrap(err)
		if unwrapped == nil {
			return err
		}
		err = unwrapped
	}
}

func (r connectivityReport) IsSuccess() bool {
	if r.Test.Error == nil {
		return true
	} else {
		return false
	}
}

func init() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [flags...]\n", path.Base(os.Args[0]))
		flag.PrintDefaults()
	}
}
func newTCPTraceDialer(
	onDNS func(ctx context.Context, domain string) func(di httptrace.DNSDoneInfo),
	onDial func(ctx context.Context, network, addr string, connErr error)) transport.StreamDialer {
	dialer := &transport.TCPDialer{}
	var onDNSDone func(di httptrace.DNSDoneInfo)
	return transport.FuncStreamDialer(func(ctx context.Context, addr string) (transport.StreamConn, error) {
		ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
			DNSStart: func(di httptrace.DNSStartInfo) {
				onDNSDone = onDNS(ctx, di.Host)
			},
			DNSDone: func(di httptrace.DNSDoneInfo) {
				if onDNSDone != nil {
					onDNSDone(di)
					onDNSDone = nil
				}
			},
			ConnectDone: func(network, addr string, connErr error) {
				onDial(ctx, network, addr, connErr)
			},
		})
		return dialer.DialStream(ctx, addr)
	})
}

func newUDPTraceDialer(
	onDNS func(ctx context.Context, domain string) func(di httptrace.DNSDoneInfo)) transport.PacketDialer {
	dialer := &transport.UDPDialer{}
	var onDNSDone func(di httptrace.DNSDoneInfo)
	return transport.FuncPacketDialer(func(ctx context.Context, addr string) (net.Conn, error) {
		ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
			DNSStart: func(di httptrace.DNSStartInfo) {
				onDNSDone = onDNS(ctx, di.Host)
			},
			DNSDone: func(di httptrace.DNSDoneInfo) {
				if onDNSDone != nil {
					onDNSDone(di)
					onDNSDone = nil
				}
			},
		})
		return dialer.DialPacket(ctx, addr)
	})
}

func main() {
	verboseFlag := flag.Bool("v", false, "Enable debug output")
	transportFlag := flag.String("transport", "", "Transport config")
	domainFlag := flag.String("domain", "example.com.", "Domain name to resolve in the test")
	resolverFlag := flag.String("resolver", "8.8.8.8,2001:4860:4860::8888", "Comma-separated list of addresses of DNS resolver to use for the test")
	protoFlag := flag.String("proto", "tcp,udp", "Comma-separated list of the protocols to test. Must be \"tcp\", \"udp\", or a combination of them")
	reportToFlag := flag.String("report-to", "", "URL to send JSON error reports to")
	reportSuccessFlag := flag.Float64("report-success-rate", 0.1, "Report success to collector with this probability - must be between 0 and 1")
	reportFailureFlag := flag.Float64("report-failure-rate", 1, "Report failure to collector with this probability - must be between 0 and 1")

	flag.Parse()

	logLevel := slog.LevelInfo
	if *verboseFlag {
		logLevel = slog.LevelDebug
	}
	slog.SetDefault(slog.New(tint.NewHandler(
		os.Stderr,
		&tint.Options{NoColor: !term.IsTerminal(int(os.Stderr.Fd())), Level: logLevel},
	)))

	// Perform custom range validation for sampling rate
	if *reportSuccessFlag < 0.0 || *reportSuccessFlag > 1.0 {
		slog.Error("Error: report-success-rate must be between 0 and 1.", "report-success-rate", *reportSuccessFlag)
		flag.Usage()
		os.Exit(1)
	}

	if *reportFailureFlag < 0.0 || *reportFailureFlag > 1.0 {
		slog.Error("Error: report-failure-rate must be between 0 and 1.", "report-failure-rate", *reportFailureFlag)
		flag.Usage()
		os.Exit(1)
	}

	var reportCollector report.Collector
	if *reportToFlag != "" {
		collectorURL, err := url.Parse(*reportToFlag)
		if err != nil {
			slog.Error("Failed to parse collector URL", "url", err)
			os.Exit(1)
		}
		remoteCollector := &report.RemoteCollector{
			CollectorURL: collectorURL,
			HttpClient:   &http.Client{Timeout: 10 * time.Second},
		}
		retryCollector := &report.RetryCollector{
			Collector:    remoteCollector,
			MaxRetry:     3,
			InitialDelay: 1 * time.Second,
		}
		reportCollector = &report.SamplingCollector{
			Collector:       retryCollector,
			SuccessFraction: *reportSuccessFlag,
			FailureFraction: *reportFailureFlag,
		}
	} else {
		reportCollector = &report.WriteCollector{Writer: os.Stdout}
	}

	// Things to test:
	// - TCP working. Where's the error?
	// - UDP working
	// - Different server IPs
	// - Server IPv4 dial support
	// - Server IPv6 dial support

	success := false
	jsonEncoder := json.NewEncoder(os.Stdout)
	jsonEncoder.SetEscapeHTML(false)
	for _, resolverHost := range strings.Split(*resolverFlag, ",") {
		resolverHost := strings.TrimSpace(resolverHost)
		resolverAddress := net.JoinHostPort(resolverHost, "53")
		for _, proto := range strings.Split(*protoFlag, ",") {
			proto = strings.TrimSpace(proto)
			var resolver dns.Resolver
			var mu sync.Mutex
			dnsReports := make([]dnsReport, 0)
			tcpReports := make([]tcpReport, 0)
			registry := configurl.NewDefaultRegistry()
			onDNS := func(ctx context.Context, domain string) func(di httptrace.DNSDoneInfo) {
				dnsStart := time.Now()
				return func(di httptrace.DNSDoneInfo) {
					report := dnsReport{
						QueryName:  domain,
						Time:       dnsStart.UTC().Truncate(time.Second),
						DurationMs: time.Since(dnsStart).Milliseconds(),
					}
					if di.Err != nil {
						report.Error = di.Err.Error()
					}
					for _, ip := range di.Addrs {
						report.AnswerIPs = append(report.AnswerIPs, ip.IP.String())
					}
					mu.Lock()
					dnsReports = append(dnsReports, report)
					mu.Unlock()
				}
			}
			dialStream := func(ctx context.Context, addr string) (transport.StreamConn, error) {
				hostname, _, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				onDial := func(ctx context.Context, network, addr string, connErr error) {
					ip, port, err := net.SplitHostPort(addr)
					if err != nil {
						return
					}
					report := tcpReport{
						Hostname: hostname,
						IP:       ip,
						Port:     port,
					}
					if connErr != nil {
						report.Error = connErr.Error()
					}
					mu.Lock()
					tcpReports = append(tcpReports, report)
					mu.Unlock()
				}
				return newTCPTraceDialer(onDNS, onDial).DialStream(ctx, addr)
			}
			baseSD := transport.FuncStreamDialer(dialStream)
			newStreamBase := func(context.Context, configurl.Registry, *configurl.Config) (transport.StreamDialer, error) {
				return baseSD, nil
			}
			configurl.RegisterBase(registry, newStreamBase)
			dialPacket := func(ctx context.Context, addr string) (net.Conn, error) {
				return newUDPTraceDialer(onDNS).DialPacket(ctx, addr)
			}
			basePD := transport.FuncPacketDialer(dialPacket)
			newPacketBase := func(context.Context, configurl.Registry, *configurl.Config) (transport.PacketDialer, error) {
				return basePD, nil
			}
			configurl.RegisterBase(registry, newPacketBase)

			switch proto {
			case "tcp":
				streamDialer, err := configurl.New[transport.StreamDialer](context.Background(), registry, *transportFlag)
				if err != nil {
					slog.Error("Failed to create StreamDialer", "error", err)
					os.Exit(1)
				}
				resolver = dns.NewTCPResolver(streamDialer, resolverAddress)

			case "udp":
				packetDialer, err := configurl.New[transport.PacketDialer](context.Background(), registry, *transportFlag)
				if err != nil {
					slog.Error("Failed to create PacketDialer", "error", err)
					os.Exit(1)
				}
				resolver = dns.NewUDPResolver(packetDialer, resolverAddress)
			default:
				slog.Error(`Invalid proto. Must be "tcp" or "udp"`, "proto", proto)
				os.Exit(1)
			}
			startTime := time.Now()
			result, err := connectivity.TestConnectivityWithResolver(context.Background(), resolver, *domainFlag)
			if err != nil {
				slog.Error("Connectivity test failed to run", "error", err)
				os.Exit(1)
			}
			testDuration := time.Since(startTime)
			if result == nil {
				success = true
			}
			slog.Debug("Test done", "proto", proto, "resolver", resolverAddress, "result", result)
			sanitizedConfig, err := configurl.SanitizeConfig(*transportFlag)
			if err != nil {
				slog.Error("Failed to sanitize config", "error", err)
				os.Exit(1)
			}
			var r report.Report = connectivityReport{
				Test: testReport{
					Resolver: resolverAddress,
					Proto:    proto,
					Time:     startTime.UTC().Truncate(time.Second),
					// TODO(fortuna): Add sanitized config:
					Transport:  sanitizedConfig,
					DurationMs: testDuration.Milliseconds(),
					Error:      makeErrorRecord(result),
				},
				DNSQueries:     dnsReports,
				TCPConnections: tcpReports,
			}
			if reportCollector != nil {
				err = reportCollector.Collect(context.Background(), r)
				if err != nil {
					slog.Warn("Failed to collect report", "error", err)
				}
			}
		}
		if !success {
			os.Exit(1)
		}
	}
}
