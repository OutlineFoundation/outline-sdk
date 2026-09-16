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
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"golang.getoutline.org/sdk/dns"
	"golang.getoutline.org/sdk/x/configurl"
	"golang.org/x/net/dns/dnsmessage"
)

var debugLog log.Logger = *log.New(io.Discard, "", 0)

func init() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [flags...] <domain>\n", path.Base(os.Args[0]))
		flag.PrintDefaults()
	}
}

func rcodeToString(rcode dnsmessage.RCode) string {
	rcodeStr, _ := strings.CutPrefix(strings.ToUpper(rcode.String()), "RCODE")
	return rcodeStr
}

func main() {
	verboseFlag := flag.Bool("v", false, "Enable debug output")
	typeFlag := flag.String("type", "A", "The type of the query (A, AAAA, CNAME, NS or TXT).")
	resolverFlag := flag.String("resolver", "", "The address of the recursive DNS resolver to use in host:port format. If the port is missing, it's assumed to be 53")
	transportFlag := flag.String("transport", "", "The transport for the connection to the recursive DNS resolver")
	tcpFlag := flag.Bool("tcp", false, "Force TCP when querying the DNS resolver")
	timeoutFlag := flag.Int("timeout", 2, "Timeout in seconds")

	flag.Parse()
	if *verboseFlag {
		debugLog = *log.New(os.Stderr, "[DEBUG] ", log.LstdFlags|log.Lmicroseconds|log.Lshortfile)
	}

	domain := strings.TrimSpace(flag.Arg(0))
	if domain == "" {
		log.Fatal("Need to pass the domain to resolve in the command-line")
	}

	resolverAddr := *resolverFlag

	var resolver dns.Resolver
	providers := configurl.NewDefaultProviders()
	if *tcpFlag {
		streamDialer, err := providers.NewStreamDialer(context.Background(), *transportFlag)
		if err != nil {
			log.Fatalf("Could not create stream dialer: %v", err)
		}
		resolver = dns.NewTCPResolver(streamDialer, resolverAddr)
	} else {
		packetDialer, err := providers.NewPacketDialer(context.Background(), *transportFlag)
		if err != nil {
			log.Fatalf("Could not create packet dialer: %v", err)
		}
		resolver = dns.NewUDPResolver(packetDialer, resolverAddr)
	}

	var qtype dnsmessage.Type
	switch strings.ToUpper(*typeFlag) {
	case "A":
		qtype = dnsmessage.TypeA
	case "AAAA":
		qtype = dnsmessage.TypeAAAA
	case "CNAME":
		qtype = dnsmessage.TypeCNAME
	case "NS":
		qtype = dnsmessage.TypeNS
	case "SOA":
		qtype = dnsmessage.TypeSOA
	case "TXT":
		qtype = dnsmessage.TypeTXT
	default:
		log.Fatalf("Unsupported query type %v", *typeFlag)
	}

	q, err := dns.NewQuestion(domain, qtype)
	if err != nil {
		log.Fatalf("Question creation failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeoutFlag)*time.Second)
	defer cancel()
	response, err := resolver.Query(ctx, q)

	if err != nil {
		log.Fatalf("Query failed: %v", err)
	}

	if response.RCode != dnsmessage.RCodeSuccess {
		log.Fatalf("Got response code %v", rcodeToString(response.RCode))
	}
	debugLog.Println(response.GoString())
	for _, answer := range response.Answers {
		if answer.Header.Type != qtype {
			continue
		}
		switch answer.Header.Type {
		case dnsmessage.TypeA:
			fmt.Println(net.IP(answer.Body.(*dnsmessage.AResource).A[:]))
		case dnsmessage.TypeAAAA:
			fmt.Println(net.IP(answer.Body.(*dnsmessage.AAAAResource).AAAA[:]))
		case dnsmessage.TypeCNAME:
			fmt.Println(answer.Body.(*dnsmessage.CNAMEResource).CNAME.String())
		case dnsmessage.TypeNS:
			fmt.Println(answer.Body.(*dnsmessage.NSResource).NS.String())
		case dnsmessage.TypeSOA:
			soa := answer.Body.(*dnsmessage.SOAResource)
			fmt.Printf("ns: %v email: %v minTTL: %v\n", soa.NS, soa.MBox, soa.MinTTL)
		case dnsmessage.TypeTXT:
			fmt.Println(strings.Join(answer.Body.(*dnsmessage.TXTResource).TXT, ", "))
		default:
			fmt.Println(answer.Body.GoString())
		}
	}
}
