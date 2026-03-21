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

package smart

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"time"
	"unicode"

	"golang.getoutline.org/sdk/dns"
	"golang.org/x/net/dns/dnsmessage"
)

// makeFullyQualified makes the domain fully-qualified, ending on a dot (".").
// This is useful in domain resolution to avoid ambiguity with local domains
// and domain search.
func makeFullyQualified(domain string) string {
	if len(domain) > 0 && domain[len(domain)-1] == '.' {
		return domain
	}
	return domain + "."
}

// mixCase randomizes the case of the domain letters.
func mixCase(domain string) string {
	var mixed []rune
	for _, r := range domain {
		if rand.Intn(2) == 0 {
			mixed = append(mixed, unicode.ToLower(r))
		} else {
			mixed = append(mixed, unicode.ToUpper(r))
		}
	}
	return string(mixed)
}

func evaluateNetResolver(ctx context.Context, resolver *net.Resolver, testDomain string) ([]net.IP, error) {
	requestDomain := mixCase(testDomain)
	_, err := lookupCNAME(ctx, requestDomain)
	if err != nil {
		return nil, fmt.Errorf("could not get cname: %w", err)
	}
	ips, err := resolver.LookupIP(ctx, "ip", requestDomain)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup IPs: %w", err)
	}
	if len(ips) == 0 {
		return nil, errors.New("no ip answer")
	}
	for _, ip := range ips {
		if ip.IsLoopback() {
			return nil, fmt.Errorf("localhost ip: %v", ip)
		}
		if ip.IsPrivate() {
			return nil, fmt.Errorf("private ip: %v", ip)
		}
		if ip.IsUnspecified() {
			return nil, fmt.Errorf("zero ip: %v", ip)
		}
		// TODO: consider validating the IPs: fingerprint, TCP connection, hardcoded ground truth, trusted response, TLS connection.
	}
	return ips, nil
}

func getIPs(answers []dnsmessage.Resource) []net.IP {
	var ips []net.IP
	for _, answer := range answers {
		if answer.Header.Type != dnsmessage.TypeA && answer.Header.Type != dnsmessage.TypeAAAA {
			continue
		}
		var ip net.IP
		switch rr := answer.Body.(type) {
		case *dnsmessage.AResource:
			ip = net.IP(rr.A[:])
		case *dnsmessage.AAAAResource:
			ip = net.IP(rr.AAAA[:])
		default:
			continue
		}
		ips = append(ips, ip)
	}
	return ips
}

func evaluateAddressResponse(response dnsmessage.Message, requestDomain string) ([]net.IP, error) {
	if response.RCode != dnsmessage.RCodeSuccess {
		return nil, fmt.Errorf("rcode is not success: %v", response.RCode)
	}
	if len(response.Answers) == 0 {
		return nil, errors.New("no answers")
	}
	ips := getIPs(response.Answers)
	if len(ips) == 0 {
		return ips, fmt.Errorf("no ip answer: %v", response.Answers)
	}
	for _, ip := range ips {
		if ip.IsLoopback() {
			return nil, fmt.Errorf("localhost ip: %v", ip)
		}
		if ip.IsPrivate() {
			return nil, fmt.Errorf("private ip: %v", ip)
		}
		if ip.IsUnspecified() {
			return nil, fmt.Errorf("zero ip: %v", ip)
		}
	}
	// All popular recursive resolvers we tested maintain the domain case of the request.
	// Note that this is not the case of authoritative resolvers. Some of them will return
	// a fully normalized domain name, or normalize part of it.
	if response.Answers[0].Header.Name.String() != requestDomain {
		return ips, fmt.Errorf("domain mismatch: got %v, expected %v", response.Answers[0].Header.Name, requestDomain)
	}
	return ips, nil
}

func evaluateCNAMEResponse(response dnsmessage.Message, requestDomain string) error {
	if response.RCode != dnsmessage.RCodeSuccess {
		return fmt.Errorf("rcode is not success: %v", response.RCode)
	}
	if len(response.Answers) == 0 {
		var numSOA int
		for _, answer := range response.Authorities {
			if _, ok := answer.Body.(*dnsmessage.SOAResource); ok {
				numSOA++
			}
		}
		if numSOA != 1 {
			return fmt.Errorf("SOA records is %v, expected 1", numSOA)
		}
		return nil
	}
	var cname string
	for _, answer := range response.Answers {
		if answer.Header.Type != dnsmessage.TypeCNAME {
			return fmt.Errorf("bad answer type: %v", answer.Header.Type)
		}
		if rr, ok := answer.Body.(*dnsmessage.CNAMEResource); ok {
			if cname != "" {
				return fmt.Errorf("found too many CNAMEs: %v %v", cname, rr.CNAME)
			}
			cname = rr.CNAME.String()
		}
	}
	if cname == "" {
		return errors.New("no CNAME in answers")
	}
	return nil
}

func testDNSResolver(baseCtx context.Context, oneTestTimeout time.Duration, resolver *smartResolver, testDomain string) ([]net.IP, error) {
	// We special case the system resolver, since we can't get a dns.RoundTripper.
	if resolver.Resolver == nil {
		ctx, cancel := context.WithTimeout(baseCtx, oneTestTimeout)
		defer cancel()
		return evaluateNetResolver(ctx, new(net.Resolver), testDomain)
	}

	requestDomain := mixCase(testDomain)

	q, err := dns.NewQuestion(requestDomain, dnsmessage.TypeA)
	if err != nil {
		return nil, fmt.Errorf("failed to create question: %w", err)
	}
	ctxA, cancelA := context.WithTimeout(baseCtx, oneTestTimeout)
	defer cancelA()
	response, err := resolver.Query(ctxA, q)
	if err != nil {
		return nil, fmt.Errorf("request for A query failed: %w", err)
	}

	if resolver.Secure {
		// For secure DNS, we just need to check if we can communicate with it.
		// No need to analyze content, since it is protected by TLS.
		return getIPs(response.Answers), nil
	}

	ips, err := evaluateAddressResponse(*response, requestDomain)
	if err != nil {
		return ips, fmt.Errorf("failed A test: %w", err)
	}

	// TODO(fortuna): Consider testing whether we can establish a TCP connection to ip:443.

	// Run CNAME test, which helps in case the resolver returns a public IP, as is the
	// case in China.
	q, err = dns.NewQuestion(requestDomain, dnsmessage.TypeCNAME)
	if err != nil {
		return nil, fmt.Errorf("failed to create question: %w", err)
	}
	ctxCNAME, cancelCNAME := context.WithTimeout(baseCtx, oneTestTimeout)
	defer cancelCNAME()
	response, err = resolver.Query(ctxCNAME, q)
	if err != nil {
		return nil, fmt.Errorf("request for CNAME query failed: %w", err)
	}
	err = evaluateCNAMEResponse(*response, requestDomain)
	if err != nil {
		return nil, fmt.Errorf("failed CNAME test: %w", err)
	}
	return ips, nil
}
