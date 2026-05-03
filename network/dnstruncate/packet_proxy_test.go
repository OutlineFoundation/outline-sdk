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

package dnstruncate

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.getoutline.org/sdk/network"
	"golang.getoutline.org/sdk/network/packetrelay"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

// Make sure TC & NOERROR & ANCOUNT are set in the DNS response
func TestTruncatedBitIsSetInResponse(t *testing.T) {
	session := newInstantDNSSessionForTest(t)
	resolverAddr := netip.MustParseAddrPort("1.2.3.4:53")
	require.NotNil(t, resolverAddr)

	dnsReq := constructDNSRequestOrResponse(t, false, 0x2468, []string{"www.google.com", "www.youtube.com"})
	expected := constructDNSRequestOrResponse(t, true, 0x2468, []string{"www.google.com", "www.youtube.com"})

	dnsResp, err := session.Query(dnsReq, resolverAddr)
	require.NoError(t, err)
	require.Equal(t, expected, dnsResp)

	require.NoError(t, session.Close())
}

// Make sure invalid DNS requests should result in an error
func TestInvalidDNSRequestReturnsError(t *testing.T) {
	session := newInstantDNSSessionForTest(t)
	resolverAddr := netip.MustParseAddrPort("[::1]:53")
	require.NotNil(t, resolverAddr)

	// dns request size too small
	dnsReq := constructDNSRequestOrResponse(t, false, 0x2345, []string{"www.google.com"})
	_, err := session.Query(dnsReq[:11], resolverAddr)
	require.Error(t, err)
	session.AssertNoResponseFrom(resolverAddr)

	// minimum valid dns request size
	dnsResp, err := session.Query(dnsReq[:12], resolverAddr)
	require.NoError(t, err)
	require.NotNil(t, dnsResp)

	require.NoError(t, session.Close())
}

// Make sure proxy won't response on port other than 53
func TestPacketNotSentToPort53ReturnsError(t *testing.T) {
	session := newInstantDNSSessionForTest(t)

	invalidResolvers := []string{
		"3.4.5.6:54",
		"127.0.0.1:52",
		"6.5.4.3:853",
		"8.8.8.8:443",
	}

	dnsReq := constructDNSRequestOrResponse(t, false, 0x3456, []string{"www.google.com"})
	for _, resolver := range invalidResolvers {
		resolverAddr := netip.MustParseAddrPort(resolver)
		require.NotNil(t, resolverAddr)

		resp, err := session.Query(dnsReq, resolverAddr)
		require.ErrorIs(t, err, network.ErrPortUnreachable)
		require.Nil(t, resp)
		session.AssertNoResponseFrom(resolverAddr)
	}

	require.NoError(t, session.Close())
}

// Make sure SendPacket to a closed proxy should result in an error
func TestWriteToClosedProxyReturnsError(t *testing.T) {
	session := newInstantDNSSessionForTest(t)
	resolverAddr := netip.MustParseAddrPort("1.2.3.4:53")
	require.NotNil(t, resolverAddr)

	require.NoError(t, session.Close())
	dnsReq := constructDNSRequestOrResponse(t, false, 0x4567, []string{"www.google.com"})
	resp, err := session.Query(dnsReq, resolverAddr)
	require.ErrorIs(t, err, packetrelay.ErrClosed)
	require.Nil(t, resp)
	session.AssertNoResponseFrom(resolverAddr)
}

// Make sure NewAssociation returns valid interfaces
func TestNewAssociationReturnsValidInterfaces(t *testing.T) {
	p := createProxyForTest(t)
	sender, receiver, err := p.NewAssociation()
	require.NoError(t, err)
	require.NotNil(t, sender)
	require.NotNil(t, receiver)
}

// Make sure multiple goroutines can call SendPacket to the same session
func TestMultipleWriteToRaceCondition(t *testing.T) {
	const clientCnt = 20
	const iterationCntPerClient = 20

	session := newInstantDNSSessionForTest(t)

	wg := &sync.WaitGroup{}
	wg.Add(clientCnt)
	for i := 0; i < clientCnt; i++ {
		go func(idx int) {
			resolverAddr := netip.MustParseAddrPort(fmt.Sprintf("127.0.0.%d:53", idx+1))
			require.NotNil(t, resolverAddr)

			for j := 0; j < iterationCntPerClient; j++ {
				txid := uint16(idx*1000 + j)
				req := constructDNSRequestOrResponse(t, false, txid, []string{"www.google.com"})
				expected := constructDNSRequestOrResponse(t, true, txid, []string{"www.google.com"})

				resp, err := session.Query(req, resolverAddr)
				require.NoError(t, err)
				require.Equal(t, expected, resp)
			}
			wg.Done()
		}(i)
	}

	wg.Wait()
	require.NoError(t, session.Close())
}

/********** Test utilities **********/

func createProxyForTest(t *testing.T) packetrelay.PacketRelay {
	p, err := NewPacketRelay()
	require.NoError(t, err)
	require.NotNil(t, p)
	return p
}

func constructDNSQuestionsFromDomainNames(questions []string) []layers.DNSQuestion {
	result := make([]layers.DNSQuestion, 0)
	for _, name := range questions {
		result = append(result, layers.DNSQuestion{
			Name:  []byte(name),
			Type:  layers.DNSTypeA,
			Class: layers.DNSClassIN,
		})
	}
	return result
}

// constructDNSRequestOrResponse creates the following DNS request/response:
//
//	[ `id` ]:                                2 bytes
//	[ Standard-Query/Response + Recursive ]: 0x01/0x81
//	[ Reserved/Response-No-Err ]:            0x00
//	[ Questions-Count ]:                     2 bytes    (= len(questions))
//	[ Answers Count ]:                       2 bytes    (= 0x00 0x00 / len(questions))
//	[ Authorities Count ]:                   0x00 0x00
//	[ Resources Count ]:                     0x00 0x01
//	[ `questions` ]:                         ? bytes
//	[ Additional Resources ]:                ? bytes   (= OPT(payload_size=4096))
//
// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
//
// The response is actually invalid because it doesn't contain any answers section (but Answers Count == 1). We have to
// do this due to the DNS retry logic in Windows 7:
//   - https://github.com/eycorsican/go-tun2socks/blob/master/proxy/dnsfallback/udp.go#L59-L63
func constructDNSRequestOrResponse(t *testing.T, response bool, id uint16, questions []string) []byte {
	require.NotEmpty(t, questions)
	pkt := layers.DNS{
		ID:        id,
		RD:        true,
		QDCount:   uint16(len(questions)),
		Questions: constructDNSQuestionsFromDomainNames(questions),
		ARCount:   1,
		Additionals: []layers.DNSResourceRecord{
			{
				Type:  layers.DNSTypeOPT,
				Class: 4096, // Payload size
			},
		},
	}
	if response {
		pkt.QR = true
		pkt.TC = true
		pkt.ResponseCode = layers.DNSResponseCodeNoErr
		pkt.ANCount = uint16(len(questions))
	}

	buf := gopacket.NewSerializeBuffer()
	err := pkt.SerializeTo(buf, gopacket.SerializeOptions{})
	require.NoError(t, err)
	require.Greater(t, len(buf.Bytes()), 12)
	return buf.Bytes()
}

type dnsResponseState struct {
	ch       chan []byte
	received bool
}

// instantPacketSession sends UDP request, and return the response instantly (see Query).
type instantPacketSession struct {
	t         *testing.T
	sender    packetrelay.PacketSender
	receiver  packetrelay.PacketReceiver
	responses sync.Map // server addr (string) -> *dnsResponseState
	closed    bool
	mu        sync.Mutex
}

func newInstantDNSSessionForTest(t *testing.T) *instantPacketSession {
	p := createProxyForTest(t)
	s := &instantPacketSession{
		t: t,
	}
	sender, receiver, err := p.NewAssociation()
	require.NoError(t, err)
	require.NotNil(t, sender)
	require.NotNil(t, receiver)
	s.sender = sender
	s.receiver = receiver

	// Start the receive loop
	go func() {
		_ = s.receiver.ReceivePackets(s)
	}()

	return s
}

func (s *instantPacketSession) Query(req []byte, dest netip.AddrPort) ([]byte, error) {
	ch := make(chan []byte, 1)
	s.responses.Store(dest.String(), &dnsResponseState{ch: ch})

	err := s.sender.SendPacket(req, dest)
	if err != nil {
		return nil, err
	}

	// Wait for response with timeout
	select {
	case resp := <-ch:
		return resp, nil
	case <-time.After(2 * time.Second):
		return nil, errors.New("timeout waiting for DNS response")
	}
}

func (s *instantPacketSession) AssertNoResponseFrom(source netip.AddrPort) {
	// Wait a bit to ensure no packet arrives asynchronously
	time.Sleep(50 * time.Millisecond)
	stateObj, ok := s.responses.Load(source.String())
	if !ok {
		return
	}
	state := stateObj.(*dnsResponseState)
	require.False(s.t, state.received)
}

func (s *instantPacketSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		return s.sender.Close()
	}
	return nil
}

func (s *instantPacketSession) HandlePacket(p []byte, source netip.AddrPort) error {
	if stateObj, ok := s.responses.Load(source.String()); ok {
		state := stateObj.(*dnsResponseState)
		state.received = true
		buf := make([]byte, len(p))
		copy(buf, p)
		select {
		case state.ch <- buf:
		default:
		}
	}
	return nil
}
