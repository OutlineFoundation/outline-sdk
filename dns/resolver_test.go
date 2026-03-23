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

package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
)

func TestNewQuestionTypes(t *testing.T) {
	testDomain := "example.com."
	qname, err := dnsmessage.NewName(testDomain)
	require.NoError(t, err)
	for _, qtype := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA, dnsmessage.TypeCNAME} {
		t.Run(qtype.String(), func(t *testing.T) {
			q, err := NewQuestion(testDomain, qtype)
			require.NoError(t, err)
			require.Equal(t, qname, q.Name)
			require.Equal(t, qtype, q.Type)
			require.Equal(t, dnsmessage.ClassINET, q.Class)
		})
	}
}

func TestNewQuestionNotFQDN(t *testing.T) {
	testDomain := "example.com"
	q, err := NewQuestion(testDomain, dnsmessage.TypeAAAA)
	require.NoError(t, err)
	require.Equal(t, dnsmessage.MustNewName("example.com."), q.Name)
}

func TestNewQuestionRoot(t *testing.T) {
	testDomain := "."
	qname, err := dnsmessage.NewName(testDomain)
	require.NoError(t, err)
	q, err := NewQuestion(testDomain, dnsmessage.TypeAAAA)
	require.NoError(t, err)
	require.Equal(t, qname, q.Name)
}

func TestNewQuestionEmpty(t *testing.T) {
	testDomain := ""
	q, err := NewQuestion(testDomain, dnsmessage.TypeAAAA)
	require.NoError(t, err)
	require.Equal(t, dnsmessage.MustNewName("."), q.Name)
}

func TestNewQuestionLongName(t *testing.T) {
	testDomain := strings.Repeat("a.", 200)
	_, err := NewQuestion(testDomain, dnsmessage.TypeAAAA)
	require.Error(t, err)
}

func Test_appendRequest(t *testing.T) {
	id := uint16(1234)
	offset := 2
	buf, err := appendRequest(id, ".", uint16(dnsmessage.TypeAAAA), make([]byte, offset))
	require.NoError(t, err)
	require.Equal(t, make([]byte, offset), buf[:offset])

	// offset + 12 bytes header + 5 question + 11 EDNS(0) OPT RR
	require.Equal(t, offset+28, len(buf))

	require.Equal(t, id, binary.BigEndian.Uint16(buf[offset:]))

	var request dnsmessage.Message
	err = request.Unpack(buf[offset:])
	require.NoError(t, err)
	require.Equal(t, id, request.ID)
	require.Equal(t, 1, len(request.Questions))
	expectedQ, err := NewQuestion(".", dnsmessage.TypeAAAA)
	require.NoError(t, err)
	require.Equal(t, *expectedQ, request.Questions[0])
	require.Equal(t, 0, len(request.Answers))
	require.Equal(t, 0, len(request.Authorities))
	// ENDS(0) OPT resource record.
	require.Equal(t, 1, len(request.Additionals))
	// As per https://datatracker.ietf.org/doc/html/rfc6891#section-6.1.2
	optRR := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:   dnsmessage.MustNewName("."),
			Type:   dnsmessage.TypeOPT,
			Class:  maxUDPMessageSize,
			TTL:    0,
			Length: 0,
		},
		Body: &dnsmessage.OPTResource{},
	}
	require.Equal(t, optRR, request.Additionals[0])
}

func Test_foldCase(t *testing.T) {
	require.Equal(t, byte('Y'), foldCase('Y'))
	require.Equal(t, byte('Y'), foldCase('y'))
	// Only fold ASCII
	require.Equal(t, byte('ý'), foldCase('ý'))
	require.Equal(t, byte('-'), foldCase('-'))
}

func Test_equalASCIIName(t *testing.T) {
	require.True(t, equalASCIIName(dnsmessage.MustNewName("My-Example.Com"), dnsmessage.MustNewName("mY-eXAMPLE.cOM")))
	require.False(t, equalASCIIName(dnsmessage.MustNewName("example.com"), dnsmessage.MustNewName("example.net")))
	require.False(t, equalASCIIName(dnsmessage.MustNewName("example.com"), dnsmessage.MustNewName("example.com.br")))
	require.False(t, equalASCIIName(dnsmessage.MustNewName("example.com"), dnsmessage.MustNewName("myexample.com")))
}

func Test_checkResponse(t *testing.T) {
	reqID := uint16(rand.Uint32())
	const reqName = "example.com."
	const reqType = dnsmessage.TypeAAAA
	matchQ := dnsmessage.Question{
		Name:  dnsmessage.MustNewName(reqName),
		Type:  reqType,
		Class: dnsmessage.ClassINET,
	}
	expectedHdr := dnsmessage.Header{ID: reqID, Response: true}
	t.Run("Match", func(t *testing.T) {
		err := checkResponse(reqID, reqName, uint16(reqType), expectedHdr, []dnsmessage.Question{matchQ})
		require.NoError(t, err)
	})
	t.Run("CaseInsensitive", func(t *testing.T) {
		mixedQ := matchQ
		mixedQ.Name = dnsmessage.MustNewName("Example.Com.")
		err := checkResponse(reqID, reqName, uint16(reqType), expectedHdr, []dnsmessage.Question{mixedQ})
		require.NoError(t, err)
	})
	t.Run("NotResponse", func(t *testing.T) {
		badHdr := expectedHdr
		badHdr.Response = false
		err := checkResponse(reqID, reqName, uint16(reqType), badHdr, []dnsmessage.Question{matchQ})
		require.Error(t, err)
	})
	t.Run("BadID", func(t *testing.T) {
		badHdr := expectedHdr
		badHdr.ID = reqID + 1
		err := checkResponse(reqID, reqName, uint16(reqType), badHdr, []dnsmessage.Question{matchQ})
		require.Error(t, err)
	})
	t.Run("NoQuestions", func(t *testing.T) {
		err := checkResponse(reqID, reqName, uint16(reqType), expectedHdr, []dnsmessage.Question{})
		require.Error(t, err)
	})
	t.Run("BadQuestionType", func(t *testing.T) {
		badQ := matchQ
		badQ.Type = dnsmessage.TypeA
		err := checkResponse(reqID, reqName, uint16(reqType), expectedHdr, []dnsmessage.Question{badQ})
		require.Error(t, err)
	})
	t.Run("BadQuestionClass", func(t *testing.T) {
		badQ := matchQ
		badQ.Class = dnsmessage.ClassCHAOS
		err := checkResponse(reqID, reqName, uint16(reqType), expectedHdr, []dnsmessage.Question{badQ})
		require.Error(t, err)
	})
	t.Run("BadQuestionName", func(t *testing.T) {
		badQ := matchQ
		badQ.Name = dnsmessage.MustNewName("notexample.invalid.")
		err := checkResponse(reqID, reqName, uint16(reqType), expectedHdr, []dnsmessage.Question{badQ})
		require.Error(t, err)
	})
}

func newMessageResponse(req dnsmessage.Message, answer dnsmessage.ResourceBody, ttl uint32) (dnsmessage.Message, error) {
	var resp dnsmessage.Message
	if len(req.Questions) != 1 {
		return resp, fmt.Errorf("Invalid number of questions %v", len(req.Questions))
	}
	q := req.Questions[0]
	resp.ID = req.ID
	resp.Header.Response = true
	resp.Questions = []dnsmessage.Question{q}
	resp.Answers = []dnsmessage.Resource{{
		Header: dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: q.Class, TTL: ttl},
		Body:   answer,
	}}
	resp.Authorities = []dnsmessage.Resource{}
	resp.Additionals = []dnsmessage.Resource{}
	return resp, nil
}

type queryResult struct {
	data []byte
	err  error
}

func testDatagramExchange(t *testing.T, server func(request dnsmessage.Message, conn net.Conn)) ([]byte, error) {
	front, back := net.Pipe()
	clientDone := make(chan queryResult)
	go func() {
		data, err := queryDatagram(front, "example.com.", uint16(dnsmessage.TypeAAAA))
		clientDone <- queryResult{data, err}
	}()
	// Read request.
	buf := make([]byte, 512)
	n, err := back.Read(buf)
	require.NoError(t, err)
	buf = buf[:n]
	// Verify request.
	var reqMsg dnsmessage.Message
	reqMsg.Unpack(buf)
	reqID := reqMsg.ID
	expectedBuf, err := appendRequest(reqID, "example.com.", uint16(dnsmessage.TypeAAAA), make([]byte, 0, 512))
	require.NoError(t, err)
	require.Equal(t, expectedBuf, buf)

	server(reqMsg, back)

	result := <-clientDone
	return result.data, result.err
}

func Test_queryDatagram(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		var respSent dnsmessage.Message
		rawResp, err := testDatagramExchange(t, func(req dnsmessage.Message, conn net.Conn) {
			// Send bogus response.
			_, err := conn.Write([]byte{0, 0})
			require.NoError(t, err)

			// Prepare response message.
			respSent, err = newMessageResponse(req, &dnsmessage.AAAAResource{AAAA: [16]byte(net.IPv6loopback)}, 100)
			require.NoError(t, err)

			// Send message with invalid ID first.
			badMsg := respSent
			badMsg.ID = req.ID + 1
			buf, err := (&badMsg).Pack()
			require.NoError(t, err)
			_, err = conn.Write(buf)
			require.NoError(t, err)

			// Send valid response.
			buf, err = (&respSent).Pack()
			require.NoError(t, err)
			_, err = conn.Write(buf)
			require.NoError(t, err)
		})
		require.NoError(t, err)
		require.NotNil(t, rawResp)
		var respRcvd dnsmessage.Message
		require.NoError(t, respRcvd.Unpack(rawResp))
		require.Equal(t, respSent, respRcvd)
	})
	t.Run("BadResponse", func(t *testing.T) {
		_, err := testDatagramExchange(t, func(req dnsmessage.Message, conn net.Conn) {
			// Send bad response.
			_, err := conn.Write([]byte{0})
			require.NoError(t, err)
			// Close writer.
			conn.Close()
		})
		require.ErrorIs(t, err, ErrReceive)
		require.Equal(t, 2, len(errors.Unwrap(err).(interface{ Unwrap() []error }).Unwrap()))
		require.ErrorIs(t, err, io.EOF)
	})
	t.Run("FailedClientWrite", func(t *testing.T) {
		front, back := net.Pipe()
		back.Close()
		clientDone := make(chan queryResult)
		go func() {
			data, err := queryDatagram(front, "example.com.", uint16(dnsmessage.TypeAAAA))
			clientDone <- queryResult{data, err}
		}()
		// Wait for queryDatagram.
		result := <-clientDone
		require.ErrorIs(t, result.err, ErrSend)
		require.ErrorIs(t, result.err, io.ErrClosedPipe)
	})
	t.Run("FailedClientRead", func(t *testing.T) {
		front, back := net.Pipe()
		clientDone := make(chan queryResult)
		go func() {
			data, err := queryDatagram(front, "example.com.", uint16(dnsmessage.TypeAAAA))
			clientDone <- queryResult{data, err}
		}()
		back.Read(make([]byte, 521))
		back.Close()
		// Wait for queryDatagram.
		result := <-clientDone
		require.ErrorIs(t, result.err, ErrReceive)
		require.ErrorIs(t, result.err, io.EOF)
	})
}

func testStreamExchange(t *testing.T, server func(request dnsmessage.Message, conn net.Conn)) ([]byte, error) {
	front, back := net.Pipe()
	clientDone := make(chan queryResult)
	go func() {
		data, err := queryStream(front, "example.com.", uint16(dnsmessage.TypeAAAA))
		clientDone <- queryResult{data, err}
	}()
	// Read request.
	var msgLen uint16
	require.NoError(t, binary.Read(back, binary.BigEndian, &msgLen))
	buf := make([]byte, msgLen)
	n, err := back.Read(buf)
	require.NoError(t, err)
	buf = buf[:n]
	// Verify request.
	var reqMsg dnsmessage.Message
	reqMsg.Unpack(buf)
	reqID := reqMsg.ID
	expectedBuf, err := appendRequest(reqID, "example.com.", uint16(dnsmessage.TypeAAAA), make([]byte, 0, 512))
	require.NoError(t, err)
	require.Equal(t, expectedBuf, buf)

	server(reqMsg, back)

	result := <-clientDone
	return result.data, result.err
}

func Test_queryStream(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		var respSent dnsmessage.Message
		rawResp, err := testStreamExchange(t, func(req dnsmessage.Message, conn net.Conn) {
			var err error
			// Prepare response message.
			respSent, err = newMessageResponse(req, &dnsmessage.AAAAResource{AAAA: [16]byte(net.IPv6loopback)}, 100)
			require.NoError(t, err)

			// Send response.
			buf, err := (&respSent).Pack()
			require.NoError(t, err)
			require.NoError(t, binary.Write(conn, binary.BigEndian, uint16(len(buf))))
			_, err = conn.Write(buf)
			require.NoError(t, err)
		})
		require.NoError(t, err)
		require.NotNil(t, rawResp)
		var respRcvd dnsmessage.Message
		require.NoError(t, respRcvd.Unpack(rawResp))
		require.Equal(t, respSent, respRcvd)
	})
	t.Run("ShortRead", func(t *testing.T) {
		_, err := testStreamExchange(t, func(req dnsmessage.Message, conn net.Conn) {
			// Send response.
			_, err := conn.Write([]byte{0})
			require.NoError(t, err)

			// Close writer.
			conn.Close()
		})
		require.ErrorIs(t, err, ErrReceive)
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})
	t.Run("ShortMessage", func(t *testing.T) {
		_, err := testStreamExchange(t, func(req dnsmessage.Message, conn net.Conn) {
			// Send response.
			_, err := conn.Write([]byte{0, 100, 0})
			require.NoError(t, err)
			// Close writer.
			conn.Close()
		})
		require.ErrorIs(t, err, ErrReceive)
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})
	t.Run("BadMessageFormat", func(t *testing.T) {
		_, err := testStreamExchange(t, func(req dnsmessage.Message, conn net.Conn) {
			// Send response.
			_, err := conn.Write([]byte{0, 2, 0, 0})
			require.NoError(t, err)

			// Close writer.
			conn.Close()
		})
		require.ErrorIs(t, err, ErrBadResponse)
	})
	t.Run("BadMessageContent", func(t *testing.T) {
		_, err := testStreamExchange(t, func(req dnsmessage.Message, conn net.Conn) {
			// Make response with no answer and invalid ID.
			resp := req
			resp.ID = req.ID + 1
			resp.Response = true
			buf, err := resp.AppendPack(make([]byte, 2, 514))
			require.NoError(t, err)
			binary.BigEndian.PutUint16(buf, uint16(len(buf)-2))
			// Send response.
			_, err = conn.Write(buf)
			require.NoError(t, err)

			// Close writer.
			conn.Close()
		})
		require.ErrorIs(t, err, ErrBadResponse)
	})
	t.Run("FailedClientWrite", func(t *testing.T) {
		front, back := net.Pipe()
		back.Close()
		clientDone := make(chan queryResult)
		go func() {
			data, err := queryStream(front, "example.com.", uint16(dnsmessage.TypeAAAA))
			clientDone <- queryResult{data, err}
		}()
		// Wait for client.
		result := <-clientDone
		require.ErrorIs(t, result.err, ErrSend)
		require.ErrorIs(t, result.err, io.ErrClosedPipe)
	})
	t.Run("FailedClientRead", func(t *testing.T) {
		front, back := net.Pipe()
		clientDone := make(chan queryResult)
		go func() {
			data, err := queryStream(front, "example.com.", uint16(dnsmessage.TypeAAAA))
			clientDone <- queryResult{data, err}
		}()
		back.Read(make([]byte, 521))
		back.Close()
		// Wait for queryDatagram.
		result := <-clientDone
		require.ErrorIs(t, result.err, ErrReceive)
		require.ErrorIs(t, result.err, io.EOF)
	})
}

func Test_ensurePort(t *testing.T) {
	require.Equal(t, "example.com:8080", ensurePort("example.com:8080", "80"))
	require.Equal(t, "example.com:443", ensurePort("example.com", "443"))
	require.Equal(t, "example.com:443", ensurePort("example.com:", "443"))
	require.Equal(t, "8.8.8.8:8080", ensurePort("8.8.8.8:8080", "443"))
	require.Equal(t, "8.8.8.8:443", ensurePort("8.8.8.8", "443"))
	require.Equal(t, "8.8.8.8:443", ensurePort("8.8.8.8:", "443"))
	require.Equal(t, "[2001:4860:4860::8888]:8080", ensurePort("[2001:4860:4860::8888]:8080", "443"))
	require.Equal(t, "[2001:4860:4860::8888]:443", ensurePort("2001:4860:4860::8888", "443"))
	require.Equal(t, "[2001:4860:4860::8888]:443", ensurePort("[2001:4860:4860::8888]:", "443"))
}
