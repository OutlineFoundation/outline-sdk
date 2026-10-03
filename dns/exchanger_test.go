// Copyright 2026 The Outline Authors
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
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.getoutline.org/sdk/transport"
	"golang.org/x/net/dns/dnsmessage"
)

// newTestQuery returns a wire-format query for example.com. with the given ID.
func newTestQuery(t *testing.T, id uint16) []byte {
	t.Helper()
	q, err := NewQuestion("example.com.", dnsmessage.TypeA)
	require.NoError(t, err)
	query, err := appendRequest(id, *q, make([]byte, 0, 512))
	require.NoError(t, err)
	return query
}

// newTestResponse returns a wire-format response to query, answering with 127.0.0.1.
func newTestResponse(t *testing.T, query []byte) []byte {
	t.Helper()
	var msg dnsmessage.Message
	require.NoError(t, msg.Unpack(query))
	msg.Response = true
	msg.Answers = []dnsmessage.Resource{{
		Header: dnsmessage.ResourceHeader{
			Name:  msg.Questions[0].Name,
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
			TTL:   100,
		},
		Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}},
	}}
	response, err := msg.Pack()
	require.NoError(t, err)
	return response
}

func TestParseQuery(t *testing.T) {
	t.Run("Question", func(t *testing.T) {
		info, err := parseQuery(newTestQuery(t, 0x1234))
		require.NoError(t, err)
		require.Equal(t, uint16(0x1234), info.id)
		require.NotNil(t, info.question)
		require.Equal(t, "example.com.", info.question.Name.String())
		require.Equal(t, dnsmessage.TypeA, info.question.Type)
	})
	t.Run("NoQuestion", func(t *testing.T) {
		msg := dnsmessage.Message{Header: dnsmessage.Header{ID: 42}}
		query, err := msg.Pack()
		require.NoError(t, err)
		info, err := parseQuery(query)
		require.NoError(t, err)
		require.Equal(t, uint16(42), info.id)
		require.Nil(t, info.question)
	})
	t.Run("NotAQuery", func(t *testing.T) {
		query := newTestQuery(t, 1)
		response := newTestResponse(t, query)
		_, err := parseQuery(response)
		require.ErrorContains(t, err, "not a query")
	})
	t.Run("Garbage", func(t *testing.T) {
		_, err := parseQuery([]byte{0, 0})
		require.Error(t, err)
	})
}

func TestCheckRawResponse(t *testing.T) {
	query := newTestQuery(t, 0xbeef)
	info, err := parseQuery(query)
	require.NoError(t, err)

	t.Run("Valid", func(t *testing.T) {
		require.NoError(t, checkRawResponse(newTestResponse(t, query), info))
	})
	t.Run("CaseInsensitiveName", func(t *testing.T) {
		// Resolvers may echo the question with different case, as with 0x20 encoding.
		var msg dnsmessage.Message
		require.NoError(t, msg.Unpack(newTestResponse(t, query)))
		name, err := dnsmessage.NewName("ExAmPlE.CoM.")
		require.NoError(t, err)
		msg.Questions[0].Name = name
		response, err := msg.Pack()
		require.NoError(t, err)
		require.NoError(t, checkRawResponse(response, info))
	})
	t.Run("NotAResponse", func(t *testing.T) {
		require.ErrorContains(t, checkRawResponse(query, info), "response bit not set")
	})
	t.Run("WrongID", func(t *testing.T) {
		other := newTestQuery(t, 0xf00d)
		require.ErrorContains(t, checkRawResponse(newTestResponse(t, other), info), "message id does not match")
	})
	t.Run("WrongQuestion", func(t *testing.T) {
		q, err := NewQuestion("other.example.", dnsmessage.TypeA)
		require.NoError(t, err)
		otherQuery, err := appendRequest(0xbeef, *q, make([]byte, 0, 512))
		require.NoError(t, err)
		err = checkRawResponse(newTestResponse(t, otherQuery), info)
		require.ErrorContains(t, err, "response question doesn't match request")
	})
	t.Run("Garbage", func(t *testing.T) {
		require.Error(t, checkRawResponse([]byte{0, 0}, info))
	})
	t.Run("IDOnlyWhenQueryHasNoQuestion", func(t *testing.T) {
		require.NoError(t, checkRawResponse(newTestResponse(t, query), queryInfo{id: 0xbeef}))
	})
}

func TestExchangeDatagram(t *testing.T) {
	t.Run("ReturnsResponseVerbatim", func(t *testing.T) {
		front, back := net.Pipe()
		query := newTestQuery(t, 0x0102)
		info, err := parseQuery(query)
		require.NoError(t, err)

		type result struct {
			response []byte
			err      error
		}
		done := make(chan result)
		go func() {
			response, err := exchangeDatagram(front, query, info)
			done <- result{response, err}
		}()

		// The query must reach the server byte for byte: its ID, flags and EDNS(0)
		// options belong to whoever created it.
		buf := make([]byte, 1024)
		n, err := back.Read(buf)
		require.NoError(t, err)
		require.Equal(t, query, buf[:n])

		sent := newTestResponse(t, query)
		_, err = back.Write(sent)
		require.NoError(t, err)

		got := <-done
		require.NoError(t, got.err)
		require.Equal(t, sent, got.response)
	})

	t.Run("IgnoresMismatchedDatagrams", func(t *testing.T) {
		front, back := net.Pipe()
		query := newTestQuery(t, 0x0102)
		info, err := parseQuery(query)
		require.NoError(t, err)

		done := make(chan []byte)
		go func() {
			response, err := exchangeDatagram(front, query, info)
			require.NoError(t, err)
			done <- response
		}()
		_, err = back.Read(make([]byte, 1024))
		require.NoError(t, err)

		// Unparseable datagram.
		_, err = back.Write([]byte{0xff})
		require.NoError(t, err)
		// Valid response to a different query, as an off-path attacker would inject.
		_, err = back.Write(newTestResponse(t, newTestQuery(t, 0x0999)))
		require.NoError(t, err)
		// The real response.
		sent := newTestResponse(t, query)
		_, err = back.Write(sent)
		require.NoError(t, err)

		require.Equal(t, sent, <-done)
	})

	t.Run("DoesNotModifyQuery", func(t *testing.T) {
		front, back := net.Pipe()
		query := newTestQuery(t, 0x0102)
		original := bytesClone(query)
		info, err := parseQuery(query)
		require.NoError(t, err)

		done := make(chan struct{})
		go func() {
			defer close(done)
			_, err := exchangeDatagram(front, query, info)
			require.NoError(t, err)
		}()
		_, err = back.Read(make([]byte, 1024))
		require.NoError(t, err)
		_, err = back.Write(newTestResponse(t, query))
		require.NoError(t, err)
		<-done
		require.Equal(t, original, query)
	})
}

func TestNewUDPExchangerRejectsInvalidQuery(t *testing.T) {
	dialer := transport.FuncPacketDialer(func(ctx context.Context, addr string) (net.Conn, error) {
		require.Fail(t, "must not dial for an invalid query")
		return nil, nil
	})
	_, err := NewUDPExchanger(dialer, "192.0.2.1").Exchange(context.Background(), []byte{0, 0})
	require.ErrorIs(t, err, ErrBadRequest)
}

func TestExchangeStream(t *testing.T) {
	t.Run("FramesMessages", func(t *testing.T) {
		front, back := net.Pipe()
		query := newTestQuery(t, 0x0102)

		type result struct {
			response []byte
			err      error
		}
		done := make(chan result)
		go func() {
			response, err := exchangeStream(front, query)
			done <- result{response, err}
		}()

		var msgLen uint16
		require.NoError(t, binary.Read(back, binary.BigEndian, &msgLen))
		require.Equal(t, uint16(len(query)), msgLen)
		received := make([]byte, msgLen)
		_, err := io.ReadFull(back, received)
		require.NoError(t, err)
		require.Equal(t, query, received)

		sent := newTestResponse(t, query)
		require.NoError(t, binary.Write(back, binary.BigEndian, uint16(len(sent))))
		_, err = back.Write(sent)
		require.NoError(t, err)

		got := <-done
		require.NoError(t, got.err)
		require.Equal(t, sent, got.response)
	})

	t.Run("MessageTooLarge", func(t *testing.T) {
		front, _ := net.Pipe()
		_, err := exchangeStream(front, make([]byte, maxMessageSize+1))
		require.ErrorIs(t, err, ErrBadRequest)
	})
}

func TestNewHTTPSExchanger(t *testing.T) {
	query := newTestQuery(t, 0)
	response := newTestResponse(t, query)

	var gotMethod, gotContentType string
	var gotBody []byte
	status := http.StatusOK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotContentType = r.Header.Get("Content-Type")
		var err error
		gotBody, err = io.ReadAll(r.Body)
		require.NoError(t, err)
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(response)
	}))
	defer server.Close()

	dialer := transport.FuncStreamDialer(func(ctx context.Context, addr string) (transport.StreamConn, error) {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			return nil, err
		}
		return conn.(*net.TCPConn), nil
	})
	exchanger := NewHTTPSExchanger(dialer, server.Listener.Addr().String(), server.URL+"/dns-query")

	t.Run("Success", func(t *testing.T) {
		got, err := exchanger.Exchange(context.Background(), query)
		require.NoError(t, err)
		require.Equal(t, http.MethodPost, gotMethod)
		require.Equal(t, "application/dns-message", gotContentType)
		require.Equal(t, query, gotBody)
		require.Equal(t, response, got)
	})

	t.Run("HTTPError", func(t *testing.T) {
		status = http.StatusTooManyRequests
		defer func() { status = http.StatusOK }()
		_, err := exchanger.Exchange(context.Background(), query)
		require.ErrorIs(t, err, ErrReceive)
	})
}

// bytesClone is a local copy helper, to keep the assertion independent of the code under test.
func bytesClone(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
