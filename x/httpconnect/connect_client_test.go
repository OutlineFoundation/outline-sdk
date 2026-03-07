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

package httpconnect

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	stdTLS "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/transport/tls"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"

	"golang.getoutline.org/sdk/x/httpproxy"
)

func newTargetSrv(t *testing.T, resp interface{}) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		jsonResp, err := json.Marshal(resp)
		require.NoError(t, err)

		_, err = w.Write(jsonResp)
		require.NoError(t, err)
	}))
}

func Test_NewConnectClient_Ok(t *testing.T) {
	t.Parallel()

	var _ io.ReadWriteCloser = (net.Conn)(nil)

	tcpDialer := &transport.TCPDialer{}
	h1ConnectHandler := httpproxy.NewConnectHandler(tcpDialer)

	type closeFunc func()

	type TestCase struct {
		name          string
		prepareDialer func(t *testing.T) (transport.StreamDialer, closeFunc)
		wantErr       string
	}

	tests := []TestCase{
		{
			name: "ok. Plain HTTP/1 with headers",
			prepareDialer: func(t *testing.T) (transport.StreamDialer, closeFunc) {
				creds := base64.StdEncoding.EncodeToString([]byte("username:password"))

				proxySrv := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
					require.Equal(t, "Basic "+creds, request.Header.Get("Proxy-Authorization"))
					h1ConnectHandler.ServeHTTP(writer, request)
				}))

				proxyURL, err := url.Parse(proxySrv.URL)
				require.NoError(t, err, "Parse")

				tr, err := NewHTTPProxyTransport(tcpDialer, proxyURL.Host, WithPlainHTTP())
				require.NoError(t, err, "NewHTTPProxyTransport")

				connClient, err := NewConnectClient(tr, WithHeaders(http.Header{
					"Proxy-Authorization": []string{"Basic " + creds},
				}))
				require.NoError(t, err, "NewConnectClient")

				return connClient, proxySrv.Close
			},
		},
		{
			name: "ok. HTTP/1.1 with TLS",
			prepareDialer: func(t *testing.T) (transport.StreamDialer, closeFunc) {
				proxySrv := httptest.NewUnstartedServer(h1ConnectHandler)

				rootCA, key := generateRootCA(t)
				proxySrv.TLS = &stdTLS.Config{Certificates: []stdTLS.Certificate{key}}
				certPool := x509.NewCertPool()
				certPool.AddCert(rootCA)

				proxySrv.StartTLS()

				proxyURL, err := url.Parse(proxySrv.URL)
				require.NoError(t, err, "Parse")

				tr, err := NewHTTPProxyTransport(
					tcpDialer,
					proxyURL.Host,
					WithTLSOptions(tls.WithCertVerifier(&tls.StandardCertVerifier{Roots: certPool})),
				)
				require.NoError(t, err, "NewHTTPProxyTransport")

				connClient, err := NewConnectClient(tr)
				require.NoError(t, err, "NewConnectClient")

				return connClient, proxySrv.Close
			},
		},
		{
			name: "ok. HTTP/2 with TLS",
			prepareDialer: func(t *testing.T) (transport.StreamDialer, closeFunc) {
				proxySrv := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
					require.Equal(t, "HTTP/2.0", request.Proto, "Proto")
					require.Equal(t, http.MethodConnect, request.Method, "Method")

					conn, err := net.Dial("tcp", request.URL.Host)
					require.NoError(t, err, "Dial")
					defer conn.Close()

					writer.WriteHeader(http.StatusOK)
					writer.(http.Flusher).Flush()

					wg := &sync.WaitGroup{}

					wg.Add(1)
					go func() {
						defer wg.Done()
						io.Copy(conn, request.Body)
					}()

					wg.Add(1)
					go func() {
						defer wg.Done()
						// we can't use io.Copy, because it doesn't flush
						fw := &flusherWriter{
							Flusher: writer.(http.Flusher),
							Writer:  writer,
						}
						fw.ReadFrom(conn)
					}()

					wg.Wait()
				}))

				rootCA, key := generateRootCA(t)
				proxySrv.TLS = &stdTLS.Config{Certificates: []stdTLS.Certificate{key}}
				certPool := x509.NewCertPool()
				certPool.AddCert(rootCA)

				proxySrv.EnableHTTP2 = true
				proxySrv.StartTLS()

				proxyURL, err := url.Parse(proxySrv.URL)
				require.NoError(t, err, "Parse")

				tr, err := NewHTTPProxyTransport(
					tcpDialer,
					proxyURL.Host,
					WithTLSOptions(
						tls.WithCertVerifier(&tls.StandardCertVerifier{Roots: certPool}),
						tls.WithALPN([]string{"h2"}),
					),
				)
				require.NoError(t, err, "NewHTTPProxyTransport")

				connClient, err := NewConnectClient(tr)
				require.NoError(t, err, "NewConnectClient")

				return connClient, proxySrv.Close
			},
		},
		{
			name: "fail. enforced HTTP/2, but server doesn't support it",
			prepareDialer: func(t *testing.T) (transport.StreamDialer, closeFunc) {
				connectHandler := httpproxy.NewConnectHandler(tcpDialer)
				proxySrv := httptest.NewUnstartedServer(connectHandler)

				rootCA, key := generateRootCA(t)
				proxySrv.TLS = &stdTLS.Config{Certificates: []stdTLS.Certificate{key}}
				certPool := x509.NewCertPool()
				certPool.AddCert(rootCA)

				proxySrv.StartTLS()

				proxyURL, err := url.Parse(proxySrv.URL)
				require.NoError(t, err, "Parse")

				tr, err := NewHTTPProxyTransport(
					tcpDialer,
					proxyURL.Host,
					WithTLSOptions(
						tls.WithCertVerifier(&tls.StandardCertVerifier{Roots: certPool}),
						tls.WithALPN([]string{"h2"}),
					),
				)
				require.NoError(t, err, "NewHTTPProxyTransport")

				connClient, err := NewConnectClient(tr)
				require.NoError(t, err, "NewConnectClient")

				return connClient, proxySrv.Close
			},
			wantErr: "tls: no application protocol",
		},
		{
			name: "ok. H2C (cleartext H2, prior knowledge)",
			prepareDialer: func(t *testing.T) (transport.StreamDialer, closeFunc) {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err, "Listen")

				h2srv := &http2.Server{}
				h2Handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
					require.Equal(t, "HTTP/2.0", request.Proto, "Proto")
					require.Equal(t, http.MethodConnect, request.Method, "Method")

					conn, err := net.Dial("tcp", request.URL.Host)
					require.NoError(t, err, "Dial")
					defer conn.Close()

					writer.WriteHeader(http.StatusOK)
					writer.(http.Flusher).Flush()

					wg := &sync.WaitGroup{}

					wg.Add(1)
					go func() {
						defer wg.Done()
						io.Copy(conn, request.Body)
					}()

					wg.Add(1)
					go func() {
						defer wg.Done()
						fw := &flusherWriter{
							Flusher: writer.(http.Flusher),
							Writer:  writer,
						}
						fw.ReadFrom(conn)
					}()

					wg.Wait()
				})

				go func() {
					for {
						conn, err := ln.Accept()
						if err != nil {
							return
						}
						go h2srv.ServeConn(conn, &http2.ServeConnOpts{Handler: h2Handler})
					}
				}()

				tr, err := NewH2ProxyTransport(tcpDialer, ln.Addr().String(), WithPlainHTTP())
				require.NoError(t, err, "NewH2ProxyTransport")

				connClient, err := NewConnectClient(tr)
				require.NoError(t, err, "NewConnectClient")

				return connClient, func() { ln.Close() }
			},
		},
		{
			name: "ok. HTTP/3 over QUIC with TLS",
			prepareDialer: func(t *testing.T) (transport.StreamDialer, closeFunc) {
				rootCA, key := generateRootCA(t)
				certPool := x509.NewCertPool()
				certPool.AddCert(rootCA)

				srvConn, err := net.ListenPacket("udp", "127.0.0.1:0")
				require.NoError(t, err, "ListenPacket")

				proxySrv := &http3.Server{
					Addr: "127.0.0.1:0",
					Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
						require.Equal(t, "HTTP/3.0", request.Proto, "Proto")
						require.Equal(t, http.MethodConnect, request.Method, "Method")

						conn, err := net.Dial("tcp", request.URL.Host)
						require.NoError(t, err, "DialStream")
						defer conn.Close()

						writer.WriteHeader(http.StatusOK)
						writer.(http.Flusher).Flush()

						streamer, ok := writer.(http3.HTTPStreamer)
						if !ok {
							t.Fatal("http.ResponseWriter expected to implement http3.HTTPStreamer")
						}
						stream := streamer.HTTPStream()
						defer stream.Close()

						wg := &sync.WaitGroup{}

						wg.Add(1)
						go func() {
							defer wg.Done()
							io.Copy(stream, conn)
						}()

						wg.Add(1)
						go func() {
							defer wg.Done()
							io.Copy(conn, stream)
						}()

						wg.Wait()
					}),
					TLSConfig: &stdTLS.Config{
						Certificates: []stdTLS.Certificate{key},
					},
				}
				go func() {
					_ = proxySrv.Serve(srvConn)
				}()

				cliConn, err := net.ListenPacket("udp", "127.0.0.1:0")
				require.NoError(t, err, "DialPacket")

				tr, err := NewHTTP3ProxyTransport(
					cliConn.(net.PacketConn),
					srvConn.LocalAddr().String(),
					WithTLSOptions(tls.WithCertVerifier(&tls.StandardCertVerifier{Roots: certPool})),
				)
				require.NoError(t, err, "NewHTTP3ProxyTransport")

				connClient, err := NewConnectClient(tr)
				require.NoError(t, err, "NewConnectClient")

				return connClient, func() {
					_ = cliConn.Close()
					_ = proxySrv.Close()
					_ = srvConn.Close()
				}
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			type Response struct {
				Message string `json:"message"`
			}
			wantResp := Response{Message: "hello"}

			targetSrv := newTargetSrv(t, wantResp)
			defer targetSrv.Close()

			connClient, srvCloser := tt.prepareDialer(t)
			defer srvCloser()

			hc := &http.Client{
				Transport: &http.Transport{
					DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
						conn, err := connClient.DialStream(ctx, addr)
						if err != nil {
							return nil, err
						}
						require.Equal(t, conn.RemoteAddr().String(), addr)

						return conn, nil
					},
				},
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetSrv.URL, nil)
			req.Close = true // close the connection after the request to close the tunnel right away
			require.NoError(t, err, "NewRequest")

			resp, err := hc.Do(req)
			if tt.wantErr != "" {
				require.Contains(t, err.Error(), tt.wantErr, "Do")
				return
			}
			require.NoError(t, err, "Do")
			defer resp.Body.Close()

			require.Equal(t, http.StatusOK, resp.StatusCode)

			var gotResp Response
			err = json.NewDecoder(resp.Body).Decode(&gotResp)
			require.NoError(t, err, "Decode")

			require.Equal(t, wantResp, gotResp, "Response")
		})
	}
}

func generateRootCA(t *testing.T) (*x509.Certificate, stdTLS.Certificate) {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Test Root CA"}},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	require.NoError(t, err)

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := stdTLS.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert, tlsCert
}

type flusherWriter struct {
	http.Flusher
	io.Writer
}

func (fw flusherWriter) ReadFrom(r io.Reader) (int64, error) {
	var (
		buf   = make([]byte, 32*1024)
		total int64
	)
	for {
		nr, er := r.Read(buf)
		if nr > 0 {
			nw, ew := fw.Writer.Write(buf[:nr])
			total += int64(nw)
			if ew != nil {
				return total, ew
			}
			fw.Flush()
		}
		if er != nil {
			if er == io.EOF {
				return total, nil
			}
			return total, er
		}
	}
}
