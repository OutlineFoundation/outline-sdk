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
	"flag"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/lmittmann/tint"
	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/x/configurl"
	"golang.getoutline.org/sdk/x/websocket"
	"golang.org/x/term"
)

type natConn struct {
	net.Conn
	mappingTimeout time.Duration
}

// Consider ReadFrom/WriteTo
func (c *natConn) Write(b []byte) (int, error) {
	c.Conn.SetDeadline(time.Now().Add(c.mappingTimeout))
	return c.Conn.Write(b)
}

func main() {
	var logLevel slog.LevelVar
	slog.SetDefault(slog.New(tint.NewHandler(
		os.Stderr,
		&tint.Options{NoColor: !term.IsTerminal(int(os.Stderr.Fd())), Level: &logLevel})))
	listenFlag := flag.String("listen", "localhost:8080", "Local proxy address to listen on")
	transportFlag := flag.String("transport", "", "Transport config")
	backendFlag := flag.String("backend", "", "Address of the endpoint to forward traffic to")
	tcpPathFlag := flag.String("tcp_path", "/tcp", "Path where to run the WebSocket TCP forwarder")
	udpPathFlag := flag.String("udp_path", "/udp", "Path where to run the WebSocket UDP forwarder")
	flag.Parse()

	if *backendFlag == "" {
		log.Fatal("Must specify flag -backend")
	}

	listener, err := net.Listen("tcp", *listenFlag)
	if err != nil {
		log.Fatalf("Could not listen on address %v: %v", *listenFlag, err)
	}
	defer listener.Close()
	slog.Info("Proxy listening", "address", listener.Addr().String())

	registry := configurl.NewDefaultRegistry()
	mux := http.NewServeMux()
	if *tcpPathFlag != "" {
		dialer, err := configurl.New[transport.StreamDialer](context.Background(), registry, *transportFlag)
		if err != nil {
			log.Fatalf("Could not create stream dialer: %v", err)
		}
		endpoint := transport.StreamDialerEndpoint{Dialer: dialer, Address: *backendFlag}
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			slog.Info("Got stream request", "request", r)
			clientConn, err := websocket.Upgrade(w, r, http.Header{})
			if err != nil {
				slog.Error("failed to accept Websocket connection", "error", err)
				http.Error(w, "Failed to accept Websocket connection", http.StatusBadGateway)
				return
			}
			defer clientConn.Close()

			targetConn, err := endpoint.ConnectStream(r.Context())
			if err != nil {
				slog.Error("Failed to connect to the origin", "error", err)
				return
			}
			defer targetConn.Close()

			go func() {
				defer targetConn.CloseWrite()
				_, err := io.Copy(targetConn, clientConn)
				if err != nil {
					slog.Error("Failed to relay client traffic to target", "error", err)
				}
			}()
			_, err = io.Copy(clientConn, targetConn)
			if err != nil {
				slog.Error("Failed to relay target traffic to client", "error", err)
			}
			clientConn.CloseWrite()
		})
		mux.Handle(*tcpPathFlag, http.StripPrefix(*tcpPathFlag, handler))
	}
	if *udpPathFlag != "" {
		dialer, err := configurl.New[transport.PacketDialer](context.Background(), registry, *transportFlag)
		if err != nil {
			log.Fatalf("Could not create stream dialer: %v", err)
		}
		endpoint := transport.PacketDialerEndpoint{Dialer: dialer, Address: *backendFlag}
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			slog.Info("Got packet request", "request", r)
			clientConn, err := websocket.Upgrade(w, r, http.Header{})
			if err != nil {
				slog.Error("failed to accept Websocket connection", "error", err)
				http.Error(w, "Failed to accept Websocket connection", http.StatusBadGateway)
				return
			}
			defer clientConn.Close()

			targetConn, err := endpoint.ConnectPacket(r.Context())
			if err != nil {
				slog.Error("Failed to connect to the origin", "error", err)
				return
			}
			// Expire connection after 5 minutes of idle time, as per
			// https://datatracker.ietf.org/doc/html/rfc4787#section-4.3
			targetConn = &natConn{targetConn, 5 * time.Minute}
			defer targetConn.Close()

			done := false
			go func() {
				defer targetConn.Close()
				_, err := io.Copy(targetConn, clientConn)
				if err != nil && !done {
					slog.Error("Failed to relay client traffic to target", "error", err)
				}
				done = true
			}()
			_, err = io.Copy(clientConn, targetConn)
			if err != nil && !done {
				slog.Error("Failed to relay target traffic to client", "error", err)
			}
			done = true
			clientConn.Close()
		})
		mux.Handle(*udpPathFlag, http.StripPrefix(*udpPathFlag, handler))
	}
	server := http.Server{Handler: mux}
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Error running web server: %v", err)
		}
	}()

	// Wait for interrupt signal to stop the proxy.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
	log.Println("Shutting down")
	// Gracefully shut down the server, with a 5s timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Failed to shutdown gracefully: %v", err)
	}
}
