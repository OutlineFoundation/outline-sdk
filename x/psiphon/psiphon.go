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

package psiphon

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"runtime"
	"strings"
	"sync"
	"unicode"

	"golang.getoutline.org/sdk/transport"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/ClientLibrary/clientlib"
)

// The single [Dialer] we can have.
var singletonDialer Dialer

var (
	errNotStartedDial = errors.New("dialer has not been started yet")
	errNotStartedStop = errors.New("tried to stop dialer that is not running")
)

// DialerConfig specifies the parameters for [Dialer].
type DialerConfig struct {
	// Used as the directory for the datastore, remote server list, and obfuscasted
	// server list.
	// Empty string means the default will be used (current working directory).
	// Strongly recommended.
	DataRootDirectory string

	// Raw JSON config provided by Psiphon.
	ProviderConfig json.RawMessage
}

// Dialer is a [transport.StreamDialer] that uses Psiphon to connect to a destination.
// There's only one possible Psiphon Dialer available at any time, which is accessible via [GetSingletonDialer].
// The zero value of this type is invalid.
//
// The Dialer must be configured first with [Dialer.Start] before it can be used, and [Dialer.Stop] must be
// called before you can start it again with a new configuration. Dialer.Stop should be called
// when you no longer need the Dialer in order to release resources.
type Dialer struct {
	// Controls the Dialer state and Psiphon's global state.
	mu sync.Mutex
	// Used by DialStream.
	tunnel psiphonTunnel
	// Used by Stop.
	stop func()
}

type psiphonTunnel interface {
	Dial(remoteAddr string) (net.Conn, error)
	Stop()
}

var _ transport.StreamDialer = (*Dialer)(nil)

// DialStream implements [transport.StreamDialer].
// The context is not used because Psiphon's implementation doesn't support it. If you need cancellation,
// you will need to add it independently.
func (d *Dialer) DialStream(unusedContext context.Context, addr string) (transport.StreamConn, error) {
	d.mu.Lock()
	tunnel := d.tunnel
	d.mu.Unlock()
	if tunnel == nil {
		return nil, errNotStartedDial
	}
	netConn, err := tunnel.Dial(addr)
	if err != nil {
		return nil, err
	}
	return streamConn{netConn}, nil
}

func getClientPlatform() string {
	clientPlatformAllowChars := func(r rune) bool {
		return !unicode.IsSpace(r) && r != '_'
	}
	goos := strings.Join(strings.FieldsFunc(runtime.GOOS, clientPlatformAllowChars), "-")
	goarch := strings.Join(strings.FieldsFunc(runtime.GOARCH, clientPlatformAllowChars), "-")
	return "outline-sdk_" + goos + "_" + goarch
}

// Allows for overriding in tests.
var startTunnel func(ctx context.Context, config *DialerConfig) (psiphonTunnel, error) = psiphonStartTunnel

func psiphonStartTunnel(tunnelCtx context.Context, config *DialerConfig) (psiphonTunnel, error) {
	if config == nil {
		return nil, errors.New("config must not be nil")
	}

	// Note that these parameters override anything in the provider config.
	clientPlatform := getClientPlatform()
	trueValue := true
	params := clientlib.Parameters{
		DataRootDirectory: &config.DataRootDirectory,
		ClientPlatform:    &clientPlatform,
		// Disable Psiphon's local proxy servers, which we don't use.
		DisableLocalSocksProxy: &trueValue,
		DisableLocalHTTPProxy:  &trueValue,
	}

	return clientlib.StartTunnel(tunnelCtx, config.ProviderConfig, "", params, nil, nil)
}

// Start configures and runs the Dialer. It must be called before you can use the Dialer. It returns when the tunnel is ready.
func (d *Dialer) Start(startCtx context.Context, config *DialerConfig) error {
	resultCh := make(chan error)
	go func() {
		d.mu.Lock()
		defer d.mu.Unlock()

		if d.stop != nil {
			// If we are already started stop first.
			stop := d.stop
			d.stop = nil
			// Make sure we unlock the mutex so that the previous Start can complete.
			d.mu.Unlock()
			stop()
			d.mu.Lock()
		}

		// startCtx is intended for the lifetime of the startup.
		// dialerCtx is intended for the lifetime of the tunnel.
		dialerCtx, dialerCancel := context.WithCancel(context.Background())
		defer dialerCancel()

		// This ties startCtx and dialerCtx together
		// so dialerCtx will be cancelled if startCtx is cancelled.
		// We run detatchContexts after startTunnel to disconnect them.
		detatchContexts := context.AfterFunc(startCtx, func() {
			dialerCancel()
		})

		tunnelDone := make(chan struct{})
		defer close(tunnelDone)
		d.stop = func() {
			// Tell start to stop.
			dialerCancel()
			// Wait for tunnel to be done.
			<-tunnelDone
		}
		defer func() {
			// Cleanup.
			d.stop = nil
		}()

		d.mu.Unlock()
		tunnel, err := startTunnel(dialerCtx, config)

		d.mu.Lock()
		detatchContexts()

		if dialerCtx.Err() != nil {
			err = context.Cause(dialerCtx)
		}
		if err != nil {
			resultCh <- err
			return
		}
		d.tunnel = tunnel
		defer func() {
			d.tunnel = nil
			tunnel.Stop()
		}()
		resultCh <- nil

		d.mu.Unlock()
		// wait for Stop
		<-dialerCtx.Done()
		d.mu.Lock()
	}()
	return <-resultCh
}

// Stop stops the Dialer background processes, releasing resources and allowing it to be reconfigured.
// It returns when the Dialer is completely stopped.
func (d *Dialer) Stop() error {
	d.mu.Lock()
	stop := d.stop
	d.mu.Unlock()

	if stop == nil {
		return errNotStartedStop
	}
	stop()
	return nil
}

// GetSingletonDialer returns the single Psiphon dialer instance.
func GetSingletonDialer() *Dialer {
	return &singletonDialer
}

// streamConn wraps a [net.Conn] to provide a [transport.StreamConn] interface.
type streamConn struct {
	net.Conn
}

var _ transport.StreamConn = (*streamConn)(nil)

func (c streamConn) CloseWrite() error {
	return nil
}

func (c streamConn) CloseRead() error {
	return nil
}
