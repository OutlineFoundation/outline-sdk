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

//go:build psiphon

package psiphon

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/ClientLibrary/clientlib"
	"github.com/stretchr/testify/require"
)

func newTestConfig(tb testing.TB) (*DialerConfig, func()) {
	tempDir, err := os.MkdirTemp("", "psiphon")
	require.NoError(tb, err)
	return &DialerConfig{
		DataRootDirectory: tempDir,
		ProviderConfig: json.RawMessage(`{
			"PropagationChannelId": "ID1",
			"SponsorId": "ID2"
		}`),
	}, func() { os.RemoveAll(tempDir) }
}

func TestDialer_Start_Successful(t *testing.T) {
	dialer := GetSingletonDialer()
	startTunnel = func(ctx context.Context, config *DialerConfig) (psiphonTunnel, error) {
		return &clientlib.PsiphonTunnel{}, nil
	}
	defer func() {
		startTunnel = psiphonStartTunnel
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, dialer.Start(ctx, nil))
	require.NotNil(t, dialer.tunnel)
	require.NoError(t, dialer.Start(ctx, nil))
	require.NoError(t, dialer.Stop())
	require.Nil(t, dialer.tunnel)
	require.ErrorIs(t, dialer.Stop(), errNotStartedStop)
	require.NoError(t, dialer.Start(ctx, nil))
	require.NoError(t, dialer.Stop())
}

func TestDialer_StopOnStart(t *testing.T) {
	dialer := GetSingletonDialer()
	startCalled := make(chan struct{})
	startTunnel = func(ctx context.Context, config *DialerConfig) (psiphonTunnel, error) {
		startCalled <- struct{}{}
		<-ctx.Done()
		return nil, context.Cause(ctx)
	}
	defer func() {
		startTunnel = psiphonStartTunnel
	}()

	resultCh := make(chan error)
	go func() {
		resultCh <- dialer.Start(context.Background(), nil)
	}()
	<-startCalled
	require.NoError(t, dialer.Stop())
	require.Error(t, <-resultCh)
}

func TestDialer_StartOnStart(t *testing.T) {
	dialer := GetSingletonDialer()
	startCalled := make(chan struct{})
	startTunnel = func(ctx context.Context, config *DialerConfig) (psiphonTunnel, error) {
		startCalled <- struct{}{}
		<-ctx.Done()
		return nil, context.Cause(ctx)
	}
	defer func() {
		startTunnel = psiphonStartTunnel
	}()

	resultCh := make(chan error)
	go func() {
		resultCh <- dialer.Start(context.Background(), nil)
	}()
	<-startCalled
	startTunnel = func(ctx context.Context, config *DialerConfig) (psiphonTunnel, error) {
		return &errorTunnel{}, nil
	}
	require.NoError(t, dialer.Start(context.Background(), nil))
	require.NoError(t, dialer.Stop())
	require.Error(t, <-resultCh)
}

func TestDialer_Start_NilConfig(t *testing.T) {
	require.Error(t, GetSingletonDialer().Start(context.Background(), nil))
}

func TestDialer_Start_Cancelled(t *testing.T) {
	cfg, delete := newTestConfig(t)
	defer delete()
	errCh := make(chan error)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		errCh <- GetSingletonDialer().Start(ctx, cfg)
	}()
	cancel()
	err := <-errCh
	require.ErrorIs(t, err, context.Canceled)
}

func TestDialer_Start_Timeout(t *testing.T) {
	cfg, delete := newTestConfig(t)
	defer delete()
	errCh := make(chan error)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now())
	defer cancel()
	go func() {
		errCh <- GetSingletonDialer().Start(ctx, cfg)
	}()
	err := <-errCh
	require.ErrorIs(t, err, context.Canceled)
}

type errorTunnel struct {
	err     error
	stopped bool
}

func (t *errorTunnel) Dial(addr string) (net.Conn, error) {
	return nil, t.err
}

func (t *errorTunnel) Stop() {
	t.stopped = true
}

func TestDialer_DialStream(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dialer := GetSingletonDialer()

	// Dial before Start.
	_, err := dialer.DialStream(ctx, "")
	require.ErrorIs(t, err, errNotStartedDial)

	var tunnel errorTunnel
	startTunnel = func(ctx context.Context, config *DialerConfig) (psiphonTunnel, error) {
		tunnel.stopped = false
		return &tunnel, nil
	}
	defer func() {
		startTunnel = psiphonStartTunnel
	}()
	// Make sure it works on restarts.
	for i := 0; i < 2; i++ {
		// Dial after Start.
		require.NoError(t, dialer.Start(ctx, nil))
		require.False(t, tunnel.stopped)
		conn, err := dialer.DialStream(ctx, "")
		require.NoError(t, err)
		require.NoError(t, conn.CloseRead())
		require.NoError(t, conn.CloseWrite())

		// Dial after Stop.
		require.NoError(t, dialer.Stop())
		require.True(t, tunnel.stopped)
		_, err = dialer.DialStream(context.TODO(), "")
		require.ErrorIs(t, err, errNotStartedDial)
	}
}

func TestDialer_DialStream_Error(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dialer := GetSingletonDialer()
	tunnel := errorTunnel{
		err: errors.New("failed to dial"),
	}
	startTunnel = func(ctx context.Context, config *DialerConfig) (psiphonTunnel, error) {
		tunnel.stopped = false
		return &tunnel, nil
	}
	defer func() {
		startTunnel = psiphonStartTunnel
	}()
	require.NoError(t, dialer.Start(ctx, nil))
	require.False(t, tunnel.stopped)
	_, err := dialer.DialStream(ctx, "")
	require.Equal(t, tunnel.err, err)
	require.NoError(t, dialer.Stop())
}

func TestDialer_Stop_NotStarted(t *testing.T) {
	err := GetSingletonDialer().Stop()
	require.ErrorIs(t, err, errNotStartedStop)
}
