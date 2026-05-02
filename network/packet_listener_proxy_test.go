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

package network

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"golang.getoutline.org/sdk/transport"
	"github.com/stretchr/testify/require"
)

func TestWithWriteTimeoutOptionWorks(t *testing.T) {
	pl := &transport.UDPListener{}

	defProxy, err := NewPacketProxyFromPacketListener(pl)
	require.NoError(t, err)
	require.NotNil(t, defProxy)
	require.Equal(t, 30*time.Second, defProxy.writeIdleTimeout) // default timeout is 30s

	altProxy, err := NewPacketProxyFromPacketListener(pl, WithPacketListenerWriteIdleTimeout(5*time.Minute))
	require.NoError(t, err)
	require.NotNil(t, altProxy)
	require.Equal(t, 5*time.Minute, altProxy.writeIdleTimeout)
}

// --- Mock Helpers ---

type mockPacketConn struct {
	mu            sync.Mutex
	readErr       error
	readCh        chan []byte // Sends data to ReadFrom
	writeErr      error
	closed        bool
	closeCh       chan struct{}
	readDeadline  time.Time
	writeDeadline time.Time
}

func newMockPacketConn() *mockPacketConn {
	return &mockPacketConn{
		readCh:  make(chan []byte, 10),
		closeCh: make(chan struct{}),
	}
}

func (m *mockPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return 0, nil, io.EOF
	}
	if m.readErr != nil {
		err := m.readErr
		m.readErr = nil // Clear after one use for targeted error injection
		m.mu.Unlock()
		return 0, nil, err
	}
	m.mu.Unlock()

	select {
	case data, ok := <-m.readCh:
		if !ok {
			return 0, nil, io.EOF
		}
		n := copy(b, data)
		return n, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}, nil
	case <-m.closeCh:
		return 0, nil, io.EOF
	}
}

func (m *mockPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, io.ErrClosedPipe
	}
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	return len(b), nil
}

func (m *mockPacketConn) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return io.ErrClosedPipe
	}
	m.closed = true
	close(m.closeCh)
	m.mu.Unlock()
	return nil
}

func (m *mockPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
}

func (m *mockPacketConn) SetDeadline(t time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.readDeadline = t
	m.writeDeadline = t
	return nil
}

func (m *mockPacketConn) SetReadDeadline(t time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.readDeadline = t
	return nil
}

func (m *mockPacketConn) SetWriteDeadline(t time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writeDeadline = t
	return nil
}

func (m *mockPacketConn) isClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

type mockPacketListener struct {
	mu          sync.Mutex
	conn        net.PacketConn
	listenErr   error
	listenDelay time.Duration
	listenCount int
}

func (m *mockPacketListener) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	m.mu.Lock()
	m.listenCount++
	delay := m.listenDelay
	err := m.listenErr
	conn := m.conn
	m.mu.Unlock()

	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	if err != nil {
		return nil, err
	}

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	return conn, nil
}

func (m *mockPacketListener) getListenCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.listenCount
}

type mockResponseReceiver struct {
	writeFromCh chan []byte
	closeCh     chan struct{}
}

func newMockResponseReceiver() *mockResponseReceiver {
	return &mockResponseReceiver{
		writeFromCh: make(chan []byte, 10),
		closeCh:     make(chan struct{}),
	}
}

func (m *mockResponseReceiver) WriteFrom(p []byte, source net.Addr) (int, error) {
	m.writeFromCh <- append([]byte(nil), p...)
	return len(p), nil
}

func (m *mockResponseReceiver) Close() error {
	close(m.closeCh)
	return nil
}

// --- Tests ---

func TestStateTransitions(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// 1. NewSession -> Uninitialized
		mockConn := newMockPacketConn()
		mockListener := &mockPacketListener{conn: mockConn}
		proxy, err := NewPacketProxyFromPacketListener(mockListener)
		require.NoError(t, err)

		receiver := newMockResponseReceiver()
		sender, err := proxy.NewSession(receiver)
		require.NoError(t, err)
		require.NotNil(t, sender)
		defer sender.Close()
		require.Equal(t, 0, mockListener.getListenCount()) // Still Uninitialized

		// 2. Uninitialized -> Active (First successful WriteTo)
		_, err = sender.WriteTo([]byte("hello"), netip.MustParseAddrPort("127.0.0.1:1234"))
		require.NoError(t, err)
		require.Equal(t, 1, mockListener.getListenCount()) // Now Active

		// 3. Active -> Active (Subsequent WriteTo)
		_, err = sender.WriteTo([]byte("world"), netip.MustParseAddrPort("127.0.0.1:1234"))
		require.NoError(t, err)
		require.Equal(t, 1, mockListener.getListenCount()) // Still 1

		// 4. Active -> Closed (via Close)
		err = sender.Close()
		require.NoError(t, err)
		require.True(t, mockConn.isClosed())

		// 5. Closed -> Closed (WriteTo returns ErrClosed)
		_, err = sender.WriteTo([]byte("dead"), netip.MustParseAddrPort("127.0.0.1:1234"))
		require.ErrorIs(t, err, ErrClosed)
	})
}

func TestUninitializedRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockConn := newMockPacketConn()
		mockListener := &mockPacketListener{
			conn:      mockConn,
			listenErr: errors.New("temporary network error"),
		}
		proxy, err := NewPacketProxyFromPacketListener(mockListener)
		require.NoError(t, err)

		receiver := newMockResponseReceiver()
		sender, err := proxy.NewSession(receiver)
		require.NoError(t, err)
		defer sender.Close()

		// WriteTo fails because ListenPacket fails
		_, err = sender.WriteTo([]byte("hello"), netip.MustParseAddrPort("127.0.0.1:1234"))
		require.Error(t, err)
		require.Equal(t, 1, mockListener.getListenCount())

		// Fix the error in the mock
		mockListener.mu.Lock()
		mockListener.listenErr = nil
		mockListener.mu.Unlock()

		// Retry WriteTo -> Should SUCCEED!
		_, err = sender.WriteTo([]byte("hello again"), netip.MustParseAddrPort("127.0.0.1:1234"))
		require.NoError(t, err)
		require.Equal(t, 2, mockListener.getListenCount())
	})
}

func TestUninitializedClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockListener := &mockPacketListener{}
		receiver := newMockResponseReceiver()
		proxy, err := NewPacketProxyFromPacketListener(mockListener)
		require.NoError(t, err)

		sender, err := proxy.NewSession(receiver)
		require.NoError(t, err)
		defer sender.Close()

		// Close without ever writing
		err = sender.Close()
		require.NoError(t, err)

		// Verify ListenPacket was NEVER called
		require.Equal(t, 0, mockListener.getListenCount())

		// Verify receiver was closed
		select {
		case <-receiver.closeCh:
			// Success
		case <-time.After(1 * time.Second):
			t.Fatal("Receiver should have been closed")
		}
	})
}

func TestIdleTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockConn := newMockPacketConn()
		mockListener := &mockPacketListener{conn: mockConn}
		// Set a short timeout for testing
		proxy, err := NewPacketProxyFromPacketListener(mockListener, WithPacketListenerWriteIdleTimeout(100*time.Millisecond))
		require.NoError(t, err)

		receiver := newMockResponseReceiver()
		sender, err := proxy.NewSession(receiver)
		require.NoError(t, err)
		defer sender.Close()

		// 1. Timeout in Uninitialized state
		// Wait for 150ms (virtual time!)
		time.Sleep(150 * time.Millisecond)

		// Session should be closed
		_, err = sender.WriteTo([]byte("too late"), netip.MustParseAddrPort("127.0.0.1:1234"))
		require.ErrorIs(t, err, ErrClosed)
		require.Equal(t, 0, mockListener.getListenCount()) // Never initialized

		// 2. Timeout in Active state
		receiver2 := newMockResponseReceiver()
		sender2, err := proxy.NewSession(receiver2)
		require.NoError(t, err)
		defer sender2.Close()

		// Make it Active
		_, err = sender2.WriteTo([]byte("hello"), netip.MustParseAddrPort("127.0.0.1:1234"))
		require.NoError(t, err)

		// Wait for 50ms (timer is at 50ms/100ms)
		time.Sleep(50 * time.Millisecond)

		// Write again -> Resets timer to 100ms!
		_, err = sender2.WriteTo([]byte("keepalive"), netip.MustParseAddrPort("127.0.0.1:1234"))
		require.NoError(t, err)

		// Wait for 70ms (timer at 70ms/100ms)
		time.Sleep(70 * time.Millisecond)
		// Still active!
		_, err = sender2.WriteTo([]byte("still here"), netip.MustParseAddrPort("127.0.0.1:1234"))
		require.NoError(t, err)

		// Wait for 150ms -> Should time out!
		time.Sleep(150 * time.Millisecond)

		_, err = sender2.WriteTo([]byte("too late"), netip.MustParseAddrPort("127.0.0.1:1234"))
		require.ErrorIs(t, err, ErrClosed)
	})
}

func TestListenPacketTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Mock listener that takes 1 second to return
		mockListener := &mockPacketListener{
			listenDelay: 1 * time.Second,
		}
		// Set timeout to 100ms
		proxy, err := NewPacketProxyFromPacketListener(mockListener, WithPacketListenerWriteIdleTimeout(100*time.Millisecond))
		require.NoError(t, err)

		receiver := newMockResponseReceiver()
		sender, err := proxy.NewSession(receiver)
		require.NoError(t, err)
		defer sender.Close()

		// WriteTo should fail with context deadline exceeded
		_, err = sender.WriteTo([]byte("hello"), netip.MustParseAddrPort("127.0.0.1:1234"))
		require.Error(t, err)
		require.True(t, errors.Is(err, context.DeadlineExceeded))
	})
}

func TestConcurrency(t *testing.T) {
	// Run multiple concurrent WriteTo calls
	mockConn := newMockPacketConn()
	mockListener := &mockPacketListener{conn: mockConn}
	proxy, err := NewPacketProxyFromPacketListener(mockListener)
	require.NoError(t, err)

	receiver := newMockResponseReceiver()
	sender, err := proxy.NewSession(receiver)
	require.NoError(t, err)
	defer sender.Close()

	// Use a number of concurrent writes large enough to exercise concurrency
	// and trigger potential data races, but small enough to keep the test fast.
	const concurrentWrites = 50

	var wg sync.WaitGroup
	errCh := make(chan error, concurrentWrites)
	for i := 0; i < concurrentWrites; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := sender.WriteTo([]byte("data"), netip.MustParseAddrPort("127.0.0.1:1234"))
			if err != nil {
				errCh <- err
			}
		}()
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		require.NoError(t, err)
	}

	// Verify ListenPacket called EXACTLY ONCE
	require.Equal(t, 1, mockListener.getListenCount())
}

func TestRecoverableErrors(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockConn := newMockPacketConn()
		mockListener := &mockPacketListener{conn: mockConn}
		proxy, err := NewPacketProxyFromPacketListener(mockListener)
		require.NoError(t, err)

		receiver := newMockResponseReceiver()
		sender, err := proxy.NewSession(receiver)
		require.NoError(t, err)
		defer sender.Close()

		// Initialize
		_, err = sender.WriteTo([]byte("hello"), netip.MustParseAddrPort("127.0.0.1:1234"))
		require.NoError(t, err)

		// Inject ErrShortBuffer into ReadFrom
		mockConn.mu.Lock()
		mockConn.readErr = io.ErrShortBuffer
		mockConn.mu.Unlock()

		// Wait for goroutine to process the error
		synctest.Wait()

		// Verify receiver was NOT closed (ErrShortBuffer is recoverable)
		select {
		case <-receiver.closeCh:
			t.Fatal("Receiver should NOT be closed on ErrShortBuffer")
		default:
			// Success
		}

		// Send valid data
		mockConn.readCh <- []byte("valid response")

		// Verify receiver gets the valid data
		select {
		case data := <-receiver.writeFromCh:
			require.Equal(t, []byte("valid response"), data)
		case <-time.After(1 * time.Second):
			t.Fatal("Receiver should have received valid data")
		}
	})
}
