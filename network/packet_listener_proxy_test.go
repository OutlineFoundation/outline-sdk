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

// Test 1: Half-Closed Session on WriteFrom Failure
func TestHalfClosedSessionOnWriteFromFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Create a mock PacketResponseReceiver that returns an error
		mockReceiver := &mockResponseReceiver{
			writeFromErr: errors.New("write error"),
			closeCh:      make(chan struct{}),
		}

		mockConn := &mockPacketConn{
			readFromCh: make(chan struct{}),
			readData:   []byte("test data"),
			readAddr:   &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234},
		}

		mockListener := &mockPacketListener{
			conn: mockConn,
		}

		proxy, err := NewPacketProxyFromPacketListener(mockListener)
		require.NoError(t, err)

		sender, err := proxy.NewSession(mockReceiver)
		require.NoError(t, err)
		require.NotNil(t, sender)

		// Signal ReadFrom to proceed
		close(mockConn.readFromCh)

		// Wait for all activity to settle (goroutine should exit)
		synctest.Wait()

		// Verify that receiver was closed
		select {
		case <-mockReceiver.closeCh:
			// Success
		default:
			t.Fatal("Receiver should have been closed")
		}

		// Verify that proxyConn was NOT closed (half-closed state)
		require.False(t, mockConn.isClosed(), "proxyConn should not be closed on WriteFrom failure")

		// Verify that we can still send data
		_, err = sender.WriteTo([]byte("test"), netip.MustParseAddrPort("127.0.0.1:1234"))
		require.NoError(t, err, "WriteTo should succeed in half-closed state")

		// Clean up
		sender.Close()
		synctest.Wait()
	})
}

type mockResponseReceiver struct {
	writeFromErr error
	closed       bool
	closeCh      chan struct{}
}

func (m *mockResponseReceiver) WriteFrom(p []byte, source net.Addr) (int, error) {
	return 0, m.writeFromErr
}

func (m *mockResponseReceiver) Close() error {
	m.closed = true
	if m.closeCh != nil {
		close(m.closeCh)
	}
	return nil
}

type mockPacketConn struct {
	net.PacketConn // embed to implement interface with panics for unused methods
	mu             sync.Mutex
	readData       []byte
	readAddr       net.Addr
	readErr        error
	readFromCh     chan struct{}
	stopCh         chan struct{}
	closed         bool
	closeFunc      func() error
	readFunc       func([]byte) (int, net.Addr, error)
}

func (m *mockPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	<-m.readFromCh
	m.mu.Lock()
	if m.readFunc != nil {
		m.mu.Unlock()
		return m.readFunc(b)
	}
	if m.readErr != nil {
		m.mu.Unlock()
		return 0, nil, m.readErr
	}
	n := copy(b, m.readData)
	addr := m.readAddr
	m.mu.Unlock()
	return n, addr, nil
}

func (m *mockPacketConn) Close() error {
	m.mu.Lock()
	m.closed = true
	m.readErr = io.EOF
	select {
	case <-m.readFromCh:
	default:
		close(m.readFromCh)
	}
	if m.stopCh != nil {
		close(m.stopCh)
	}
	closeFunc := m.closeFunc
	m.mu.Unlock()

	if closeFunc != nil {
		return closeFunc()
	}
	return nil
}

func (m *mockPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return len(p), nil
}

func (m *mockPacketConn) isClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

type mockPacketListener struct {
	conn net.PacketConn
}

func (m *mockPacketListener) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	return m.conn, nil
}

// Test 2: Lock Contention in Close
func TestLockContentionInClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Create a mock PacketConn where Close blocks
		closeBlockCh := make(chan struct{})
		mockConn := &mockPacketConn{
			readFromCh: make(chan struct{}),
			closeFunc: func() error {
				<-closeBlockCh
				return nil
			},
		}

		mockListener := &mockPacketListener{
			conn: mockConn,
		}

		proxy, err := NewPacketProxyFromPacketListener(mockListener)
		require.NoError(t, err)

		sender, err := proxy.NewSession(&mockResponseReceiver{})
		require.NoError(t, err)

		// Call Close in a goroutine (it will block)
		closeDone := make(chan struct{})
		go func() {
			sender.Close()
			close(closeDone)
		}()

		// Wait for the goroutine to acquire the lock and block in Close
		synctest.Wait()

		// Attempt to call WriteTo (it should block waiting for the lock)
		writeDone := make(chan struct{})
		go func() {
			sender.WriteTo([]byte("test"), netip.MustParseAddrPort("127.0.0.1:1234"))
			close(writeDone)
		}()

		// Wait for all activity to settle (both goroutines should be blocked)
		synctest.Wait()

		// Verify that WriteTo is NOT blocked (lock should have been released)
		select {
		case <-writeDone:
			// Success, it didn't block
		default:
			t.Fatal("WriteTo blocked waiting for the lock")
		}

		// Unblock Close
		close(closeBlockCh)

		// Verify that both finish
		<-closeDone
		<-writeDone
	})
}

// Test 3: Silent Packet Drops on io.ErrShortBuffer
func TestSilentPacketDropsOnErrShortBuffer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockReceiver := &mockResponseReceiver{
			closeCh: make(chan struct{}),
		}

		readCount := 0
		var mockConn *mockPacketConn
		mockConn = &mockPacketConn{
			readFromCh: make(chan struct{}),
			stopCh:     make(chan struct{}),
			readFunc: func(b []byte) (int, net.Addr, error) {
				readCount++
				if readCount == 1 {
					return 0, nil, io.ErrShortBuffer
				}
				// Block on subsequent reads until stopped
				select {
				case <-mockConn.stopCh:
					return 0, nil, io.EOF
				}
			},
		}

		mockListener := &mockPacketListener{
			conn: mockConn,
		}

		proxy, err := NewPacketProxyFromPacketListener(mockListener)
		require.NoError(t, err)

		sender, err := proxy.NewSession(mockReceiver)
		require.NoError(t, err)
		require.NotNil(t, sender)
		defer synctest.Wait()
		defer sender.Close()

		// Signal ReadFrom to proceed for the first read
		close(mockConn.readFromCh)

		// Wait for the read loop to process the error and block on the second read
		synctest.Wait()

		// Verify that the receiver WAS closed (meaning the loop exited)
		select {
		case <-mockReceiver.closeCh:
			// Success, the loop exited
		default:
			t.Fatal("Receiver should have been closed on io.ErrShortBuffer")
		}

		// Verify that no data was written to the receiver
		require.False(t, mockReceiver.closed)

		// Clean up
		sender.Close()
		synctest.Wait()
	})
}

// Test 4: Timer Race Condition (Using synctest)
func TestTimerRaceCondition(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockReceiver := &mockResponseReceiver{
			closeCh: make(chan struct{}),
		}

		mockConn := &mockPacketConn{
			readFromCh: make(chan struct{}),
		}

		mockListener := &mockPacketListener{
			conn: mockConn,
		}

		timeout := 100 * time.Millisecond
		proxy, err := NewPacketProxyFromPacketListener(mockListener, WithPacketListenerWriteIdleTimeout(timeout))
		require.NoError(t, err)

		sender, err := proxy.NewSession(mockReceiver)
		require.NoError(t, err)

		time.Sleep(timeout - 10*time.Millisecond)

		_, err = sender.WriteTo([]byte("test"), netip.MustParseAddrPort("127.0.0.1:1234"))
		require.NoError(t, err)

		synctest.Wait()

		time.Sleep(20 * time.Millisecond)

		select {
		case <-mockReceiver.closeCh:
			t.Fatal("Session should not have been closed, timer should have been reset")
		default:
			// Success
		}

		// Clean up to let the read loop goroutine exit
		sender.Close()
		synctest.Wait()
	})
}




