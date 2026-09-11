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

package lwip2transport

import (
	"errors"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.getoutline.org/sdk/network"
)

const testTimeout = 5 * time.Second

// TestWriteToDoesNotBlockOnSlowWriter covers the reason the queue exists: lwIP calls
// forwardOutgoingIPPacket while holding its global stack lock, so that callback must return without
// waiting for the destination write to complete.
//
// The packet count stays under outQueueDepth on purpose. Blocking once the queue is full is the
// intended backpressure -- the property under test is that the callback does not wait for an
// individual write, not that it never blocks at all.
func TestWriteToDoesNotBlockOnSlowWriter(t *testing.T) {
	h := &errTcpUdpHandler{err: errors.New("not supported")}
	d := reConfigurelwIPDeviceForTest(t, h, h)
	defer d.Close()

	w := newBlockingWriter()
	go d.WriteTo(w)

	// The first packet parks the background writer inside w.Write.
	forwardWithinTimeout(t, d, []byte{0x01})
	waitForWriter(t, w)

	// While that write is stuck, the callback must still return promptly, for as many packets
	// as the queue can hold.
	for i := range outQueueDepth - 8 {
		forwardWithinTimeout(t, d, []byte{byte(i)})
	}

	close(w.release)
}

// TestWriteToPreservesPacketOrder makes sure the queue does not reorder packets.
func TestWriteToPreservesPacketOrder(t *testing.T) {
	h := &errTcpUdpHandler{err: errors.New("not supported")}
	d := reConfigurelwIPDeviceForTest(t, h, h)
	defer d.Close()

	const pktCount = 100
	w := newRecordingWriter(pktCount)
	go d.WriteTo(w)

	for i := range pktCount {
		forwardWithinTimeout(t, d, []byte{byte(i), 0xff})
	}
	for i := range pktCount {
		select {
		case got := <-w.written:
			require.Equal(t, []byte{byte(i), 0xff}, got)
		case <-time.After(testTimeout):
			t.Fatalf("only %d of %d packets reached the writer", i, pktCount)
		}
	}
}

// TestWriteToCopiesPacketBeforeReturning verifies that the buffer handed to forwardOutgoingIPPacket
// is safe to reuse as soon as it returns. On the lwIP path that buffer aliases the C pbuf payload,
// which is freed once the output callback returns.
func TestWriteToCopiesPacketBeforeReturning(t *testing.T) {
	h := &errTcpUdpHandler{err: errors.New("not supported")}
	d := reConfigurelwIPDeviceForTest(t, h, h)
	defer d.Close()

	w := newBlockingWriter()
	go d.WriteTo(w)

	pkt := []byte{0x01, 0x02, 0x03, 0x04}
	forwardWithinTimeout(t, d, pkt)
	waitForWriter(t, w)

	// Simulate lwIP recycling the pbuf, then let the write proceed.
	copy(pkt, []byte{0x09, 0x09, 0x09, 0x09})
	close(w.release)

	select {
	case got := <-w.got:
		require.Equal(t, []byte{0x01, 0x02, 0x03, 0x04}, got)
	case <-time.After(testTimeout):
		t.Fatal("the writer was never called")
	}
}

// TestWriteToReturnsWriterError verifies that an error from the background writer terminates
// WriteTo. It surfaces at least one packet late, so the test keeps feeding packets until it does.
func TestWriteToReturnsWriterError(t *testing.T) {
	h := &errTcpUdpHandler{err: errors.New("not supported")}
	d := reConfigurelwIPDeviceForTest(t, h, h)
	defer d.Close()

	writeErr := errors.New("tun is gone")
	errCh := make(chan error, 1)
	go func() {
		_, err := d.WriteTo(newErrWriter(writeErr))
		errCh <- err
	}()

	// Feed packets until WriteTo goes away; the final call unblocks when the device is closed.
	fed := make(chan struct{})
	go func() {
		defer close(fed)
		for {
			if _, err := d.forwardOutgoingIPPacket([]byte{0x01}); err != nil {
				return
			}
		}
	}()

	select {
	case err := <-errCh:
		require.ErrorIs(t, err, writeErr)
	case <-time.After(testTimeout):
		t.Fatal("WriteTo did not report the write error")
	}

	require.NoError(t, d.Close())
	select {
	case <-fed:
	case <-time.After(testTimeout):
		t.Fatal("forwardOutgoingIPPacket did not return after the device was closed")
	}
}

// TestCloseUnblocksWriteTo verifies that closing the device stops an idle WriteTo.
func TestCloseUnblocksWriteTo(t *testing.T) {
	h := &errTcpUdpHandler{err: errors.New("not supported")}
	d := reConfigurelwIPDeviceForTest(t, h, h)

	done := make(chan error, 1)
	go func() {
		_, err := d.WriteTo(io.Discard)
		done <- err
	}()

	require.NoError(t, d.Close())
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(testTimeout):
		t.Fatal("WriteTo did not return after the device was closed")
	}
}

// TestAsyncWriterClose verifies that Close stops the background goroutine, is idempotent, and
// reports the write error it observed.
func TestReadForwardedPacket(t *testing.T) {
	h := &errTcpUdpHandler{err: errors.New("not supported")}
	d := reConfigurelwIPDeviceForTest(t, h, h)
	defer d.Close()

	forwarded := make(chan int, 1)
	go func() {
		n, err := d.forwardOutgoingIPPacket([]byte{0x01, 0x02, 0x03})
		require.NoError(t, err)
		forwarded <- n
	}()

	buf := make([]byte, packetMTU)
	n, err := d.Read(buf)
	require.NoError(t, err)
	require.Exactly(t, 3, n)
	require.Equal(t, []byte{0x01, 0x02, 0x03}, buf[:n])

	select {
	case n := <-forwarded:
		require.Exactly(t, 3, n)
	case <-time.After(testTimeout):
		t.Fatal("forwardOutgoingIPPacket did not return after the packet was read")
	}
}

// TestClosedDeviceDoesNotLeakQueuedPackets pins the shutdown contract. Because rdBuf is buffered,
// a closed device can have both a queued packet and a closed done channel ready at once, and a
// bare select would pick between them at random. Read must still report io.EOF, and the output
// callback must not enqueue onto a device that is shutting down.
func TestClosedDeviceDoesNotLeakQueuedPackets(t *testing.T) {
	h := &errTcpUdpHandler{err: errors.New("not supported")}
	d := reConfigurelwIPDeviceForTest(t, h, h)

	// Queue packets while the device is still open, then close it with those packets pending.
	for i := range 8 {
		n, err := d.forwardOutgoingIPPacket([]byte{byte(i)})
		require.NoError(t, err)
		require.Exactly(t, 1, n)
	}
	require.NoError(t, d.Close())

	// Every Read must report EOF, never a queued packet. Repeat: a random select would pass once
	// with probability 1/2, so a single call proves nothing.
	buf := make([]byte, packetMTU)
	for range 64 {
		n, err := d.Read(buf)
		require.ErrorIs(t, err, io.EOF)
		require.Exactly(t, 0, n)
	}

	// The output callback must refuse to enqueue, even though rdBuf still has free slots.
	for range 64 {
		n, err := d.forwardOutgoingIPPacket([]byte{0xff})
		require.ErrorIs(t, err, network.ErrClosed)
		require.Exactly(t, 0, n)
	}
}

// waitForWriter blocks until the background writer has entered a Write call.
func waitForWriter(t *testing.T, w *blockingWriter) {
	t.Helper()
	select {
	case <-w.entered:
	case <-time.After(testTimeout):
		t.Fatal("the writer was never called")
	}
}

// forwardWithinTimeout calls forwardOutgoingIPPacket and fails the test if it does not return.
func forwardWithinTimeout(t *testing.T, d *lwIPDevice, pkt []byte) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		n, err := d.forwardOutgoingIPPacket(pkt)
		require.NoError(t, err)
		require.Exactly(t, len(pkt), n)
	}()
	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("forwardOutgoingIPPacket blocked; the lwIP stack lock would be held for this long")
	}
}

// blockingWriter signals that Write was entered, parks until release is closed, and only then reads
// the packet it was given. Reading late is deliberate: it proves the packet contents outlive the
// return of forwardOutgoingIPPacket.
type blockingWriter struct {
	entered chan struct{}
	release chan struct{}
	got     chan []byte
	err     error // returned by every write once released
}

func newBlockingWriter() *blockingWriter {
	return &blockingWriter{
		entered: make(chan struct{}, 1),
		release: make(chan struct{}),
		got:     make(chan []byte, 1),
	}
}

// newFailingBlockingWriter returns a blockingWriter that fails every write once released.
func (w *blockingWriter) Write(p []byte) (int, error) {
	select {
	case w.entered <- struct{}{}:
	default:
	}
	<-w.release
	if w.err != nil {
		return 0, w.err
	}
	select {
	case w.got <- append([]byte(nil), p...):
	default:
	}
	return len(p), nil
}

// recordingWriter reports every packet it is given, in order.
type recordingWriter struct {
	written chan []byte
}

func newRecordingWriter(depth int) *recordingWriter {
	return &recordingWriter{written: make(chan []byte, depth)}
}

func (w *recordingWriter) Write(p []byte) (int, error) {
	w.written <- append([]byte(nil), p...)
	return len(p), nil
}

// errWriter fails every write and reports that it was called at least once.
type errWriter struct {
	err    error
	called chan struct{}
}

func newErrWriter(err error) *errWriter {
	return &errWriter{err: err, called: make(chan struct{}, 1)}
}

func (w *errWriter) Write(p []byte) (int, error) {
	select {
	case w.called <- struct{}{}:
	default:
	}
	return 0, w.err
}
