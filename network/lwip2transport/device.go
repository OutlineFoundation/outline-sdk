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

package lwip2transport

import (
	"errors"
	"io"
	"sync"

	lwip "github.com/eycorsican/go-tun2socks/core"
	"golang.getoutline.org/sdk/network"
	"golang.getoutline.org/sdk/network/packetrelay"
	"golang.getoutline.org/sdk/transport"
)

const packetMTU = 1500

// outQueueDepth bounds the queue of outgoing packets waiting for the consumer. At packetBufCap per
// slot this caps queue memory at ~512 KiB. Once it is full forwardOutgoingIPPacket blocks, which is
// genuine backpressure: the consumer is truly slower than lwIP is producing.
const outQueueDepth = 256

// packetBufCap is the capacity of a pooled packet buffer. It is larger than packetMTU so a
// full-MTU packet never forces the copy in forwardOutgoingIPPacket to reallocate.
const packetBufCap = 2048

// Compilation guard against interface implementation
var _ network.IPDevice = (*lwIPDevice)(nil)

type lwIPDevice struct {
	tcp   *tcpHandler
	udp   lwip.UDPConnHandler
	stack lwip.LWIPStack

	// whether the device has been closed
	done chan struct{}

	// Outgoing IP packets, already copied out of the lwIP pbuf and owned by whoever receives
	// them. Buffered so forwardOutgoingIPPacket does not block; see the comment there.
	rdBuf chan []byte

	// pktPool recycles those copies.
	pktPool sync.Pool
}

// Singleton instance
var instMu sync.Mutex
var inst *lwIPDevice = nil

// ConfigureDevice configures the singleton LwIP device using the [transport.StreamDialer] to handle TCP streams and
// the [transport.PacketProxy] to handle UDP packets.
//
// LwIP device is a [network.IPDevice] that can translate IP packets to TCP/UDP traffic and vice versa. It uses the
// [lwIP library] to perform the translation.
//
// LwIP device must be a singleton object due to limitations in [lwIP library]. If you try to call ConfigureDevice more
// than once, we will Close the previous device and reconfigure it.
//
// To use a LwIP device:
//  1. Call [ConfigureDevice] with two handlers for TCP and UDP traffic.
//  2. Write IP packets to the device. The device will translate the IP packets to TCP/UDP traffic and send them to the
//     appropriate handlers.
//  3. Read IP packets from the device to get the TCP/UDP responses.
//
// A LwIP device is NOT thread-safe. However it is safe to use Write, Read/WriteTo and Close in different goroutines.
// Keep in mind that only one goroutine can call Write at a time, and only one goroutine can use either Read or
// WriteTo at a time.
//
// Deprecated: Use [ConfigureDeviceWithRelay] instead.
//
// [lwIP library]: https://savannah.nongnu.org/projects/lwip/
func ConfigureDevice(sd transport.StreamDialer, pp network.PacketProxy) (network.IPDevice, error) {
	if sd == nil || pp == nil {
		return nil, errors.New("both sd and pp are required")
	}

	instMu.Lock()
	defer instMu.Unlock()

	if inst != nil {
		inst.Close()
	}
	inst = &lwIPDevice{
		tcp:   newTCPHandler(sd),
		udp:   newUDPHandler(pp),
		stack: lwip.NewLWIPStack(),
		done:  make(chan struct{}),
		rdBuf: make(chan []byte, outQueueDepth),
	}
	lwip.RegisterTCPConnHandler(inst.tcp)
	lwip.RegisterUDPConnHandler(inst.udp)
	lwip.RegisterOutputFn(inst.forwardOutgoingIPPacket)

	return inst, nil
}

// ConfigureDeviceWithRelay configures the singleton LwIP device using the [transport.StreamDialer] to handle TCP streams and
// the [packetrelay.PacketRelay] to handle UDP packets.
//
// This is the modernized equivalent of [ConfigureDevice], allowing native adoption of the flow-based PacketRelay API.
func ConfigureDeviceWithRelay(sd transport.StreamDialer, pr packetrelay.PacketRelay) (network.IPDevice, error) {
	if sd == nil || pr == nil {
		return nil, errors.New("both sd and pr are required")
	}

	instMu.Lock()
	defer instMu.Unlock()

	if inst != nil {
		inst.Close()
	}
	inst = &lwIPDevice{
		tcp:   newTCPHandler(sd),
		udp:   newUDPRelayHandler(pr),
		stack: lwip.NewLWIPStack(),
		done:  make(chan struct{}),
		rdBuf: make(chan []byte, outQueueDepth),
	}
	lwip.RegisterTCPConnHandler(inst.tcp)
	lwip.RegisterUDPConnHandler(inst.udp)
	lwip.RegisterOutputFn(inst.forwardOutgoingIPPacket)

	return inst, nil
}

// Close implements [io.Closer] and [network.IPDevice]. It closes the device, rendering it unusable for I/O.
//
// Close does not close other objects that are passed to this device, such as the [transport.StreamDialer],
// [transport.PacketListener] or [io.Writer]. You are responsible for closing these objects yourself.
func (d *lwIPDevice) Close() error {
	// make sure we don't close the channel twice
	select {
	case <-d.done:
		return nil
	default:
		close(d.done)
		return d.stack.Close()
	}
}

// MTU implements [network.IPDevice]. It returns the maximum buffer size of a single IP packet that can be processed by
// this device.
func (d *lwIPDevice) MTU() int {
	return packetMTU
}

// forwardOutgoingIPPacket queues an IP packet response `b` for the consumer. The packet is then
// delivered by Read, or written to the destination if WriteTo has been called.
//
// forwardOutgoingIPPacket is registered as lwIP's output function, and lwIP calls it while holding
// its global stack lock. The inbound path needs that same lock for every packet handed to
// stack.Write, so this function must not block on the consumer: doing so serializes the whole
// stack behind the consumer's write and starves the reader.
//
// It therefore copies the packet and returns without waiting. The copy is not an optimization --
// `b` aliases the C pbuf payload (see go-tun2socks core/output_export.go), which lwIP frees as
// soon as this callback returns, so ownership has to be taken before then.
//
// forwardOutgoingIPPacket might be called by multiple goroutines (for example, when multiple UDP
// packets arrive at the same time); the channel send serializes them.
func (d *lwIPDevice) forwardOutgoingIPPacket(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	// Checked before the send below. rdBuf is buffered, so on a closed device both cases of that
	// select can be ready at once, and select picks between ready cases at random -- which would
	// let a packet be queued onto a device that is already shutting down.
	select {
	case <-d.done:
		return 0, network.ErrClosed
	default:
	}
	bufp := d.getBuf()
	*bufp = append((*bufp)[:0], b...)
	select {
	case d.rdBuf <- *bufp:
		return len(b), nil
	case <-d.done:
		d.recycle(*bufp)
		return 0, network.ErrClosed
	}
}

// getBuf borrows a packet buffer from the pool, allocating one if the pool is empty.
func (d *lwIPDevice) getBuf() *[]byte {
	if v := d.pktPool.Get(); v != nil {
		return v.(*[]byte)
	}
	b := make([]byte, 0, packetBufCap)
	return &b
}

// recycle returns a packet buffer to the pool once the consumer is done with it.
func (d *lwIPDevice) recycle(s []byte) {
	if cap(s) >= packetBufCap {
		b := s[:0]
		d.pktPool.Put(&b)
	}
}

// Read implements [io.Reader] and [network.IPDevice]. It reads one IP packet from the TCP/UDP response, blocking until
// a packet arrives or this device is closed. If a packet is too long to fit in the supplied buffer `p`, the excess
// bytes are discarded.
//
// Read returns [io.EOF] error if this device is closed or no more data is available. A closed
// device reports io.EOF even if packets are still queued: those packets belong to a session that
// has ended, and the [network.IPDevice] contract promises io.EOF once closed.
func (d *lwIPDevice) Read(p []byte) (int, error) {
	// Checked before the receive below, which would otherwise be free to pick a queued packet over
	// the closed done channel; select chooses among ready cases at random.
	select {
	case <-d.done:
		return 0, io.EOF
	default:
	}
	select {
	case s := <-d.rdBuf:
		n := copy(p, s)
		d.recycle(s)
		return n, nil
	case <-d.done:
		return 0, io.EOF
	}
}

// WriteTo implements [io.WriterTo]. It writes all IP packets from TCP/UDP responses to `w` until all data is written
// or an error occurs. Packets come from the pooled buffer filled by forwardOutgoingIPPacket.
//
// WriteTo returns the total number of bytes written and any error encountered during the write. If there are no more
// data available, WriteTo returns nil error instead of [io.EOF].
func (d *lwIPDevice) WriteTo(w io.Writer) (int64, error) {
	nw := int64(0)
	for {
		// Checked before the receive below for the same reason as in Read: with a buffered rdBuf
		// both cases can be ready on a closed device, and packets from an ended session must not
		// be written to the destination.
		select {
		case <-d.done:
			return nw, nil
		default:
		}
		select {
		case s := <-d.rdBuf:
			n, err := w.Write(s)
			nw += int64(n)
			d.recycle(s)
			if err != nil {
				return nw, err
			}
		case <-d.done:
			return nw, nil
		}
	}
}

// Write implements [io.Writer] and [network.IPDevice]. It writes a single IP packet to this device. The device will
// then translate the IP packet into a TCP or UDP traffic.
//
// Write returns [network.ErrClosed] if this device is already closed.
func (d *lwIPDevice) Write(b []byte) (int, error) {
	select {
	case <-d.done:
		return 0, network.ErrClosed
	default:
	}
	n, err := d.stack.Write(b)
	// Workaround: lwip netstack did not use a typed error.
	if err != nil && err.Error() == "stack closed" {
		return n, network.ErrClosed
	}
	return n, err
}
