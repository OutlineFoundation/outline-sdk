//go:build linux

package wait_stream

import (
	"golang.org/x/sys/unix"
)

func isSocketFdSendingBytes(fd int) (bool, error) {
	tcpInfo, err := unix.GetsockoptTCPInfo(fd, unix.IPPROTO_TCP, unix.TCP_INFO)
	if err != nil {
		return false, err
	}
	return tcpInfo.Notsent_bytes != 0, nil
}
