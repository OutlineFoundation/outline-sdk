//go:build !linux

package wait_stream

import (
	"errors"
	"fmt"
)

func isSocketFdSendingBytes(_ int) (bool, error) {
	return false, fmt.Errorf("%w: checking if socket is sending bytes is not implemented on this platform", errors.ErrUnsupported)
}
