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

package configurl

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.getoutline.org/sdk/transport"
)

// writeRecorderConn records the payload of each Write call.
type writeRecorderConn struct {
	net.Conn
	writes []string
}

func (c *writeRecorderConn) Write(b []byte) (int, error) {
	c.writes = append(c.writes, string(b))
	return len(b), nil
}

func (c *writeRecorderConn) CloseRead() error  { return nil }
func (c *writeRecorderConn) CloseWrite() error { return nil }

func newSplitTestDialer(t *testing.T, configText string) (transport.StreamDialer, func() []*writeRecorderConn) {
	var mu sync.Mutex
	var conns []*writeRecorderConn
	base := transport.FuncStreamDialer(func(ctx context.Context, addr string) (transport.StreamConn, error) {
		conn := &writeRecorderConn{}
		mu.Lock()
		conns = append(conns, conn)
		mu.Unlock()
		return conn, nil
	})
	providers := NewExtensibleProvider[transport.StreamDialer](base)
	registerSplitStreamDialer(&providers, "split", providers.NewInstance)
	config, err := ParseConfig(configText)
	require.NoError(t, err)
	dialer, err := providers.NewInstance(context.Background(), config)
	require.NoError(t, err)
	return dialer, func() []*writeRecorderConn {
		mu.Lock()
		defer mu.Unlock()
		return conns
	}
}

func TestSplit_EveryConnectionIsSplit(t *testing.T) {
	dialer, conns := newSplitTestDialer(t, "split:2,2*1")
	for i := 0; i < 3; i++ {
		conn, err := dialer.DialStream(context.Background(), "example.com:443")
		require.NoError(t, err)
		_, err = conn.Write([]byte("hello world"))
		require.NoError(t, err)
	}
	for i, conn := range conns() {
		require.Equal(t, []string{"he", "l", "l", "o world"}, conn.writes, "connection %d", i)
	}
}

func TestSplit_ConcurrentDials(t *testing.T) {
	dialer, conns := newSplitTestDialer(t, "split:3")
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := dialer.DialStream(context.Background(), "example.com:443")
			require.NoError(t, err)
			_, err = conn.Write([]byte("hello"))
			require.NoError(t, err)
		}()
	}
	wg.Wait()
	require.Len(t, conns(), 10)
	for i, conn := range conns() {
		require.Equal(t, []string{"hel", "lo"}, conn.writes, "connection %d", i)
	}
}
