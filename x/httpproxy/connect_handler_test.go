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

package httpproxy

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"golang.getoutline.org/sdk/transport"
	"github.com/stretchr/testify/require"
)

func TestNewConnectHandler(t *testing.T) {
	h := NewConnectHandler(transport.FuncStreamDialer(func(ctx context.Context, addr string) (transport.StreamConn, error) {
		return nil, errors.New("not implemented")
	}))

	ch, ok := h.(*connectHandler)
	require.True(t, ok)
	require.NotNil(t, ch.dialer)

	req := httptest.NewRequest("CONNECT", "example.invalid:0", nil)
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	require.Equal(t, 502, resp.Result().StatusCode)
}
