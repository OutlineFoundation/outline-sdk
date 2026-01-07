// Copyright 2025 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package soax

import (
	"context"
	"errors"
	"net"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/things-go/go-socks5"
)

func TestSessionConfig_newUsername_AllFields(t *testing.T) {
	config := ProxySessionConfig{
		Auth: ProxyAuthConfig{
			PackageID:  123456,
			PackageKey: "my_package_key",
		},
		Node: ProxyNodeConfig{
			CountryCode: "US",
			RegionID:    "new york",
			CityID:      "new york city",
			ISPID:       "verizon",
		},
		Session: SessionConfig{
			ID:       "my_session",
			Duration: 10 * time.Minute,
			IdleTTL:  5 * time.Minute,
		},
	}
	userinfo := config.newUserPassword()
	require.Equal(t,
		"package-123456-country-us-region-new%20york-city-new%20york%20city-isp-verizon-sessionid-my_session-sessionlength-600-idlettl-300:my_package_key",
		userinfo.String())
	require.Equal(t, "package-123456-country-us-region-new york-city-new york city-isp-verizon-sessionid-my_session-sessionlength-600-idlettl-300", userinfo.Username())
	password, isSet := userinfo.Password()
	require.True(t, isSet)
	require.Equal(t, "my_package_key", password)
}

func TestSessionConfig_newUsername_PackageOnly(t *testing.T) {
	config := ProxySessionConfig{
		Auth: ProxyAuthConfig{
			PackageID:  123456,
			PackageKey: "my_package_key",
		},
	}
	require.Equal(t, "package-123456:my_package_key", config.newUserPassword().String())
}

func TestSessionConfig_newSession_SetsDefaults(t *testing.T) {
	config := ProxySessionConfig{
		Auth: ProxyAuthConfig{
			PackageID:  123456,
			PackageKey: "my_package_key",
		},
	}
	session := config.NewSession()
	require.NotNil(t, session)
	require.NotContains(t, session.config.Session.ID, "-")
	require.NotEmpty(t, session.config.Session.ID)
	require.Equal(t, 1*time.Hour, session.config.Session.Duration)
	require.Equal(t, 1*time.Hour, session.config.Session.IdleTTL)
	require.Equal(t, proxyAddress, session.config.Endpoint)
}

func TestSessionConfig_newSession_NotPersistent(t *testing.T) {
	config := ProxySessionConfig{
		Auth: ProxyAuthConfig{
			PackageID:  123456,
			PackageKey: "my_package_key",
		},
		Session: SessionNotPersistent,
	}
	session := config.NewSession()
	require.NotNil(t, session)
	require.Empty(t, session.config.Session.ID)
	require.Equal(t, time.Duration(-1), session.config.Session.Duration)
	require.Equal(t, time.Duration(0), session.config.Session.IdleTTL)
	require.Equal(t, proxyAddress, session.config.Endpoint)
	require.Equal(t, "package-123456:my_package_key", session.config.newUserPassword().String())
}

type FuncCredentialStore func(user, password, userAddr string) bool

func (f FuncCredentialStore) Valid(user, password, userAddr string) bool {
	return f(user, password, userAddr)
}

var _ socks5.CredentialStore = FuncCredentialStore(nil)

func TestSession_NewSOCKS5Client(t *testing.T) {
	config := ProxySessionConfig{
		Auth: ProxyAuthConfig{
			PackageID:  123456,
			PackageKey: "my_package_key",
		},
	}
	var userinfo url.Userinfo

	// Create a SOCKS5 server that expects the credentials from the config.
	cator := socks5.UserPassAuthenticator{
		Credentials: FuncCredentialStore(func(userToCheck, passwordToCheck, userAddr string) bool {
			require.Equal(t, userinfo.Username(), userToCheck)
			expectedPassword, _ := userinfo.Password()
			require.Equal(t, expectedPassword, passwordToCheck)
			return true
		}),
	}
	server := socks5.NewServer(
		socks5.WithAuthMethods([]socks5.Authenticator{cator}),
	)

	var running sync.WaitGroup
	// Create SOCKS5 proxy on localhost with a random port.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	running.Add(1)
	go func() {
		defer running.Done()
		err := server.Serve(listener)
		// The server will be stopped by closing the listener.
		if err != nil && !errors.Is(err, net.ErrClosed) {
			require.NoError(t, err)
		}
	}()
	defer func() {
		listener.Close()
		running.Wait()
	}()

	// The SOCKS5 server from things-go/go-socks5 will try to connect to this address.
	// We need a listener, otherwise the Dial will fail with connection refused.
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer targetListener.Close()

	// Set the endpoint to our test server.
	config.Endpoint = listener.Addr().String()
	session := config.NewSession()
	userinfo = *session.config.newUserPassword()
	client, err := session.NewSOCKS5Client()
	require.NoError(t, err)
	require.NotNil(t, client)

	_, err = client.DialStream(context.Background(), targetListener.Addr().String())
	require.NoError(t, err)
}
