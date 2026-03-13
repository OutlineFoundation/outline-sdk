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

//go:build linux && !android

// TODO(fortuna): remove once Linux tests are re-enabled for Ubuntu 24.
//lint:file-ignore U1000 getter functions are only called from tests, which are temporarily disabled on Linux

package sysproxy

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

type ProxyType string

const (
	proxyTypeHTTP  ProxyType = "http"
	proxyTypeHTTPS ProxyType = "https"
	proxyTypeSOCKS ProxyType = "socks"
)

func SetWebProxy(host string, port string) error {
	// Set HTTP and HTTPS proxy settings
	if err := setProxySettings(proxyTypeHTTP, host, port); err != nil {
		return err
	}
	if err := setProxySettings(proxyTypeHTTPS, host, port); err != nil {
		return err
	}
	if err := setManualMode(); err != nil {
		return err
	}
	return nil
}

func DisableWebProxy() error {
	return gnomeSettingsSetString("org.gnome.system.proxy", "mode", "none")
}

func SetSOCKSProxy(host string, port string) error {
	// Set SOCKS proxy settings
	if err := setProxySettings(proxyTypeSOCKS, host, port); err != nil {
		return err
	}
	if err := setManualMode(); err != nil {
		return err
	}
	return nil
}

func DisableSOCKSProxy() error {
	return gnomeSettingsSetString("org.gnome.system.proxy", "mode", "none")
}

func setManualMode() error {
	return gnomeSettingsSetString("org.gnome.system.proxy", "mode", "manual")
}

func setProxySettings(p ProxyType, host string, port string) error {
	switch p {
	case proxyTypeHTTP:
		if err := gnomeSettingsSetString("org.gnome.system.proxy.http", "host", host); err != nil {
			return err
		}
		if err := gnomeSettingsSetString("org.gnome.system.proxy.http", "port", port); err != nil {
			return err
		}
	case proxyTypeHTTPS:
		if err := gnomeSettingsSetString("org.gnome.system.proxy.https", "host", host); err != nil {
			return err
		}
		if err := gnomeSettingsSetString("org.gnome.system.proxy.https", "port", port); err != nil {
			return err
		}
	case proxyTypeSOCKS:
		if err := gnomeSettingsSetString("org.gnome.system.proxy.socks", "host", host); err != nil {
			return err
		}
		if err := gnomeSettingsSetString("org.gnome.system.proxy.socks", "port", port); err != nil {
			return err
		}
	}
	return nil
}

func gnomeSettingsSetString(settings, key, value string) error {
	err := exec.Command("gsettings", "set", settings, key, value).Run()
	if err != nil {
		return fmt.Errorf("gsettings command failed: %w", err)
	}
	return nil
}

func getWebProxy() (host string, port string, enabled bool, err error) {
	httpHost, err := gnomeSettingsGetString("org.gnome.system.proxy.http", "host")
	if err != nil {
		return "", "", false, err
	}
	httpPort, err := gnomeSettingsGetString("org.gnome.system.proxy.http", "port")
	if err != nil {
		return "", "", false, err
	}

	httpsHost, err := gnomeSettingsGetString("org.gnome.system.proxy.https", "host")
	if err != nil {
		return "", "", false, err
	}
	httpsPort, err := gnomeSettingsGetString("org.gnome.system.proxy.https", "port")
	if err != nil {
		return "", "", false, err
	}

	mode, err := gnomeSettingsGetString("org.gnome.system.proxy", "mode")
	if err != nil {
		return "", "", false, err
	}

	if httpHost != httpsHost || httpPort != httpsPort {
		return "", "", false, errors.New("HTTP and HTTPS proxy settings are different")
	}

	return httpHost, httpPort, mode != "none", nil
}

func getSOCKSProxy() (host string, port string, enabled bool, err error) {

	socksHost, err := gnomeSettingsGetString("org.gnome.system.proxy.socks", "host")
	if err != nil {
		return "", "", false, err
	}
	socksPort, err := gnomeSettingsGetString("org.gnome.system.proxy.socks", "port")
	if err != nil {
		return "", "", false, err
	}

	mode, err := gnomeSettingsGetString("org.gnome.system.proxy", "mode")
	if err != nil {
		return "", "", false, err
	}

	return socksHost, socksPort, mode != "none", nil
}

func gnomeSettingsGetString(settings, key string) (string, error) {
	out, err := exec.Command("gsettings", "get", settings, key).Output()
	trimmed := strings.TrimSpace(string(out))
	return strings.Trim(string(trimmed), "'"), err
}
