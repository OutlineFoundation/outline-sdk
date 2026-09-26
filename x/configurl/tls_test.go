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

package configurl

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.getoutline.org/sdk/transport/tls"
)

func TestTLS_SNI(t *testing.T) {
	config, err := ParseConfig("tls:sni=www.google.com")
	require.NoError(t, err)
	options, err := parseOptions(config.URL)
	require.NoError(t, err)
	certVerifier := &tls.StandardCertVerifier{CertificateName: "host"}
	cfg := tls.ClientConfig{ServerName: "host", CertVerifier: certVerifier}
	for _, option := range options {
		option("host", &cfg)
	}
	require.Equal(t, "www.google.com", cfg.ServerName)
	require.Equal(t, certVerifier, cfg.CertVerifier)
}

func TestTLS_NoSNI(t *testing.T) {
	config, err := ParseConfig("tls:sni=")
	require.NoError(t, err)
	options, err := parseOptions(config.URL)
	require.NoError(t, err)
	certVerifier := &tls.StandardCertVerifier{CertificateName: "host"}
	cfg := tls.ClientConfig{ServerName: "host", CertVerifier: certVerifier}
	for _, option := range options {
		option("host", &cfg)
	}
	require.Equal(t, "", cfg.ServerName)
	require.Equal(t, certVerifier, cfg.CertVerifier)
}

func TestTLS_MultipleSNI(t *testing.T) {
	config, err := ParseConfig("tls:sni=www.google.com&sni=second")
	require.NoError(t, err)
	_, err = parseOptions(config.URL)
	require.Error(t, err)
}

func TestTLS_CertName(t *testing.T) {
	config, err := ParseConfig("tls:certname=www.google.com")
	require.NoError(t, err)
	options, err := parseOptions(config.URL)
	require.NoError(t, err)
	cfg := tls.ClientConfig{ServerName: "host", CertVerifier: &tls.StandardCertVerifier{CertificateName: "host"}}
	for _, option := range options {
		option("host", &cfg)
	}
	require.Equal(t, "host", cfg.ServerName)
	require.Equal(t, "www.google.com", cfg.CertVerifier.(*tls.StandardCertVerifier).CertificateName)
}

func TestTLS_Combined(t *testing.T) {
	config, err := ParseConfig("tls:SNI=sni.example.com&CertName=certname.example.com")
	require.NoError(t, err)
	options, err := parseOptions(config.URL)
	require.NoError(t, err)
	cfg := tls.ClientConfig{ServerName: "host", CertVerifier: &tls.StandardCertVerifier{CertificateName: "host"}}
	for _, option := range options {
		option("host", &cfg)
	}
	require.Equal(t, "sni.example.com", cfg.ServerName)
	require.Equal(t, "certname.example.com", cfg.CertVerifier.(*tls.StandardCertVerifier).CertificateName)
}

func TestTLS_UnsupportedOption(t *testing.T) {
	config, err := ParseConfig("tls:unsupported")
	require.NoError(t, err)
	_, err = parseOptions(config.URL)
	require.Error(t, err)
}
