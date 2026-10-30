package smart

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseConfig_InvalidConfig(t *testing.T) {
	config := `
dns:
  - randomkey: {}
`
	configBytes := []byte(config)
	finder := &finder{}
	_, err := finder.parseConfig(configBytes)
	require.Error(t, err)
}

func TestParseConfig_ValidConfig(t *testing.T) {
	config := `
dns:
  - system: {}
  - udp: { address: ns1.tic.ir }
  - tcp: { address: ns1.tic.ir }
  - udp: { address: tmcell.tm }
  - udp: { address: dns1.transtelecom.net. }
  - tls:
      name: captive-portal.badssl.com
      address: captive-portal.badssl.com:443
  - https: { name: mitm-software.badssl.com }

tls:
  - ""
  - split:1
  - split:2
  - split:5
  - tlsfrag:1

fallback:
  - ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTprSzdEdHQ0MkJLOE9hRjBKYjdpWGFK@1.2.3.4:9999/?outline=1
  - psiphon: {
      "PropagationChannelId":"FFFFFFFFFFFFFFFF",
      "SponsorId":"FFFFFFFFFFFFFFFF",
    }
  - socks5://192.168.1.10:1080
`
	configBytes := []byte(config)
	finder := &finder{}
	parsedConfig, err := finder.parseConfig(configBytes)
	require.NoError(t, err)

	expectedConfig := configConfig{
		DNS: []dnsEntryConfig{
			{System: &struct{}{}},
			{UDP: &udpEntryConfig{Address: "ns1.tic.ir"}},
			{TCP: &tcpEntryConfig{Address: "ns1.tic.ir"}},
			{UDP: &udpEntryConfig{Address: "tmcell.tm"}},
			{UDP: &udpEntryConfig{Address: "dns1.transtelecom.net."}},
			{TLS: &tlsEntryConfig{Name: "captive-portal.badssl.com", Address: "captive-portal.badssl.com:443"}},
			{HTTPS: &httpsEntryConfig{Name: "mitm-software.badssl.com"}},
		},
		TLS: []string{"", "split:1", "split:2", "split:5", "tlsfrag:1"},
		Fallback: []fallbackEntryConfig{
			"ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTprSzdEdHQ0MkJLOE9hRjBKYjdpWGFK@1.2.3.4:9999/?outline=1",
			map[string]any{
				"psiphon": map[string]any{
					"PropagationChannelId": "FFFFFFFFFFFFFFFF",
					"SponsorId":            "FFFFFFFFFFFFFFFF",
				},
			},
			"socks5://192.168.1.10:1080",
		},
	}

	require.Equal(t, expectedConfig, parsedConfig)
}

func TestParseConfig_YamlPsiphonConfig(t *testing.T) {
	config := `
fallback:
  - psiphon: 
      PropagationChannelId: FFFFFFFFFFFFFFFF
      SponsorId: FFFFFFFFFFFFFFFF
`
	configBytes := []byte(config)
	finder := &finder{}
	parsedConfig, err := finder.parseConfig(configBytes)
	require.NoError(t, err)

	expectedConfig := configConfig{
		Fallback: []fallbackEntryConfig{
			map[string]any{
				"psiphon": map[string]any{
					"PropagationChannelId": "FFFFFFFFFFFFFFFF",
					"SponsorId":            "FFFFFFFFFFFFFFFF",
				},
			},
		},
	}

	require.Equal(t, expectedConfig, parsedConfig)
}

func TestMakeConfigErrorSignature(t *testing.T) {
	t.Run("Simple string", func(t *testing.T) {
		config := "ss://simple"
		signature := makeConfigErrorSignature(context.Background(), config)
		require.Equal(t, `ss://simple`, signature)
	})

	t.Run("Simple map", func(t *testing.T) {
		config := map[string]any{"psiphon": map[string]any{"SponsorId": "sponsor"}}
		signature := makeConfigErrorSignature(context.Background(), config)
		require.Equal(t, `{psiphon: {SponsorId: sponsor}}`, signature)
	})

	t.Run("Long string", func(t *testing.T) {
		config := "ss://longlonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglong"
		signature := makeConfigErrorSignature(context.Background(), config)
		require.Equal(t, `ss://longlonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglo…`, signature)
	})

	t.Run("Long map", func(t *testing.T) {
		config := map[string]any{"psiphon": map[string]any{"SponsorId": "longlonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglong"}}
		signature := makeConfigErrorSignature(context.Background(), config)
		require.Equal(t, `{psiphon: {SponsorId: longlonglonglonglonglonglonglonglonglonglonglonglonglongl…`, signature)
	})
}
