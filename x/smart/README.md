# Smart Dialer

The **Smart Dialer** searches for a strategy that unblocks DNS and TLS for a given list of test domains. It takes a config describing multiple strategies to pick from.

## YAML config for the Smart Dialer

The config that the Smart Dialer takes is in a YAML format. Here is an example:

```yaml
dns:
  - system: {}
  - https:
      name: 8.8.8.8
  - https:
      name: 9.9.9.9
tls:
  - ""
  - split:2
  - tlsfrag:1

fallback:
  - ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTprSzdEdHQ0MkJLOE9hRjBKYjdpWGFK@1.2.3.4:9999/?outline=1
```

### DNS Configuration

*   The `dns` field specifies a list of DNS resolvers to test.
*   Each DNS resolver can be one of the following types:
    *   `system`: Use the system resolver. Specify with an empty object.
    *   `https`: Use an encrypted DNS over HTTPS (DoH) resolver.
    *   `tls`: Use an encrypted DNS over TLS (DoT) resolver.
    *   `udp`: Use a UDP resolver.
    *   `tcp`: Use a TCP resolver.

#### DNS-over-HTTPS Resolver (DoH)

```yaml
https:
  name: dns.google
  address: 8.8.8.8
```

*   `name`: The domain name of the DoH server.
*   `address`: The host:port of the DoH server. Defaults to `name`:443.

#### DNS-over-TLS Resolver (DoT)

```yaml
tls:
  name: dns.google
  address: 8.8.8.8
```

*   `name`: The domain name of the DoT server.
*   `address`: The host:port of the DoT server. Defaults to `name`:853.

#### UDP Resolver

```yaml
udp:
  address: 8.8.8.8
```

*   `address`: The host:port of the UDP resolver.

#### TCP Resolver

```yaml
tcp:
  address: 8.8.8.8
```

*   `address`: The host:port of the TCP resolver.

### TLS Configuration

*   The `tls` field specifies a list of TLS transports to test.
*   Each TLS transport is a string that specifies the transport to use.
*   For example, `override:host=cloudflare.net|tlsfrag:1` specifies a transport that uses domain fronting with Cloudflare and TLS fragmentation. See the [config documentation](https://pkg.go.dev/golang.getoutline.org/sdk/x/configurl#hdr-Configuration_Format) for details.

### Fallback Configuration

A fallback configuration is used if none of the proxyless strategies are able to connect. For example it can specify a backup proxy server to attempt the user's connection. Using a fallback will be slower to start, since first the other DNS/TLS strategies must fail/timeout.

The fallback strings should be:

*   A valid StreamDialer config string as defined in [configurl](https://pkg.go.dev/golang.getoutline.org/sdk/x/configurl#hdr-Proxy_Protocols)
*   A valid Psiphon configuration object as a child of a `psiphon` field.

#### Shadowsocks server example

```yaml
fallback:
  - ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTprSzdEdHQ0MkJLOE9hRjBKYjdpWGFK@1.2.3.4:9999/?outline=1
```

#### SOCKS5 server example

```yaml
fallback:
  - socks5://[USERINFO]@[HOST]:[PORT]
```

#### Psiphon config example

> [!WARNING]
> The Psiphon library is not included in the build by default because the Psiphon codebase uses GPL. To support Psiphon configuration please build using the [`psiphon` build tag](https://pkg.go.dev/golang.getoutline.org/sdk/x/psiphon).
> When integrating Psiphon into your application please work with the Psiphon team at sponsor@psiphon.ca

JSON is a subset of YAML. If you have an existing psiphon JSON configuration file you can simply copy-and-paste it into your smart-proxy config.yaml file like so:

```yaml
fallback:
  - psiphon: <YOUR_PSIPHON_CONFIG_HERE>
```

```yaml
fallback:
  - psiphon: {
      "PropagationChannelId": "FFFFFFFFFFFFFFFF",
      "SponsorId": "FFFFFFFFFFFFFFFF",
      "DisableLocalSocksProxy" : true,
      "DisableLocalHTTPProxy" : true,
      ...
    }
```

### Using the Smart Dialer

To use the Smart Dialer, create a `StrategyFinder` object and call the `NewDialer` method, passing in the list of test domains and the JSON config. The `NewDialer` method will return a `transport.StreamDialer` that can be used to create connections using the found strategy. For example:

```go
finder := &smart.StrategyFinder{
    TestTimeout:  5 * time.Second,
    LogWriter:   os.Stdout,
    StreamDialer: &transport.TCPDialer{},
    PacketDialer: &transport.UDPDialer{},
}

configBytes := []byte(`
dns:
  - system: {}
  - https:
      name: 8.8.8.8
  - https:
      name: 9.9.9.9
tls:
  - ""
  - split:2
  - tlsfrag:1
fallback:
  - ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTprSzdEdHQ0MkJLOE9hRjBKYjdpWGFK@1.2.3.4:9999/?outline=1
`)

dialer, err := finder.NewDialer(context.Background(), []string{"www.google.com"}, configBytes)
if err != nil {
    // Handle error.
}

// Use dialer to create connections.
```

Please note that this is a basic example and may need to be adapted for your specific use case.

## Adding a new fallback strategy

Fallback strategies are used when none of the proxyless strategies are successful. They are typically proxies that are expected to be more reliable.

To add a new fallback strategy:

1. Create a `FallbackParser` function. This function takes a `YAMLNode` and returns a `transport.StreamDialer` and a config signature.
2. Register the `FallbackParser` with the `mobileproxy.SmartDialerOptions.RegisterFallbackParser` method.

For example, this is how you can register a fallback that is configured with `{error: "my error message"}` that
always returns an error on dial:

```go
func RegisterErrorConfig(opt *mobileproxy.SmartDialerOptions, name string) {
	opt.RegisterFallbackParser(name, func(ctx context.Context, yamlNode smart.YAMLNode) (transport.StreamDialer, string, error) {
		switch typed := yamlNode.(type) {
		case string:
			dialer := transport.FuncStreamDialer(func(ctx context.Context, addr string) (transport.StreamConn, error) {
				return nil, errors.New(typed)
			})
			return dialer, typed, nil
		default:
			return nil, "", fmt.Errorf("invalid error dialer config")
		}
	})
}

func main() {
	// ...
  opts := mobileproxy.NewSmartDialerOptions(mobileproxy.NewListFromLines(*testDomainsFlag), *configFlag)
	opts.SetLogWriter(mobileproxy.NewStderrLogWriter())
	RegisterErrorConfig(opts, "error")
  //...
}
```
