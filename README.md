# Outline SDK (Beta)

[![Build Status](https://github.com/OutlineFoundation/outline-sdk/actions/workflows/test.yml/badge.svg)](https://github.com/OutlineFoundation/outline-sdk/actions/workflows/test.yml?query=branch%3Amain)
[![Go Report Card](https://goreportcard.com/badge/golang.getoutline.org/sdk)](https://goreportcard.com/report/golang.getoutline.org/sdk)
[![Go Reference](https://pkg.go.dev/badge/golang.getoutline.org/sdk.svg)](https://pkg.go.dev/golang.getoutline.org/sdk)

<p align="center">
<img src="https://github.com/OutlineFoundation/outline-brand/blob/main/assets/powered_by_outline/color/logo.png?raw=true" width=400pt />
</p>

> [!IMPORTANT]
> **New Module Path**
>
> As part of the [Outline transition](https://medium.com/jigsaw/introducing-the-outline-foundation-an-independent-home-for-outline-39fba2ab4e25) from Jigsaw to the new Outline Foundation, we have migrated our Go module paths to:
> - `golang.getoutline.org/sdk`
> - `golang.getoutline.org/sdk/x`
>
> **Please update your imports to the new paths as soon as possible.** The old `github.com/Jigsaw-Code/outline-sdk` paths are now deprecated and will no longer receive updates. If you encounter errors using `go get` or `go run` with the old paths, please switch to the new module paths. Future stable releases are published exclusively under the new module paths.

The Outline SDK allows you to:

- Create tools to protect against network-level interference.
- [Add network-level interference protection to existing apps](#add-the-sdk-to-your-app), such as content or communication apps.
- Troubleshoot connectivity and measure interference with a collection of [command-line tools](#command-line-tools).

## Table of Contents

<details>
<summary>Click to expand</summary>

- [Advantages](#advantages)
  - [Interoperable and Reusable](#interoperable-and-reusable)
  - [Bypass DNS-based Blocking](#bypass-dns-based-blocking)
  - [Bypass SNI-based Blocking](#bypass-sni-based-blocking)
  - [Tunnel Connections over a Proxy](#tunnel-connections-over-a-proxy)
  - [Build a VPN](#build-a-vpn)
- [Add the SDK to Your App](#add-the-sdk-to-your-app)
  - [Generated Mobile Library](#generated-mobile-library)
  - [Side Service](#side-service)
  - [Go Library](#go-library)
  - [Generated C Library](#generated-c-library)
- [Wrap your website in a SDK-enabled App](#wrap-your-website-in-a-sdk-enabled-app)
- [Command-line Tools](#command-line-tools)
  - [Resolve a Domain Name](#resolve-a-domain-name)
  - [Fetch a Web Page](#fetch-a-web-page)
  - [Run a Local Forward Proxy](#run-a-local-forward-proxy)
  - [Test Proxy Connectivity](#test-proxy-connectivity)
  - [Test Download Speed](#test-download-speed)

</details>

## Advantages

| Multi-Platform | Proven Technology | Composable |
|:-:|:-:|:-:|
| Supports Android, iOS, Windows, macOS and Linux. | Field-tested in the Outline Client and Server, helping millions to access the internet under harsh conditions. | Designed for modularity and reuse, allowing you to craft custom transports. |

### Interoperable and Reusable

The Outline SDK is built upon a simple basic concepts, defined as interoperable interfaces that allow for composition and easy reuse.

**Connections** enable communication between two endpoints over an abstract transport. There are two types of connections:
  - `transport.StreamConn`: stream-based connection, like TCP and the `SOCK_STREAM` Posix socket type.
  - `transport.PacketConn`: datagram-based connection, like UDP and the `SOCK_DGRAM` Posix socket type. We use "Packet" instead of "Datagram" because that is the convention in the Go standard library.

Connections can be wrapped to create nested connections over a new transport. For example, a `StreamConn` could be over TCP, over TLS over TCP, over HTTP over TLS over TCP, over QUIC, among other options.

**Dialers** enable the creation of connections given a host:port address while encapsulating the underlying transport or proxy protocol. The `StreamDialer` and `PacketDialer` types create `StreamConn` and `PacketConn` connections, respectively, given an address. Dialers can also be nested. For example, a TLS Stream Dialer can use a TCP dialer to create a `StreamConn` backed by a TCP connection, then create a TLS `StreamConn` backed by the TCP `StreamConn`. A SOCKS5-over-TLS Dialer could use the TLS Dialer to create the TLS `StreamConn` to the proxy before doing the SOCKS5 connection to the target address.

**Resolvers** (`dns.Resolver`) enable the answering of DNS questions while encapsulating the underlying algorithm or protocol. Resolvers are primarily used to map domain names to IP addresses.


### Bypass DNS-based Blocking

The Outline SDK offers two types of strategies for evading DNS-based blocking: resilient DNS or address override.

- The [dns](https://pkg.go.dev/golang.getoutline.org/sdk/dns) package can replace the resolution based on the system resolver with more resillient options:
  - Encrypted DNS over HTTPS (DoH) or TLS (DoT)
  - Alternative hosts and ports for UDP and TCP resolvers, making it possible to use resolvers that are not blocked.
- The `override` config from [x/configurl](https://pkg.go.dev/golang.getoutline.org/sdk/x/configurl) with a `host` option can be used to force a specific address,
  or you can implement your own Dialer that can map addresses.

### Bypass SNI-based Blocking

The Outline SDK offers several strategies for evading SNI-based blocking:

At the TCP layer:

- TCP stream fragmentation with [transport/split](https://pkg.go.dev/golang.getoutline.org/sdk/transport/split)
- TLS record fragmentation with [transport/tlsfrag](https://pkg.go.dev/golang.getoutline.org/sdk/transport/tlsfrag)

At the application layer:

- Domain-fronting and SNI hiding with [transport/tls](https://pkg.go.dev/golang.getoutline.org/sdk/transport/tls)


### Tunnel Connections over a Proxy

The Outline SDK offers two protocols to create connections over proxies:

- Shadowsocks, available in [transport/shadowsocks](https://pkg.go.dev/golang.getoutline.org/sdk/transport/shadowsocks).
  Easily create servers in the cloud using the [Outline Manager](https://getoutline.org/get-started/#step-1).
- SOCKS5, available in [transport/socks5](https://pkg.go.dev/golang.getoutline.org/sdk/transport/socks5). You can leverage a [local SOCKS5 proxy that tunnels connections over SSH](https://www.digitalocean.com/community/tutorials/how-to-route-web-traffic-securely-without-a-vpn-using-a-socks-tunnel).

### Build a VPN

Use the [network](https://pkg.go.dev/golang.getoutline.org/sdk/network) package to create TUN-based VPNs using transport-layer proxies (often called "tun2socks").


## Add the SDK to Your App

Choose from one of the following methods to integrate the Outline SDK into your project:

- **Generated Mobile Library**: For Android, iOS, and macOS apps. Uses [`gomobile bind`](https://pkg.go.dev/golang.org/x/mobile/cmd/gomobile) to generate Java and Objective-C bindings.
- **Side Service**: For desktop and Android apps. Runs a standalone Go binary that your application communicates with (not available on iOS due to subprocess limitations).
- **Go Library**: Directly import the SDK into your Go application. [API Reference](https://pkg.go.dev/golang.getoutline.org/sdk).
- **Generated C Library**: Generate C bindings using [`go build`](https://pkg.go.dev/cmd/go#hdr-Build_modes).

The Outline Client uses a **generated mobile library** on Android, iOS and macOS (based on Cordova) and a **side service** on Windows and Linux (based on Electron).

Below we provide more details on each integration approach. For more details about setting up and using Outline SDK features, see the [Discussions tab](https://github.com/OutlineFoundation/outline-sdk/discussions).

### Generated Mobile Library

See our [MobileProxy page](./x/mobileproxy/) to learn about the easiest way to integrate the Outline SDK into a mobile app. It runs a local forward proxy that implements resillience strategies that you can use to configure your app's networking libraries.

For advanced users, it is possible to generate your own mobile library, following these steps:

1. **Create a Go library**: Create a Go package that wraps the SDK functionalities you need.
1. **Generate mobile library**: Use [`gomobile bind`](https://pkg.go.dev/golang.org/x/mobile/cmd/gomobile) to generate Android Archives (AAR) and Apple Frameworks with Java and Objective-C bindings.
    - Android examples: [Outline Android Archive](https://github.com/OutlineFoundation/outline-go-tun2socks/blob/dada2652ae2c6205f2daa3f88c805bbd6b28a713/Makefile#L27), [Intra Android Archive](https://github.com/OutlineFoundation/outline-go-tun2socks/blob/dada2652ae2c6205f2daa3f88c805bbd6b28a713/Makefile#L21).
    - Apple examples: [Outline iOS Framework](https://github.com/OutlineFoundation/outline-go-tun2socks/blob/dada2652ae2c6205f2daa3f88c805bbd6b28a713/Makefile#L30), [Outline macOS Framework](https://github.com/OutlineFoundation/outline-go-tun2socks/blob/dada2652ae2c6205f2daa3f88c805bbd6b28a713/Makefile#L36).
1. **Integrate into your app**: Add the generated library to your app. For more details, see Go Mobile's [SDK applications and generating bindings](https://go.dev/wiki/Mobile#sdk-applications-and-generating-bindings).

> **Note**: You must use `gomobile bind` on the package you create, not directly on the SDK packages.


### Side Service

To integrate the SDK as a side service, follow these steps:

1. **Define IPC mechanism**: Choose an inter-process communication (IPC) mechanism (for example, sockets, standard I/O).
1. **Build the service**: Create a Go binary that includes the server-side of the IPC and used the SDK.
    - Examples: [Outline Electron backend code](https://github.com/OutlineFoundation/outline-go-tun2socks/blob/master/outline/electron/main.go), [Outline Windows Client backend build](https://github.com/OutlineFoundation/outline-go-tun2socks/blob/dada2652ae2c6205f2daa3f88c805bbd6b28a713/Makefile#L67), [Outline Linux Client backend build](https://github.com/OutlineFoundation/outline-go-tun2socks/blob/dada2652ae2c6205f2daa3f88c805bbd6b28a713/Makefile#L56).
1. **Bundle the service**: Include the Go binary in your application bundle.
    - Examples: [Outline Windows Client](https://github.com/OutlineFoundation/outline-apps/blob/b06819922037230ee3ba9471097c40793af819e8/src/electron/electron-builder.json#L21), [Outline Linux Client](https://github.com/OutlineFoundation/outline-apps/blob/b06819922037230ee3ba9471097c40793af819e8/src/electron/electron-builder.json#L10)
1. **Start the service**: Launch the Go binary as a subprocess from your application.
    - Example: [Outline Electron Clients](https://github.com/OutlineFoundation/outline-apps/blob/b06819922037230ee3ba9471097c40793af819e8/src/electron/go_vpn_tunnel.ts#L227)
1. **Service Calls**: Add code to your app for communication with the service.


### Go Library

To integrate the Outline SDK as a Go library, you can directly import it into your Go application. See the [API Reference](https://pkg.go.dev/golang.getoutline.org/sdk) for what's available.

This approach is suitable for both command-line and GUI-based applications. You can build GUI-based applications in Go with frameworks like [Wails](https://wails.io/), [Fyne.io](https://fyne.io/), [Qt for Go](https://therecipe.github.io/qt/), or [Go Mobile app](https://pkg.go.dev/golang.org/x/mobile/app).

For examples, see [x/examples](./x/examples/).

### Generated C Library

This approach is suited for applications that require C bindings. It is similar to the Generated Mobile Library approach, where you need to first create a Go library to generate bindings for.

Steps:

1. **Create a Go library**: Create a Go package that wraps the SDK functionalities you need. Functions to be exported must be marked with `//export`, as described in the [cgo documentation](https://pkg.go.dev/cmd/cgo#hdr-C_references_to_Go).
1. **Generate C library**: Use `go build` with the [appropriate `-buildmode` flag](https://pkg.go.dev/cmd/go#hdr-Build_modes). Anternatively, you can use [SWIG](https://swig.org/Doc4.1/Go.html#Go).
1. **Integrate into your app**: Add the generated C library to your application, according to your build system.

You can find detailed steps at the tutorial [Go for beginners: Getting started](https://github.com/OutlineFoundation/outline-sdk/discussions/67).

## Wrap your website in a SDK-enabled App

See our [Web Wrapper example](./x/examples/website-wrapper-app/) for a simple way to package your existing website into a mobile app with built-in resilience features provided by the Outline SDK.

## Command-line Tools

The Outline SDK has several command-line utilities that illustrate the usage of the SDK, but are also valuable for debugging and trying the different strategies without having to build an app.

They all take a `-transport` flag with a config that specifies what transport should be used to establish connections.
The config format can be found in [x/configurl](https://pkg.go.dev/golang.getoutline.org/sdk/x/configurl).


### Resolve a Domain Name

The [`resolve` tool](https://pkg.go.dev/golang.getoutline.org/sdk/x/tools/resolve) resolves a domain name, similar to `dig`:

```console
$ go run golang.getoutline.org/sdk/x/tools/resolve@latest -type A -transport "tls" -resolver 8.8.8.8:853 -tcp getoutline.org.
216.239.34.21
216.239.32.21
216.239.38.21
216.239.36.21
```


### Fetch a Web Page

The [`fetch` tool](https://pkg.go.dev/golang.getoutline.org/sdk/x/tools/fetch) fetches
a URL, similar to `curl`. The example below would bypass blocking of `meduza.io` in Russia:

```console
$ go run golang.getoutline.org/sdk/x/tools/fetch@latest -transport "override:host=cloudflare.net|tlsfrag:1" -method HEAD -v https://meduza.io/
[DEBUG] 2023/12/28 18:44:56.490836 main.go:105: Cf-Ray: [83cdac8ecdccc40e-EWR]
[DEBUG] 2023/12/28 18:44:56.491231 main.go:105: Alt-Svc: [h3=":443"; ma=86400]
[DEBUG] 2023/12/28 18:44:56.491237 main.go:105: Date: [Thu, 28 Dec 2023 23:44:56 GMT]
[DEBUG] 2023/12/28 18:44:56.491241 main.go:105: Connection: [keep-alive]
[DEBUG] 2023/12/28 18:44:56.491247 main.go:105: Strict-Transport-Security: [max-age=31536000; includeSubDomains; preload]
[DEBUG] 2023/12/28 18:44:56.491251 main.go:105: Cache-Control: [max-age=0 no-cache, no-store]
[DEBUG] 2023/12/28 18:44:56.491257 main.go:105: X-Content-Type-Options: [nosniff]
[DEBUG] 2023/12/28 18:44:56.491262 main.go:105: Server: [cloudflare]
[DEBUG] 2023/12/28 18:44:56.491266 main.go:105: Content-Type: [text/html; charset=utf-8]
[DEBUG] 2023/12/28 18:44:56.491270 main.go:105: Expires: [Thu, 28 Dec 2023 23:44:56 GMT]
[DEBUG] 2023/12/28 18:44:56.491273 main.go:105: Cf-Cache-Status: [DYNAMIC]
```

### Run a Local Forward Proxy

The [`http2transport` tool](https://pkg.go.dev/golang.getoutline.org/sdk/x/tools/http2transport) runs a local proxy that creates connections according to the transport. It's effectively a circumvention tool.

The example below is analogous to the previous fetch example.

Start the local proxy:

```console
$ go run golang.getoutline.org/sdk/x/tools/http2transport@latest -transport "override:host=cloudflare.net|tlsfrag:1" -localAddr localhost:8080
2023/12/28 18:50:48 Proxy listening on 127.0.0.1:8080
```

Using the proxy with `curl`:

```console
$ curl -p -x http://localhost:8080 https://meduza.io --head
HTTP/1.1 200 Connection established

HTTP/2 200
date: Thu, 28 Dec 2023 23:51:01 GMT
content-type: text/html; charset=utf-8
strict-transport-security: max-age=31536000; includeSubDomains; preload
expires: Thu, 28 Dec 2023 23:51:01 GMT
cache-control: max-age=0
cache-control: no-cache, no-store
cf-cache-status: DYNAMIC
x-content-type-options: nosniff
server: cloudflare
cf-ray: 83cdb579bbec4376-EWR
alt-svc: h3=":443"; ma=86400
```

### Test Proxy Connectivity

The [`test-connectivity` tool](https://pkg.go.dev/golang.getoutline.org/sdk/x/tools/test-connectivity) is useful to test connectivity to a proxy. It uses DNS resolutions over TCP and UDP using the transport to test if there is stream and datagram connectivity.

```console
$ go run golang.getoutline.org/sdk/x/tools/test-connectivity@latest -transport "$OUTLINE_KEY" && echo success || echo failure
{"resolver":"8.8.8.8:53","proto":"tcp","time":"2023-12-28T23:57:45Z","duration_ms":39,"error":null}
{"resolver":"8.8.8.8:53","proto":"udp","time":"2023-12-28T23:57:45Z","duration_ms":17,"error":null}
{"resolver":"[2001:4860:4860::8888]:53","proto":"tcp","time":"2023-12-28T23:57:45Z","duration_ms":31,"error":null}
{"resolver":"[2001:4860:4860::8888]:53","proto":"udp","time":"2023-12-28T23:57:45Z","duration_ms":16,"error":null}
success
```

### Test Download Speed

The [`fetch-speed` tool](https://pkg.go.dev/golang.getoutline.org/sdk/x/tools/fetch-speed) fetches
a URL, similar to `curl` and calculates the download speed. It could be used for troubleshooting.

```console
$ go run golang.getoutline.org/sdk/x/tools/fetch-speed@latest -transport ss://[redacted]@[redacted]:80 http://speedtest.ftp.otenet.gr/files/test10Mb.db

Downloaded 10.00 MB in 1.78s

Downloaded Speed: 5.61 MB/s
```
