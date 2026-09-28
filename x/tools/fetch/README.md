# Outline Fetch

This app illustrates how to use different transports to fetch a URL in Go.

When using HTTP/3, `-quic-versions` selects the ordered QUIC versions. For
example, force RFC 9369 QUIC v2 with:

```console
fetch -proto h3 -quic-versions 2 -method HEAD -v https://example.com/
```

The tool logs the negotiated QUIC version and wire codepoint after a successful
HTTP/3 request. Use `1,2` (the default) to prefer v1, or `2,1` to prefer v2
while allowing fallback through version negotiation.

### QUIC preludes

Preludes are configured through `-transport`, not through dedicated flags, so
they compose with the rest of the transport stack. The `quicprelude` type sends
datagrams ahead of every packet that may carry a QUIC ClientHello, on the same
socket and therefore the same four-tuple:

```console
fetch -proto h3 -quic-versions 1 -method HEAD -v \
  -transport 'quicprelude:count=1&version=0x1a2a3a4a' https://example.com/
```

Every option may be omitted, and a bare `quicprelude` is the configuration to
reach for first:

| Option | Default | Meaning |
|---|---|---|
| `count` | `1` | Number of datagrams, at most 16; `0` disables the prelude |
| `mode` | `invalid-initial` | Or `random`, which is useful as a control |
| `length` | `match` | `match` sizes each datagram like the packet it precedes; or give a byte count |
| `version` | `reserved` | Range to draw a fresh codepoint from per datagram: `reserved` (`0x?a?a?a?a`) or `draft`; or a fixed `v1`, `v2`, or hex value |

Because it is an ordinary transport, it stacks above a proxy, and the prelude
then travels the same path as the traffic it precedes:

```console
fetch -proto h3 -quic-versions 1 -method HEAD -v \
  -transport 'socks5://user:pass@proxy.example:1080|quicprelude:count=1' \
  https://example.com/
```

These options are intended for authorized measurement of path and middlebox
behavior. Packet captures are recommended when exact wire behavior matters.

Direct fetch:

```sh
$ go run golang.getoutline.org/sdk/x/tools/fetch@latest https://ipinfo.io
{
  ...
  "city": "Amsterdam",
  "region": "North Holland",
  "country": "NL",
  ...
}                                  
```

Using a Shadowsocks server:

```sh
$ go run golang.getoutline.org/sdk/x/tools/fetch@latest -transport ss://[redacted]@[redacted]:80 https://ipinfo.io
{
  ...
  "region": "New Jersey",
  "country": "US",
  "org": "AS14061 DigitalOcean, LLC",
  ...
}
```

Using a SOCKS5 server:

```sh
$ go run golang.getoutline.org/sdk/x/tools/fetch@latest -transport socks5://[redacted]:5703 https://ipinfo.io
{
  ... 
  "city": "Berlin",
  "region": "Berlin",
  "country": "DE",
  ...
}
```

Using packet splitting:

```sh
$ go run golang.getoutline.org/sdk/x/tools/fetch@latest -transport split:3  https://ipinfo.io
{
  ...
  "city": "Amsterdam",
  "region": "North Holland",
  "country": "NL",
  ...
}                                  
```

You should see this on Wireshark:

<img width="652" alt="image" src="https://github.com/OutlineFoundation/outline-sdk/assets/113565/9c19667d-d0fb-4d33-b0a6-275674481dce">

## Using ECH

Pass the `-ech-config` flag with the base64-encoded ECH Config in binary format (as per the standard proposal).

```console
$ go run golang.getoutline.org/sdk/x/tools/fetch@latest 'https://test.defo.ie/echstat.php?format=json'
{"SSL_ECH_OUTER_SNI": "NONE","SSL_ECH_INNER_SNI": "NONE","SSL_ECH_STATUS": "not attempted","date": "2025-09-05T14:26:43+00:00","config": "min-ng.test.defo.ie"}

$ dig +short test.defo.ie HTTPS
1 . ech=AEb+DQBCqQAgACBlm7cfDx/gKuUAwRTe+Y9MExbIyuLpLcgTORIdi69uewAEAAEAAQATcHVibGljLnRlc3QuZGVmby5pZQAA

$ go run golang.getoutline.org/sdk/x/tools/fetch@latest --ech-config=AEb+DQBCqQAgACBlm7cfDx/gKuUAwRTe+Y9MExbIyuLpLcgTORIdi69uewAEAAEAAQATcHVibGljLnRlc3QuZGVmby5pZQAA 'https://test.defo.ie/echstat.php?format=json'
{"SSL_ECH_OUTER_SNI": "public.test.defo.ie","SSL_ECH_INNER_SNI": "test.defo.ie","SSL_ECH_STATUS": "success", "date": "2025-09-05T14:22:52+00:00","config": "min-ng.test.defo.ie"}
```
