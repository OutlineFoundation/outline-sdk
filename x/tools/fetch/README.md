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

### QUIC prelude measurements

For controlled network measurements, `-quic-prelude-count` sends traffic to
the selected server on the same UDP socket before the HTTP/3 connection. The
available `-quic-prelude-mode` values are:

- `random`: opaque random datagrams;
- `quic-v1-invalid`: QUIC v1 Initial-shaped datagrams with invalid
  authenticated encryption, sized by `-quic-prelude-size` (default 1280 bytes,
  matching QUIC-Go's own Initials; the RFC 9000 minimum of 1200 is enforced);
- `quic-v2-invalid`: the equivalent QUIC v2 Initial-shaped datagrams; and
- `valid-v2`: genuine QUIC v2 handshake attempts using the SNI selected by
  `-quic-prelude-sni` (default `www.google.com`).

For the raw modes, the count is the exact number of datagrams. For `valid-v2`,
the count is the number of handshake attempts, each of which may produce more
than one datagram, and `-quic-prelude-timeout` (default 3 seconds) bounds each
attempt. Because the preludes are sent inside the HTTP/3 dial, their total
budget is added to `-timeout`, so the measured connection still gets the full
`-timeout` it would have had without preludes. For example:

```console
fetch -proto h3 -quic-versions 2 -quic-prelude-count 2 \
  -quic-prelude-mode quic-v2-invalid -method HEAD -v https://example.com/
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
