# Outline Fetch

This app illustrates how to use different transports to fetch a URL in Go.

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
