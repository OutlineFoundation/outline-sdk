# Outline Fetch Speed

This app illustrates how to use different transports to fetch a URL in Go and calculate the download speed.

Direct fetch:

```sh
$ go run golang.getoutline.org/sdk/x/tools/fetch-speed@latest http://speedtest.ftp.otenet.gr/files/test10Mb.db

Downloaded 10.00 MB in 1.51s

Downloaded Speed: 6.64 MB/s
```

Using a Shadowsocks server:

```sh
$ go run golang.getoutline.org/sdk/x/tools/fetch-speed@latest -transport ss://[redacted]@[redacted]:80 http://speedtest.ftp.otenet.gr/files/test10Mb.db

Downloaded 10.00 MB in 1.78s

Downloaded Speed: 5.61 MB/s
```
