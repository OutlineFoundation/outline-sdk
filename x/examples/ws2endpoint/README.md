# WebSocket Reverse Proxy

This package contains a command-line tool to expose a WebSocket endpoint that connects to
any endpoint over a transport.


## Connecting to an arbitrary endpoint


```sh
go run ./examples/ws2endpoint --backend ipinfo.io:443 --transport tls
```

Then, on a browser console, you can do:

```js
s = new WebSocket("ws://localhost:8080");
s.onmessage = (m) => console.log(m.data);
s.onopen = () => { s.send("GET /json HTTP/1.1\r\nHost: ipinfo.io\r\n\r\n"); }
```

And you will see the response. For example:

```http
HTTP/1.1 200 OK
server: nginx/1.24.0
date: Fri, 22 Mar 2024 22:07:18 GMT
content-type: application/json; charset=utf-8
Content-Length: 321
access-control-allow-origin: *
x-content-type-options: nosniff
x-envoy-upstream-service-time: 3
via: 1.1 google
strict-transport-security: max-age=2592000; includeSubDomains
Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000

{
  "ip": "[REDACTED]",
  "hostname": "[REDACTED]",
  "city": "New York City",
  "region": "New York",
  "country": "US",
  ...
  "timezone": "America/New_York",
  "readme": "https://ipinfo.io/missingauth"
}
```

## Using Cloudflare

You can expose your WebSockets on Cloudflare with [clourdflared](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/trycloudflare/). For example:

```console
% cloudflared tunnel --url http://localhost:8080

2024-03-22T22:06:27Z INF Thank you for trying Cloudflare Tunnel. Doing so, without a Cloudflare account, is a quick way to experiment and try it out. However, be aware that these account-less Tunnels have no uptime guarantee. If you intend to use Tunnels in production you should use a pre-created named tunnel by following: https://developers.cloudflare.com/cloudflare-one/connections/connect-apps
2024-03-22T22:06:27Z INF Requesting new quick Tunnel on trycloudflare.com...
2024-03-22T22:06:28Z INF +--------------------------------------------------------------------------------------------+
2024-03-22T22:06:28Z INF |  Your quick Tunnel has been created! Visit it at (it may take some time to be reachable):  |
2024-03-22T22:06:28Z INF |  https://recorders-uganda-starring-stopping.trycloudflare.com                              |
2024-03-22T22:06:28Z INF +--------------------------------------------------------------------------------------------+
```

In this case, use `wss://recorders-uganda-starring-stopping.trycloudflare.com` as the WebSocket url.

Note that the Cloudflare tunnel does not add any user authentication mechanism. You must implement authentication yourself
if you would like to prevent unauthorized access to your service.

## Shadowsocks over WebSocket

Run the reverse proxy, pointing to your Outline Server:

```sh
go run golang.getoutline.org/sdk/x/examples/ws2endpoint --backend $HOST:$PORT --listen 127.0.0.1:8080
```

Expose the endpoint on Cloudflare:

```sh
cloudflared tunnel --url http://localhost:8080
```

Connect to the Cloudflare domain. For example:

```sh
go run golang.getoutline.org/sdk/x/tools/fetch \
  -transport "tls|ws:tcp_path=/tcp|ss://${REDACTED}@prefix-marion-covered-operators.trycloudflare.com.trycloudflare.com:443" \
  https://ipinfo.io/
```

You can use override to make it easier to insert an Outline key:

```sh
go run golang.getoutline.org/sdk/x/tools/fetch \
  -transport "tls|ws:tcp_path=/tcp|override:host=prefix-marion-covered-operators.trycloudflare.com&port=443|$OUTLINE_KEY" \
  https://ipinfo.io/
```

It's possible to bypass DNS-based blocking by resolving `cloudflare.net`, and SNI-based blocking by using TLS Record Fragmentation:

```sh
go run golang.getoutline.org/sdk/x/tools/fetch \
  -transport "override:host=cloudflare.net|tlsfrag:1|tls|ws:tcp_path=/tcp|ss://${REDACTED}@prefix-marion-covered-operators.trycloudflare.com:443" \
  https://ipinfo.io/
```

The WebSockets transport supports UDP as well:

```sh
go run golang.getoutline.org/sdk/x/tools/resolve \
  -transport "tls|ws:tcp_path=/tcp&udp_path=/udp|ss://${REDACTED}@prefix-marion-covered-operators.trycloudflare.com:443"
  -resolver 8.8.8.8 \
  getoutline.org
```
