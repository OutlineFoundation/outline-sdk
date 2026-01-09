# HTTP-to-Transport

This app runs a local HTTP-CONNECT proxy that dials the target using the transport configured in the command-line.

Flags:
- `-transport` for the transport to use.
- `-addr` for the local address to listen on, in host:port format. Use `localhost:0` if you want the system to dynamically pick a port for you.

Example:
```
KEY=ss://ENCRYPTION_KEY@HOST:PORT/
go run golang.getoutline.org/sdk/x/tools/http2transport@latest -transport "$KEY" -localAddr localhost:54321
```
