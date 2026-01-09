# Outline VPN Command-Line Client

A CLI interface of Outline VPN client for Linux.

### Usage

```
go run golang.getoutline.org/sdk/x/examples/outline-cli@latest -transport "ss://<outline-server-access-key>"
```

- `-transport` : the Outline server access key from the service provider, it should start with "ss://"

### Build

You can use the following command to build the CLI.


```
cd outline-sdk/x/examples/
go build -o outline-cli  -ldflags="-extldflags=-static" ./outline-cli
```

> 💡 `cgo` will pull in the C runtime. By default, the C runtime is linked as a dynamic library. Sometimes this can cause problems when running the binary on different versions or distributions of Linux. To avoid this, we have added the `-ldflags="-extldflags=-static"` option. But if you only need to run the binary on the same machine, you can omit this option.
