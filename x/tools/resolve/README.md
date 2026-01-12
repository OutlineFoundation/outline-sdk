# Domain Resolution Tool

The `resolve` tool lets you resolve domain names with custom DNS resolvers and using configurable transports.

Usage:

```txt
Usage: resolve [flags...] <domain>
  -resolver string
        The address of the recursive DNS resolver to use in host:port format. If the port is missing, it's assumed to be 53
  -tcp
        Force TCP when querying the DNS resolver
  -transport string
        The transport for the connection to the recursive DNS resolver
  -type string
        The type of the query (A, AAAA, CNAME, NS or TXT). (default "A")
  -v    Enable debug output
```

Lookup the IPv4 for `www.rferl.org` using the system resolver:

```console
$ go run golang.getoutline.org/sdk/x/tools/resolve www.rferl.org
104.102.138.8
```

Use `-type aaaa` to lookup the IPv6:

```console
$ go run golang.getoutline.org/sdk/x/tools/resolve -type aaaa www.rferl.org
2600:141b:1c00:1098::1317
2600:141b:1c00:10a1::1317
```

Use `-resolver` to specify which resolver to use. In this case we use Google's Public DNS:

```console
$ go run golang.getoutline.org/sdk/x/tools/resolve -resolver 8.8.8.8 www.rferl.org
104.102.138.83
```

It's possible to specify a proxy to connect to the resolver using the `-transport` flag. This is very helpful for experimentation. In the example below, we resolve via a remote proxy in Russia. When using a remote server, you must also specify the resolver to use. Note in the example output how the domain is blocked with a CNAME to `fz139.ttk.ru`

```console
$ KEY=ss://[REDACTED OUTLINE KEY]
$ go run golang.getoutline.org/sdk/x/tools/resolve -type CNAME -transport "$KEY" -resolver 8.8.8.8 www.rferl.org
fz139.ttk.ru.
```

Using Quad9 in the Russian server bypasses the blocking:

```console
$ KEY=ss://[REDACTED OUTLINE KEY]
$ go run golang.getoutline.org/sdk/x/tools/resolve -type CNAME -transport "$KEY" -resolver 9.9.9.9 www.rferl.org
e4887.dscb.akamaiedge.net.
```

It's possible to specify non-standard ports. For example, OpenDNS supports port 443:

```console
$ go run golang.getoutline.org/sdk/x/tools/resolve -type CNAME -resolver 208.67.222.222:443 www.rferl.org
e4887.dscb.akamaiedge.net.
```

However, it seems UDP on alternate ports is blocked in our remote test proxy:

```console
$ KEY=ss://[REDACTED OUTLINE KEY]
$ go run golang.getoutline.org/sdk/x/tools/resolve -type CNAME -transport "$KEY" -resolver 208.67.222.222:443 www.rferl.org
2023/10/13 19:04:18 Failed to lookup CNAME: lookup www.rferl.org on 208.67.222.222:443: could not create PacketConn: could not connect to endpoint: dial udp [REDACTED ADDRESS]: i/o timeout
exit status 1
```

By forcing TCP with the `-tcp` flag, you can make it work again:

```console
$ KEY=ss://[REDACTED OUTLINE KEY]
$ go run golang.getoutline.org/sdk/x/tools/resolve -type CNAME -transport "$KEY" -resolver 208.67.222.222:443 -tcp www.rferl.org
e4887.dscb.akamaiedge.net.
```

Forcing TCP lets you use stream fragmentation. In this example, we split the first 20 bytes:

```console
$ go run golang.getoutline.org/sdk/x/tools/resolve -type CNAME -tcp -transport "split:20" -resolver 208.67.222.222:443 www.rferl.org
e4887.dscb.akamaiedge.net.
```

You can see that the domain name in the query got split:

![image](https://github.com/OutlineFoundation/outline-sdk/assets/113565/195bfa95-6d35-40ef-84e0-b1d6e690bb84)
