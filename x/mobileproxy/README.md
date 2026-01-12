# MobileProxy: Local Proxy Library for Mobile Apps

This package enables the use Go Mobile to generate a mobile library to run a local proxy and configure your app networking libraries.

**Content app without MobileProxy:**
![image](https://github.com/user-attachments/assets/d96b209c-2198-4382-8bba-12efd8f75dbb)

**Content app with MobileProxy:**
![image](https://github.com/user-attachments/assets/8b07c0b6-7948-4b61-a6b2-fe2fafdb1a33)

The integration typically consists of the following steps:
1. Build the mobile native library using Go Mobile.
1. Add the library to your application.
1. Configure and run MobileProxy within your app.
1. Update your networking code to proxy traffic through the local MobileProxy.


### Flutter Apps

To integrate the MobileProxy into a Flutter app, follow this excellent tutorial by Anash Nouri: [Flutter Embedded VPN](https://blog.stackademic.com/flutter-embedded-vpn-c47144798995). Of note: MobileProxy doesn't actually use VPN apis, and may not even need to use a proxy.

### Web Apps (Experimental)

If you are looking into converting a web site or web app into a censorship-resistant mobile app, look at the [Outline App Maker](https://github.com/OutlineFoundation/outline-app-maker). 

## Add the MobileProxy dependency

### Import natively built libraries

We build and release the Mobileproxy library separately. To learn how to use the pre-compiled version, see the [Mobileproxy SDK Repository](https://github.com/OutlineFoundation/mobileproxylib#integration)

### Build the MobileProxy libraries for Android and iOS

Should you want or need to build Mobileproxy yourself, first build the Go Mobile binaries with [`go build`](https://pkg.go.dev/cmd/go#hdr-Compile_packages_and_dependencies)

From the `x/` directory:

```bash
go build -o "$(pwd)/out/" golang.org/x/mobile/cmd/gomobile golang.org/x/mobile/cmd/gobind
```

> [!WARNING]
> The Psiphon library is not included in the build by default because the Psiphon codebase uses GPL. To support Psiphon configuration in the Mobile Proxy please build using the [`psiphon` build tag](https://pkg.go.dev/golang.getoutline.org/sdk/x/psiphon).
> When integrating Psiphon into your application please work with the Psiphon team at sponsor@psiphon.ca

Then build the iOS and Android libraries with [`gomobile bind`](https://pkg.go.dev/golang.org/x/mobile/cmd/gomobile#hdr-Build_a_library_for_Android_and_iOS)

```bash
PATH="$(pwd)/out:$PATH" gomobile bind -ldflags='-s -w' -target=ios -iosversion=11.0 -o "$(pwd)/out/mobileproxy.xcframework" golang.getoutline.org/sdk/x/mobileproxy
PATH="$(pwd)/out:$PATH" gomobile bind -ldflags='-s -w' -target=android -androidapi=21 -o "$(pwd)/out/mobileproxy.aar" golang.getoutline.org/sdk/x/mobileproxy
```

To include Psiphon support please also include the `-tags=psiphon` flag and the psiphon library.

```bash
PATH="$(pwd)/out:$PATH" gomobile bind -ldflags='-s -w' -target=ios -iosversion=11.0 -tags=psiphon -o "$(pwd)/out/mobileproxy.xcframework" golang.getoutline.org/sdk/x/mobileproxy golang.getoutline.org/sdk/x/mobileproxy/psiphon
PATH="$(pwd)/out:$PATH" gomobile bind -ldflags='-s -w' -target=android -androidapi=21 -tags=psiphon -o "$(pwd)/out/mobileproxy.aar" golang.getoutline.org/sdk/x/mobileproxy golang.getoutline.org/sdk/x/mobileproxy/psiphon
```

Then, in your native code, register Psiphon with your Smart Dialer options.

Android:

```kotlin
import mobileproxy.Mobileproxy
import psiphon.Psiphon

// ...

val testDomains = Mobileproxy.newListFromLines("www.google.com\ni.ytimg.com")
// You can get a Psiphon config from the Psiphon team at sponsor@psiphon.ca.
val psiphonConfig = "<YOUR_PSIPHON_CONFIG_JSON_HERE>"
val config = """
dns:
  - {system: {}}
tls:
  - ""
fallback:
  - {"psiphon": \(psiphonConfig)}
"""

val options = Mobileproxy.newSmartDialerOptions(testDomains, config)

// Register Psiphon
Psiphon.registerFallbackParser(options, "psiphon")

try {
    // Create the dialer
    val dialer = options.newStreamDialer()
    // ... use the dialer
} catch (e: Exception) {
    // Handle error
}
```

iOS:

```swift
import Mobileproxy
import Psiphon

// ...

let testDomains = MobileproxyNewListFromLines("www.google.com\ni.ytimg.com")
// You can get a Psiphon config from the Psiphon team at sponsor@psiphon.ca.
let psiphonConfig = "<YOUR_PSIPHON_CONFIG_JSON_HERE>"
let config = """
dns:
  - {system: {}}
tls:
  - ""
fallback:
  - {"psiphon": \(psiphonConfig)}
"""

let options = MobileproxyNewSmartDialerOptions(testDomains, config)

// Register Psiphon
PsiphonRegisterFallbackParser(options, "psiphon")

do {
    // Create the dialer
    let dialer = try options.newStreamDialer()
    // ... use the dialer
} catch {
    // Handle error
}
```

Note: Gomobile expects gobind to be in the PATH, that's why we need to prebuild it, and set up the PATH accordingly.

The `-ldflags='-s -w'` flag strips debug symbols to reduce the size of the output library.

See [our Github Test Action](https://github.com/OutlineFoundation/outline-sdk/blob/main/.github/workflows/test.yml) for how we build the Mobileproxy in our tests.

<details>
<summary>Sample iOS generated Code</summary>

The header file below is an example of the Objective-C interface that Go Mobile generates.

> **Warning**: this example may diverge from what is actually generated by the current code. Use the coed you generate instead.

`Mobileproxy.objc.h`:

```objc
// Objective-C API for talking to golang.getoutline.org/sdk/x/mobileproxy Go package.
//   gobind -lang=objc golang.getoutline.org/sdk/x/mobileproxy
//
// File is generated by gobind. Do not edit.

#ifndef __Mobileproxy_H__
#define __Mobileproxy_H__

@import Foundation;
#include "ref.h"
#include "Universe.objc.h"


@class MobileproxyProxy;
@class MobileproxyStreamDialer;
@class MobileproxyStringList;
@protocol MobileproxyLogWriter;
@class MobileproxyLogWriter;

@protocol MobileproxyLogWriter <NSObject>
- (BOOL)writeString:(NSString* _Nullable)s n:(long* _Nullable)n error:(NSError* _Nullable* _Nullable)error;
@end

/**
 * Proxy enables you to get the actual address bound by the server and stop the service when no longer needed.
 */
@interface MobileproxyProxy : NSObject <goSeqRefInterface> {
}
@property(strong, readonly) _Nonnull id _ref;

- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
- (nonnull instancetype)init;
/**
 * Address returns the IP and port the server is bound to.
 */
- (NSString* _Nonnull)address;
/**
 * Host returns the IP the server is bound to.
 */
- (NSString* _Nonnull)host;
/**
 * Port returns the port the server is bound to.
 */
- (long)port;
/**
 * Stop gracefully stops the proxy service, waiting for at most timeout seconds before forcefully closing it.
The function takes a timeoutSeconds number instead of a [time.Duration] so it's compatible with Go Mobile.
 */
- (void)stop:(long)timeoutSeconds;
@end

/**
 * StreamDialer encapsulates the logic to create stream connections (like TCP).
 */
@interface MobileproxyStreamDialer : NSObject <goSeqRefInterface> {
}
@property(strong, readonly) _Nonnull id _ref;

- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
/**
 * NewStreamDialerFromConfig creates a [StreamDialer] based on the given config.
The config format is specified in https://pkg.go.dev/golang.getoutline.org/sdk/x/configurl#hdr-Configuration_Format.
 */
- (nullable instancetype)initFromConfig:(NSString* _Nullable)transportConfig;
// skipped field StreamDialer.StreamDialer with unsupported type: golang.getoutline.org/sdk/transport.StreamDialer

// skipped method StreamDialer.DialStream with unsupported parameter or return types

@end

/**
 * StringList allows us to pass a list of strings to the Go Mobile functions, since Go Mobiule doesn't
support slices as parameters.
 */
@interface MobileproxyStringList : NSObject <goSeqRefInterface> {
}
@property(strong, readonly) _Nonnull id _ref;

- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
- (nonnull instancetype)init;
/**
 * Append adds the string value to the end of the list.
 */
- (void)append:(NSString* _Nullable)value;
@end

/**
 * NewListFromLines creates a StringList by splitting the input string on new lines.
 */
FOUNDATION_EXPORT MobileproxyStringList* _Nullable MobileproxyNewListFromLines(NSString* _Nullable lines);

/**
 * NewSmartStreamDialer automatically selects a DNS and TLS strategy to use, and return a [StreamDialer]
that will use the selected strategy.
It uses testDomain to find a strategy that works when accessing those domains.
The strategies to search are given in the searchConfig. An example can be found in
https://github.com/OutlineFoundation/outline-sdk/blob/main/x/examples/smart-proxy/config.yaml
 */
FOUNDATION_EXPORT MobileproxyStreamDialer* _Nullable MobileproxyNewSmartStreamDialer(MobileproxyStringList* _Nullable testDomains, NSString* _Nullable searchConfig, id<MobileproxyLogWriter> _Nullable logWriter, NSError* _Nullable* _Nullable error);

/**
 * NewStderrLogWriter creates a [LogWriter] that writes to the standard error output.
 */
FOUNDATION_EXPORT id<MobileproxyLogWriter> _Nullable MobileproxyNewStderrLogWriter(void);

/**
 * NewStreamDialerFromConfig creates a [StreamDialer] based on the given config.
The config format is specified in https://pkg.go.dev/golang.getoutline.org/sdk/x/configurl#hdr-Configuration_Format.
 */
FOUNDATION_EXPORT MobileproxyStreamDialer* _Nullable MobileproxyNewStreamDialerFromConfig(NSString* _Nullable transportConfig, NSError* _Nullable* _Nullable error);

/**
 * RunProxy runs a local web proxy that listens on localAddress, and handles proxy requests by
establishing connections to requested destination using the [StreamDialer].
 */
FOUNDATION_EXPORT MobileproxyProxy* _Nullable MobileproxyRunProxy(NSString* _Nullable localAddress, MobileproxyStreamDialer* _Nullable dialer, NSError* _Nullable* _Nullable error);

@class MobileproxyLogWriter;

/**
 * LogWriter is used as a sink for logging.
 */
@interface MobileproxyLogWriter : NSObject <goSeqRefInterface, MobileproxyLogWriter> {
}
@property(strong, readonly) _Nonnull id _ref;

- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
- (BOOL)writeString:(NSString* _Nullable)s n:(long* _Nullable)n error:(NSError* _Nullable* _Nullable)error;
@end

#endif
```

</details>

<details>
  <summary>Sample Android generated Code</summary>

The files below are examples of the Java interface that Go Mobile generates.

> **Warning**: this example may diverge from what is actually generated by the current code. Use the coed you generate instead.

`LogWriter.java`:

```java
// Code generated by gobind. DO NOT EDIT.

// Java class mobileproxy.LogWriter is a proxy for talking to a Go program.
//
//   autogenerated by gobind -lang=java golang.getoutline.org/sdk/x/mobileproxy
package mobileproxy;

import go.Seq;

/**
 * LogWriter is used as a sink for logging.
 */
public interface LogWriter {
	public long writeString(String s) throws Exception;
	
}
```
`StreamDialer.java`:

```java
// Code generated by gobind. DO NOT EDIT.

// Java class mobileproxy.StreamDialer is a proxy for talking to a Go program.
//
//   autogenerated by gobind -lang=java golang.getoutline.org/sdk/x/mobileproxy
package mobileproxy;

import go.Seq;

/**
 * StreamDialer encapsulates the logic to create stream connections (like TCP).
 */
public final class StreamDialer implements Seq.Proxy {
	static { Mobileproxy.touch(); }
	
	private final int refnum;
	
	@Override public final int incRefnum() {
	      Seq.incGoRef(refnum, this);
	      return refnum;
	}
	
	/**
	 * NewStreamDialerFromConfig creates a [StreamDialer] based on the given config.
	 * The config format is specified in https://pkg.go.dev/golang.getoutline.org/sdk/x/configurl#hdr-Configuration_Format.
	 */
	public StreamDialer(String transportConfig) {
		this.refnum = __NewStreamDialerFromConfig(transportConfig);
		Seq.trackGoRef(refnum, this);
	}
	
	private static native int __NewStreamDialerFromConfig(String transportConfig);
	
	StreamDialer(int refnum) { this.refnum = refnum; Seq.trackGoRef(refnum, this); }
	
	// skipped field StreamDialer.StreamDialer with unsupported type: golang.getoutline.org/sdk/transport.StreamDialer
	
	// skipped method StreamDialer.DialStream with unsupported parameter or return types
	
	@Override public boolean equals(Object o) {
		if (o == null || !(o instanceof StreamDialer)) {
		    return false;
		}
		StreamDialer that = (StreamDialer)o;
		// skipped field StreamDialer.StreamDialer with unsupported type: golang.getoutline.org/sdk/transport.StreamDialer
		
		return true;
	}
	
	@Override public int hashCode() {
	    return java.util.Arrays.hashCode(new Object[] {});
	}
	
	@Override public String toString() {
		StringBuilder b = new StringBuilder();
		b.append("StreamDialer").append("{");
		return b.append("}").toString();
	}
}
```


`Mobileproxy.java`:

```java
// Code generated by gobind. DO NOT EDIT.

// Java class mobileproxy.Mobileproxy is a proxy for talking to a Go program.
//
//   autogenerated by gobind -lang=java golang.getoutline.org/sdk/x/mobileproxy
package mobileproxy;

import go.Seq;

public abstract class Mobileproxy {
	static {
		Seq.touch(); // for loading the native library
		_init();
	}
	
	private Mobileproxy() {} // uninstantiable
	
	// touch is called from other bound packages to initialize this package
	public static void touch() {}
	
	private static native void _init();
	
	private static final class proxyLogWriter implements Seq.Proxy, LogWriter {
		private final int refnum;
		
		@Override public final int incRefnum() {
		      Seq.incGoRef(refnum, this);
		      return refnum;
		}
		
		proxyLogWriter(int refnum) { this.refnum = refnum; Seq.trackGoRef(refnum, this); }
		
		public native long writeString(String s) throws Exception;
	}
	
	
	/**
	 * NewListFromLines creates a StringList by splitting the input string on new lines.
	 */
	public static native StringList newListFromLines(String lines);
	/**
	 * NewSmartStreamDialer automatically selects a DNS and TLS strategy to use, and return a [StreamDialer]
	 * that will use the selected strategy.
	 * It uses testDomain to find a strategy that works when accessing those domains.
	 * The strategies to search are given in the searchConfig. An example can be found in
	 * https://github.com/OutlineFoundation/outline-sdk/blob/main/x/examples/smart-proxy/config.yaml
	 */
	public static native StreamDialer newSmartStreamDialer(StringList testDomains, String searchConfig, LogWriter logWriter) throws Exception;
	/**
	 * NewStderrLogWriter creates a [LogWriter] that writes to the standard error output.
	 */
	public static native LogWriter newStderrLogWriter();
	/**
	 * NewStreamDialerFromConfig creates a [StreamDialer] based on the given config.
	 * The config format is specified in https://pkg.go.dev/golang.getoutline.org/sdk/x/configurl#hdr-Configuration_Format.
	 */
	public static native StreamDialer newStreamDialerFromConfig(String transportConfig) throws Exception;
	/**
	 * RunProxy runs a local web proxy that listens on localAddress, and handles proxy requests by
	 * establishing connections to requested destination using the [StreamDialer].
	 */
	public static native Proxy runProxy(String localAddress, StreamDialer dialer) throws Exception;
}
```

`Proxy.java`:
  
```java
// Code generated by gobind. DO NOT EDIT.

// Java class mobileproxy.Proxy is a proxy for talking to a Go program.
//
//   autogenerated by gobind -lang=java golang.getoutline.org/sdk/x/mobileproxy
package mobileproxy;

import go.Seq;

/**
 * Proxy enables you to get the actual address bound by the server and stop the service when no longer needed.
 */
public final class Proxy implements Seq.Proxy {
	static { Mobileproxy.touch(); }
	
	private final int refnum;
	
	@Override public final int incRefnum() {
	      Seq.incGoRef(refnum, this);
	      return refnum;
	}
	
	Proxy(int refnum) { this.refnum = refnum; Seq.trackGoRef(refnum, this); }
	
	public Proxy() { this.refnum = __New(); Seq.trackGoRef(refnum, this); }
	
	private static native int __New();
	
	/**
	 * Address returns the IP and port the server is bound to.
	 */
	public native String address();
	/**
	 * Host returns the IP the server is bound to.
	 */
	public native String host();
	/**
	 * Port returns the port the server is bound to.
	 */
	public native long port();
	/**
	 * Stop gracefully stops the proxy service, waiting for at most timeout seconds before forcefully closing it.
	 * The function takes a timeoutSeconds number instead of a [time.Duration] so it&#39;s compatible with Go Mobile.
	 */
	public native void stop(long timeoutSeconds);
	@Override public boolean equals(Object o) {
		if (o == null || !(o instanceof Proxy)) {
		    return false;
		}
		Proxy that = (Proxy)o;
		return true;
	}
	
	@Override public int hashCode() {
	    return java.util.Arrays.hashCode(new Object[] {});
	}
	
	@Override public String toString() {
		StringBuilder b = new StringBuilder();
		b.append("Proxy").append("{");
		return b.append("}").toString();
	}
}
```

`StringList.java`:
  
```java
// Code generated by gobind. DO NOT EDIT.

// Java class mobileproxy.StringList is a proxy for talking to a Go program.
//
//   autogenerated by gobind -lang=java golang.getoutline.org/sdk/x/mobileproxy
package mobileproxy;

import go.Seq;

/**
 * StringList allows us to pass a list of strings to the Go Mobile functions, since Go Mobiule doesn&#39;t
 * support slices as parameters.
 */
public final class StringList implements Seq.Proxy {
	static { Mobileproxy.touch(); }
	
	private final int refnum;
	
	@Override public final int incRefnum() {
	      Seq.incGoRef(refnum, this);
	      return refnum;
	}
	
	StringList(int refnum) { this.refnum = refnum; Seq.trackGoRef(refnum, this); }
	
	public StringList() { this.refnum = __New(); Seq.trackGoRef(refnum, this); }
	
	private static native int __New();
	
	/**
	 * Append adds the string value to the end of the list.
	 */
	public native void append(String value);
	@Override public boolean equals(Object o) {
		if (o == null || !(o instanceof StringList)) {
		    return false;
		}
		StringList that = (StringList)o;
		return true;
	}
	
	@Override public int hashCode() {
	    return java.util.Arrays.hashCode(new Object[] {});
	}
	
	@Override public String toString() {
		StringBuilder b = new StringBuilder();
		b.append("StringList").append("{");
		return b.append("}").toString();
	}
}
```



</details>

### Add the library to your mobile project

To add the library to your mobile project, see Go Mobile's [Building and deploying to iOS](https://go.dev/wiki/Mobile#building-and-deploying-to-ios-1) and [Building and deploying to Android](https://go.dev/wiki/Mobile#building-and-deploying-to-android-1).


## Configure and run the local proxy forwarder

You have the option to use a static configuration (which you may fetch dynamically from a remote resource), or use the Smart Proxy, which picks a DNS and TLS strategy for you automatically and doesn't need to tunnel traffic.

### Using static transport configuration

You need to call the `RunProxy` function passing the local address to use, and the transport configuration.

On Android, you can have the following Kotlin code:
```kotlin
// Use port zero to let the system pick an open port for you.
val dialer = StreamDialer("split:3")

val proxy = Mobileproxy.runProxy("localhost:0", dialer)
// Configure your networking library using proxy.host() and proxy.port() or proxy.address().
// ...
// Stop running the proxy.
proxy.stop()
```

### Using the Smart Proxy

The Smart Proxy can automatically try multiple strategies to unblock access to the test domains you specify.
You need to specify a strategy config in YAML format ([example](../examples/smart-proxy/config.yaml)). 

On Android, the Kotlin code would look like this:
```kotlin
// Use port zero to let the system pick an open port for you.
val testDomains = Mobileproxy.newListFromLines("www.youtube.com\ni.ytimg.com")
val strategiesConfig = "..."  // Config YAML.
val dialer = Mobileproxy.newSmartStreamDialer(testDomains, strategiesConfig, Mobileproxy.newStderrLogWriter())

val proxy = Mobileproxy.runProxy("localhost:0", dialer)
// Configure your networking library using proxy.host() and proxy.port() or proxy.address().
// ...
// Stop running the proxy.
proxy.stop()
```

## Configure your HTTP client or networking library

You need to configure your networking library to use the local proxy. How you do it depends on the networking library you are using.


### Dart/Flutter HttpClient

Set the proxy with the [`HttpClient.findProxy`]([url](https://api.flutter.dev/flutter/dart-io/HttpClient/findProxy.html)) function.

Dart example:

```dart
  HttpClient client = HttpClient();
  client.findProxy = (Uri uri) {
    return "PROXY " + proxy.address();
  };
```


### OkHttp (Android only)

Set the proxy with [`OkHttpClient.Builder.proxy`](https://square.github.io/okhttp/4.x/okhttp/okhttp3/-ok-http-client/-builder/proxy/).

Kotlin example:

```kotlin
val proxyConfig = Proxy(Proxy.Type.HTTP, InetSocketAddress(proxy.host(), proxy.port()))
val client = OkHttpClient.Builder().proxy(proxyConfig).build()
```

### JVM (Java, Kotlin)

In the JVM, you can configure the proxy to use with [system properties](https://docs.oracle.com/javase/8/docs/technotes/guides/net/proxies.html):
```kotlin
System.setProperty("http.proxyHost", proxy.host())
System.setProperty("http.proxyPort", String.valueOf(proxy.port()))
System.setProperty("https.proxyHost", proxy.host())
System.setProperty("https.proxyPort", String.valueOf(proxy.port()))
```

Note that this may not fully work on Android, since it will only affect the JVM, not native code. You should also make sure you set this early in your code.

### Web View

#### Android

On Android, you can easily apply a proxy configuration to all the web views in your application with the [`androidx.webview`](https://developer.android.com/reference/androidx/webkit/ProxyController) library like so:

```kotlin
ProxyController.getInstance()
		.setProxyOverride(
				ProxyConfig.Builder()
						.addProxyRule(this.proxy!!.address())
						.build(),
				{}, // execution context for the following callback - do anything needed here once the proxy is applied, like refreshing web views 
				{} // callback to be called once the ProxyConfig is applied
		)
```

#### iOS

As of iOS 17, you can add a proxy configuration to a `WKWebView` via its [`WKWebsiteDataStore` property](https://developer.apple.com/documentation/webkit/wkwebviewconfiguration).

```swift
let configuration = WKWebViewConfiguration()

let endpoint = NWEndpoint.hostPort(
		host: NWEndpoint.Host(proxyHost),
		port: NWEndpoint.Port(proxyPort)!
)
let proxyConfig = ProxyConfiguration.init(httpCONNECTProxy: endpoint)

let websiteDataStore = WKWebsiteDataStore.default()
websiteDataStore.proxyConfigurations = [proxyConfig]

// Other webview configuration options... see https://developer.apple.com/documentation/webkit/wkwebviewconfiguration

let webview = WKWebView(
	configuration: configuration,
)

// use this webview as you would normally!
```

## Clean up

```bash
rm -rf ./out/
```
