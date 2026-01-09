# DNS System Resolver Lookup Utility

To run:

```console
go run github.com/Jigsaw-Code/outline-sdk/x/examples/fyne-tools@latest
```

## Android

Package for Android and install on emulator or device:
```
go run fyne.io/fyne/v2/cmd/fyne package -os android && adb install Net_Tools.apk
```

Note: the generated APK is around 85MB.


## Windows

If you are on Windows, you can just use the regular `go build` or `go run` command.

Because the app uses cgo, we need to cross-compilation tools to build from other platforms.

If you are on macOS, you can build the Windows app with [MinGW-x64](https://www.mingw-w64.org/).

First install MinGW-w64. MacPorts is the [official channel](https://www.mingw-w64.org/downloads/#macports):

```
sudo port install x86_64-w64-mingw32-gcc
```

With Homebrew (unofficial):

```
brew install mingw-w64
```

Build the app (64-bit):

```
GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC="x86_64-w64-mingw32-gcc" go build .
```

The first build will take minutes, since there's a lot of platform code to be built.
Subsequent builds will be incremental and take a few seconds.

## Screenshots

<img width="400" alt="image" src="https://github.com/OutlineFoundation/outline-sdk/assets/113565/8cead9da-461e-41c8-8ce3-f263d77c6ee8">

<img width="462" alt="image" src="https://github.com/OutlineFoundation/outline-sdk/assets/113565/9782eab3-d142-4be7-9431-5384c866384d">