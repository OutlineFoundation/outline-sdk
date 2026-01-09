# Local Proxy with Fyne

This folder has a graphical application that runs a local proxy given a address and configuration.
It uses [Fyne](https://fyne.io/) for the UI.


<img width="231" alt="image" src="https://github.com/OutlineFoundation/outline-sdk/assets/113565/5d985cb6-3df7-4781-88b0-29f62b22d6d9">
<img width="231" alt="image" src="https://github.com/OutlineFoundation/outline-sdk/assets/113565/396390ab-4c47-4da9-a544-68645b28e45a">

You can configure your system to use the proxy, as per the instructions below:

- [Windows](https://support.microsoft.com/en-us/windows/use-a-proxy-server-in-windows-03096c53-0554-4ffe-b6ab-8b1deee8dae1)
- [macOS](https://support.apple.com/guide/mac-help/change-proxy-settings-on-mac-mchlp2591/mac)
- [Ubuntu](https://help.ubuntu.com/stable/ubuntu-help/net-proxy.html.en)
- [Other systems and browsers](https://www.avast.com/c-how-to-set-up-a-proxy) (disregard the Avast ads)

## Network Mode
By default the proxy runs on `localhost`, meaning only your host can access it. You can change the address to your local network IP address, and
that will make the proxy available to all devices on the network. Consider the fact that anyone can find and access your server before running
it in local network mode in a public network or a network you don't trust.

## Global Mode
We don't recommend using 0.0.0.0, since that may open up your machine to the outside, and currently there's no encryption or authentication to protect the access.

## Desktop

You can run the app without explicitly cloning the repository with:

```sh
go run github.com/Jigsaw-Code/outline-sdk/x/examples/fyne-proxy@latest
```

To run the local version while developing, from the `fyne-proxy` directory:

```sh
go run .
```

To package, from the app folder:

```sh
go run fyne.io/fyne/v2/cmd/fyne package
```


## Android

To run the app, start the emulator, call fyne install to build and install the app. See https://developer.android.com/studio/run/emulator-commandline

```sh
# Point ANDROID_NDK_HOME to the right location
export ANDROID_NDK_HOME="$HOME/Library/Android/sdk/ndk/26.1.10909125"
# Start the emulator.
$ANDROID_HOME/emulator/emulator -no-boot-anim -avd Pixel_3a_API_33_arm64-v8a
go run fyne.io/fyne/v2/cmd/fyne install -os android
```

If you need, you can build the APK, then install like this:

```sh
go run fyne.io/fyne/v2/cmd/fyne package -os android -appID com.example.myapp
$ANDROID_HOME/platform-tools/adb install ./Local_Proxy.apk
```

## iOS

Install on a running simulator:

```sh
go run fyne.io/fyne/v2/cmd/fyne install -os iossimulator
```

If you package it first, you can install the .app with:

```sh
xcrun simctl install booted ./Local_Proxy.app
```

To install on a real device, you need `ios-deploy` (`brew install ios-deploy`). After you connect your phone, run:

```sh
go run fyne.io/fyne/v2/cmd/fyne install -os ios
```
