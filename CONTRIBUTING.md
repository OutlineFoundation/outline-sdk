# How to contribute

We'd love to accept your patches and contributions to this project.

Please review [Google's Open Source Community Guidelines](https://opensource.google/conduct/).

## Contribution process

If you don't know what to contribute, a good start is to go over the [issue tracker](https://github.com/OutlineFoundation/outline-sdk/issues).

For new features, it's best to share your idea first before going too deep into the implementation,
so we can align on the design.

* If there's a feature request open, share your proposal there.
* Otherwise, start with a discussion on [API Proposals](https://github.com/OutlineFoundation/outline-sdk/discussions/categories/api-proposals).

For bug fixes, you can send a PR directly.

### Code reviews

All submissions, including submissions by project members, require review. We
use GitHub pull requests for this purpose. Consult
[GitHub Help](https://help.github.com/articles/about-pull-requests/) for more
information on using pull requests.

### Sign our Contributor License Agreement

Contributions to this project must be accompanied by a
[Contributor License Agreement](https://cla.developers.google.com/about) (CLA).
You (or your employer) retain the copyright to your contribution; this simply
gives us permission to use and redistribute your contributions as part of the
project.

If you or your current employer have already signed the Google CLA (even if it
was for a different project), you probably don't need to do it again.

Visit <https://cla.developers.google.com/> to see your current agreements or to
sign a new one.

## Repository structure

The repository has two Go modules:

* The root (`/`) module, where all the basic definitions and stable libraries live
* The `/x` module, where higher-level code, extensions and experimental libraries live.

New libraries should start in the `x/` module. We encourage you to create an example in `x/examples` or extend
one of the tools in `x/tools/` to demonstrate your feature.

Only low-level libraries that have been validated should move to the root module.

You cannot make atomic changes across module boundaries. If you need to change both the root and `x` modules
You need to first change root, merge, then you can refer to it in `x`.
Module `x` has a pinned version of the root module in its [`go.mod`](./x/go.mod) file.

To build and run code in the `x` module, you have to enter the `x` folder, or use `go -C x` flag from the repository root.
For example:

```sh
go run -C x ./tools/fetch https://ipinfo.io
```

Or

```sh
go -C x mod tidy
```

## Write Go Documentation

Writing and improving existing documentation is a good way to start with contributions.

The best way to ensure you got the Go doc formatting right is to visualize it.
To visualize the Go documentation you wrote, run:

```sh
go tool pkgsite -dev
```

Then open http://localhost:8080 on your browser. The `-dev` flag is optional and enables developer mode, reloading content on changes.

## Style

We use the standard Go style. Use `gofmt -w <path>` tool to make sure the style is correct.

## Cross-platform Development

### Building

In Go you can compile for other target operating system and architecture by specifying the `GOOS` and `GOARCH` environment variables and using the [`go build` command](https://pkg.go.dev/cmd/go#hdr-Compile_packages_and_dependencies). That only works if you are not using [Cgo](https://pkg.go.dev/cmd/cgo) to call C code.

<details>
  <summary>Examples</summary>

MacOS example:

```console
% GOOS=darwin go build -C x -o ./bin/ ./examples/test-connectivity 
% file ./x/bin/test-connectivity 
./x/bin/test-connectivity: Mach-O 64-bit executable x86_64
```

Linux example:

```console
% GOOS=linux go build -C x -o ./bin/ ./examples/test-connectivity 
% file ./x/bin/test-connectivity                      
./x/bin/test-connectivity: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, Go BuildID=n0WfUGLum4Y6OpYxZYuz/lbtEdv_kvyUCd3V_qOqb/CC_6GAQqdy_ebeYTdn99/Tk_G3WpBWi8vxqmIlIuU, with debug_info, not stripped
```

Windows example:

```console
% GOOS=windows go build -C x -o ./bin/ ./examples/test-connectivity 
% file ./x/bin/test-connectivity.exe 
./x/bin/test-connectivity.exe: PE32+ executable (console) x86-64 (stripped to external PDB), for MS Windows
```

</details>

### Running Android binaries

To run Android binaries, you must have an Android simulator running or a physical device plugged in.

The easiest way is to run a binary is to use the [`go run` command](https://pkg.go.dev/cmd/go#hdr-Compile_and_run_Go_program) directly with the `-exec` flag and our convenience tool `run_on_android.sh`:

```sh
GOOS=android GOARCH=arm64 go -C x run -exec "$(pwd)/run_on_android.sh" ./tools/resolve --resolver 8.8.8.8 example.com
```

It also works with the [`go test` command](https://pkg.go.dev/cmd/go#hdr-Test_packages):

```sh
GOOS=android GOARCH=arm64 go test -exec "$(pwd)/run_on_android.sh"  ./...
```

To build with [cgo](https://pkg.go.dev/cmd/cgo) on Android, you need to set the `CC` environment variable to point to the `clang` compiler in the Android NDK.
The path to the C compiler depends on your Android NDK version, host OS, and target architecture. You can find the correct path within the NDK's `toolchains/llvm/prebuilt/` directory.

For example, to run a tool on a 64-bit ARM Android 30 device from macOS:

```sh
CC="$ANDROID_HOME/ndk/21.3.6528147/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android30-clang" CGO_ENABLED=1 GOOS=android GOARCH=arm64 go -C x run -exec "$(pwd)/run_on_android.sh" ./tools/fetch "https://example.com"
```


<details>
  <summary>Details and direct invocation</summary>

The `run_on_android.sh` script uses the [Android Debug Bridge (`adb`)](https://developer.android.com/tools/adb) to run the binary on a connected Android device (physical or emulator). You must have `adb` in your `PATH`. You can check for connected devices using `adb devices`:

```console
% adb devices
List of devices attached
emulator-5554	device
```

The script will:
1. Push the binary to a temporary location on the device (`/data/local/tmp/test/`).
2. Execute the binary on the device with the provided arguments.
3. Remove the binary from the device after execution.

</details>

### Running Linux binaries

To run Linux binaries you can use a Linux container via [Podman](https://podman.io/).

#### Set up podman
<details>
  <summary>Instructions</summary>

[Install Podman](https://podman.io/docs/installation) (once). On macOS:

```sh
brew install podman
```

Create the podman service VM (once) with the [`podman machine init` command](https://docs.podman.io/en/latest/markdown/podman-machine-init.1.html):

```sh
podman machine init
```

Start the VM with the [`podman machine start` command](https://docs.podman.io/en/latest/markdown/podman-machine-start.1.html), after every time it is stopped:

```sh
podman machine start
```

You can see the VM running with the [`podman machine list` command](https://docs.podman.io/en/latest/markdown/podman-machine-list.1.html):

```console
% podman machine list
NAME                     VM TYPE     CREATED        LAST UP            CPUS        MEMORY      DISK SIZE
podman-machine-default*  qemu        3 minutes ago  Currently running  1           2.147GB     107.4GB
```

When you are done with development, you can stop the machine with the [`podman machine stop` command](https://docs.podman.io/en/latest/markdown/podman-machine-stop.1.html):

```sh
podman machine stop
```

</details>

#### Run

The easiest way is to run a binary is to use the [`go run` command](https://pkg.go.dev/cmd/go#hdr-Compile_and_run_Go_program) directly with the `-exec` flag and our convenience tool `run_on_podman.sh`:

```sh
GOOS=linux go run -C x -exec "$(pwd)/run_on_podman.sh" ./examples/test-connectivity
```

It also works with the [`go test` command](https://pkg.go.dev/cmd/go#hdr-Test_packages):

```sh
GOOS=linux go test -exec "$(pwd)/run_on_podman.sh"  ./...
```

<details>
  <summary>Details and direct invocation</summary>

The `run_on_podman.sh` script uses the [`podman run` command](https://docs.podman.io/en/latest/markdown/podman-run.1.html) and a minimal ["distroless" container image](https://github.com/GoogleContainerTools/distroless) to run the binary you want:

```sh
podman run --arch $(uname -m) --rm -it -v "${bin}":/outline/bin gcr.io/distroless/static-debian11 /outline/bin "$@"
```

You can also use `podman run` directly to run a pre-built binary:

```console
% podman run --rm -it -v ./x/bin:/outline gcr.io/distroless/static-debian11 /outline/test-connectivity
Usage of /outline/test-connectivity:
  -domain string
        Domain name to resolve in the test (default "example.com.")
  -key string
        Outline access key
  -proto string
        Comma-separated list of the protocols to test. Muse be "tcp", "udp", or a combination of them (default "tcp,udp")
  -resolver string
        Comma-separated list of addresses of DNS resolver to use for the test (default "8.8.8.8,2001:4860:4860::8888")
  -v    Enable debug output
```

Flags explanation:

* `--rm`: Remove container (and pod if created) after exit
* `-i` (interactive): Keep STDIN open even if not attached
* `-t` (tty): Allocate a pseudo-TTY for container
* `-v` (volume): Bind mount a volume into the container. Volume source will be on the server machine, not the client

</details>

### Running Windows binaries

To run Windows binaries you can use [Wine](https://en.wikipedia.org/wiki/Wine_(software)) to emulate a Windows environment.
This is not the same as a real Windows environment, so make sure you test on actual Windows machines.

#### Install Wine

<details>
  <summary>Instructions</summary>

Follow the instructions at https://wiki.winehq.org/Download.

On macOS:

```sh
brew tap homebrew/cask-versions
brew install --cask --no-quarantine wine-stable
```

After installation, `wine64` should be on your `PATH`. Check with `wine64 --version`:

```sh
wine64 --version
```

</details>

#### Run

You can pass `wine64` as the `-exec` parameter in the `go` calls.

To build:

```sh
GOOS=windows go run -C x -exec "wine64" ./examples/test-connectivity
```

For tests:

```sh
GOOS=windows go test -exec "wine64"  ./...
```

## Testing

All new code must be accompanied by tests. Tests should be placed in `_test.go` files alongside the code they are testing.

### Running Tests

To run all tests in the repository, run the following commands from the root of the repository:

```sh
go test -race ./...
go test -C x -race ./...
```

This will run all tests except those that have external network dependencies.

### Network Dependant Tests

Some tests have external network dependencies. These tests are tagged with the `nettest` build tag and are not run by default. To run these tests, you must include the `-tags nettest` flag. Our CI runs these tests.

For example:

```sh
go test -v -race -tags nettest
```

### Benchmarks

To run benchmarks:

```sh
go test -race -bench '.' ./... -benchtime=100ms
go -C x test -race -bench '.' ./... -benchtime=100ms
```

### Continuous Integration (CI)

All pull requests are tested on our CI system. The CI runs all tests, including `nettest`s, on Linux, macOS, and Windows. It also runs tests on an Android emulator. You can see the CI configuration in [`.github/workflows/test.yml`](.github/workflows/test.yml).
