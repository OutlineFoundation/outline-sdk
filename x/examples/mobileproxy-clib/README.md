# Mobileproxy CLib Wrapper

This is a C wrapper for the mobileproxy library. It is intended to be used downstream by native wrappers like Swift or Java.

## Demo

To run the demo, you first must build the library for your platform. You can build the library by running:

```bash
cd x

CGO_ENABLED=1 go build -buildmode=c-shared -o=examples/mobileproxy-clib/demo/mobileproxy-clib ./examples/mobileproxy-clib
```

Then, you can build and run the demo by doing the following:

```bash
cd examples/mobileproxy-clib/demo

# build the demo
gcc -o demo demo.c mobileproxy-clib

# run the demo
./demo
```
