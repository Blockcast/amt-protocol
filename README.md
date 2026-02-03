# AMT Protocol Library

Rust implementation of the Automatic Multicast Tunneling (AMT) protocol ([RFC 7450](https://tools.ietf.org/html/rfc7450)).

Multi-platform library with FFI, WASM, and JNI targets.

## Building

### FFI (for CGO/C/C++)

```bash
make ffi
# Output: target/release/libamt_protocol.{so,a}
```

### Install to system

```bash
make install
# Or with custom prefix:
make install INSTALL_PREFIX=/opt/amt
```

### WASM (for web browsers)

```bash
make install-wasm-deps  # one-time
make wasm
# Output: dist/wasm/
```

### Android JNI

```bash
make install-android-deps  # one-time
export ANDROID_NDK_HOME=/path/to/ndk
make jni
# Output: dist/android/
```

## Usage with Go (CGO)

After installing the library:

```go
import "github.com/blockcast/go-amt"
```

Build with CGO enabled:

```bash
CGO_ENABLED=1 go build
```

## Features

- **ffi**: C FFI bindings (staticlib + cdylib)
- **wasm**: WebAssembly via wasm-bindgen
- **jni**: Android JNI bindings

## License

MIT
