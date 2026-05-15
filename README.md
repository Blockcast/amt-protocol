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
- **native**: tokio-based async runtime + `amt-verify` CLI

## CLI: `amt-verify`

A native CLI for end-to-end AMT tunnel verification (one-shot or `--watch`),
built when this crate is compiled with `--features native`:

```bash
cargo build --release --no-default-features --features native --bin amt-verify
```

See [`docs/runbook-staging-e2e.md`](docs/runbook-staging-e2e.md) for the
staging verification procedure.

## License

MIT
