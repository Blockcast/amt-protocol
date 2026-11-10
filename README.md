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
# Output: dist/android/<abi>/libamt_protocol.so  (arm64-v8a, armeabi-v7a, x86, x86_64)
```

The library exports the JNI symbols for `com.blockcast.sdk.amt.AmtGateway`;
load it with `System.loadLibrary("amt_protocol")`. Minimum Android API level
is 21 (cargo-ndk's default).

#### Prebuilt libraries

[`.github/workflows/android-jni.yml`](.github/workflows/android-jni.yml) runs
`make jni` on every pull request and push to `main`, and uploads
`dist/android/` as the workflow artifact `android-jni` (jniLibs layout,
`<abi>/libamt_protocol.so`; artifacts expire after the repository's retention
period). On a `v*` tag it also attaches to the GitHub release:

- `libamt_protocol-android-<abi>-<tag>.tar.gz`, one per ABI
- `libamt_protocol-android-<tag>.zip`, all four ABIs in jniLibs layout
- `SHA256SUMS`

The toolchain is pinned in that workflow: the Rust version from
`rust-toolchain.toml`, the Android NDK (an LTS release, downloaded from
Google and sha256-verified) and the cargo-ndk version. cargo-ndk links with
`-z max-page-size=16384`, so the libraries load on 16 KiB-page devices.

To pin a consumer to a release, fetch by tag and verify before unpacking into
the app's `jniLibs` directory:

```bash
TAG=v0.2.0  # any release tag cut after this workflow landed
BASE=https://github.com/Blockcast/amt-protocol/releases/download/$TAG
curl -fsSLO "$BASE/libamt_protocol-android-$TAG.zip" -O "$BASE/SHA256SUMS"
sha256sum -c --ignore-missing SHA256SUMS
unzip -o "libamt_protocol-android-$TAG.zip" -d app/src/main/jniLibs/
```

Record the tag and the `SHA256SUMS` line in the consuming project; do not
pin to a `main` artifact, which is rebuilt on every push.

The Kotlin library module in [`android/`](android/README.md) wraps the JNI surface;
copy `dist/android/` into its `jniLibs` directory as described there.

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
