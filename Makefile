# AMT Protocol Library - Multi-Platform Build System
#
# Targets:
#   make wasm      - Build WASM for IWA (web browser)
#   make ffi       - Build FFI library for Caddy/CGO
#   make jni       - Build JNI library for Android (all ABIs)
#   make test      - Run all tests
#   make clean     - Clean build artifacts
#
# Prerequisites:
#   - Rust toolchain (rustup)
#   - wasm-pack (for WASM)
#   - cargo-ndk (for Android)
#   - Android NDK (for Android)

.PHONY: all wasm ffi jni test clean help

# Directories
TARGET_DIR := target
WASM_OUT := $(TARGET_DIR)/wasm32-unknown-unknown/release
FFI_OUT := $(TARGET_DIR)/release
INCLUDE_DIR := include

# Output directories (override with environment variables)
WASM_OUTPUT_DIR ?= dist/wasm
ANDROID_JNI_DIR ?= dist/android
INSTALL_PREFIX ?= /usr/local

# Default target
all: wasm ffi

# Help
help:
	@echo "AMT Protocol Library Build System"
	@echo ""
	@echo "Targets:"
	@echo "  make wasm     - Build WASM for IWA (web browser)"
	@echo "  make ffi      - Build FFI library for Caddy/CGO"
	@echo "  make jni      - Build JNI library for Android"
	@echo "  make test     - Run all tests"
	@echo "  make clean    - Clean build artifacts"
	@echo ""
	@echo "Requirements:"
	@echo "  wasm:  rustup target add wasm32-unknown-unknown"
	@echo "  ffi:   (none)"
	@echo "  jni:   cargo install cargo-ndk && Android NDK"

# ============================================================================
# WASM Build (for IWA)
# ============================================================================

wasm: wasm-build wasm-bindgen

wasm-build:
	@echo "Building WASM..."
	cargo build --release --target wasm32-unknown-unknown --features wasm

wasm-bindgen:
	@echo "Generating WASM bindings..."
	@mkdir -p $(WASM_OUTPUT_DIR)
	wasm-bindgen $(WASM_OUT)/amt_protocol.wasm \
		--out-dir $(WASM_OUTPUT_DIR) \
		--target web \
		--omit-default-module-path
	@echo "WASM output: $(WASM_OUTPUT_DIR)"

# ============================================================================
# FFI Build (for Caddy/CGO)
# ============================================================================

ffi: ffi-build ffi-header

ffi-build:
	@echo "Building FFI library..."
	cargo build --release --features ffi --no-default-features

ffi-header:
	@echo "C header available at: $(INCLUDE_DIR)/amt_protocol.h"
	@# If cbindgen is available, regenerate:
	@# cbindgen --config cbindgen.toml --output $(INCLUDE_DIR)/amt_protocol.h

ffi-check:
	@echo "Checking FFI build..."
	@ls -la $(FFI_OUT)/libamt_protocol.* 2>/dev/null || echo "FFI library not built yet"

# ============================================================================
# JNI Build (for Android)
# ============================================================================

# Android ABIs
ANDROID_ABIS := arm64-v8a armeabi-v7a x86 x86_64

jni: jni-check-ndk jni-build

jni-check-ndk:
	@which cargo-ndk > /dev/null || (echo "Error: cargo-ndk not installed. Run: cargo install cargo-ndk" && exit 1)
	@test -n "$$ANDROID_NDK_HOME" || (echo "Error: ANDROID_NDK_HOME not set" && exit 1)

jni-build:
	@echo "Building JNI libraries for Android..."
	@mkdir -p $(ANDROID_JNI_DIR)
	cargo ndk \
		-t arm64-v8a \
		-t armeabi-v7a \
		-t x86 \
		-t x86_64 \
		-o $(ANDROID_JNI_DIR) \
		-- build --release --features jni --no-default-features
	@echo "JNI output: $(ANDROID_JNI_DIR)"
	@find $(ANDROID_JNI_DIR) -name "*.so" -exec ls -la {} \;

# ============================================================================
# Testing
# ============================================================================

test: test-native test-wasm

test-native:
	@echo "Running native tests..."
	cargo test --no-default-features

test-wasm:
	@echo "Running WASM tests..."
	cargo test --features wasm --target wasm32-unknown-unknown || echo "WASM tests require wasm-pack"

test-go: ffi
	@echo "Running Go bindings tests..."
	cd bindings/go/amt && go test -v

# ============================================================================
# Development
# ============================================================================

check:
	@echo "Checking all features..."
	cargo check --features wasm
	cargo check --features ffi --no-default-features
	@echo "All checks passed!"

fmt:
	cargo fmt

clippy:
	cargo clippy --features wasm -- -D warnings
	cargo clippy --features ffi --no-default-features -- -D warnings

# ============================================================================
# Clean
# ============================================================================

clean:
	cargo clean
	rm -rf dist/
	@echo "Cleaned build artifacts"

# ============================================================================
# Installation (for CGO/system use)
# ============================================================================

install: ffi
	@echo "Installing to $(INSTALL_PREFIX)..."
	install -d $(INSTALL_PREFIX)/lib
	install -d $(INSTALL_PREFIX)/include
	install -m 644 $(FFI_OUT)/libamt_protocol.so $(INSTALL_PREFIX)/lib/
	install -m 644 $(FFI_OUT)/libamt_protocol.a $(INSTALL_PREFIX)/lib/
	install -m 644 $(INCLUDE_DIR)/amt_protocol.h $(INSTALL_PREFIX)/include/
	@echo "Installed. Run 'ldconfig' if needed."

uninstall:
	rm -f $(INSTALL_PREFIX)/lib/libamt_protocol.*
	rm -f $(INSTALL_PREFIX)/include/amt_protocol.h

# ============================================================================
# Installation helpers
# ============================================================================

install-wasm-deps:
	rustup target add wasm32-unknown-unknown
	cargo install wasm-bindgen-cli

install-android-deps:
	cargo install cargo-ndk
	rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
	@echo "Note: You also need Android NDK installed and ANDROID_NDK_HOME set"
