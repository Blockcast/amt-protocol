//! AMT (Automatic Multicast Tunneling) Protocol Implementation
//!
//! This crate implements RFC 7450 - Automatic Multicast Tunneling for multiple platforms.
//! Supports WebAssembly, FFI (CGO, JNI), and UniFFI (iOS/macOS) targets.
//!
//! ## Overview
//!
//! AMT encapsulates PIM multicast traffic over unicast UDP tunnels, enabling
//! multicast reception in networks without native multicast routing.
//!
//! This implementation focuses on the **control plane**:
//! - AMT handshake (Discovery, Advertisement, Request, Query)
//! - IGMP/MLD report generation
//! - State machine management
//!
//! The **data plane** (packet parsing) is handled in TypeScript for zero-copy performance.
//!
//! ## Platform Support
//!
//! - **WASM** (default): For web browsers via wasm-bindgen
//! - **FFI**: For native platforms via C ABI (CGO for Go, JNI for Android)
//! - **UniFFI**: For iOS/macOS via uniffi

pub mod constants;
pub mod config;
pub mod error;
pub mod messages;
pub mod platform;
pub mod gateway;
pub mod igmp;
pub mod mld;
pub mod driad;

#[cfg(feature = "wasm")]
pub mod wasm;

#[cfg(feature = "ffi")]
pub mod ffi;

#[cfg(feature = "jni")]
pub mod jni;

pub use constants::*;
pub use config::AmtConfig;
pub use error::{AmtError, Result};
pub use messages::{AmtMessage, MessageType};
pub use platform::Platform;
pub use gateway::{AmtGateway, GatewayState, GroupKey, GroupInfo};
pub use igmp::{IgmpV3Report, IgmpRecord, RecordType};
pub use mld::{MldV2Report, MldRecord};
pub use driad::{DriadRelayAddress, DriadResolver};

// Re-export platform implementations based on features
#[cfg(feature = "wasm")]
pub use platform::wasm_platform::WasmPlatform;

#[cfg(feature = "ffi")]
pub use platform::ffi_platform::FfiPlatform;
