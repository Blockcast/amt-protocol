//! Platform impl for native (non-WASM, non-FFI) Rust callers.

use std::time::{SystemTime, UNIX_EPOCH};
use crate::platform::Platform;

#[derive(Debug, Default, Clone, Copy)]
pub struct NativePlatform;

impl NativePlatform {
    pub fn new() -> Self { Self }
}

impl Platform for NativePlatform {
    fn random_bytes(&self, buf: &mut [u8]) {
        getrandom::getrandom(buf).expect("getrandom failed");
    }
    fn log_debug(&self, msg: &str) {
        tracing::debug!(target: "amt", "{}", msg);
    }
    fn log_info(&self, msg: &str) {
        tracing::info!(target: "amt", "{}", msg);
    }
    fn log_error(&self, msg: &str) {
        tracing::error!(target: "amt", "{}", msg);
    }
    fn now_millis(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time before epoch")
            .as_millis() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_platform_random_bytes_changes_each_call() {
        let p = NativePlatform::new();
        let mut a = [0u8; 8];
        let mut b = [0u8; 8];
        p.random_bytes(&mut a);
        p.random_bytes(&mut b);
        assert_ne!(a, b);
    }

    #[test]
    fn native_platform_now_millis_is_recent() {
        let p = NativePlatform::new();
        let t = p.now_millis();
        // 2026-01-01 in ms.
        assert!(t > 1_767_225_600_000);
    }
}
