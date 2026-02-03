//! Platform Abstraction for Multi-Target Compilation
//!
//! This module provides a Platform trait that abstracts platform-specific
//! functionality, enabling the AMT protocol implementation to compile for:
//! - WASM (web browsers via wasm-bindgen)
//! - FFI (native platforms via C ABI)
//! - JNI (Android via jni-rs)
//! - UniFFI (iOS/macOS via uniffi)

/// Platform abstraction trait
///
/// Implementations provide platform-specific functionality for:
/// - Random number generation (cryptographically secure)
/// - Logging (debug/info/error levels)
/// - Time (current timestamp in milliseconds)
pub trait Platform: Send + Sync {
    /// Fill buffer with cryptographically secure random bytes
    fn random_bytes(&self, buf: &mut [u8]);

    /// Log a debug message
    fn log_debug(&self, msg: &str);

    /// Log an info message
    fn log_info(&self, msg: &str);

    /// Log an error message
    fn log_error(&self, msg: &str);

    /// Get current time in milliseconds since Unix epoch
    fn now_millis(&self) -> u64;
}

/// Generate a random u32 nonce using the platform's random source
pub fn generate_nonce<P: Platform>(platform: &P) -> u32 {
    let mut bytes = [0u8; 4];
    platform.random_bytes(&mut bytes);
    u32::from_be_bytes(bytes)
}

// ============================================================================
// WASM Platform Implementation
// ============================================================================

#[cfg(feature = "wasm")]
pub mod wasm_platform {
    use super::Platform;

    /// WASM platform implementation using web-sys APIs
    pub struct WasmPlatform;

    impl WasmPlatform {
        pub fn new() -> Self {
            Self
        }
    }

    impl Default for WasmPlatform {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Platform for WasmPlatform {
        fn random_bytes(&self, buf: &mut [u8]) {
            getrandom::getrandom(buf).expect("Failed to generate random bytes");
        }

        fn log_debug(&self, msg: &str) {
            web_sys::console::debug_1(&msg.into());
        }

        fn log_info(&self, msg: &str) {
            web_sys::console::log_1(&msg.into());
        }

        fn log_error(&self, msg: &str) {
            web_sys::console::error_1(&msg.into());
        }

        fn now_millis(&self) -> u64 {
            js_sys::Date::now() as u64
        }
    }
}

// ============================================================================
// FFI Platform Implementation (for CGO, JNI, UniFFI)
// ============================================================================

#[cfg(feature = "ffi")]
pub mod ffi_platform {
    use super::Platform;
    use std::sync::Arc;

    /// Callback type for logging
    pub type LogCallback = Arc<dyn Fn(&str) + Send + Sync>;

    /// FFI platform implementation for native targets
    ///
    /// Uses standard library for random/time, callbacks for logging
    pub struct FfiPlatform {
        log_debug_cb: Option<LogCallback>,
        log_info_cb: Option<LogCallback>,
        log_error_cb: Option<LogCallback>,
    }

    impl FfiPlatform {
        pub fn new() -> Self {
            Self {
                log_debug_cb: None,
                log_info_cb: None,
                log_error_cb: None,
            }
        }

        /// Create with logging callbacks
        pub fn with_logging(
            debug_cb: Option<LogCallback>,
            info_cb: Option<LogCallback>,
            error_cb: Option<LogCallback>,
        ) -> Self {
            Self {
                log_debug_cb: debug_cb,
                log_info_cb: info_cb,
                log_error_cb: error_cb,
            }
        }

        /// Set debug logging callback
        pub fn set_debug_callback(&mut self, cb: LogCallback) {
            self.log_debug_cb = Some(cb);
        }

        /// Set info logging callback
        pub fn set_info_callback(&mut self, cb: LogCallback) {
            self.log_info_cb = Some(cb);
        }

        /// Set error logging callback
        pub fn set_error_callback(&mut self, cb: LogCallback) {
            self.log_error_cb = Some(cb);
        }
    }

    impl Default for FfiPlatform {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Platform for FfiPlatform {
        fn random_bytes(&self, buf: &mut [u8]) {
            getrandom::getrandom(buf).expect("Failed to generate random bytes");
        }

        fn log_debug(&self, msg: &str) {
            if let Some(cb) = &self.log_debug_cb {
                cb(msg);
            }
            #[cfg(debug_assertions)]
            eprintln!("[DEBUG] {}", msg);
        }

        fn log_info(&self, msg: &str) {
            if let Some(cb) = &self.log_info_cb {
                cb(msg);
            }
            #[cfg(debug_assertions)]
            println!("[INFO] {}", msg);
        }

        fn log_error(&self, msg: &str) {
            if let Some(cb) = &self.log_error_cb {
                cb(msg);
            }
            eprintln!("[ERROR] {}", msg);
        }

        fn now_millis(&self) -> u64 {
            use std::time::{SystemTime, UNIX_EPOCH};
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_millis() as u64
        }
    }
}

// ============================================================================
// Test Platform Implementation
// ============================================================================

#[cfg(test)]
pub mod test_platform {
    use super::Platform;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Test platform with deterministic behavior
    pub struct TestPlatform {
        time: AtomicU64,
        nonce_seed: AtomicU64,
    }

    impl TestPlatform {
        pub fn new() -> Self {
            Self {
                time: AtomicU64::new(1000),
                nonce_seed: AtomicU64::new(0x12345678),
            }
        }

        /// Set the current time for testing
        pub fn set_time(&self, time: u64) {
            self.time.store(time, Ordering::SeqCst);
        }

        /// Advance time by given milliseconds
        pub fn advance_time(&self, ms: u64) {
            self.time.fetch_add(ms, Ordering::SeqCst);
        }

        /// Set the nonce seed for deterministic testing
        pub fn set_nonce_seed(&self, seed: u64) {
            self.nonce_seed.store(seed, Ordering::SeqCst);
        }
    }

    impl Default for TestPlatform {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Platform for TestPlatform {
        fn random_bytes(&self, buf: &mut [u8]) {
            // Use a simple PRNG for deterministic testing
            let mut seed = self.nonce_seed.load(Ordering::SeqCst);
            for byte in buf.iter_mut() {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                *byte = (seed >> 33) as u8;
            }
            self.nonce_seed.store(seed, Ordering::SeqCst);
        }

        fn log_debug(&self, msg: &str) {
            println!("[TEST DEBUG] {}", msg);
        }

        fn log_info(&self, msg: &str) {
            println!("[TEST INFO] {}", msg);
        }

        fn log_error(&self, msg: &str) {
            eprintln!("[TEST ERROR] {}", msg);
        }

        fn now_millis(&self) -> u64 {
            self.time.load(Ordering::SeqCst)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_platform::TestPlatform;

    #[test]
    fn test_platform_random_bytes() {
        let platform = TestPlatform::new();
        let mut buf1 = [0u8; 4];
        let mut buf2 = [0u8; 4];

        platform.random_bytes(&mut buf1);
        platform.random_bytes(&mut buf2);

        // With deterministic PRNG, subsequent calls should produce different values
        assert_ne!(buf1, buf2);
    }

    #[test]
    fn test_platform_time() {
        let platform = TestPlatform::new();

        assert_eq!(platform.now_millis(), 1000);

        platform.advance_time(500);
        assert_eq!(platform.now_millis(), 1500);

        platform.set_time(2000);
        assert_eq!(platform.now_millis(), 2000);
    }

    #[test]
    fn test_generate_nonce() {
        let platform = TestPlatform::new();
        platform.set_nonce_seed(0xDEADBEEF);

        let nonce1 = generate_nonce(&platform);
        let nonce2 = generate_nonce(&platform);

        assert_ne!(nonce1, nonce2);
    }
}
