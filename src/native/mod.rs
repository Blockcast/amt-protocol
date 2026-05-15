//! Native (tokio + std::net + UDP) runtime layer. Gated behind feature = "native".

pub mod platform;

pub use platform::NativePlatform;
