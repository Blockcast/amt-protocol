//! Native (tokio + std::net + UDP) runtime layer. Gated behind feature = "native".

pub mod gateway;
pub mod platform;
pub mod resolver;

pub use gateway::{AsyncAmtGateway, AsyncAmtGatewayBuilder, DataEvent};
pub use platform::NativePlatform;
