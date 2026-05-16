//! Native (tokio + std::net + UDP) runtime layer. Gated behind feature = "native".

pub mod platform;
pub mod gateway;
pub mod resolver;

pub use platform::NativePlatform;
pub use gateway::{AsyncAmtGateway, AsyncAmtGatewayBuilder, DataEvent};
