//! Client-facing transports.
//!
//! Transports are traits so that adding one (WebSocket, vsock, …) does not touch
//! routing, policy, or audit (CLAUDE.md §7). M0 ships [`http::HttpTransport`]
//! (Streamable HTTP) and [`stdio::StdioTransport`].

pub mod http;
pub mod stdio;

use crate::error::Result;
use crate::gateway::Gateway;

/// A client-facing transport. Implementors terminate one wire protocol, apply
/// the shared gateway (auth, routing, relay), and run until shut down.
pub trait Transport {
    /// Run the transport to completion, borrowing the shared [`Gateway`].
    fn serve(self, gateway: Gateway) -> impl std::future::Future<Output = Result<()>> + Send;
}
