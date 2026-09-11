//! stdio transport.
//!
//! Newline-delimited JSON-RPC on stdin/stdout. stdio is a local pipe with no
//! per-message credential, so the session is bound to an explicitly configured
//! principal and tenant carried in [`AuthContext`] - an authenticated binding,
//! not an anonymous bypass (CLAUDE.md §5 row #4). Responses are buffered per
//! line here because the stdio framing is itself line-oriented; the HTTP
//! transport is the streaming path.

use pc_proto_mcp::Message;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{debug, info, warn};

use crate::auth::AuthContext;
use crate::error::Result;
use crate::gateway::Gateway;

use super::Transport;

/// stdio listener bound to a configured principal.
#[derive(Clone, Debug)]
pub struct StdioTransport {
    ctx: AuthContext,
}

impl StdioTransport {
    #[must_use]
    pub fn new(ctx: AuthContext) -> Self {
        Self { ctx }
    }
}

impl Transport for StdioTransport {
    async fn serve(self, gateway: Gateway) -> Result<()> {
        let stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
        let mut lines = BufReader::new(stdin).lines();
        info!(
            tenant = %self.ctx.tenant,
            principal = %self.ctx.principal,
            upstream = %self.ctx.upstream,
            "stdio transport ready"
        );

        while let Some(line) = lines.next_line().await? {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let bytes = axum::body::Bytes::from(line.clone().into_bytes());

            let Ok(msg) = Message::parse(trimmed.as_bytes()) else {
                warn!("dropping malformed stdio frame");
                continue;
            };
            if let Some(outcome) = gateway.negotiate(&msg) {
                debug!(effective = %outcome.effective(), "protocol negotiated");
            }
            debug!(
                method = msg.method().unwrap_or("<response>"),
                "relaying stdio call"
            );

            // stdio expects compact single-line JSON responses.
            match gateway
                .upstreams()
                .forward(&self.ctx.upstream, bytes, Some("application/json"))
                .await
            {
                Ok(resp) => match resp.bytes().await {
                    Ok(body) => {
                        stdout.write_all(&body).await?;
                        stdout.write_all(b"\n").await?;
                        stdout.flush().await?;
                    }
                    Err(e) => warn!(error = %e, "failed reading upstream response"),
                },
                Err(e) => warn!(error = %e, "upstream request failed"),
            }
        }
        Ok(())
    }
}
