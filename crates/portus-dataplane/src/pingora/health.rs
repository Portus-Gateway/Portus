//! `/healthz` and `/readyz` on the health port, answered from the core's
//! [`Readiness`] state.

use std::sync::Arc;

use async_trait::async_trait;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_proxy::{ProxyHttp, Session};

use portus_dataplane_core::readiness::Readiness;

pub struct HealthHandler {
    pub readiness: Arc<Readiness>,
}

#[async_trait]
impl ProxyHttp for HealthHandler {
    type CTX = ();
    fn new_ctx(&self) -> Self::CTX {}

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        let path = session.req_header().uri.path();
        let (status, body) = match path {
            "/healthz" => (200, "ok"),
            "/readyz" => {
                if self.readiness.is_ready() {
                    (200, "ready")
                } else {
                    (503, "not ready")
                }
            }
            _ => (404, "not found"),
        };
        let mut header = pingora_http::ResponseHeader::build(status, None)?;
        header.insert_header("Content-Length", body.len().to_string())?;
        session.write_response_header(Box::new(header), false).await?;
        session.write_response_body(Some(bytes::Bytes::from(body)), true).await?;
        Ok(true)
    }

    async fn upstream_peer(&self, _session: &mut Session, _ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        Err(pingora_core::Error::explain(
            pingora_core::ErrorType::HTTPStatus(500),
            "health handler should not proxy",
        ))
    }
}
