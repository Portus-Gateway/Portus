//! `/healthz`, `/readyz` and `/metrics` on Rama.

use std::convert::Infallible;
use std::sync::Arc;

use rama::http::{Body, Request, Response, StatusCode};
use rama::Service;

use portus_dataplane_core::readiness::Readiness;

#[derive(Clone)]
pub struct HealthService(pub Arc<Readiness>);

impl Service<Request> for HealthService {
    type Output = Response;
    type Error = Infallible;

    async fn serve(&self, req: Request) -> Result<Self::Output, Self::Error> {
        let path = req.uri().path().map(|p| p.as_encoded_str().into_owned()).unwrap_or_default();
        let (status, body) = match path.as_str() {
            "/healthz" => (StatusCode::OK, "ok"),
            "/readyz" => {
                if self.0.is_ready() {
                    (StatusCode::OK, "ready")
                } else {
                    (StatusCode::SERVICE_UNAVAILABLE, "not ready")
                }
            }
            _ => (StatusCode::NOT_FOUND, "not found"),
        };
        Ok(text(status, body.to_string()))
    }
}

#[derive(Clone)]
pub struct MetricsService;

impl Service<Request> for MetricsService {
    type Output = Response;
    type Error = Infallible;

    async fn serve(&self, _req: Request) -> Result<Self::Output, Self::Error> {
        let encoder = prometheus::TextEncoder::new();
        Ok(match encoder.encode_to_string(&prometheus::gather()) {
            Ok(body) => {
                let mut resp = text(StatusCode::OK, body);
                resp.headers_mut().insert(
                    "content-type",
                    rama::http::HeaderValue::from_static("text/plain; version=0.0.4"),
                );
                resp
            }
            Err(e) => text(StatusCode::INTERNAL_SERVER_ERROR, format!("metrics encoding failed: {e}")),
        })
    }
}

fn text(status: StatusCode, body: String) -> Response {
    let mut resp = Response::new(Body::from(body));
    *resp.status_mut() = status;
    resp
}
