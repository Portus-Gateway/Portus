//! ExtAuthPolicy: ask an authorization service whether a request may pass
//! (the forward-auth contract oauth2-proxy, Authelia and Authentik speak).
//!
//! The data plane sends a `GET` to the service with the client's headers and
//! `X-Forwarded-{Method,Proto,Host,Uri,For}`; no body. A 2xx answer allows
//! the request, and the configured response headers are copied into the
//! request to the backend (client copies of them removed first). Any other
//! answer goes back to the client as it is, so a 302 to a login page or a 401
//! with its challenge works. When the service cannot answer the request is
//! refused with 503, or allowed when the policy fails open.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderName, HeaderValue, Method};
use http_body_util::{BodyExt, Empty, Limited};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

use crate::jwt::ClaimHeaders;
use crate::plan::Reply;
use crate::pool::Pool;
use crate::router::RequestHeaders;

/// Largest denial body passed back to the client.
const MAX_DENIAL_BODY: usize = 64 * 1024;

/// Headers never copied between the hops (RFC 9110 §7.6.1), plus the
/// framing ones this module sets itself.
fn is_hop_header(name: &str) -> bool {
    matches!(
        name,
        "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "te" | "trailer" | "upgrade" | "content-length" | "host"
    )
}

/// The forward-auth headers describing the original request.
const X_FORWARDED_METHOD: HeaderName = HeaderName::from_static("x-forwarded-method");
const X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");
const X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");
const X_FORWARDED_URI: HeaderName = HeaderName::from_static("x-forwarded-uri");
const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");

static CLIENT: LazyLock<Client<HttpConnector, Empty<Bytes>>> = LazyLock::new(|| {
    let mut connector = HttpConnector::new();
    connector.set_nodelay(true);
    connector.set_connect_timeout(Some(Duration::from_secs(2)));
    Client::builder(TokioExecutor::new()).pool_idle_timeout(Duration::from_secs(30)).build(connector)
});

/// A route's ExtAuthPolicy.
#[derive(Debug)]
pub struct ExtAuth {
    /// The authorization Service (a `ProxySnapshot::lbs` key with `port`).
    /// Empty when the reference was not permitted: every request is refused.
    pub service_name: Arc<str>,
    pub port: u16,
    pub path: String,
    pub timeout: Duration,
    pub fail_open: bool,
    /// Client headers sent to the service; `None` sends all of them.
    pub request_headers: Option<Vec<HeaderName>>,
    /// Service response headers copied into the backend request on allow.
    pub response_headers: Arc<Vec<HeaderName>>,
}

/// What the service decided.
#[derive(Debug)]
pub enum Decision {
    /// Forward, setting these headers on the backend request.
    Allow(ClaimHeaders),
    /// Answer the client with this.
    Deny(Reply),
}

/// The original request as the service sees it.
pub struct Original<'a, H: RequestHeaders + ?Sized> {
    pub method: &'a str,
    pub scheme: &'a str,
    pub host: &'a str,
    pub path_and_query: &'a str,
    pub client_ip: Option<IpAddr>,
    pub headers: &'a H,
}

impl ExtAuth {
    /// Ask the service about `original`, using an endpoint from `pool`.
    pub async fn check<H: RequestHeaders + ?Sized>(&self, pool: Option<&Pool>, original: &Original<'_, H>) -> Decision {
        if self.service_name.is_empty() {
            return Decision::Deny(Reply::text(500, "authorization service not permitted"));
        }
        let Some(endpoint) = pool.and_then(Pool::select) else {
            log::warn!("ext auth: no ready endpoints for {}:{}", self.service_name, self.port);
            return self.unavailable();
        };
        let request = match self.request(endpoint, original) {
            Ok(r) => r,
            Err(e) => {
                log::warn!("ext auth: cannot build the check request for {}:{}: {e}", self.service_name, self.port);
                return self.unavailable();
            }
        };
        let response = match tokio::time::timeout(self.timeout, CLIENT.request(request)).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                log::warn!("ext auth: {}:{} ({endpoint}) failed: {e}", self.service_name, self.port);
                return self.unavailable();
            }
            Err(_) => {
                log::warn!("ext auth: {}:{} ({endpoint}) did not answer within {:?}", self.service_name, self.port, self.timeout);
                return self.unavailable();
            }
        };
        let (parts, body) = response.into_parts();
        if parts.status.is_success() {
            let set = self
                .response_headers
                .iter()
                .flat_map(|name| parts.headers.get_all(name).iter().map(move |v| (name.clone(), v.clone())))
                .collect();
            return Decision::Allow(Arc::new(set));
        }
        let body = match tokio::time::timeout(self.timeout, Limited::new(body, MAX_DENIAL_BODY).collect()).await {
            Ok(Ok(b)) => b.to_bytes(),
            _ => Bytes::new(),
        };
        let mut headers: Vec<(HeaderName, HeaderValue)> = vec![(http::header::CONTENT_LENGTH, HeaderValue::from(body.len()))];
        headers.extend(parts.headers.iter().filter(|(n, _)| !is_hop_header(n.as_str())).map(|(n, v)| (n.clone(), v.clone())));
        Decision::Deny(Reply { status: parts.status.as_u16(), headers, body, keepalive: true })
    }

    fn unavailable(&self) -> Decision {
        if self.fail_open {
            Decision::Allow(Arc::new(Vec::new()))
        } else {
            Decision::Deny(Reply::text(503, "authorization service unavailable"))
        }
    }

    fn request<H: RequestHeaders + ?Sized>(&self, endpoint: SocketAddr, original: &Original<'_, H>) -> Result<http::Request<Empty<Bytes>>, http::Error> {
        let mut builder = http::Request::builder().method(Method::GET).uri(format!("http://{endpoint}{}", self.path));
        let headers = builder.headers_mut().expect("a fresh builder has headers");
        original.headers.for_each(&mut |name, value| {
            let wanted = match &self.request_headers {
                Some(list) => list.iter().any(|h| h.as_str().eq_ignore_ascii_case(name)),
                None => !is_hop_header(name),
            };
            if wanted
                && let (Ok(n), Ok(v)) = (HeaderName::from_bytes(name.as_bytes()), HeaderValue::from_bytes(value))
            {
                headers.append(n, v);
            }
        });
        let mut set = |name: HeaderName, value: &str| {
            if let Ok(v) = HeaderValue::from_str(value) {
                headers.insert(name, v);
            }
        };
        set(X_FORWARDED_METHOD, original.method);
        set(X_FORWARDED_PROTO, original.scheme);
        set(X_FORWARDED_HOST, original.host);
        set(X_FORWARDED_URI, original.path_and_query);
        if let Some(ip) = original.client_ip {
            set(X_FORWARDED_FOR, &ip.to_string());
        }
        builder.body(Empty::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderMap;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// An authorization service that records each request's head and
    /// answers with `reply` after `delay`.
    async fn service(reply: &'static str, delay: Duration) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let log = Arc::clone(&log);
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    log.lock().unwrap().push(String::from_utf8_lossy(&buf[..n]).to_string());
                    tokio::time::sleep(delay).await;
                    let _ = sock.write_all(reply.as_bytes()).await;
                });
            }
        });
        (addr, seen)
    }

    fn pool_for(addr: SocketAddr) -> Pool {
        Pool::new([addr], None)
    }

    fn ext_auth(timeout_ms: u64, fail_open: bool) -> ExtAuth {
        ExtAuth {
            service_name: Arc::from("authz"),
            port: 4180,
            path: "/oauth2/auth".to_string(),
            timeout: Duration::from_millis(timeout_ms),
            fail_open,
            request_headers: None,
            response_headers: Arc::new(vec![HeaderName::from_static("x-auth-request-user"), HeaderName::from_static("x-auth-request-groups")]),
        }
    }

    fn headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("cookie", HeaderValue::from_static("_oauth2_proxy=abc"));
        h.insert("authorization", HeaderValue::from_static("Bearer t"));
        h.insert("connection", HeaderValue::from_static("keep-alive"));
        h.insert("content-length", HeaderValue::from_static("5"));
        h
    }

    fn original(h: &HeaderMap) -> Original<'_, HeaderMap> {
        Original {
            method: "POST",
            scheme: "https",
            host: "app.example.com",
            path_and_query: "/orders?id=7",
            client_ip: Some("203.0.113.9".parse().unwrap()),
            headers: h,
        }
    }

    #[tokio::test]
    async fn a_2xx_allows_and_copies_the_listed_headers() {
        let (addr, seen) = service(
            "HTTP/1.1 202 Accepted\r\ncontent-length: 0\r\nx-auth-request-user: alice\r\nx-auth-request-groups: eng\r\nx-auth-request-groups: ops\r\nx-other: no\r\n\r\n",
            Duration::ZERO,
        )
        .await;
        let h = headers();
        let decision = ext_auth(1000, false).check(Some(&pool_for(addr)), &original(&h)).await;
        let Decision::Allow(set) = decision else { panic!("expected allow, got {decision:?}") };
        let got: Vec<(&str, &str)> = set.iter().map(|(n, v)| (n.as_str(), v.to_str().unwrap())).collect();
        assert_eq!(got, vec![("x-auth-request-user", "alice"), ("x-auth-request-groups", "eng"), ("x-auth-request-groups", "ops")]);

        let request = seen.lock().unwrap()[0].to_ascii_lowercase();
        assert!(request.starts_with("get /oauth2/auth http/1.1\r\n"), "{request}");
        for line in ["cookie: _oauth2_proxy=abc", "authorization: bearer t", "x-forwarded-method: post", "x-forwarded-proto: https", "x-forwarded-host: app.example.com", "x-forwarded-uri: /orders?id=7", "x-forwarded-for: 203.0.113.9"] {
            assert!(request.contains(line), "missing {line:?} in {request}");
        }
        assert!(!request.contains("content-length: 5"), "the client's framing headers are not sent");
    }

    #[tokio::test]
    async fn a_denial_is_returned_to_the_client_as_it_is() {
        let (addr, _) = service("HTTP/1.1 302 Found\r\nlocation: https://login.example.com/start\r\nset-cookie: csrf=1\r\ncontent-length: 5\r\nconnection: close\r\n\r\nlogin", Duration::ZERO).await;
        let h = headers();
        let Decision::Deny(reply) = ext_auth(1000, false).check(Some(&pool_for(addr)), &original(&h)).await else { panic!("expected deny") };
        assert_eq!(reply.status, 302);
        assert_eq!(&reply.body[..], b"login");
        let header = |n: &str| reply.headers.iter().find(|(k, _)| k == n).map(|(_, v)| v.to_str().unwrap().to_string());
        assert_eq!(header("location").as_deref(), Some("https://login.example.com/start"));
        assert_eq!(header("set-cookie").as_deref(), Some("csrf=1"));
        assert_eq!(header("content-length").as_deref(), Some("5"));
        assert!(header("connection").is_none(), "hop headers stay on their hop");
    }

    #[tokio::test]
    async fn an_unreachable_or_slow_service_refuses_unless_the_policy_fails_open() {
        let (slow, _) = service("HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n", Duration::from_millis(500)).await;
        let h = headers();
        for (pool, why) in [(Some(pool_for(slow)), "timeout"), (None, "no endpoints")] {
            let Decision::Deny(reply) = ext_auth(100, false).check(pool.as_ref(), &original(&h)).await else { panic!("{why}: expected deny") };
            assert_eq!(reply.status, 503, "{why}");
            let Decision::Allow(set) = ext_auth(100, true).check(pool.as_ref(), &original(&h)).await else { panic!("{why}: expected fail-open") };
            assert!(set.is_empty());
        }
        let refused = ExtAuth { service_name: Arc::from(""), ..ext_auth(100, true) };
        let Decision::Deny(reply) = refused.check(None, &original(&h)).await else { panic!("expected deny") };
        assert_eq!(reply.status, 500, "a reference that is not permitted never fails open");
    }

    #[tokio::test]
    async fn an_allow_list_limits_the_headers_sent() {
        let (addr, seen) = service("HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n", Duration::ZERO).await;
        let h = headers();
        let auth = ExtAuth { request_headers: Some(vec![HeaderName::from_static("cookie")]), ..ext_auth(1000, false) };
        assert!(matches!(auth.check(Some(&pool_for(addr)), &original(&h)).await, Decision::Allow(_)));
        let request = seen.lock().unwrap()[0].to_ascii_lowercase();
        assert!(request.contains("cookie: _oauth2_proxy=abc"));
        assert!(!request.contains("authorization:"), "{request}");
        assert!(request.contains("x-forwarded-uri: /orders?id=7"), "the forwarded headers are always sent");
    }
}
