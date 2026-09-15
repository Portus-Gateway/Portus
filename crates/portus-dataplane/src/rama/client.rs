//! The upstream HTTP client: TCP → rustls (per request, from extensions) →
//! HTTP/1 or HTTP/2, pooled on a key that includes the TLS verification
//! parameters so a connection verified under one BackendTLSPolicy never
//! serves a request from another. Connections are leased exclusively, one
//! request at a time, HTTP/2 included; multiplexing is a later step.

use std::time::Duration;

use rama::error::BoxError;
use rama::extensions::{Extension, ExtensionsRef};
use rama::http::client::{
    BasicHttpConId, BasicHttpConnIdentifier, BindBodyToConnLayer, HttpConnectRequestAdapter, HttpConnector,
};
use rama::http::layer::version_adapter::RequestVersionAdapter;
use rama::http::{Body, Request, Response, Version};
use rama::net::client::pool::{ConnID, LruDropPool, PooledConnector, ReqToConnID};
use rama::net::client::{ConnectRequest, EstablishedClientConnection};
use rama::net::http::TargetHttpVersion;
use rama::rt::Executor;
use rama::service::BoxService;
use rama::tcp::client::TcpStreamConnector;
use rama::tcp::client::service::TcpConnector;
use rama::tcp::TcpStream;
use rama::tls::client::TlsClientConfig;
use rama::tls::rustls::client::TlsConnector;
use rama::{Layer, Service};

/// Upstream connections kept per pod (idle and leased). The exclusive pool
/// leases one connection per in-flight request, so this also bounds
/// concurrent upstream requests; the pool requires the active cap not to
/// exceed the total. 512 covers 3× the bench's 256 client connections and
/// keeps idle-connection buffers bounded.
const POOL_MAX_TOTAL: usize = 512;
const POOL_MAX_ACTIVE: usize = POOL_MAX_TOTAL;
const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const POOL_WAIT_TIMEOUT: Duration = Duration::from_secs(10);

/// Per-request marker: a fingerprint of the TLS verification parameters and
/// client identity the request must be sent under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Extension)]
pub struct UpstreamTlsKey(pub u64);

/// Pool key: Rama's route identity plus our TLS fingerprint and the target
/// HTTP version.
#[derive(Debug, Clone, PartialEq)]
pub struct ConnKey {
    base: BasicHttpConId,
    tls: Option<u64>,
    version: Option<Version>,
}

impl ConnID for ConnKey {}

#[derive(Debug, Clone, Default)]
pub struct PortusConnIdentifier;

impl ReqToConnID<ConnectRequest> for PortusConnIdentifier {
    type ID = ConnKey;

    fn id(&self, req: &ConnectRequest) -> Result<Self::ID, BoxError> {
        Ok(ConnKey {
            base: BasicHttpConnIdentifier::default().id(req)?,
            tls: req.extensions().get_ref::<UpstreamTlsKey>().map(|k| k.0),
            version: req.extensions().get_ref::<TargetHttpVersion>().map(|v| v.0),
        })
    }
}

/// Dials upstreams with TCP_NODELAY, as Pingora's connector does. Rama's
/// default connector leaves Nagle on, which stalls request/response bodies
/// written in two segments behind delayed ACKs.
#[derive(Debug, Clone, Default)]
struct NoDelayConnector;

impl TcpStreamConnector for NoDelayConnector {
    type Error = std::io::Error;

    async fn connect(&self, addr: std::net::SocketAddr) -> Result<TcpStream, Self::Error> {
        let stream = tokio::net::TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;
        Ok(stream.into())
    }
}

pub type Client = BoxService<Request, Response, BoxError>;

/// Connect (or lease) and send, nothing else. Rama's `EasyHttpWebClient`
/// does the same two steps but also clones the connection's extensions into
/// the request on every call; a proxy does not need that.
struct DirectClient<C>(C);

impl<C, Conn> Service<Request> for DirectClient<C>
where
    C: Service<Request, Output = EstablishedClientConnection<Conn, Request>, Error: Into<BoxError>>,
    Conn: Service<Request, Output = Response, Error: Into<BoxError>> + Send,
{
    type Output = Response;
    type Error = BoxError;

    async fn serve(&self, req: Request) -> Result<Response, BoxError> {
        let EstablishedClientConnection { input, conn } = self.0.serve(req).await.map_err(Into::into)?;
        conn.serve(input).await.map_err(Into::into)
    }
}

/// Assemble the connector stack by hand: the easy builder hard-wires the
/// default pool key.
pub fn build(exec: Executor) -> Result<Client, BoxError> {
    let tcp = TcpConnector::new().with_connector(NoDelayConnector);
    let tls = TlsConnector::auto(tcp).with_base_config(TlsClientConfig::default_http());
    let http = HttpConnector::<_, Body>::new(tls, exec);
    // The exclusive LRU pool: one request per leased connection, O(1) return,
    // a pointer-compare scan under its lock. Rama's multiplexing pool sweeps
    // every pooled connection twice per request under a global mutex, which
    // capped the traffic ladder at ~90k QPS with 256 client connections.
    let pool = LruDropPool::try_new(POOL_MAX_ACTIVE, POOL_MAX_TOTAL)?.with_idle_timeout(POOL_IDLE_TIMEOUT);
    let pooled = PooledConnector::new(http, pool, PortusConnIdentifier).with_wait_for_pool_timeout(POOL_WAIT_TIMEOUT);
    let connector = BindBodyToConnLayer::new().into_layer(pooled);
    let connector = RequestVersionAdapter::new(HttpConnectRequestAdapter::new(connector));
    Ok(DirectClient(connector).boxed())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_client_stack_builds_with_the_configured_pool_limits() {
        // The pool validates its limits at construction; a bad constant must
        // fail here, not at pod start.
        build(Executor::default()).expect("client builds");
    }

    #[test]
    fn pool_key_separates_tls_policies_and_versions_on_one_route() {
        let base = ConnKey {
            base: BasicHttpConnIdentifier::default()
                .id(&Request::builder().uri("https://10.0.0.1:8443/").body(()).unwrap())
                .unwrap(),
            tls: Some(1),
            version: None,
        };
        let same = base.clone();
        assert_eq!(base, same);
        assert_ne!(base, ConnKey { tls: Some(2), ..base.clone() });
        assert_ne!(base, ConnKey { version: Some(Version::HTTP_2), ..base.clone() });
    }
}
