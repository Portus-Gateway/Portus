//! OpenTelemetry tracing for forwarded requests.
//!
//! Off unless an OTLP endpoint is configured. When on, every forwarded
//! request gets a SERVER span: the trace continues the client's W3C
//! `traceparent` when it sends a valid one, the backend receives a
//! `traceparent` naming this span as its parent, and sampled spans are
//! queued and exported in batches over OTLP/gRPC by a dedicated thread.
//! Requests the gateway answers itself (redirects, refusals) are not traced.
//!
//! Configuration is the standard SDK environment:
//!
//! | Variable | Default |
//! |---|---|
//! | `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`, `OTEL_EXPORTER_OTLP_ENDPOINT` | unset: tracing off |
//! | `OTEL_TRACES_SAMPLER`, `OTEL_TRACES_SAMPLER_ARG` | `parentbased_always_on`, `1.0` |
//! | `OTEL_SERVICE_NAME`, `OTEL_RESOURCE_ATTRIBUTES` | `portus-dataplane` |
//! | `OTEL_EXPORTER_OTLP_HEADERS` (and `_TRACES_`) | none |
//! | `OTEL_EXPORTER_OTLP_TIMEOUT` (and `_TRACES_`) | 10000 ms |
//! | `OTEL_TRACES_EXPORTER=none`, `OTEL_SDK_DISABLED=true` | tracing off |

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crossbeam_queue::ArrayQueue;
use http::HeaderValue;
use log::{info, warn};
use portus_types::proto::opentelemetry::proto::collector::trace::v1::trace_service_client::TraceServiceClient;
use portus_types::proto::opentelemetry::proto::collector::trace::v1::ExportTraceServiceRequest;
use portus_types::proto::opentelemetry::proto::common::v1::{any_value, AnyValue, InstrumentationScope, KeyValue};
use portus_types::proto::opentelemetry::proto::resource::v1::Resource;
use portus_types::proto::opentelemetry::proto::trace::v1::{span, status, ResourceSpans, ScopeSpans, Span as SpanProto, Status};

use crate::router::{header_str, RequestHeaders};

/// Finished spans waiting for the exporter; beyond this they are dropped.
const QUEUE_CAPACITY: usize = 8192;
/// Spans per export call (`OTEL_BSP_MAX_EXPORT_BATCH_SIZE` default).
const BATCH_SIZE: usize = 512;
/// Longest a finished span waits before export (`OTEL_BSP_SCHEDULE_DELAY` default).
const SCHEDULE_DELAY: Duration = Duration::from_secs(5);
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_SERVICE_NAME: &str = "portus-dataplane";

pub const TRACEPARENT: &str = "traceparent";
pub const TRACESTATE: &str = "tracestate";

/// A valid W3C `traceparent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceParent {
    pub trace_id: [u8; 16],
    pub span_id: [u8; 8],
    pub sampled: bool,
}

/// Parse a `traceparent` value; `None` for anything the W3C spec says to
/// ignore (bad lengths, upper-case hex, version `ff`, all-zero ids).
pub fn parse_traceparent(value: &[u8]) -> Option<TraceParent> {
    // version "-" trace-id "-" parent-id "-" flags: 2+1+32+1+16+1+2 = 55.
    if value.len() < 55 || value[2] != b'-' || value[35] != b'-' || value[52] != b'-' {
        return None;
    }
    let version = hex_byte(&value[0..2])?;
    // Version 00 is exactly 55 bytes; a later version may append "-..." fields.
    match version {
        0xff => return None,
        0x00 if value.len() != 55 => return None,
        _ if value.len() > 55 && value[55] != b'-' => return None,
        _ => {}
    }
    let mut trace_id = [0u8; 16];
    for (i, b) in trace_id.iter_mut().enumerate() {
        *b = hex_byte(&value[3 + 2 * i..5 + 2 * i])?;
    }
    let mut span_id = [0u8; 8];
    for (i, b) in span_id.iter_mut().enumerate() {
        *b = hex_byte(&value[36 + 2 * i..38 + 2 * i])?;
    }
    let flags = hex_byte(&value[53..55])?;
    if trace_id == [0; 16] || span_id == [0; 8] {
        return None;
    }
    Some(TraceParent { trace_id, span_id, sampled: flags & 1 == 1 })
}

fn hex_byte(pair: &[u8]) -> Option<u8> {
    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        }
    }
    Some(nibble(pair[0])? << 4 | nibble(pair[1])?)
}

fn push_hex(out: &mut Vec<u8>, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for b in bytes {
        out.push(HEX[(b >> 4) as usize]);
        out.push(HEX[(b & 0xf) as usize]);
    }
}

/// What decides whether a new span is recorded and exported.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Sampler {
    /// Follow the caller's sampled flag when there is a parent.
    pub parent_based: bool,
    pub root: RootSampler,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RootSampler {
    AlwaysOn,
    AlwaysOff,
    /// Sample when the trace id's low 56 bits fall below this bound, so every
    /// service sampling at the same ratio keeps the same traces.
    Ratio(u64),
}

const RATIO_SPACE: u64 = 1 << 56;

impl Sampler {
    /// From `OTEL_TRACES_SAMPLER` / `OTEL_TRACES_SAMPLER_ARG`; unknown names
    /// fall back to the spec default, `parentbased_always_on`.
    pub fn from_env_values(name: Option<&str>, arg: Option<&str>) -> Self {
        let ratio = || {
            let r = arg.and_then(|a| a.trim().parse::<f64>().ok()).filter(|r| (0.0..=1.0).contains(r)).unwrap_or(1.0);
            RootSampler::Ratio((r * RATIO_SPACE as f64) as u64)
        };
        let (parent_based, root) = match name.map(str::trim).unwrap_or("parentbased_always_on") {
            "always_on" => (false, RootSampler::AlwaysOn),
            "always_off" => (false, RootSampler::AlwaysOff),
            "traceidratio" => (false, ratio()),
            "parentbased_always_off" => (true, RootSampler::AlwaysOff),
            "parentbased_traceidratio" => (true, ratio()),
            "parentbased_always_on" => (true, RootSampler::AlwaysOn),
            other => {
                warn!("unsupported OTEL_TRACES_SAMPLER {other:?}; using parentbased_always_on");
                (true, RootSampler::AlwaysOn)
            }
        };
        Self { parent_based, root }
    }

    pub fn sample(&self, trace_id: &[u8; 16], parent: Option<&TraceParent>) -> bool {
        if self.parent_based
            && let Some(p) = parent
        {
            return p.sampled;
        }
        match self.root {
            RootSampler::AlwaysOn => true,
            RootSampler::AlwaysOff => false,
            RootSampler::Ratio(bound) => {
                let mut low = [0u8; 8];
                low[1..].copy_from_slice(&trace_id[9..]);
                u64::from_be_bytes(low) < bound
            }
        }
    }
}

/// What the plan knows about the request when its span starts.
pub struct RequestInfo<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub host: &'a str,
    pub scheme: &'a str,
    pub peer_ip: Option<IpAddr>,
    /// Backend Service the route chose.
    pub service: &'a str,
    pub port: u16,
}

/// One forwarded request's span. Unsampled spans still propagate their
/// context, so a backend that follows its parent does not sample either.
pub struct Span {
    trace_id: [u8; 16],
    span_id: [u8; 8],
    /// The span continues the client's trace (a valid `traceparent` came in).
    continued: bool,
    /// Set only when sampled: the span as it will be exported, less its end.
    record: Option<Box<SpanProto>>,
    start: Instant,
}

impl Span {
    pub fn sampled(&self) -> bool {
        self.record.is_some()
    }

    pub fn trace_id(&self) -> [u8; 16] {
        self.trace_id
    }

    /// Whether the client's `tracestate` belongs to this trace: it does not
    /// when the span started a new one.
    pub fn continued(&self) -> bool {
        self.continued
    }

    /// `traceparent` for the backend request: this span is its parent.
    pub fn traceparent(&self) -> HeaderValue {
        let mut v = Vec::with_capacity(55);
        v.extend_from_slice(b"00-");
        push_hex(&mut v, &self.trace_id);
        v.push(b'-');
        push_hex(&mut v, &self.span_id);
        v.extend_from_slice(if self.sampled() { b"-01" } else { b"-00" });
        HeaderValue::from_bytes(&v).unwrap_or_else(|_| HeaderValue::from_static(""))
    }

    /// Close the span with the response status the client saw (0: none was
    /// sent) and hand it to the exporter. Unsampled spans cost nothing here.
    pub fn end(&self, status: u16) {
        let (Some(record), Some(tracer)) = (self.record.as_ref(), TRACER.get()) else {
            return;
        };
        tracer.enqueue(finished(record, status, self.start.elapsed()));
    }
}

fn finished(record: &SpanProto, status: u16, elapsed: Duration) -> SpanProto {
    let mut span = record.clone();
    span.end_time_unix_nano = span.start_time_unix_nano + elapsed.as_nanos() as u64;
    if status > 0 {
        span.attributes.push(int_attr("http.response.status_code", i64::from(status)));
    }
    // A server span is an error on a 5xx or when no response went out; 4xx
    // is the client's error, not this span's.
    if status == 0 || status >= 500 {
        span.attributes.push(str_attr("error.type", if status == 0 { "no_response".to_string() } else { status.to_string() }));
        span.status = Some(Status { code: status::StatusCode::Error as i32, message: String::new() });
    }
    span
}

fn str_attr(key: &str, value: String) -> KeyValue {
    KeyValue { key: key.to_string(), value: Some(AnyValue { value: Some(any_value::Value::StringValue(value)) }) }
}

fn int_attr(key: &str, value: i64) -> KeyValue {
    KeyValue { key: key.to_string(), value: Some(AnyValue { value: Some(any_value::Value::IntValue(value)) }) }
}

fn random_nonzero<const N: usize>() -> [u8; N] {
    loop {
        let id: [u8; N] = rand::random();
        if id != [0; N] {
            return id;
        }
    }
}

fn unix_nanos() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos() as u64)
}

/// Where spans go: the sampler, the queue and its drop counter.
pub struct Tracer {
    sampler: Sampler,
    queue: ArrayQueue<SpanProto>,
    dropped: AtomicU64,
    wake: tokio::sync::Notify,
}

static TRACER: OnceLock<Tracer> = OnceLock::new();

/// Start a span for a forwarded request, or `None` when tracing is off.
pub fn start_span(headers: &(impl RequestHeaders + ?Sized), info: &RequestInfo<'_>) -> Option<Span> {
    TRACER.get().map(|t| t.start(headers, info))
}

impl Tracer {
    fn new(sampler: Sampler) -> Self {
        Self { sampler, queue: ArrayQueue::new(QUEUE_CAPACITY), dropped: AtomicU64::new(0), wake: tokio::sync::Notify::new() }
    }

    pub fn start(&self, headers: &(impl RequestHeaders + ?Sized), info: &RequestInfo<'_>) -> Span {
        let parent = headers.get(TRACEPARENT).and_then(parse_traceparent);
        let trace_id = parent.map_or_else(random_nonzero::<16>, |p| p.trace_id);
        let span_id = random_nonzero::<8>();
        let record = self.sampler.sample(&trace_id, parent.as_ref()).then(|| {
            let mut attributes = vec![
                str_attr("http.request.method", info.method.to_string()),
                str_attr("url.path", info.path.to_string()),
                str_attr("url.scheme", info.scheme.to_string()),
                str_attr("server.address", info.host.to_string()),
                str_attr("portus.backend.service", info.service.to_string()),
                int_attr("portus.backend.port", i64::from(info.port)),
            ];
            if let Some(ip) = info.peer_ip {
                attributes.push(str_attr("client.address", ip.to_string()));
            }
            if let Some(ua) = header_str(headers, "user-agent") {
                attributes.push(str_attr("user_agent.original", ua.to_string()));
            }
            Box::new(SpanProto {
                trace_id: trace_id.to_vec(),
                span_id: span_id.to_vec(),
                parent_span_id: parent.map(|p| p.span_id.to_vec()).unwrap_or_default(),
                name: info.method.to_string(),
                kind: span::SpanKind::Server as i32,
                start_time_unix_nano: unix_nanos(),
                attributes,
                ..Default::default()
            })
        });
        Span { trace_id, span_id, continued: parent.is_some(), record, start: Instant::now() }
    }

    fn enqueue(&self, span: SpanProto) {
        if self.queue.push(span).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        } else if self.queue.len() >= BATCH_SIZE {
            self.wake.notify_one();
        }
    }

    fn drain(&self) -> Vec<SpanProto> {
        let n = self.queue.len().min(BATCH_SIZE);
        (0..n).map_while(|_| self.queue.pop()).collect()
    }
}

/// A sampled span for `headers`, for tests outside this module (the
/// process-wide tracer is never installed in tests).
#[cfg(test)]
pub(crate) fn test_span(headers: &(impl RequestHeaders + ?Sized)) -> Span {
    let info = RequestInfo { method: "GET", path: "/", host: "test", scheme: "http", peer_ip: None, service: "svc", port: 80 };
    Tracer::new(Sampler::from_env_values(None, None)).start(headers, &info)
}

/// Exporter settings read from the environment.
#[derive(Debug, Clone, PartialEq)]
pub struct ExportConfig {
    pub endpoint: String,
    pub headers: Vec<(String, String)>,
    pub timeout: Duration,
    pub resource: Vec<(String, String)>,
    pub sampler: Sampler,
}

impl ExportConfig {
    /// `None` when tracing is off: no endpoint, `OTEL_TRACES_EXPORTER=none`
    /// or `OTEL_SDK_DISABLED=true`.
    pub fn from_env(var: impl Fn(&str) -> Option<String>) -> Option<Self> {
        let var = |k: &str| var(k).filter(|v| !v.trim().is_empty());
        if var("OTEL_SDK_DISABLED").is_some_and(|v| v.trim().eq_ignore_ascii_case("true")) {
            return None;
        }
        if let Some(exporter) = var("OTEL_TRACES_EXPORTER")
            && exporter.trim() != "otlp"
        {
            if exporter.trim() != "none" {
                warn!("unsupported OTEL_TRACES_EXPORTER {exporter:?}; tracing is off");
            }
            return None;
        }
        let endpoint = var("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT").or_else(|| var("OTEL_EXPORTER_OTLP_ENDPOINT"))?;
        let headers = [var("OTEL_EXPORTER_OTLP_HEADERS"), var("OTEL_EXPORTER_OTLP_TRACES_HEADERS")]
            .into_iter()
            .flatten()
            .flat_map(|v| parse_pairs(&v))
            .collect();
        let timeout = var("OTEL_EXPORTER_OTLP_TRACES_TIMEOUT")
            .or_else(|| var("OTEL_EXPORTER_OTLP_TIMEOUT"))
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map_or(DEFAULT_TIMEOUT, Duration::from_millis);
        let mut resource = var("OTEL_RESOURCE_ATTRIBUTES").map(|v| parse_pairs(&v)).unwrap_or_default();
        let service = var("OTEL_SERVICE_NAME")
            .or_else(|| resource.iter().find(|(k, _)| k == "service.name").map(|(_, v)| v.clone()))
            .unwrap_or_else(|| DEFAULT_SERVICE_NAME.to_string());
        resource.retain(|(k, _)| k != "service.name");
        resource.insert(0, ("service.name".to_string(), service));
        let sampler = Sampler::from_env_values(var("OTEL_TRACES_SAMPLER").as_deref(), var("OTEL_TRACES_SAMPLER_ARG").as_deref());
        Some(Self { endpoint: endpoint.trim().to_string(), headers, timeout, resource, sampler })
    }
}

/// `k=v,k2=v2` with percent-encoded values (W3C Baggage format, as the SDK
/// spec uses for headers and resource attributes). Malformed entries are skipped.
fn parse_pairs(s: &str) -> Vec<(String, String)> {
    s.split(',')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            let k = k.trim();
            (!k.is_empty()).then(|| (k.to_string(), percent_decode(v.trim())))
        })
        .collect()
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let Some(b) = bytes.get(i + 1..i + 3).and_then(|p| {
                let p = [p[0].to_ascii_lowercase(), p[1].to_ascii_lowercase()];
                hex_byte(&p)
            })
        {
            out.push(b);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Read the environment and, when tracing is configured, install the tracer
/// and start the exporter thread. Called once at startup.
pub fn init_from_env() -> Result<(), String> {
    let Some(config) = ExportConfig::from_env(|k| std::env::var(k).ok()) else {
        return Ok(());
    };
    let channel = tonic::transport::Endpoint::from_shared(config.endpoint.clone())
        .map_err(|e| format!("invalid OTLP endpoint {}: {e}", config.endpoint))?
        .timeout(config.timeout)
        .connect_timeout(config.timeout);
    let channel = if config.endpoint.starts_with("https://") {
        channel
            .tls_config(tonic::transport::ClientTlsConfig::new().with_webpki_roots())
            .map_err(|e| format!("OTLP endpoint {} TLS: {e}", config.endpoint))?
    } else {
        channel
    };
    let metadata = metadata(&config.headers)?;
    if TRACER.set(Tracer::new(config.sampler)).is_err() {
        return Err("tracing initialised twice".to_string());
    }
    info!("tracing on: OTLP/gRPC to {} ({:?})", config.endpoint, config.sampler);
    let Some(tracer) = TRACER.get() else { return Ok(()) };
    spawn_exporter(tracer, channel, metadata, resource(&config.resource)).map(|_| ())
}

/// Run [`export_loop`] on a thread with its own runtime. The channel is
/// created inside that runtime: tonic's lazy connect needs a reactor, and
/// `bootstrap` runs outside any runtime.
fn spawn_exporter(
    tracer: &'static Tracer,
    endpoint: tonic::transport::Endpoint,
    metadata: tonic::metadata::MetadataMap,
    resource: Resource,
) -> Result<std::thread::JoinHandle<()>, String> {
    std::thread::Builder::new()
        .name("otlp-export".into())
        .spawn(move || match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(rt) => rt.block_on(async move { export_loop(tracer, endpoint.connect_lazy(), metadata, resource).await }),
            Err(e) => warn!("OTLP exporter runtime: {e}; spans will not be exported"),
        })
        .map_err(|e| format!("OTLP exporter thread: {e}"))
}

fn metadata(headers: &[(String, String)]) -> Result<tonic::metadata::MetadataMap, String> {
    let mut map = tonic::metadata::MetadataMap::new();
    for (k, v) in headers {
        let key = tonic::metadata::MetadataKey::from_bytes(k.to_ascii_lowercase().as_bytes())
            .map_err(|_| format!("invalid OTLP header name {k:?}"))?;
        let value = v.parse().map_err(|_| format!("invalid value for OTLP header {k:?}"))?;
        map.insert(key, value);
    }
    Ok(map)
}

fn resource(attrs: &[(String, String)]) -> Resource {
    Resource { attributes: attrs.iter().map(|(k, v)| str_attr(k, v.clone())).collect(), ..Default::default() }
}

fn export_request(resource: &Resource, spans: Vec<SpanProto>) -> ExportTraceServiceRequest {
    ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            resource: Some(resource.clone()),
            scope_spans: vec![ScopeSpans {
                scope: Some(InstrumentationScope {
                    name: "portus-dataplane".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    ..Default::default()
                }),
                spans,
                ..Default::default()
            }],
            ..Default::default()
        }],
    }
}

async fn export_loop(
    tracer: &Tracer,
    channel: tonic::transport::Channel,
    metadata: tonic::metadata::MetadataMap,
    resource: Resource,
) {
    let mut client = TraceServiceClient::new(channel);
    let mut failing = false;
    let mut reported_drops = 0;
    loop {
        if tracer.queue.len() < BATCH_SIZE {
            let _ = tokio::time::timeout(SCHEDULE_DELAY, tracer.wake.notified()).await;
        }
        let dropped = tracer.dropped.load(Ordering::Relaxed);
        if dropped > reported_drops {
            warn!("tracing: {} spans dropped, the export queue was full", dropped - reported_drops);
            reported_drops = dropped;
        }
        loop {
            let spans = tracer.drain();
            if spans.is_empty() {
                break;
            }
            let n = spans.len();
            let mut request = tonic::Request::new(export_request(&resource, spans));
            *request.metadata_mut() = metadata.clone();
            match client.export(request).await {
                Ok(_) if failing => {
                    info!("tracing: OTLP export recovered");
                    failing = false;
                }
                Ok(_) => {}
                Err(e) => {
                    if !failing {
                        warn!("tracing: OTLP export of {n} spans failed: {e}; dropping spans until it recovers");
                        failing = true;
                    }
                    break;
                }
            }
            if n < BATCH_SIZE {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderMap;

    const PARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    fn info() -> RequestInfo<'static> {
        RequestInfo {
            method: "GET",
            path: "/orders",
            host: "shop.example.com",
            scheme: "https",
            peer_ip: Some("10.0.0.9".parse().unwrap()),
            service: "orders",
            port: 8080,
        }
    }

    fn headers(traceparent: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(tp) = traceparent {
            h.insert(TRACEPARENT, tp.parse().unwrap());
        }
        h.insert("user-agent", "curl/8".parse().unwrap());
        h
    }

    fn sampler(name: &str, arg: Option<&str>) -> Sampler {
        Sampler::from_env_values(Some(name), arg)
    }

    #[test]
    fn traceparent_parses_the_spec_example() {
        let tp = parse_traceparent(PARENT.as_bytes()).unwrap();
        assert_eq!(tp.trace_id[0], 0x4b);
        assert_eq!(tp.trace_id[15], 0x36);
        assert_eq!(tp.span_id, [0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7]);
        assert!(tp.sampled);
        let unsampled = parse_traceparent(b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00").unwrap();
        assert!(!unsampled.sampled);
    }

    #[test]
    fn traceparent_rejects_what_the_spec_says_to_ignore() {
        for bad in [
            "",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",
            "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
            "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra",
            "00_4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01x",
        ] {
            assert_eq!(parse_traceparent(bad.as_bytes()), None, "{bad:?}");
        }
    }

    #[test]
    fn traceparent_accepts_a_later_version_with_extra_fields() {
        let tp = parse_traceparent(b"01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-future").unwrap();
        assert!(tp.sampled);
    }

    #[test]
    fn parent_based_sampler_follows_the_parent() {
        let s = sampler("parentbased_always_off", None);
        let sampled = parse_traceparent(PARENT.as_bytes()).unwrap();
        let unsampled = TraceParent { sampled: false, ..sampled };
        assert!(s.sample(&sampled.trace_id, Some(&sampled)));
        assert!(!s.sample(&sampled.trace_id, Some(&unsampled)));
        assert!(!s.sample(&sampled.trace_id, None), "root falls to always_off");
        assert!(sampler("parentbased_always_on", None).sample(&sampled.trace_id, None));
    }

    #[test]
    fn non_parent_based_samplers_ignore_the_parent() {
        let sampled = parse_traceparent(PARENT.as_bytes()).unwrap();
        assert!(!sampler("always_off", None).sample(&sampled.trace_id, Some(&sampled)));
        let unsampled = TraceParent { sampled: false, ..sampled };
        assert!(sampler("always_on", None).sample(&sampled.trace_id, Some(&unsampled)));
    }

    #[test]
    fn ratio_sampler_keys_on_the_trace_id() {
        let mut low = [0u8; 16];
        low[15] = 1;
        let mut high = [0u8; 16];
        high[9..].fill(0xff);
        let half = sampler("traceidratio", Some("0.5"));
        assert!(half.sample(&low, None));
        assert!(!half.sample(&high, None));
        assert!(!sampler("traceidratio", Some("0")).sample(&low, None));
        assert!(sampler("traceidratio", Some("1")).sample(&high, None));
        // Out-of-range or unparsable ratios fall back to 1.0.
        assert_eq!(sampler("traceidratio", Some("2")), sampler("traceidratio", Some("1")));
        assert_eq!(sampler("traceidratio", Some("x")), sampler("traceidratio", None));
    }

    #[test]
    fn unknown_sampler_falls_back_to_the_spec_default() {
        assert_eq!(sampler("jaeger_remote", None), Sampler::from_env_values(None, None));
        assert_eq!(Sampler::from_env_values(None, None), Sampler { parent_based: true, root: RootSampler::AlwaysOn });
    }

    #[test]
    fn span_continues_the_callers_trace_and_parents_the_backend() {
        let tracer = Tracer::new(sampler("parentbased_always_on", None));
        let span = tracer.start(&headers(Some(PARENT)), &info());
        let parent = parse_traceparent(PARENT.as_bytes()).unwrap();
        assert_eq!(span.trace_id(), parent.trace_id);
        assert_eq!(span.record.as_ref().unwrap().parent_span_id, parent.span_id.to_vec());
        let upstream = parse_traceparent(span.traceparent().as_bytes()).unwrap();
        assert_eq!(upstream.trace_id, parent.trace_id);
        assert_ne!(upstream.span_id, parent.span_id, "the backend's parent is this span");
        assert!(upstream.sampled);
    }

    #[test]
    fn unsampled_span_still_propagates_with_the_flag_cleared() {
        let tracer = Tracer::new(sampler("parentbased_always_on", None));
        let span = tracer.start(&headers(Some("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00")), &info());
        assert!(!span.sampled());
        let upstream = parse_traceparent(span.traceparent().as_bytes()).unwrap();
        assert!(!upstream.sampled);
        assert_eq!(upstream.trace_id, span.trace_id());
    }

    #[test]
    fn span_without_a_valid_parent_starts_a_new_trace() {
        let tracer = Tracer::new(sampler("parentbased_always_on", None));
        let span = tracer.start(&headers(Some("garbage")), &info());
        assert!(span.sampled());
        let record = span.record.as_ref().unwrap();
        assert!(record.parent_span_id.is_empty());
        assert_eq!(record.trace_id, span.trace_id().to_vec());
    }

    fn attr<'a>(span: &'a SpanProto, key: &str) -> Option<&'a any_value::Value> {
        span.attributes.iter().find(|kv| kv.key == key).and_then(|kv| kv.value.as_ref()?.value.as_ref())
    }

    #[test]
    fn finished_span_carries_the_request_and_the_status() {
        let tracer = Tracer::new(sampler("always_on", None));
        let span = tracer.start(&headers(None), &info());
        let done = finished(span.record.as_ref().unwrap(), 200, Duration::from_millis(3));
        assert_eq!(done.name, "GET");
        assert_eq!(done.kind, span::SpanKind::Server as i32);
        assert_eq!(done.end_time_unix_nano - done.start_time_unix_nano, 3_000_000);
        assert_eq!(attr(&done, "http.request.method"), Some(&any_value::Value::StringValue("GET".into())));
        assert_eq!(attr(&done, "url.path"), Some(&any_value::Value::StringValue("/orders".into())));
        assert_eq!(attr(&done, "server.address"), Some(&any_value::Value::StringValue("shop.example.com".into())));
        assert_eq!(attr(&done, "client.address"), Some(&any_value::Value::StringValue("10.0.0.9".into())));
        assert_eq!(attr(&done, "user_agent.original"), Some(&any_value::Value::StringValue("curl/8".into())));
        assert_eq!(attr(&done, "portus.backend.service"), Some(&any_value::Value::StringValue("orders".into())));
        assert_eq!(attr(&done, "portus.backend.port"), Some(&any_value::Value::IntValue(8080)));
        assert_eq!(attr(&done, "http.response.status_code"), Some(&any_value::Value::IntValue(200)));
        assert_eq!(done.status, None);
    }

    #[test]
    fn server_errors_and_missing_responses_mark_the_span_failed_but_4xx_does_not() {
        let tracer = Tracer::new(sampler("always_on", None));
        let span = tracer.start(&headers(None), &info());
        let record = span.record.as_ref().unwrap();
        let err = status::StatusCode::Error as i32;
        assert_eq!(finished(record, 503, Duration::ZERO).status.map(|s| s.code), Some(err));
        let none = finished(record, 0, Duration::ZERO);
        assert_eq!(none.status.as_ref().map(|s| s.code), Some(err));
        assert_eq!(attr(&none, "http.response.status_code"), None);
        assert_eq!(attr(&none, "error.type"), Some(&any_value::Value::StringValue("no_response".into())));
        assert_eq!(finished(record, 404, Duration::ZERO).status, None);
    }

    #[test]
    fn full_queue_drops_and_counts() {
        let tracer = Tracer::new(sampler("always_on", None));
        for _ in 0..QUEUE_CAPACITY + 3 {
            tracer.enqueue(SpanProto::default());
        }
        assert_eq!(tracer.dropped.load(Ordering::Relaxed), 3);
        assert_eq!(tracer.drain().len(), BATCH_SIZE);
        assert_eq!(tracer.queue.len(), QUEUE_CAPACITY - BATCH_SIZE);
    }

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| pairs.iter().find(|(name, _)| *name == k).map(|(_, v)| v.to_string())
    }

    #[test]
    fn tracing_is_off_without_an_endpoint_or_when_disabled() {
        assert_eq!(ExportConfig::from_env(env(&[])), None);
        assert_eq!(ExportConfig::from_env(env(&[("OTEL_EXPORTER_OTLP_ENDPOINT", "  ")])), None);
        let on = [("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4317")];
        assert!(ExportConfig::from_env(env(&on)).is_some());
        for off in [("OTEL_SDK_DISABLED", "TRUE"), ("OTEL_TRACES_EXPORTER", "none"), ("OTEL_TRACES_EXPORTER", "zipkin")] {
            assert_eq!(ExportConfig::from_env(env(&[on[0], off])), None, "{off:?}");
        }
    }

    #[test]
    fn export_config_reads_the_standard_variables() {
        let c = ExportConfig::from_env(env(&[
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://generic:4317"),
            ("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "https://traces.example.com"),
            ("OTEL_EXPORTER_OTLP_HEADERS", "authorization=Bearer%20abc, x-team = ops"),
            ("OTEL_EXPORTER_OTLP_TIMEOUT", "2500"),
            ("OTEL_RESOURCE_ATTRIBUTES", "service.name=ignored,deployment.environment=prod,broken"),
            ("OTEL_SERVICE_NAME", "edge"),
            ("OTEL_TRACES_SAMPLER", "parentbased_traceidratio"),
            ("OTEL_TRACES_SAMPLER_ARG", "0.25"),
        ]))
        .unwrap();
        assert_eq!(c.endpoint, "https://traces.example.com");
        assert_eq!(c.headers, vec![("authorization".into(), "Bearer abc".into()), ("x-team".into(), "ops".into())]);
        assert_eq!(c.timeout, Duration::from_millis(2500));
        assert_eq!(
            c.resource,
            vec![("service.name".into(), "edge".into()), ("deployment.environment".into(), "prod".into())]
        );
        assert_eq!(c.sampler, Sampler { parent_based: true, root: RootSampler::Ratio(RATIO_SPACE / 4) });
    }

    #[test]
    fn service_name_comes_from_resource_attributes_then_the_default() {
        let from_attrs = ExportConfig::from_env(env(&[
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://c:4317"),
            ("OTEL_RESOURCE_ATTRIBUTES", "service.name=gw"),
        ]))
        .unwrap();
        assert_eq!(from_attrs.resource, vec![("service.name".into(), "gw".into())]);
        let default = ExportConfig::from_env(env(&[("OTEL_EXPORTER_OTLP_ENDPOINT", "http://c:4317")])).unwrap();
        assert_eq!(default.resource, vec![("service.name".into(), DEFAULT_SERVICE_NAME.into())]);
    }

    #[test]
    fn percent_decoding_leaves_malformed_escapes_alone() {
        assert_eq!(percent_decode("a%2Cb%3d"), "a,b=");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
    }

    #[test]
    fn metadata_rejects_invalid_header_names() {
        assert!(metadata(&[("Authorization".into(), "Bearer x".into())]).is_ok());
        assert!(metadata(&[("bad header".into(), "x".into())]).is_err());
    }

    mod collector {
        use super::*;
        use portus_types::proto::opentelemetry::proto::collector::trace::v1::trace_service_server::{
            TraceService, TraceServiceServer,
        };
        use portus_types::proto::opentelemetry::proto::collector::trace::v1::ExportTraceServiceResponse;
        use tokio::sync::mpsc;

        struct Fake(mpsc::UnboundedSender<(Option<String>, ExportTraceServiceRequest)>);

        #[tonic::async_trait]
        impl TraceService for Fake {
            async fn export(
                &self,
                request: tonic::Request<ExportTraceServiceRequest>,
            ) -> Result<tonic::Response<ExportTraceServiceResponse>, tonic::Status> {
                let auth = request.metadata().get("authorization").and_then(|v| v.to_str().ok()).map(str::to_string);
                let _ = self.0.send((auth, request.into_inner()));
                Ok(tonic::Response::new(ExportTraceServiceResponse::default()))
            }
        }

        /// `bootstrap` starts the exporter outside any Tokio runtime; it once
        /// built its gRPC channel there and panicked ("no reactor running"),
        /// which aborts a release build: every traced pod crash-looped.
        #[test]
        fn exporter_starts_outside_a_runtime() {
            let (tx, mut rx) = mpsc::unbounded_channel();
            let (addr_tx, addr_rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                tokio::runtime::Runtime::new().unwrap().block_on(async move {
                    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                    addr_tx.send(listener.local_addr().unwrap()).unwrap();
                    tonic::transport::Server::builder()
                        .add_service(TraceServiceServer::new(Fake(tx)))
                        .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                        .await
                        .unwrap();
                })
            });
            let addr = addr_rx.recv().unwrap();

            let tracer: &'static Tracer = Box::leak(Box::new(Tracer::new(sampler("always_on", None))));
            for _ in 0..BATCH_SIZE {
                let span = tracer.start(&headers(None), &info());
                tracer.enqueue(finished(span.record.as_ref().unwrap(), 200, Duration::ZERO));
            }
            let endpoint = tonic::transport::Endpoint::from_shared(format!("http://{addr}")).unwrap();
            let exporter = spawn_exporter(tracer, endpoint, tonic::metadata::MetadataMap::new(), resource(&[])).unwrap();

            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            let received = loop {
                if let Ok((_, req)) = rx.try_recv() {
                    break req;
                }
                assert!(!exporter.is_finished(), "the exporter thread died");
                assert!(std::time::Instant::now() < deadline, "nothing exported");
                std::thread::sleep(Duration::from_millis(20));
            };
            assert_eq!(received.resource_spans[0].scope_spans[0].spans.len(), BATCH_SIZE);
        }

        #[tokio::test]
        async fn exporter_sends_batches_with_resource_and_headers() {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (tx, mut rx) = mpsc::unbounded_channel();
            tokio::spawn(
                tonic::transport::Server::builder()
                    .add_service(TraceServiceServer::new(Fake(tx)))
                    .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)),
            );

            // A leaked tracer stands in for the process-wide one.
            let tracer: &'static Tracer = Box::leak(Box::new(Tracer::new(sampler("always_on", None))));
            for _ in 0..BATCH_SIZE + 1 {
                let span = tracer.start(&headers(Some(PARENT)), &info());
                tracer.enqueue(finished(span.record.as_ref().unwrap(), 200, Duration::from_millis(1)));
            }
            let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}")).unwrap().connect_lazy();
            let meta = metadata(&[("authorization".into(), "Bearer t".into())]).unwrap();
            let res = resource(&[("service.name".into(), "edge".into())]);
            tokio::spawn(export_loop(tracer, channel, meta, res));

            let mut spans = 0;
            while spans < BATCH_SIZE + 1 {
                let (auth, req) = tokio::time::timeout(Duration::from_secs(10), rx.recv()).await.unwrap().unwrap();
                assert_eq!(auth.as_deref(), Some("Bearer t"));
                let rs = &req.resource_spans[0];
                let service = &rs.resource.as_ref().unwrap().attributes[0];
                assert_eq!(service.key, "service.name");
                let batch = &rs.scope_spans[0].spans;
                assert!(batch.len() <= BATCH_SIZE);
                assert!(batch.iter().all(|s| s.trace_id == parse_traceparent(PARENT.as_bytes()).unwrap().trace_id));
                spans += batch.len();
            }
            assert_eq!(spans, BATCH_SIZE + 1);
        }
    }
}
