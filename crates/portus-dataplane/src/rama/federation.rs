//! MCP federation on the Rama stack: the fan-out the core's
//! `ai::federation` module describes. One client request becomes one
//! request per member (initialize, notifications, tools/list, DELETE) or
//! one request to the member a tool name points at (tools/call); the
//! client's session id carries every member's session, so any pod serves
//! any request and nothing is kept between them.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use log::warn;
use rama::http::body::util::{BodyExt, Full};
use rama::http::{Body, HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Version};
use rama::net::address::Host;
use rama::net::Protocol;
use rama::net::uri::Uri;
use rama::tls::client::TlsServerName;
use rama::extensions::ExtensionsRef;
use serde_json::Value;

use portus_dataplane_core::ai::federation::{
    decode_sessions, encode_sessions, local_result, merge_initialize, merge_tools_list, response_message, result_of, rewrite_tool_call,
    Federation, Member, CODE_INVALID_PARAMS, CODE_MEMBER_UNAVAILABLE, CODE_METHOD_NOT_FOUND,
};
use portus_dataplane_core::ai::mcp::{error_body, split_session, tag_session};
use portus_dataplane_core::plan::{Forward, Reply};
use portus_dataplane_core::pool::{endpoint_tag, Pool};
use portus_dataplane_core::router::BodyFields;

use super::client::UpstreamTarget;
use super::proxy::{reply_response, status_response, ProxyService};

/// Largest member reply the gateway reads into memory to merge.
const MEMBER_REPLY_MAX: usize = 4 * 1024 * 1024;
/// Request headers the client sent that members should see too.
const PASSED_HEADERS: &[&str] = &["content-type", "accept", "mcp-protocol-version", "user-agent"];

/// One member's reply to a fan-out request.
struct MemberReply {
    /// The session the member (or its endpoint tag) answered with, tagged.
    session: Option<String>,
    message: Option<Value>,
    status: u16,
}

impl ProxyService {
    /// Serve one request on a federated route. `sessions` are the member
    /// sessions from the client's `Mcp-Session-Id`; `fields` the scanned
    /// body fields; `request_id` the JSON-RPC id as JSON text.
    pub(super) async fn federate(
        &self,
        req: Request,
        plan: &Forward,
        fed: &Federation,
        lbs: &hashbrown::HashMap<(Arc<str>, u16), Arc<Pool>>,
        fields: Option<&BodyFields>,
        request_id: Option<&str>,
    ) -> Response {
        let field = |key: &str| fields.and_then(|f| f.iter().find(|(k, _)| *k == key)).map(|(_, v)| v.as_str());
        let deadline = plan.request_timeout.or(plan.read_timeout).or(plan.connect_timeout);
        let sessions: Vec<(String, String)> = req
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .and_then(decode_sessions)
            .unwrap_or_default();
        let session_of = |member: &str| sessions.iter().find(|(m, _)| m == member).map(|(_, s)| s.as_str());
        let passed: Vec<(HeaderName, HeaderValue)> = PASSED_HEADERS
            .iter()
            .filter_map(|n| req.headers().get(*n).map(|v| (HeaderName::from_static(n), v.clone())))
            .collect();

        match *req.method() {
            Method::GET => {
                // Server-initiated streams across several members are not merged.
                let mut resp = status_response(StatusCode::METHOD_NOT_ALLOWED);
                resp.headers_mut().insert("allow", HeaderValue::from_static("POST, DELETE"));
                return resp;
            }
            Method::DELETE => {
                for m in &fed.members {
                    let Some(sid) = session_of(&m.name) else { continue };
                    let _ = self.member_call(m, lbs, Method::DELETE, &passed, Some(sid), Bytes::new(), deadline).await;
                }
                return status_response(StatusCode::OK);
            }
            Method::POST => {}
            _ => return status_response(StatusCode::METHOD_NOT_ALLOWED),
        }

        let body = match collect_body(req.into_body(), plan.max_request_body_bytes).await {
            Ok(b) => b,
            Err(status) => return status_response(status),
        };
        let method = field("method").unwrap_or("");
        let id = request_id.unwrap_or("null");

        if method.starts_with("notifications/") {
            for m in &fed.members {
                let _ = self.member_call(m, lbs, Method::POST, &passed, session_of(&m.name), body.clone(), deadline).await;
            }
            return status_response(StatusCode::ACCEPTED);
        }
        match method {
            "initialize" => {
                let mut sessions_out: Vec<(String, String)> = Vec::with_capacity(fed.members.len());
                let mut results: Vec<(String, Value)> = Vec::with_capacity(fed.members.len());
                for m in &fed.members {
                    match self.member_call(m, lbs, Method::POST, &passed, None, body.clone(), deadline).await {
                        Ok(reply) if reply.message.as_ref().and_then(result_of).is_some() => {
                            if let Some(sid) = reply.session {
                                sessions_out.push((m.name.to_string(), sid));
                            }
                            results.push((m.name.to_string(), reply.message.and_then(|msg| result_of(&msg).cloned()).unwrap_or_default()));
                        }
                        other => {
                            let why = match other {
                                Ok(reply) => format!("answered {} without a result", reply.status),
                                Err(e) => e,
                            };
                            warn!("federation {}: member {} did not initialize: {why}", fed.id, m.name);
                            return reply_response(Reply::json(200, error_body(Some(id), CODE_MEMBER_UNAVAILABLE, &format!("MCP server {} is unavailable: {why}", m.name))));
                        }
                    }
                }
                let refs: Vec<(&str, &Value)> = results.iter().map(|(n, v)| (n.as_str(), v)).collect();
                let mut reply = Reply::json(200, merge_initialize(id, &refs));
                if let Ok(v) = HeaderValue::from_str(&encode_sessions(sessions_out.iter().map(|(m, s)| (m.as_str(), s.as_str())))) {
                    reply = reply.with_header(http::header::HeaderName::from_static("mcp-session-id"), http_value(&v));
                }
                reply_response(reply)
            }
            "tools/list" => {
                let mut results: Vec<(String, Value)> = Vec::with_capacity(fed.members.len());
                for m in &fed.members {
                    match self.member_call(m, lbs, Method::POST, &passed, session_of(&m.name), body.clone(), deadline).await {
                        Ok(reply) => match reply.message.as_ref().and_then(result_of) {
                            Some(r) => results.push((m.name.to_string(), r.clone())),
                            None => warn!("federation {}: member {} answered tools/list with {} and no result; its tools are left out", fed.id, m.name, reply.status),
                        },
                        Err(e) => warn!("federation {}: member {} tools/list failed: {e}; its tools are left out", fed.id, m.name),
                    }
                }
                let refs: Vec<(&str, &Value)> = results.iter().map(|(n, v)| (n.as_str(), v)).collect();
                reply_response(Reply::json(200, merge_tools_list(id, &refs)))
            }
            "tools/call" => {
                let Some((member, tool)) = field("tool").and_then(|t| fed.route_tool(t)) else {
                    let named = field("tool").unwrap_or("(none)");
                    return reply_response(Reply::json(200, error_body(Some(id), CODE_INVALID_PARAMS, &format!("unknown tool {named}: tools are named <server>.<tool>"))));
                };
                let Some(rewritten) = rewrite_tool_call(&body, tool) else {
                    return reply_response(Reply::json(200, error_body(Some(id), CODE_INVALID_PARAMS, "tools/call params could not be read")));
                };
                match self.member_response(member, lbs, Method::POST, &passed, session_of(&member.name), Bytes::from(rewritten), deadline).await {
                    Ok((mut resp, _)) => {
                        // The client holds the envelope, never a member's own id.
                        resp.headers_mut().remove("mcp-session-id");
                        resp
                    }
                    Err(e) => {
                        warn!("federation {}: member {} tools/call failed: {e}", fed.id, member.name);
                        reply_response(Reply::json(200, error_body(Some(id), CODE_MEMBER_UNAVAILABLE, &format!("MCP server {} is unavailable", member.name))))
                    }
                }
            }
            other => match local_result(id, other) {
                Some(body) => reply_response(Reply::json(200, body)),
                None => reply_response(Reply::json(200, error_body(Some(id), CODE_METHOD_NOT_FOUND, &format!("method {other} is not served by this federation")))),
            },
        }
    }

    /// One request to a member, its reply read whole and parsed.
    async fn member_call(
        &self,
        member: &Member,
        lbs: &hashbrown::HashMap<(Arc<str>, u16), Arc<Pool>>,
        method: Method,
        passed: &[(HeaderName, HeaderValue)],
        session: Option<&str>,
        body: Bytes,
        deadline: Option<Duration>,
    ) -> Result<MemberReply, String> {
        let (resp, backend) = self.member_response(member, lbs, method, passed, session, body, deadline).await?;
        let status = resp.status().as_u16();
        let content_type = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        // The member's own session id, tagged with the endpoint that holds it.
        let session_out = resp
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .map(|id| match split_session(id) {
                (Some(_), _) => id.to_string(),
                (None, _) => tag_session(&endpoint_tag(&backend), id),
            });
        let bytes = resp.into_body().limited(MEMBER_REPLY_MAX).collect().await.map_err(|e| format!("reading the reply: {e}"))?.to_bytes();
        Ok(MemberReply { session: session_out, message: response_message(&content_type, &bytes), status })
    }

    /// One request to a member; the response is handed back as it streams,
    /// with the endpoint that answered.
    async fn member_response(
        &self,
        member: &Member,
        lbs: &hashbrown::HashMap<(Arc<str>, u16), Arc<Pool>>,
        method: Method,
        passed: &[(HeaderName, HeaderValue)],
        session: Option<&str>,
        body: Bytes,
        deadline: Option<Duration>,
    ) -> Result<(Response, SocketAddr), String> {
        let pool = lbs.get(&(Arc::clone(&member.service_name), member.port)).ok_or_else(|| format!("no pool for {}:{}", member.service_name, member.port))?;
        // A session pins its member endpoint by the tag in front of the id.
        let (tag, server_id) = match session {
            Some(s) => {
                let (t, id) = split_session(s);
                (t, Some(id))
            }
            None => (None, None),
        };
        let backend = tag.and_then(|t| pool.endpoint_by_tag(t)).or_else(|| pool.select()).ok_or_else(|| format!("{} has no endpoints", member.service_name))?;

        let mut headers = HeaderMap::new();
        for (n, v) in passed {
            headers.insert(n.clone(), v.clone());
        }
        for (n, v) in &member.headers {
            if let (Ok(n), Ok(v)) = (HeaderName::from_bytes(n.as_str().as_bytes()), HeaderValue::from_bytes(v.as_bytes())) {
                headers.insert(n, v);
            }
        }
        if let Some(id) = server_id
            && let Ok(v) = HeaderValue::from_str(id)
        {
            headers.insert("mcp-session-id", v);
        }
        headers.insert("accept-encoding", HeaderValue::from_static("identity"));
        if method == Method::POST {
            headers.insert("content-length", HeaderValue::from(body.len()));
        }

        let uri: Uri = format!("{}://{backend}{}", if member.tls { "https" } else { "http" }, member.path).parse().map_err(|e| format!("member uri: {e}"))?;
        let mut req = Request::new(Body::new(Full::new(body)));
        *req.method_mut() = method;
        *req.uri_mut() = uri;
        *req.version_mut() = Version::HTTP_11;
        *req.headers_mut() = headers;
        let ext = req.extensions();
        let mut tls_key = 0u64;
        if member.tls {
            if !member.sni.is_empty()
                && let Ok(host) = Host::try_from(member.sni.as_ref())
            {
                ext.insert(TlsServerName(host));
            }
            tls_key = (1u64 << 63) | (fxhash(member.sni.as_bytes()) >> 1);
        }
        ext.insert(UpstreamTarget { addr: backend, tls: member.tls, tls_key, h2: false });
        let _ = Protocol::HTTP;
        let resp = self.attempt(req, deadline).await.map_err(|e| format!("{e:?}"))?;
        Ok((resp, backend))
    }
}

async fn collect_body(body: Body, limit: u64) -> Result<Bytes, StatusCode> {
    let limited = if limit > 0 { body.limited(usize::try_from(limit).unwrap_or(usize::MAX)) } else { body.limited(8 * 1024 * 1024) };
    limited.collect().await.map(|c| c.to_bytes()).map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)
}

fn http_value(v: &HeaderValue) -> http::HeaderValue {
    http::HeaderValue::from_bytes(v.as_bytes()).unwrap_or_else(|_| http::HeaderValue::from_static(""))
}

/// A small stable hash for the TLS connection key.
fn fxhash(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, b| (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3))
}
