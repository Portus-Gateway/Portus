//! MCP federation: several MCP servers behind one gateway endpoint with
//! namespaced tool names. The gateway answers `initialize` and `tools/list`
//! itself (fanning out to every member and merging), routes `tools/call` by
//! the `<member>.` prefix of the tool name, and carries every member's
//! session inside the client's `Mcp-Session-Id`, so no gateway pod holds
//! state and any pod can serve any request. This module is the pure part:
//! the network stack does the requests.

use std::sync::Arc;

use serde_json::Value;

/// A federation as the data plane knows it. Members carry everything a
/// request to them needs except the pool, which the stack looks up in the
/// snapshot by `(service_name, port)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Federation {
    /// namespace/name of the AIProvider.
    pub id: Arc<str>,
    pub members: Vec<Member>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// Tool-name prefix.
    pub name: Arc<str>,
    pub service_name: Arc<str>,
    pub port: u16,
    pub tls: bool,
    pub sni: Arc<str>,
    /// Fixed request headers: Host and the credential.
    pub headers: Vec<(http::HeaderName, http::HeaderValue)>,
    /// Where the member serves MCP.
    pub path: Arc<str>,
}

impl Federation {
    pub fn member(&self, name: &str) -> Option<&Member> {
        self.members.iter().find(|m| m.name.as_ref() == name)
    }

    /// The member a namespaced tool name belongs to, and the tool's own name.
    pub fn route_tool<'a>(&self, tool: &'a str) -> Option<(&Member, &'a str)> {
        let (prefix, rest) = split_tool(tool)?;
        self.member(prefix).map(|m| (m, rest))
    }
}

/// Separator between a member's name and the tool's own name.
pub const SEP: char = '.';

/// `github.search` → (`github`, `search`); a name without a separator, or
/// with an empty side, belongs to nobody.
pub fn split_tool(name: &str) -> Option<(&str, &str)> {
    let (prefix, rest) = name.split_once(SEP)?;
    (!prefix.is_empty() && !rest.is_empty()).then_some((prefix, rest))
}

/// Prefix of a client session id that carries member sessions.
const ENVELOPE_PREFIX: &str = "fed.";

/// The client's session id: every member's (tagged) session id, so any
/// gateway pod can continue the session. `%`, `;` and `=` in an id are
/// percent-escaped; everything else in a session id is visible ASCII already.
pub fn encode_sessions<'a>(sessions: impl IntoIterator<Item = (&'a str, &'a str)>) -> String {
    let mut out = String::from(ENVELOPE_PREFIX);
    for (i, (member, sid)) in sessions.into_iter().enumerate() {
        if i > 0 {
            out.push(';');
        }
        out.push_str(member);
        out.push('=');
        for c in sid.chars() {
            match c {
                '%' => out.push_str("%25"),
                ';' => out.push_str("%3B"),
                '=' => out.push_str("%3D"),
                c => out.push(c),
            }
        }
    }
    out
}

/// The member sessions inside a client session id; `None` when it is not
/// one of ours.
pub fn decode_sessions(value: &str) -> Option<Vec<(String, String)>> {
    let rest = value.strip_prefix(ENVELOPE_PREFIX)?;
    if rest.is_empty() {
        return Some(Vec::new());
    }
    rest.split(';')
        .map(|pair| {
            let (member, sid) = pair.split_once('=')?;
            let sid = sid.replace("%3B", ";").replace("%3D", "=").replace("%25", "%");
            (!member.is_empty() && !sid.is_empty()).then(|| (member.to_string(), sid))
        })
        .collect()
}

/// The JSON-RPC response object in a member's reply, whether it came as one
/// JSON document or as SSE (`data:` lines). The first message carrying a
/// `result` or `error` wins.
pub fn response_message(content_type: &str, body: &[u8]) -> Option<Value> {
    let is_message = |v: &Value| v.get("result").is_some() || v.get("error").is_some();
    if content_type.to_ascii_lowercase().starts_with("text/event-stream") {
        for line in body.split(|b| *b == b'\n') {
            let line = std::str::from_utf8(line).ok()?.trim_end_matches('\r');
            if let Some(data) = line.strip_prefix("data:")
                && let Ok(v) = serde_json::from_str::<Value>(data.trim())
                && is_message(&v)
            {
                return Some(v);
            }
        }
        return None;
    }
    serde_json::from_slice::<Value>(body).ok().filter(is_message)
}

/// The JSON-RPC `result` of a member's reply, or `None` when it failed.
pub fn result_of(message: &Value) -> Option<&Value> {
    message.get("result").filter(|_| message.get("error").is_none())
}

fn response(id: &str, result: Value) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{result}}}"#)
}

/// The federation's own `initialize` result: the protocol version the
/// members agreed on (the first one's), tools only, and every member's
/// instructions under its name. `results` are the members' `result` objects.
pub fn merge_initialize(id: &str, results: &[(&str, &Value)]) -> String {
    let version = results
        .iter()
        .find_map(|(_, r)| r.get("protocolVersion").and_then(Value::as_str))
        .unwrap_or("2025-06-18");
    let instructions: Vec<String> = results
        .iter()
        .filter_map(|(name, r)| r.get("instructions").and_then(Value::as_str).filter(|s| !s.trim().is_empty()).map(|s| format!("[{name}] {s}")))
        .collect();
    let mut result = serde_json::json!({
        "protocolVersion": version,
        "capabilities": {"tools": {"listChanged": false}},
        "serverInfo": {"name": "portus", "version": env!("CARGO_PKG_VERSION")},
    });
    if !instructions.is_empty() {
        result["instructions"] = Value::String(instructions.join("\n"));
    }
    response(id, result)
}

/// The federation's `tools/list`: every member's tools with the member's
/// name in front. `results` are the members' `result` objects.
pub fn merge_tools_list(id: &str, results: &[(&str, &Value)]) -> String {
    let mut tools: Vec<Value> = Vec::new();
    for (name, r) in results {
        if let Some(list) = r.get("tools").and_then(Value::as_array) {
            for tool in list {
                let mut t = tool.clone();
                if let Some(n) = t.get("name").and_then(Value::as_str) {
                    let full = format!("{name}{SEP}{n}");
                    t["name"] = Value::String(full);
                }
                tools.push(t);
            }
        }
    }
    response(id, serde_json::json!({"tools": tools}))
}

/// The request body a member sees for a `tools/call`: the same call with
/// the member's prefix taken off the tool name.
pub fn rewrite_tool_call(body: &[u8], tool: &str) -> Option<Vec<u8>> {
    let mut v: Value = serde_json::from_slice(body).ok()?;
    let params = v.get_mut("params")?.as_object_mut()?;
    params.insert("name".to_string(), Value::String(tool.to_string()));
    serde_json::to_vec(&v).ok()
}

/// What the gateway answers by itself for methods it does not fan out:
/// `ping`, and the list methods for capabilities the federation does not
/// advertise. `None`: the method is not one of those.
pub fn local_result(id: &str, method: &str) -> Option<String> {
    let result = match method {
        "ping" => serde_json::json!({}),
        "prompts/list" => serde_json::json!({"prompts": []}),
        "resources/list" => serde_json::json!({"resources": []}),
        "resources/templates/list" => serde_json::json!({"resourceTemplates": []}),
        _ => return None,
    };
    Some(response(id, result))
}

/// JSON-RPC: the tool named is not one the federation has.
pub const CODE_INVALID_PARAMS: i32 = -32602;
/// JSON-RPC: a method the federation does not serve.
pub const CODE_METHOD_NOT_FOUND: i32 = -32601;
/// JSON-RPC: a member failed to answer.
pub const CODE_MEMBER_UNAVAILABLE: i32 = -32004;

#[cfg(test)]
mod tests {
    use super::*;

    fn member(name: &str) -> Member {
        Member { name: Arc::from(name), service_name: Arc::from(format!("aiprovider/ns/{name}")), port: 3001, tls: false, sni: Arc::from(""), headers: Vec::new(), path: Arc::from("/mcp") }
    }

    #[test]
    fn tools_route_to_their_member_by_prefix() {
        let fed = Federation { id: Arc::from("ns/fed"), members: vec![member("gh"), member("wiki")] };
        assert_eq!(fed.route_tool("gh.search").map(|(m, t)| (m.name.as_ref(), t)), Some(("gh", "search")));
        assert_eq!(fed.route_tool("wiki.read.page").map(|(m, t)| (m.name.as_ref(), t)), Some(("wiki", "read.page")), "only the first dot splits");
        assert!(fed.route_tool("search").is_none(), "no prefix");
        assert!(fed.route_tool("slack.post").is_none(), "unknown member");
        assert!(fed.route_tool(".x").is_none() && fed.route_tool("gh.").is_none());
    }

    #[test]
    fn the_session_envelope_round_trips_and_escapes_its_separators() {
        let enc = encode_sessions([("gh", "0a1b2c3d4e5f6071.abc-123"), ("wiki", "id;with=odd%chars")]);
        assert!(enc.starts_with("fed."), "{enc}");
        assert_eq!(decode_sessions(&enc), Some(vec![("gh".into(), "0a1b2c3d4e5f6071.abc-123".into()), ("wiki".into(), "id;with=odd%chars".into())]));
        assert_eq!(decode_sessions("fed."), Some(vec![]));
        assert_eq!(decode_sessions("0a1b2c3d4e5f6071.plain"), None, "a plain tagged id is not an envelope");
        assert_eq!(decode_sessions("fed.broken"), None);
        assert_eq!(decode_sessions("fed.gh="), None, "an empty member id");
    }

    #[test]
    fn member_replies_are_read_from_json_or_sse() {
        let json = br#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#;
        assert!(response_message("application/json", json).and_then(|m| result_of(&m).cloned()).is_some());
        let sse = b"event: message\nid: 9\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-06-18\"}}\n\n";
        let m = response_message("text/event-stream; charset=utf-8", sse).expect("the message with a result");
        assert_eq!(result_of(&m).and_then(|r| r.get("protocolVersion")).and_then(Value::as_str), Some("2025-06-18"));
        let err = br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"bad"}}"#;
        let m = response_message("application/json", err).unwrap();
        assert!(result_of(&m).is_none(), "an error is not a result");
        assert!(response_message("application/json", b"not json").is_none());
        assert!(response_message("application/json", br#"{"jsonrpc":"2.0","method":"notifications/x"}"#).is_none(), "a notification is not a reply");
    }

    #[test]
    fn initialize_and_tools_list_merge_across_members() {
        let a = serde_json::json!({"protocolVersion":"2025-06-18","capabilities":{"tools":{},"prompts":{}},"serverInfo":{"name":"everything"},"instructions":"Use echo."});
        let b = serde_json::json!({"protocolVersion":"2025-03-26","capabilities":{"tools":{}},"serverInfo":{"name":"wiki"},"instructions":"  "});
        let init: Value = serde_json::from_str(&merge_initialize("7", &[("gh", &a), ("wiki", &b)])).unwrap();
        assert_eq!(init["id"], 7);
        assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
        assert_eq!(init["result"]["capabilities"], serde_json::json!({"tools": {"listChanged": false}}), "tools only: no prompts, no resources");
        assert_eq!(init["result"]["serverInfo"]["name"], "portus");
        assert_eq!(init["result"]["instructions"], "[gh] Use echo.", "blank instructions are dropped");
        let ta = serde_json::json!({"tools":[{"name":"echo","description":"e","inputSchema":{"type":"object"}},{"name":"add"}]});
        let tb = serde_json::json!({"tools":[{"name":"echo"}]});
        let list: Value = serde_json::from_str(&merge_tools_list("\"x\"", &[("gh", &ta), ("wiki", &tb)])).unwrap();
        assert_eq!(list["id"], "x");
        let names: Vec<&str> = list["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(names, vec!["gh.echo", "gh.add", "wiki.echo"], "same tool names on two members no longer clash");
        assert_eq!(list["result"]["tools"][0]["description"], "e", "the rest of the tool is untouched");
        let empty: Value = serde_json::from_str(&merge_tools_list("1", &[])).unwrap();
        assert_eq!(empty["result"]["tools"], serde_json::json!([]));
    }

    #[test]
    fn tool_calls_are_rewritten_for_the_member_and_local_methods_answered() {
        let body = br#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"gh.echo","arguments":{"message":"hi"}}}"#;
        let out: Value = serde_json::from_slice(&rewrite_tool_call(body, "echo").unwrap()).unwrap();
        assert_eq!(out["params"]["name"], "echo");
        assert_eq!(out["params"]["arguments"]["message"], "hi");
        assert!(rewrite_tool_call(br#"{"jsonrpc":"2.0","id":3,"method":"tools/call"}"#, "echo").is_none(), "no params");
        assert!(rewrite_tool_call(b"{", "echo").is_none());
        let ping: Value = serde_json::from_str(&local_result("5", "ping").unwrap()).unwrap();
        assert_eq!(ping["result"], serde_json::json!({}));
        assert!(local_result("5", "prompts/list").unwrap().contains(r#""prompts":[]"#));
        assert!(local_result("5", "resources/templates/list").unwrap().contains("resourceTemplates"));
        assert!(local_result("5", "tools/call").is_none());
    }
}
