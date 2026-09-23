//! Model Context Protocol over Streamable HTTP as a dialect of the AI
//! gateway: JSON-RPC requests whose routing keys are the top-level `method`
//! and, for `tools/call`, `params.name`.

use super::scan::{FieldScanner, Progress, Scalar};

/// Bytes of a request's `params` object kept to read the tool name from. A
/// `tools/call` with bigger arguments still routes on `method`; it just has
/// no `tool` field to match.
pub const PARAMS_CAPTURE_LIMIT: usize = 64 * 1024;

const NAME_KEYS: &[&str] = &["name"];

/// The tool a `tools/call` names: `params.name`, read from the captured
/// `params` object.
pub fn tool_name(params: &[u8]) -> Option<String> {
    let mut scanner = FieldScanner::new(NAME_KEYS);
    if scanner.feed(params) == Progress::Invalid {
        return None;
    }
    match scanner.get("name") {
        Some(Scalar::Str(s)) => Some(s.clone()),
        _ => None,
    }
}

/// A JSON-RPC error object, the shape an MCP client surfaces to its user.
/// `id` is the request's id as JSON text (`"abc"`, `7`) or `null`.
pub fn error_body(id: Option<&str>, code: i32, message: &str) -> String {
    let message = serde_json::to_string(message).unwrap_or_else(|_| "\"\"".to_string());
    format!(r#"{{"jsonrpc":"2.0","id":{},"error":{{"code":{code},"message":{message}}}}}"#, id.unwrap_or("null"))
}

/// Separator between the gateway's endpoint tag and the server's own session
/// id in the `Mcp-Session-Id` a client sees.
const TAG_SEP: char = '.';

/// The session id a client holds: the tag of the endpoint that created the
/// session, then the server's own id. The server never sees the tag.
pub fn tag_session(tag: &str, server_id: &str) -> String {
    format!("{tag}{TAG_SEP}{server_id}")
}

/// Split a client-held session id into (endpoint tag, server id). A value
/// without a recognisable tag is returned whole as the server id.
pub fn split_session(value: &str) -> (Option<&str>, &str) {
    match value.split_once(TAG_SEP) {
        Some((tag, rest)) if tag.len() == crate::pool::TAG_LEN && tag.bytes().all(|b| b.is_ascii_hexdigit()) && !rest.is_empty() => (Some(tag), rest),
        _ => (None, value),
    }
}

/// JSON-RPC error codes the gateway answers with (the -32000 to -32099
/// range is reserved for implementation-defined server errors).
pub const CODE_UNAUTHENTICATED: i32 = -32001;
pub const CODE_NOT_ALLOWED: i32 = -32002;
pub const CODE_BUDGET_EXHAUSTED: i32 = -32003;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tool_name_comes_out_of_params_whatever_else_is_in_there() {
        assert_eq!(tool_name(br#"{"arguments":{"name":"decoy","q":"}"},"name":"github.search"}"#), Some("github.search".into()));
        assert_eq!(tool_name(br#"{"name":"a\/b"}"#), Some("a/b".into()));
        assert_eq!(tool_name(br#"{"arguments":{}}"#), None);
        assert_eq!(tool_name(br#"{"name":7}"#), None);
        assert_eq!(tool_name(b"[1,2]"), None);
        assert_eq!(tool_name(b"{"), None, "a truncated capture is not a name");
    }

    #[test]
    fn session_ids_carry_the_endpoint_tag_in_front_of_the_servers_id() {
        let tagged = tag_session("0a1b2c3d4e5f6071", "5c94-uuid.with.dots");
        assert_eq!(split_session(&tagged), (Some("0a1b2c3d4e5f6071"), "5c94-uuid.with.dots"));
        assert_eq!(split_session("plain-server-id"), (None, "plain-server-id"));
        assert_eq!(split_session("0a1b2c3d4e5f6071."), (None, "0a1b2c3d4e5f6071."), "an empty server id is not a tag");
        assert_eq!(split_session("zz1b2c3d4e5f6071.x"), (None, "zz1b2c3d4e5f6071.x"), "tags are hex");
    }

    #[test]
    fn error_bodies_echo_the_id_verbatim_and_escape_the_message() {
        assert_eq!(
            error_body(Some(r#""req-1""#), CODE_NOT_ALLOWED, r#"tool "x" not allowed"#),
            r#"{"jsonrpc":"2.0","id":"req-1","error":{"code":-32002,"message":"tool \"x\" not allowed"}}"#
        );
        assert_eq!(error_body(Some("7"), CODE_UNAUTHENTICATED, "no key"), r#"{"jsonrpc":"2.0","id":7,"error":{"code":-32001,"message":"no key"}}"#);
        assert_eq!(error_body(None, CODE_BUDGET_EXHAUSTED, "spent"), r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32003,"message":"spent"}}"#);
    }
}
