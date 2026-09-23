//! What one LLM request cost: token usage read out of the provider's
//! response as it streams past, the fixed-size record that carries it, and
//! the lock-free ring the request path drops it into.
//!
//! The request path never allocates for governance: the tracker holds the
//! response's small `usage` object (or the two SSE events that carry it),
//! the record is plain data with inline strings, and the ring is a bounded
//! queue whose overflow is a counter, never back-pressure.

use std::sync::atomic::{AtomicU64, Ordering};

use arrayvec::ArrayString;
use crossbeam_queue::ArrayQueue;
use memchr::{memchr, memmem};
use serde::Deserialize;

use super::scan::{FieldScanner, Progress, Scalar};

/// The API shape a provider speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    Anthropic,
    OpenAi,
    /// Model Context Protocol over Streamable HTTP (JSON-RPC); no tokens.
    Mcp,
}

impl Dialect {
    /// From an `AIProvider.spec.kind`; `openai-compatible` is OpenAI-shaped.
    pub fn parse(kind: &str) -> Option<Self> {
        match kind {
            "anthropic" => Some(Self::Anthropic),
            "openai" | "openai-compatible" => Some(Self::OpenAi),
            "mcp" => Some(Self::Mcp),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::OpenAi => "openai",
            Self::Mcp => "mcp",
        }
    }
}

/// Token counts as the provider reported them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tokens {
    pub input: u32,
    pub output: u32,
    pub cache_read: u32,
    pub cache_creation: u32,
}

/// What the tracker learned from a response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Usage {
    /// `None` when the response carried no usage (an error, a truncated
    /// stream, an OpenAI stream without `stream_options.include_usage`).
    pub tokens: Option<Tokens>,
    /// The model the provider says served the request.
    pub model: Option<String>,
}

/// Largest SSE line the tracker will hold while waiting for its newline; a
/// provider that streams a longer line is not one we parse usage from.
const SSE_LINE_MAX: usize = 1024 * 1024;

const JSON_KEYS: &[&str] = &["usage", "model"];

enum Mode {
    /// One JSON object: capture `usage` raw and `model`.
    Json(FieldScanner),
    /// Server-sent events: parse only the lines that can carry usage.
    Sse { carry: Vec<u8>, overflowed: bool },
}

/// Reads token usage out of a response body as it streams through.
pub struct UsageTracker {
    dialect: Dialect,
    mode: Mode,
    tokens: Option<Tokens>,
    model: Option<String>,
}

impl UsageTracker {
    pub fn new(dialect: Dialect, streaming: bool) -> Self {
        let mode = if streaming {
            Mode::Sse { carry: Vec::new(), overflowed: false }
        } else {
            Mode::Json(FieldScanner::new(JSON_KEYS).capturing_compounds())
        };
        Self { dialect, mode, tokens: None, model: None }
    }

    /// Scan the next chunk of the response body.
    pub fn feed(&mut self, chunk: &[u8]) {
        match &mut self.mode {
            Mode::Json(scanner) => {
                if !scanner.is_done() {
                    scanner.feed(chunk);
                }
            }
            Mode::Sse { carry, overflowed } => {
                if *overflowed {
                    return;
                }
                let mut rest = chunk;
                loop {
                    let Some(nl) = memchr(b'\n', rest) else {
                        if carry.len() + rest.len() > SSE_LINE_MAX {
                            *overflowed = true;
                            carry.clear();
                        } else {
                            carry.extend_from_slice(rest);
                        }
                        return;
                    };
                    let (line, tail) = rest.split_at(nl);
                    rest = &tail[1..];
                    if carry.is_empty() {
                        Self::sse_line(self.dialect, line, &mut self.tokens, &mut self.model);
                    } else {
                        carry.extend_from_slice(line);
                        let full = std::mem::take(carry);
                        Self::sse_line(self.dialect, &full, &mut self.tokens, &mut self.model);
                    }
                }
            }
        }
    }

    /// The response is over (or gone): what it reported.
    pub fn finish(self) -> Usage {
        let (mut tokens, mut model) = (self.tokens, self.model);
        if let Mode::Json(scanner) = self.mode {
            if let Some(Scalar::Str(m)) = scanner.get("model") {
                model = Some(m.clone());
            }
            if let Some(Scalar::Raw(raw)) = scanner.get("usage") {
                tokens = parse_usage(self.dialect, raw);
            }
            let _ = Progress::Complete;
        }
        Usage { tokens, model }
    }

    fn sse_line(dialect: Dialect, line: &[u8], tokens: &mut Option<Tokens>, model: &mut Option<String>) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(payload) = line.strip_prefix(b"data:") else { return };
        let payload = payload.strip_prefix(b" ").unwrap_or(payload);
        match dialect {
            Dialect::Anthropic => {
                if memmem::find(payload, b"\"message_start\"").is_some() {
                    if let Ok(ev) = serde_json::from_slice::<AnthropicEvent>(payload)
                        && let Some(msg) = ev.message
                    {
                        if msg.model.is_some() {
                            *model = msg.model;
                        }
                        if let Some(u) = msg.usage {
                            *tokens = Some(u.into());
                        }
                    }
                } else if memmem::find(payload, b"\"message_delta\"").is_some()
                    && let Ok(ev) = serde_json::from_slice::<AnthropicEvent>(payload)
                    && let Some(u) = ev.usage
                {
                    // Cumulative counts for the message; input-side fields are
                    // repeated here on newer API versions, absent on older.
                    let mut t = tokens.unwrap_or_default();
                    t.output = u.output_tokens.unwrap_or(t.output);
                    if let Some(i) = u.input_tokens {
                        t.input = i;
                    }
                    if let Some(c) = u.cache_read_input_tokens {
                        t.cache_read = c;
                    }
                    if let Some(c) = u.cache_creation_input_tokens {
                        t.cache_creation = c;
                    }
                    *tokens = Some(t);
                }
            }
            Dialect::OpenAi => {
                if payload == b"[DONE]" {
                    return;
                }
                let has_usage = memmem::find(payload, b"\"usage\"").is_some() && memmem::find(payload, b"\"usage\":null").is_none();
                if (has_usage || model.is_none())
                    && let Ok(chunk) = serde_json::from_slice::<OpenAiChunk>(payload)
                {
                    if model.is_none() && chunk.model.is_some() {
                        *model = chunk.model;
                    }
                    if let Some(u) = chunk.usage {
                        *tokens = Some(u.into());
                    }
                }
            }
            // MCP responses carry no usage; the record counts the call.
            Dialect::Mcp => {}
        }
    }
}

fn parse_usage(dialect: Dialect, raw: &[u8]) -> Option<Tokens> {
    match dialect {
        Dialect::Anthropic => serde_json::from_slice::<AnthropicUsage>(raw).ok().map(Into::into),
        Dialect::OpenAi => serde_json::from_slice::<OpenAiUsage>(raw).ok().map(Into::into),
        Dialect::Mcp => None,
    }
}

#[derive(Deserialize)]
struct AnthropicEvent {
    #[serde(default)]
    message: Option<AnthropicMessage>,
    #[serde(default)]
    usage: Option<AnthropicUsage>,
}

#[derive(Deserialize)]
struct AnthropicMessage {
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    usage: Option<AnthropicUsage>,
}

#[derive(Deserialize, Default)]
struct AnthropicUsage {
    #[serde(default)]
    input_tokens: Option<u32>,
    #[serde(default)]
    output_tokens: Option<u32>,
    #[serde(default)]
    cache_read_input_tokens: Option<u32>,
    #[serde(default)]
    cache_creation_input_tokens: Option<u32>,
}

impl From<AnthropicUsage> for Tokens {
    fn from(u: AnthropicUsage) -> Self {
        Tokens {
            input: u.input_tokens.unwrap_or(0),
            output: u.output_tokens.unwrap_or(0),
            cache_read: u.cache_read_input_tokens.unwrap_or(0),
            cache_creation: u.cache_creation_input_tokens.unwrap_or(0),
        }
    }
}

#[derive(Deserialize)]
struct OpenAiChunk {
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    usage: Option<OpenAiUsage>,
}

#[derive(Deserialize, Default)]
struct OpenAiUsage {
    #[serde(default)]
    prompt_tokens: Option<u32>,
    #[serde(default)]
    completion_tokens: Option<u32>,
    #[serde(default)]
    prompt_tokens_details: Option<OpenAiPromptDetails>,
}

#[derive(Deserialize, Default)]
struct OpenAiPromptDetails {
    #[serde(default)]
    cached_tokens: Option<u32>,
}

impl From<OpenAiUsage> for Tokens {
    fn from(u: OpenAiUsage) -> Self {
        let cached = u.prompt_tokens_details.and_then(|d| d.cached_tokens).unwrap_or(0);
        Tokens {
            // OpenAI's prompt_tokens includes the cached part; Anthropic's
            // input_tokens excludes it. Report the uncached remainder so the
            // four fields mean the same thing whichever provider answered.
            input: u.prompt_tokens.unwrap_or(0).saturating_sub(cached),
            output: u.completion_tokens.unwrap_or(0),
            cache_read: cached,
            cache_creation: 0,
        }
    }
}

/// Inline string capacity for names and models in a record.
pub const NAME_LEN: usize = 64;

/// One request, fixed size, no heap: what the ledger is told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageRecord {
    pub ts_unix_micros: u64,
    pub duration_micros: u64,
    pub status: u16,
    pub dialect: Dialect,
    pub stream: bool,
    pub provider: ArrayString<NAME_LEN>,
    pub route_host: ArrayString<NAME_LEN>,
    pub requested_model: ArrayString<NAME_LEN>,
    pub served_model: ArrayString<NAME_LEN>,
    pub tokens: Option<Tokens>,
    pub request_bytes: u64,
    pub response_bytes: u64,
    /// The API key the request authenticated with; 0 until keys exist.
    pub key_id: u64,
    pub request_id: u64,
    /// Set when the gateway refused the request instead of forwarding it.
    pub refusal: Option<RefusalKind>,
}

/// Why the gateway refused a request itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalKind {
    Unauthenticated,
    ModelNotAllowed,
    BudgetExhausted,
}

impl RefusalKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unauthenticated => "unauthenticated",
            Self::ModelNotAllowed => "model_not_allowed",
            Self::BudgetExhausted => "budget_exhausted",
        }
    }
}

impl UsageRecord {
    /// Copy `s` into a fixed field, truncating on a char boundary.
    pub fn name(s: &str) -> ArrayString<NAME_LEN> {
        let mut out = ArrayString::new();
        let mut end = s.len().min(NAME_LEN);
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        let _ = out.try_push_str(&s[..end]);
        out
    }
}

/// Bounded lock-free queue of records between request tasks and the drain.
pub struct UsageRing {
    queue: ArrayQueue<UsageRecord>,
    dropped: AtomicU64,
}

impl UsageRing {
    pub fn new(capacity: usize) -> Self {
        Self { queue: ArrayQueue::new(capacity), dropped: AtomicU64::new(0) }
    }

    /// Enqueue, or count the drop when the drain has fallen behind.
    pub fn push(&self, record: UsageRecord) {
        if self.queue.push(record).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Move up to `max` records into `out`; returns how many.
    pub fn drain_into(&self, out: &mut Vec<UsageRecord>, max: usize) -> usize {
        let mut n = 0;
        while n < max {
            match self.queue.pop() {
                Some(r) => {
                    out.push(r);
                    n += 1;
                }
                None => break,
            }
        }
        n
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Records lost to a full ring since start.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcp_is_a_dialect_without_tokens_for_json_and_sse_responses() {
        assert_eq!(Dialect::parse("mcp"), Some(Dialect::Mcp));
        assert_eq!(Dialect::Mcp.as_str(), "mcp");
        let mut t = UsageTracker::new(Dialect::Mcp, false);
        t.feed(br#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":5}}}"#);
        assert_eq!(t.finish(), Usage { tokens: None, model: None });
        let mut t = UsageTracker::new(Dialect::Mcp, true);
        t.feed(b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n");
        assert_eq!(t.finish(), Usage { tokens: None, model: None });
    }

    fn feed_chunked(tracker: &mut UsageTracker, body: &str, size: usize) {
        for c in body.as_bytes().chunks(size) {
            tracker.feed(c);
        }
    }

    const ANTHROPIC_JSON: &str = r#"{"id":"msg_01","type":"message","role":"assistant","model":"claude-opus-5","content":[{"type":"text","text":"Hello {\"usage\": 0}"}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":25,"cache_creation_input_tokens":3,"cache_read_input_tokens":1000,"output_tokens":12}}"#;

    #[test]
    fn anthropic_json_response_yields_tokens_and_model_at_any_chunking() {
        for size in [1, 13, 4096] {
            let mut t = UsageTracker::new(Dialect::Anthropic, false);
            feed_chunked(&mut t, ANTHROPIC_JSON, size);
            let u = t.finish();
            assert_eq!(u.model.as_deref(), Some("claude-opus-5"), "size {size}");
            assert_eq!(u.tokens, Some(Tokens { input: 25, output: 12, cache_read: 1000, cache_creation: 3 }), "size {size}");
        }
    }

    const ANTHROPIC_SSE: &str = "event: message_start\r\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-haiku-4-5\",\"content\":[],\"stop_reason\":null,\"usage\":{\"input_tokens\":25,\"cache_creation_input_tokens\":0,\"cache_read_input_tokens\":0,\"output_tokens\":1}}}\r\n\r\nevent: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello \\\"message_delta\\\" world\"}}\n\nevent: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":15}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";

    #[test]
    fn anthropic_stream_takes_input_from_message_start_and_output_from_message_delta() {
        for size in [1, 17, 8192] {
            let mut t = UsageTracker::new(Dialect::Anthropic, true);
            feed_chunked(&mut t, ANTHROPIC_SSE, size);
            let u = t.finish();
            assert_eq!(u.model.as_deref(), Some("claude-haiku-4-5"), "size {size}");
            assert_eq!(u.tokens, Some(Tokens { input: 25, output: 15, cache_read: 0, cache_creation: 0 }), "size {size}");
        }
    }

    #[test]
    fn a_stream_cut_before_message_delta_keeps_the_input_side() {
        let cut = ANTHROPIC_SSE.find("event: message_delta").unwrap();
        let mut t = UsageTracker::new(Dialect::Anthropic, true);
        t.feed(&ANTHROPIC_SSE.as_bytes()[..cut]);
        let u = t.finish();
        assert_eq!(u.tokens, Some(Tokens { input: 25, output: 1, cache_read: 0, cache_creation: 0 }));
    }

    const OPENAI_JSON: &str = r#"{"id":"chatcmpl-1","object":"chat.completion","created":1,"model":"gpt-5","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":109,"completion_tokens":12,"total_tokens":121,"prompt_tokens_details":{"cached_tokens":100}}}"#;

    #[test]
    fn openai_json_reports_uncached_input_and_cached_separately() {
        let mut t = UsageTracker::new(Dialect::OpenAi, false);
        feed_chunked(&mut t, OPENAI_JSON, 5);
        let u = t.finish();
        assert_eq!(u.model.as_deref(), Some("gpt-5"));
        assert_eq!(u.tokens, Some(Tokens { input: 9, output: 12, cache_read: 100, cache_creation: 0 }));
    }

    const OPENAI_SSE: &str = "data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-5\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"\"}}],\"usage\":null}\n\ndata: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-5\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hi\"}}],\"usage\":null}\n\ndata: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-5\",\"choices\":[],\"usage\":{\"prompt_tokens\":9,\"completion_tokens\":12,\"total_tokens\":21}}\n\ndata: [DONE]\n\n";

    #[test]
    fn openai_stream_takes_usage_from_the_final_chunk() {
        for size in [1, 23, 8192] {
            let mut t = UsageTracker::new(Dialect::OpenAi, true);
            feed_chunked(&mut t, OPENAI_SSE, size);
            let u = t.finish();
            assert_eq!(u.model.as_deref(), Some("gpt-5"), "size {size}");
            assert_eq!(u.tokens, Some(Tokens { input: 9, output: 12, cache_read: 0, cache_creation: 0 }), "size {size}");
        }
        // Without stream_options.include_usage there is no usage chunk.
        let mut t = UsageTracker::new(Dialect::OpenAi, true);
        t.feed(OPENAI_SSE.split("data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-5\",\"choices\":[],").next().unwrap().as_bytes());
        let u = t.finish();
        assert_eq!(u.model.as_deref(), Some("gpt-5"));
        assert_eq!(u.tokens, None);
    }

    #[test]
    fn error_bodies_and_junk_yield_no_usage() {
        let mut t = UsageTracker::new(Dialect::Anthropic, false);
        t.feed(br#"{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}"#);
        assert_eq!(t.finish(), Usage::default());
        let mut t = UsageTracker::new(Dialect::Anthropic, true);
        t.feed(b"<html>bad gateway</html>");
        assert_eq!(t.finish(), Usage::default());
        let mut t = UsageTracker::new(Dialect::Anthropic, true);
        t.feed(&vec![b'x'; SSE_LINE_MAX + 1]);
        t.feed(ANTHROPIC_SSE.as_bytes());
        assert_eq!(t.finish(), Usage::default(), "an overflowed stream stops tracking");
    }

    #[test]
    fn records_are_fixed_size_and_names_truncate_on_char_boundaries() {
        assert!(std::mem::size_of::<UsageRecord>() <= 400, "{}", std::mem::size_of::<UsageRecord>());
        assert_eq!(UsageRecord::name("claude-opus-5").as_str(), "claude-opus-5");
        let long = format!("{}é", "a".repeat(63));
        assert_eq!(UsageRecord::name(&long).as_str(), "a".repeat(63));
    }

    fn record(id: u64) -> UsageRecord {
        UsageRecord {
            ts_unix_micros: 0,
            duration_micros: 0,
            status: 200,
            dialect: Dialect::Anthropic,
            stream: false,
            provider: UsageRecord::name("anthropic"),
            route_host: UsageRecord::name("llm.example.com"),
            requested_model: UsageRecord::name("claude-opus-5"),
            served_model: ArrayString::new(),
            tokens: None,
            request_bytes: 0,
            response_bytes: 0,
            key_id: 0,
            request_id: id,
            refusal: None,
        }
    }

    #[test]
    fn the_ring_drops_and_counts_when_full_and_drains_in_order() {
        let ring = UsageRing::new(4);
        for i in 0..6 {
            ring.push(record(i));
        }
        assert_eq!(ring.len(), 4);
        assert_eq!(ring.dropped(), 2);
        let mut out = Vec::new();
        assert_eq!(ring.drain_into(&mut out, 3), 3);
        assert_eq!(out.iter().map(|r| r.request_id).collect::<Vec<_>>(), vec![0, 1, 2]);
        assert_eq!(ring.drain_into(&mut out, 10), 1);
        assert!(ring.is_empty());
    }
}
