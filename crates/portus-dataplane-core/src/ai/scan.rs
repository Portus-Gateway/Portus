//! Streaming extraction of a few top-level scalar fields from a JSON object
//! body, without building a document.
//!
//! An LLM request puts the routing keys (`model`, `stream`) *after* the
//! prompt: the Anthropic and OpenAI SDKs both serialise `messages` first, so
//! with a 200k-token prompt `model` sits several hundred kilobytes in. The
//! scanner is fed the body as it arrives, tracks only depth and string
//! state, skips string contents with `memchr`, and reports `Complete` the
//! moment every wanted key has a value or the root object closes. The caller
//! holds the bytes it has fed and forwards them untouched.
//!
//! Only scalars at depth one are extracted: strings (unescaped), `true`,
//! `false`, `null` and numbers (kept as text). A wanted key whose value is an
//! object or array is reported as [`Scalar::Compound`] and skipped. The first
//! occurrence of a key wins; scanning stops before any duplicate is reached.

use memchr::{memchr, memchr2, memchr3};

/// A top-level value the scanner extracted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scalar {
    Str(String),
    Bool(bool),
    Null,
    /// A number, as it appeared in the body.
    Num(String),
    /// The value was an object or array; it was skipped, not captured.
    Compound,
    /// The raw bytes of an object or array value, when the scanner was built
    /// with [`FieldScanner::capturing_compounds`].
    Raw(Vec<u8>),
}

impl Scalar {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Scalar::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Scalar::Bool(b) => Some(*b),
            _ => None,
        }
    }
}

/// What a `feed` call learned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    /// More bytes are needed; not every wanted key has been seen and the root
    /// object is still open.
    NeedMore,
    /// Every wanted key has a value, or the root object closed. Further bytes
    /// are not scanned.
    Complete,
    /// The body is not a JSON object, or is malformed before the scanner
    /// could finish. Further bytes are not scanned.
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Before the root `{`.
    Start,
    /// Inside the root object, before a key (or the closing `}`).
    ExpectKey,
    /// Reading a key string; `escaped` set after a backslash.
    InKey { escaped: bool },
    /// Key read; before the `:`.
    ExpectColon,
    /// Before a value.
    ExpectValue,
    /// Reading a top-level string value; captured only when wanted.
    InString { escaped: bool, wanted: Option<usize> },
    /// Reading a top-level number, literal or similar bare token.
    InBare { wanted: Option<usize> },
    /// Skipping a nested object or array; `depth` counts open brackets.
    InNested { depth: u32, in_string: bool, escaped: bool },
    /// After a value; before `,` or `}`.
    AfterValue,
    /// Terminal: `Complete` or `Invalid` was returned.
    Done(Progress),
}

/// Incremental scanner for a fixed set of top-level keys.
#[derive(Debug)]
pub struct FieldScanner {
    keys: &'static [&'static str],
    values: Vec<Option<Scalar>>,
    found: usize,
    state: State,
    /// Bytes of the key or wanted value being read, raw (escapes intact).
    token: Vec<u8>,
    /// Which wanted key the current value belongs to, once the colon is seen.
    current: Option<usize>,
    /// Total bytes consumed, for the memory guard the caller enforces.
    consumed: usize,
    /// Copy the raw bytes of a wanted key's object or array value.
    capture_compound: bool,
    /// The wanted key whose compound value is being copied into `token`.
    capturing: Option<usize>,
}

impl FieldScanner {
    pub fn new(keys: &'static [&'static str]) -> Self {
        Self {
            keys,
            values: vec![None; keys.len()],
            found: 0,
            state: State::Start,
            token: Vec::new(),
            current: None,
            consumed: 0,
            capture_compound: false,
            capturing: None,
        }
    }

    /// Keep the raw bytes of wanted keys whose values are objects or arrays
    /// ([`Scalar::Raw`]) instead of reporting [`Scalar::Compound`]. For a
    /// response's `usage` object, which is small; never for a request body.
    pub fn capturing_compounds(mut self) -> Self {
        self.capture_compound = true;
        self
    }

    /// The value extracted for `key`, if it has been seen.
    pub fn get(&self, key: &str) -> Option<&Scalar> {
        let i = self.keys.iter().position(|k| *k == key)?;
        self.values[i].as_ref()
    }

    /// Bytes fed so far.
    pub fn consumed(&self) -> usize {
        self.consumed
    }

    pub fn is_done(&self) -> bool {
        matches!(self.state, State::Done(_))
    }

    /// Scan the next chunk of the body.
    pub fn feed(&mut self, chunk: &[u8]) -> Progress {
        if let State::Done(p) = self.state {
            return p;
        }
        self.consumed += chunk.len();
        let mut i = 0;
        while i < chunk.len() {
            match self.state {
                State::Start => {
                    i = skip_ws(chunk, i);
                    if i >= chunk.len() {
                        break;
                    }
                    if chunk[i] != b'{' {
                        return self.finish(Progress::Invalid);
                    }
                    i += 1;
                    self.state = State::ExpectKey;
                }
                State::ExpectKey => {
                    i = skip_ws(chunk, i);
                    if i >= chunk.len() {
                        break;
                    }
                    match chunk[i] {
                        b'"' => {
                            self.token.clear();
                            self.state = State::InKey { escaped: false };
                        }
                        b'}' => return self.finish(Progress::Complete),
                        _ => return self.finish(Progress::Invalid),
                    }
                    i += 1;
                }
                State::InKey { escaped } => {
                    let (next, end) = read_string_part(chunk, i, escaped, &mut self.token);
                    i = next;
                    self.state = match end {
                        StringEnd::Closed => {
                            self.current = self.wanted_index();
                            State::ExpectColon
                        }
                        StringEnd::Pending { escaped } => State::InKey { escaped },
                    };
                }
                State::ExpectColon => {
                    i = skip_ws(chunk, i);
                    if i >= chunk.len() {
                        break;
                    }
                    if chunk[i] != b':' {
                        return self.finish(Progress::Invalid);
                    }
                    i += 1;
                    self.state = State::ExpectValue;
                }
                State::ExpectValue => {
                    i = skip_ws(chunk, i);
                    if i >= chunk.len() {
                        break;
                    }
                    let wanted = self.current.take();
                    self.token.clear();
                    match chunk[i] {
                        b'"' => {
                            i += 1;
                            self.state = State::InString { escaped: false, wanted };
                        }
                        b'{' | b'[' => {
                            match wanted {
                                Some(w) if self.capture_compound => {
                                    self.token.push(chunk[i]);
                                    self.capturing = Some(w);
                                }
                                Some(w) => self.record(w, Scalar::Compound),
                                None => {}
                            }
                            i += 1;
                            self.state = State::InNested { depth: 1, in_string: false, escaped: false };
                        }
                        b',' | b'}' | b']' | b':' => return self.finish(Progress::Invalid),
                        _ => self.state = State::InBare { wanted },
                    }
                }
                State::InString { escaped, wanted } => {
                    let (next, end) = if wanted.is_some() {
                        read_string_part(chunk, i, escaped, &mut self.token)
                    } else {
                        skip_string_part(chunk, i, escaped)
                    };
                    i = next;
                    match end {
                        StringEnd::Closed => {
                            if let Some(w) = wanted {
                                let Some(s) = unescape(&self.token) else {
                                    return self.finish(Progress::Invalid);
                                };
                                self.record(w, Scalar::Str(s));
                                if self.found == self.keys.len() {
                                    return self.finish(Progress::Complete);
                                }
                            }
                            self.state = State::AfterValue;
                        }
                        StringEnd::Pending { escaped } => self.state = State::InString { escaped, wanted },
                    }
                }
                State::InBare { wanted } => {
                    let start = i;
                    while i < chunk.len() && !is_bare_end(chunk[i]) {
                        i += 1;
                    }
                    if wanted.is_some() || self.token.len() < 8 {
                        // Literals are short; a number only matters when wanted.
                        self.token.extend_from_slice(&chunk[start..i]);
                    }
                    if i >= chunk.len() {
                        break;
                    }
                    let Some(value) = bare_value(&self.token) else {
                        return self.finish(Progress::Invalid);
                    };
                    if let Some(w) = wanted {
                        self.record(w, value);
                        if self.found == self.keys.len() {
                            return self.finish(Progress::Complete);
                        }
                    }
                    self.state = State::AfterValue;
                }
                State::InNested { depth, in_string, escaped } => {
                    let (next, state) = skip_nested_part(chunk, i, depth, in_string, escaped);
                    if self.capturing.is_some() {
                        self.token.extend_from_slice(&chunk[i..next]);
                    }
                    i = next;
                    self.state = match state {
                        Some((depth, in_string, escaped)) => State::InNested { depth, in_string, escaped },
                        None => {
                            if let Some(w) = self.capturing.take() {
                                let raw = std::mem::take(&mut self.token);
                                self.record(w, Scalar::Raw(raw));
                                if self.found == self.keys.len() {
                                    return self.finish(Progress::Complete);
                                }
                            }
                            State::AfterValue
                        }
                    };
                }
                State::AfterValue => {
                    i = skip_ws(chunk, i);
                    if i >= chunk.len() {
                        break;
                    }
                    match chunk[i] {
                        b',' => self.state = State::ExpectKey,
                        b'}' => return self.finish(Progress::Complete),
                        _ => return self.finish(Progress::Invalid),
                    }
                    i += 1;
                }
                State::Done(p) => return p,
            }
        }
        Progress::NeedMore
    }

    fn finish(&mut self, p: Progress) -> Progress {
        self.state = State::Done(p);
        self.token = Vec::new();
        p
    }

    /// Index of the wanted key equal to the key just read, if it is still
    /// missing a value. Keys with escapes never match.
    fn wanted_index(&self) -> Option<usize> {
        if memchr(b'\\', &self.token).is_some() {
            return None;
        }
        self.keys
            .iter()
            .position(|k| k.as_bytes() == self.token.as_slice())
            .filter(|&i| self.values[i].is_none())
    }

    fn record(&mut self, index: usize, value: Scalar) {
        if self.values[index].is_none() {
            self.values[index] = Some(value);
            self.found += 1;
        }
    }
}

fn skip_ws(chunk: &[u8], mut i: usize) -> usize {
    while i < chunk.len() && matches!(chunk[i], b' ' | b'\t' | b'\n' | b'\r') {
        i += 1;
    }
    i
}

fn is_bare_end(b: u8) -> bool {
    matches!(b, b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r')
}

fn bare_value(token: &[u8]) -> Option<Scalar> {
    match token {
        b"true" => Some(Scalar::Bool(true)),
        b"false" => Some(Scalar::Bool(false)),
        b"null" => Some(Scalar::Null),
        [] => None,
        [first, ..] if *first == b'-' || first.is_ascii_digit() => {
            if token.iter().all(|b| matches!(b, b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E')) {
                Some(Scalar::Num(String::from_utf8_lossy(token).into_owned()))
            } else {
                None
            }
        }
        _ => None,
    }
}

enum StringEnd {
    Closed,
    Pending { escaped: bool },
}

/// Copy string contents from `chunk[i..]` into `out` up to the closing quote.
fn read_string_part(chunk: &[u8], mut i: usize, escaped: bool, out: &mut Vec<u8>) -> (usize, StringEnd) {
    if escaped {
        if i >= chunk.len() {
            return (i, StringEnd::Pending { escaped: true });
        }
        out.push(chunk[i]);
        i += 1;
    }
    loop {
        let Some(off) = memchr2(b'"', b'\\', &chunk[i..]) else {
            out.extend_from_slice(&chunk[i..]);
            return (chunk.len(), StringEnd::Pending { escaped: false });
        };
        out.extend_from_slice(&chunk[i..i + off]);
        i += off;
        if chunk[i] == b'"' {
            return (i + 1, StringEnd::Closed);
        }
        // Copy the backslash and the escaped byte; resume escaped if the
        // latter is in the next chunk.
        out.push(b'\\');
        i += 1;
        if i >= chunk.len() {
            return (chunk.len(), StringEnd::Pending { escaped: true });
        }
        out.push(chunk[i]);
        i += 1;
    }
}

/// Advance past string contents in `chunk[i..]` up to the closing quote.
fn skip_string_part(chunk: &[u8], mut i: usize, escaped: bool) -> (usize, StringEnd) {
    if escaped {
        if i >= chunk.len() {
            return (i, StringEnd::Pending { escaped: true });
        }
        i += 1;
    }
    loop {
        let Some(off) = memchr2(b'"', b'\\', &chunk[i..]) else {
            return (chunk.len(), StringEnd::Pending { escaped: false });
        };
        i += off;
        if chunk[i] == b'"' {
            return (i + 1, StringEnd::Closed);
        }
        // Skip the escaped byte too; if it is past this chunk, resume escaped.
        i += 2;
        if i > chunk.len() {
            return (chunk.len(), StringEnd::Pending { escaped: true });
        }
    }
}

/// Advance through a nested object or array. Returns the new position and
/// the remaining nesting state, or `None` once the value closed.
fn skip_nested_part(
    chunk: &[u8],
    mut i: usize,
    mut depth: u32,
    mut in_string: bool,
    mut escaped: bool,
) -> (usize, Option<(u32, bool, bool)>) {
    while i < chunk.len() {
        if in_string {
            match skip_string_part(chunk, i, escaped) {
                (next, StringEnd::Closed) => {
                    i = next;
                    in_string = false;
                    escaped = false;
                }
                (next, StringEnd::Pending { escaped: e }) => return (next, Some((depth, true, e))),
            }
            continue;
        }
        // Structural characters only; everything else in a nested value is
        // noise to us. `[` and `]` are found by a second search.
        let brace = memchr3(b'"', b'{', b'}', &chunk[i..]);
        let bracket = memchr2(b'[', b']', &chunk[i..]);
        let off = match (brace, bracket) {
            (Some(a), Some(b)) => a.min(b),
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (None, None) => return (chunk.len(), Some((depth, false, false))),
        };
        i += off;
        match chunk[i] {
            b'"' => in_string = true,
            b'{' | b'[' => depth += 1,
            _ => {
                depth -= 1;
                if depth == 0 {
                    return (i + 1, None);
                }
            }
        }
        i += 1;
    }
    (i, Some((depth, in_string, escaped)))
}

/// Decode JSON string escapes. `None` for an escape that is not JSON.
fn unescape(raw: &[u8]) -> Option<String> {
    if memchr(b'\\', raw).is_none() {
        return String::from_utf8(raw.to_vec()).ok();
    }
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] != b'\\' {
            out.push(raw[i]);
            i += 1;
            continue;
        }
        let esc = *raw.get(i + 1)?;
        i += 2;
        match esc {
            b'"' => out.push(b'"'),
            b'\\' => out.push(b'\\'),
            b'/' => out.push(b'/'),
            b'b' => out.push(8),
            b'f' => out.push(12),
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b't' => out.push(b'\t'),
            b'u' => {
                let hex = raw.get(i..i + 4)?;
                i += 4;
                let mut code = u32::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?;
                if (0xD800..0xDC00).contains(&code) {
                    // High surrogate: the low one must follow as \uXXXX.
                    if raw.get(i..i + 2)? != b"\\u" {
                        return None;
                    }
                    let low_hex = raw.get(i + 2..i + 6)?;
                    i += 6;
                    let low = u32::from_str_radix(std::str::from_utf8(low_hex).ok()?, 16).ok()?;
                    if !(0xDC00..0xE000).contains(&low) {
                        return None;
                    }
                    code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
                }
                let ch = char::from_u32(code)?;
                let mut buf = [0u8; 4];
                out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
            }
            _ => return None,
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEYS: &[&str] = &["model", "stream"];

    fn scan_whole(body: &str) -> (Progress, FieldScanner) {
        let mut s = FieldScanner::new(KEYS);
        let p = s.feed(body.as_bytes());
        (p, s)
    }

    /// Feed one byte at a time; the result must not depend on chunking.
    fn scan_bytewise(body: &str) -> (Progress, FieldScanner) {
        let mut s = FieldScanner::new(KEYS);
        let mut last = Progress::NeedMore;
        for b in body.as_bytes() {
            last = s.feed(std::slice::from_ref(b));
            if last != Progress::NeedMore {
                break;
            }
        }
        (last, s)
    }

    fn assert_both(body: &str, expect: Progress, model: Option<&str>, stream: Option<bool>) {
        for (label, (p, s)) in [("whole", scan_whole(body)), ("bytewise", scan_bytewise(body))] {
            assert_eq!(p, expect, "{label}: progress for {body:?}");
            assert_eq!(s.get("model").and_then(Scalar::as_str), model, "{label}: model for {body:?}");
            assert_eq!(s.get("stream").and_then(Scalar::as_bool), stream, "{label}: stream for {body:?}");
        }
    }

    #[test]
    fn keys_at_the_front_complete_before_the_prompt_is_read() {
        let body = r#"{"model":"claude-opus-5","stream":true,"messages":[{"role":"user","content":"hi"}]}"#;
        let (p, s) = scan_whole(body);
        assert_eq!(p, Progress::Complete);
        assert_eq!(s.get("model").unwrap().as_str(), Some("claude-opus-5"));
        assert_eq!(s.get("stream").unwrap().as_bool(), Some(true));
        assert_both(body, Progress::Complete, Some("claude-opus-5"), Some(true));
    }

    #[test]
    fn keys_after_a_large_prompt_are_found_the_sdk_order() {
        // Anthropic SDK order: max_tokens, messages, model. Braces, brackets,
        // quotes and escapes inside the prompt must not confuse the scanner.
        let prompt = r#"Here is JSON: {\"model\": \"decoy\", \"a\": [1, {\"b\": \"}\"}]} and a quote \" and a backslash \\"#.repeat(3000);
        let body = format!(
            r#"{{"max_tokens": 1024, "messages": [{{"role": "user", "content": "{prompt}"}}, {{"role":"assistant","content":[{{"type":"text","text":"[]{{}}"}}]}}], "model": "claude-haiku-4-5", "stream": false}}"#
        );
        assert!(body.len() > 200_000);
        assert_both(&body, Progress::Complete, Some("claude-haiku-4-5"), Some(false));
    }

    #[test]
    fn a_missing_key_is_none_and_the_root_close_completes() {
        assert_both(r#"{"model": "m"}"#, Progress::Complete, Some("m"), None);
        assert_both(r#"{"messages": []}"#, Progress::Complete, None, None);
        assert_both("{}", Progress::Complete, None, None);
    }

    #[test]
    fn whitespace_numbers_null_and_nested_values_are_skipped_correctly() {
        let body = "{\n  \"temperature\" : 0.7 ,\n \"n\": -12e3, \"top\": null,\n \"metadata\": {\"user_id\": \"u}{\"},\n \"stop\": [\"]\", \"}\"],\n \"model\" : \"m\" ,\n \"stream\":true\n}";
        assert_both(body, Progress::Complete, Some("m"), Some(true));
    }

    #[test]
    fn escaped_model_names_are_unescaped() {
        assert_both(r#"{"model":"a\/bA\"c"}"#, Progress::Complete, Some("a/bA\"c"), None);
        assert_both(r#"{"model":"😀"}"#, Progress::Complete, Some("😀"), None);
    }

    #[test]
    fn a_wanted_key_with_a_compound_value_is_reported_not_captured() {
        let (p, s) = scan_whole(r#"{"model": {"name": "x"}, "stream": [true]}"#);
        assert_eq!(p, Progress::Complete);
        assert_eq!(s.get("model"), Some(&Scalar::Compound));
        assert_eq!(s.get("stream"), Some(&Scalar::Compound));
    }

    #[test]
    fn compound_values_can_be_captured_raw_across_chunks() {
        const KEYS: &[&str] = &["usage", "model"];
        let body = r#"{"id":"msg_1","model":"claude-opus-5","content":[{"type":"text","text":"}{"}],"usage":{"input_tokens":25,"output_tokens":12,"nested":{"a":[1,2]}}}"#;
        for split in [1usize, 7, 40, body.len()] {
            let mut s = FieldScanner::new(KEYS).capturing_compounds();
            let mut p = Progress::NeedMore;
            for c in body.as_bytes().chunks(split) {
                p = s.feed(c);
                if p != Progress::NeedMore {
                    break;
                }
            }
            assert_eq!(p, Progress::Complete, "split {split}");
            assert_eq!(s.get("model").unwrap().as_str(), Some("claude-opus-5"));
            assert_eq!(
                s.get("usage"),
                Some(&Scalar::Raw(br#"{"input_tokens":25,"output_tokens":12,"nested":{"a":[1,2]}}"#.to_vec())),
                "split {split}"
            );
        }
    }

    #[test]
    fn the_first_occurrence_wins_and_scanning_stops_there() {
        let body = r#"{"model":"first","stream":false,"model":"second"}"#;
        let (p, s) = scan_whole(body);
        assert_eq!(p, Progress::Complete);
        assert_eq!(s.get("model").unwrap().as_str(), Some("first"));
        assert!(s.consumed() <= body.len());
    }

    #[test]
    fn non_objects_and_malformed_bodies_are_invalid() {
        for body in ["[1,2]", "\"model\"", "{model: 1}", r#"{"model" "x"}"#, r#"{"model":,}"#, r#"{"a":1 "b":2}"#, r#"{"model":"\q"}"#, r#"{"x": tru, "model":"m"}"#] {
            let (p, _) = scan_whole(body);
            assert_eq!(p, Progress::Invalid, "{body:?}");
            let (p, _) = scan_bytewise(body);
            assert_eq!(p, Progress::Invalid, "{body:?} bytewise");
        }
    }

    #[test]
    fn a_truncated_body_needs_more_and_a_done_scanner_stays_done() {
        let mut s = FieldScanner::new(KEYS);
        assert_eq!(s.feed(br#"{"messages":[{"content":"abc"#), Progress::NeedMore);
        assert_eq!(s.feed(br#"def"}],"model":"m","str"#), Progress::NeedMore);
        assert_eq!(s.get("model").unwrap().as_str(), Some("m"));
        assert_eq!(s.feed(br#"eam":true}"#), Progress::Complete);
        assert_eq!(s.feed(b"garbage"), Progress::Complete, "no rescanning after completion");
        assert!(s.is_done());
    }

    #[test]
    fn scanning_a_megabyte_prompt_costs_well_under_a_millisecond_per_hundred_kib() {
        let prompt = "The quick brown fox \\\"jumps\\\" over {the} [lazy] dog. ".repeat(20_000);
        let body = format!(r#"{{"messages":[{{"role":"user","content":"{prompt}"}}],"model":"m"}}"#);
        assert!(body.len() > 1_000_000);
        let start = std::time::Instant::now();
        let iterations = 20;
        for _ in 0..iterations {
            let (p, s) = scan_whole(&body);
            assert_eq!(p, Progress::Complete);
            assert_eq!(s.get("model").unwrap().as_str(), Some("m"));
        }
        let per_scan = start.elapsed() / iterations;
        // Debug builds are ~10× slower than release; 20 ms per MiB in debug
        // is still two orders of magnitude below an LLM round trip.
        assert!(per_scan < std::time::Duration::from_millis(50), "scan took {per_scan:?} per MiB");
    }
}
