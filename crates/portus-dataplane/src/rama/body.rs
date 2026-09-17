//! Request-body scanning for AI routes: read frames until the core's
//! scanner has what it needs, then hand the backend a body that replays the
//! held frames before the rest of the stream. Nothing is copied: held frames
//! are the `Bytes` the server produced, and the size hint stays exact so the
//! upstream request keeps its Content-Length.

use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use rama::error::BoxError;
use rama::http::body::util::BodyExt;
use rama::http::body::{Frame, SizeHint};
use rama::http::{Body, StatusCode, StreamingBody};

use portus_dataplane_core::ai::scan::{FieldScanner, Progress, Scalar};
use portus_dataplane_core::plan::BodyNeed;
use portus_dataplane_core::router::BodyFields;

/// Read `body` until the wanted fields are known (or the body ends, or it is
/// malformed), holding at most `need.max_bytes`. Returns the fields and a
/// body that yields everything read so far followed by the remainder.
pub async fn scan_body(mut body: Body, need: BodyNeed) -> Result<(BodyFields, Body), StatusCode> {
    let mut scanner = FieldScanner::new(need.keys);
    let mut held: VecDeque<Bytes> = VecDeque::new();
    let mut held_len = 0usize;
    let mut trailers = None;
    let mut ended = false;
    loop {
        let Some(frame) = body.frame().await else {
            ended = true;
            break;
        };
        let frame = frame.map_err(|_| StatusCode::BAD_REQUEST)?;
        match frame.into_data() {
            Ok(data) => {
                held_len += data.len();
                if held_len > need.max_bytes {
                    return Err(StatusCode::PAYLOAD_TOO_LARGE);
                }
                let progress = scanner.feed(&data);
                held.push_back(data);
                if progress != Progress::NeedMore {
                    break;
                }
            }
            Err(frame) => {
                // Trailers end the body; keep them for the backend.
                trailers = frame.into_trailers().ok();
                ended = true;
                break;
            }
        }
    }
    let mut fields: BodyFields = Vec::with_capacity(need.keys.len());
    for key in need.keys {
        let value = match scanner.get(key) {
            Some(Scalar::Str(s)) => s.clone(),
            Some(Scalar::Bool(b)) => b.to_string(),
            Some(Scalar::Num(n)) => n.clone(),
            Some(Scalar::Null) => "null".to_string(),
            Some(Scalar::Compound | Scalar::Raw(_)) | None => continue,
        };
        fields.push((key, value));
    }
    let rest = if ended { None } else { Some(body) };
    let replay = Prefixed { held, held_len: held_len as u64, trailers, rest };
    Ok((fields, Body::new(replay)))
}

/// Held frames first, then the unread remainder of the original body.
struct Prefixed {
    held: VecDeque<Bytes>,
    held_len: u64,
    trailers: Option<rama::http::HeaderMap>,
    rest: Option<Body>,
}

impl StreamingBody for Prefixed {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        if let Some(chunk) = self.held.pop_front() {
            self.held_len -= chunk.len() as u64;
            return Poll::Ready(Some(Ok(Frame::data(chunk))));
        }
        if let Some(rest) = self.rest.as_mut() {
            return Pin::new(rest).poll_frame(cx);
        }
        Poll::Ready(self.trailers.take().map(|t| Ok(Frame::trailers(t))))
    }

    fn is_end_stream(&self) -> bool {
        self.held.is_empty() && self.trailers.is_none() && self.rest.as_ref().is_none_or(StreamingBody::is_end_stream)
    }

    fn size_hint(&self) -> SizeHint {
        match &self.rest {
            None => SizeHint::with_exact(self.held_len),
            Some(rest) => {
                let inner = rest.size_hint();
                let mut hint = SizeHint::new();
                hint.set_lower(self.held_len + inner.lower());
                if let Some(upper) = inner.upper() {
                    hint.set_upper(self.held_len + upper);
                }
                hint
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::stream;
    use portus_dataplane_core::plan::{AI_BODY_KEYS, AI_BODY_SCAN_LIMIT};

    fn need() -> BodyNeed {
        BodyNeed { keys: AI_BODY_KEYS, max_bytes: AI_BODY_SCAN_LIMIT }
    }

    fn chunked(parts: &[&str]) -> Body {
        let items: Vec<Result<Bytes, BoxError>> = parts.iter().map(|p| Ok(Bytes::copy_from_slice(p.as_bytes()))).collect();
        Body::from_stream(stream::iter(items))
    }

    #[tokio::test]
    async fn fields_come_out_and_the_backend_sees_the_whole_body_unchanged() {
        let parts = [r#"{"max_tokens":1024,"messages":[{"role":"user","content":"hel"#, r#"lo {\"model\": 1}"}],"#, r#""model":"claude-opus-5","stream":true,"#, r#""metadata":{"user_id":"u1"}}"#];
        let (fields, body) = scan_body(chunked(&parts), need()).await.unwrap();
        assert_eq!(fields, vec![("model", "claude-opus-5".to_string()), ("stream", "true".to_string()), ("max_tokens", "1024".to_string())]);
        let replayed = body.collect().await.unwrap().to_bytes();
        assert_eq!(replayed, Bytes::from(parts.concat()));
    }

    #[tokio::test]
    async fn a_known_length_body_keeps_an_exact_size_hint() {
        let full = r#"{"model":"m","messages":[]}"#;
        let body = Body::new(rama::http::body::util::Full::new(Bytes::from(full)));
        let (fields, replay) = scan_body(body, need()).await.unwrap();
        assert_eq!(fields, vec![("model", "m".to_string())]);
        assert_eq!(StreamingBody::size_hint(&replay).exact(), Some(full.len() as u64));
        assert!(!replay.is_end_stream());
        assert_eq!(replay.collect().await.unwrap().to_bytes(), Bytes::from(full));
    }

    #[tokio::test]
    async fn malformed_json_yields_no_fields_but_still_forwards() {
        let (fields, body) = scan_body(chunked(&["not json at all"]), need()).await.unwrap();
        assert!(fields.is_empty());
        assert_eq!(body.collect().await.unwrap().to_bytes(), Bytes::from("not json at all"));
    }

    #[tokio::test]
    async fn bodies_over_the_limit_are_refused() {
        let big = format!(r#"{{"messages":[{{"content":"{}"}}],"model":"m"}}"#, "x".repeat(300));
        let status = scan_body(chunked(&[&big]), BodyNeed { keys: AI_BODY_KEYS, max_bytes: 256 }).await.err();
        assert_eq!(status, Some(StatusCode::PAYLOAD_TOO_LARGE));
    }
}
