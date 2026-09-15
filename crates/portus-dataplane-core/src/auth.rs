//! Authentication verification for the data plane request pipeline.
//!
//! BasicAuth uses bcrypt hash verification. APIKey checks a configurable header
//! against a set of valid keys. Both return HTTP 401 on failure.

use hashbrown::HashMap;
use std::sync::{LazyLock, OnceLock};
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;

/// Minimum acceptable bcrypt cost factor. Hashes with cost below this are
/// rejected to prevent trivial brute-force attacks on stolen credentials.
const MIN_BCRYPT_COST: u32 = 10;

/// Limits concurrent bcrypt operations to half the available CPUs (minimum 1).
/// This prevents an attacker from saturating all worker threads by flooding the
/// proxy with Basic auth requests — each bcrypt verification at cost 10 takes
/// ~50-100ms, so without a bound the thread pool can be trivially exhausted.
static BCRYPT_SEMAPHORE: LazyLock<Semaphore> = LazyLock::new(|| {
    Semaphore::new(
        std::thread::available_parallelism()
            .map_or(4, |n| n.get() / 2)
            .max(1),
    )
});

/// Returns a dummy bcrypt hash generated at the minimum accepted cost factor.
/// This ensures `bcrypt::verify` always runs when the username is not found,
/// preventing timing-based username enumeration. The hash is generated at
/// `MIN_BCRYPT_COST` so that dummy verification takes the same time as
/// verifying against a real cost-10 hash, closing the timing gap that existed
/// when the dummy used a different (higher) cost.
fn dummy_hash() -> &'static str {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| {
        bcrypt::hash("", MIN_BCRYPT_COST).expect("failed to generate dummy bcrypt hash")
    })
}

/// Extract the cost factor from a bcrypt hash string.
///
/// Bcrypt hashes have the format `$2b$CC$...` (or `$2a$`, `$2y$`),
/// where CC is the two-digit cost factor. Returns `None` if the hash
/// does not follow this format.
fn extract_bcrypt_cost(hash: &str) -> Option<u32> {
    hash.split('$').nth(2)?.parse().ok()
}

/// Validate HTTP Basic Authentication credentials against bcrypt hashes.
///
/// Extracts username:password from the Authorization header (Base64-decoded),
/// then verifies the password against the stored bcrypt hash for that username.
///
/// Security properties:
/// - **Timing-safe**: unknown usernames still run `bcrypt::verify` against a
///   dummy hash so that response time does not reveal whether a username exists.
/// - **Minimum cost enforcement**: bcrypt hashes with cost < 10 are rejected
///   to prevent trivially brute-forceable credentials from being accepted.
/// - **Non-blocking**: bcrypt verification runs on a blocking thread pool with
///   bounded concurrency (see `BCRYPT_SEMAPHORE`), so worker threads are never
///   stalled by CPU-intensive hash verification.
///
/// Returns Ok(()) on success, Err(401) on auth failure, Err(503) on internal error.
pub async fn validate_basic_auth(
    auth_header: Option<&http::HeaderValue>,
    credentials: &HashMap<String, String>,
) -> Result<(), u16> {
    let header = auth_header.ok_or(401u16)?;
    let header_str = header.to_str().map_err(|_| 401u16)?;

    if !header_str.starts_with("Basic ") {
        return Err(401);
    }

    let encoded = &header_str[6..];
    let decoded = base64_decode(encoded).map_err(|_| 401u16)?;
    let decoded_str = std::str::from_utf8(&decoded).map_err(|_| 401u16)?;

    let (username, password) = decoded_str.split_once(':').ok_or(401u16)?;

    // SEC-6: Always run bcrypt::verify to prevent username enumeration via timing.
    let hash = match credentials.get(username) {
        Some(h) => h.clone(),
        None => {
            let password = password.to_string();
            let dummy = dummy_hash().to_string();
            let _permit = BCRYPT_SEMAPHORE.acquire().await.map_err(|_| 503u16)?;
            let _ = tokio::task::spawn_blocking(move || bcrypt::verify(&password, &dummy))
                .await
                .map_err(|_| 503u16)?;
            return Err(401);
        }
    };

    // SEC-7: Reject hashes with insufficient cost factor.
    let cost = extract_bcrypt_cost(&hash).unwrap_or(0);
    if cost < MIN_BCRYPT_COST {
        log::warn!(
            "BasicAuth: rejecting hash with cost {} (minimum: {})",
            cost,
            MIN_BCRYPT_COST
        );
        return Err(401);
    }

    let _permit = BCRYPT_SEMAPHORE.acquire().await.map_err(|_| 503u16)?;
    let password = password.to_string();

    tokio::task::spawn_blocking(move || {
        match bcrypt::verify(&password, &hash) {
            Ok(true) => Ok(()),
            _ => Err(401u16),
        }
    })
    .await
    .map_err(|_| 503u16)?
}

/// Validate an API key from the specified header using constant-time comparison.
///
/// Iterates all valid keys and performs a constant-time byte comparison for each,
/// so timing does not reveal which key (if any) matched. This prevents timing attacks.
///
/// Returns Ok(()) if the header value matches any valid key.
/// Returns Err(401) if missing or invalid.
pub fn validate_api_key(
    key_header: Option<&http::HeaderValue>,
    valid_keys: &hashbrown::HashSet<String>,
) -> Result<(), u16> {
    let header = key_header.ok_or(401u16)?;
    let key = header.to_str().map_err(|_| 401u16)?;

    // Constant-time comparison to prevent timing attacks.
    // We iterate ALL valid keys so timing doesn't reveal which key matched
    // or whether any key matched at all. Do NOT use any() — it short-circuits.
    //
    // Both input and each valid key are padded to a fixed-size buffer before
    // comparison, so timing is independent of key length. Without padding,
    // a length mismatch would skip `ct_eq`, leaking valid key lengths.
    //
    // 256 bytes is chosen as an upper bound for API keys: large enough for
    // any practical key format (UUIDs are 36 bytes, JWTs rarely exceed 200)
    // while small enough for efficient stack-allocated constant-time comparison.
    // Keys longer than PAD_LEN are rejected at config load time in
    // config_receiver.rs to guarantee truncation never occurs here.
    const PAD_LEN: usize = 256;

    let key_bytes = key.as_bytes();
    let key_len = key_bytes.len();

    // Pad input to fixed length
    let mut input_padded = [0u8; PAD_LEN];
    let copy_len = key_len.min(PAD_LEN);
    input_padded[..copy_len].copy_from_slice(&key_bytes[..copy_len]);

    let mut found = subtle::Choice::from(0u8);
    for k in valid_keys.iter() {
        let k_bytes = k.as_bytes();
        let k_len = k_bytes.len();

        // Pad valid key to same fixed length
        let mut valid_padded = [0u8; PAD_LEN];
        let kcopy = k_len.min(PAD_LEN);
        valid_padded[..kcopy].copy_from_slice(&k_bytes[..kcopy]);

        // Constant-time length comparison
        let len_eq = subtle::Choice::from((key_len == k_len) as u8);

        // Always compare full PAD_LEN bytes (constant time)
        let bytes_eq = valid_padded.ct_eq(&input_padded);

        found |= len_eq & bytes_eq;
    }

    if found.into() {
        Ok(())
    } else {
        Err(401)
    }
}

/// Simple Base64 decoding (standard alphabet, no padding required).
fn base64_decode(input: &str) -> Result<Vec<u8>, ()> {
    const DECODE_TABLE: [u8; 256] = {
        let mut table = [255u8; 256];
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut i = 0;
        while i < 64 {
            table[alphabet[i] as usize] = i as u8;
            i += 1;
        }
        table
    };

    let input = input.trim_end_matches('=');
    let mut output = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;

    for &byte in input.as_bytes() {
        let val = DECODE_TABLE[byte as usize];
        if val == 255 {
            return Err(());
        }
        buf = (buf << 6) | val as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashbrown::HashSet;
    use http::HeaderValue;

    #[test]
    fn test_validate_api_key_constant_time_valid() {
        let mut keys = HashSet::new();
        keys.insert("test-key-123".to_string());
        let header = HeaderValue::from_static("test-key-123");
        assert!(validate_api_key(Some(&header), &keys).is_ok());
    }

    #[test]
    fn test_validate_api_key_constant_time_invalid() {
        let mut keys = HashSet::new();
        keys.insert("test-key-123".to_string());
        let header = HeaderValue::from_static("wrong-key");
        assert_eq!(validate_api_key(Some(&header), &keys), Err(401));
    }

    #[test]
    fn test_validate_api_key_constant_time_missing() {
        let keys = HashSet::new();
        assert_eq!(validate_api_key(None, &keys), Err(401));
    }

    #[test]
    fn test_validate_api_key_constant_time_multiple_keys() {
        let mut keys = HashSet::new();
        keys.insert("key-aaa".to_string());
        keys.insert("key-bbb".to_string());
        keys.insert("key-ccc".to_string());
        // Valid key that is not the first in iteration order
        let header = HeaderValue::from_static("key-bbb");
        assert!(validate_api_key(Some(&header), &keys).is_ok());
        // Invalid key with same length as a valid key (constant-time rejects)
        let header = HeaderValue::from_static("key-zzz");
        assert_eq!(validate_api_key(Some(&header), &keys), Err(401));
    }

    #[test]
    fn test_validate_api_key_constant_time_different_lengths() {
        let mut keys = HashSet::new();
        keys.insert("short".to_string());
        // Length comparison is now constant-time via fixed-size padded comparison
        let header = HeaderValue::from_static("a-much-longer-key-value");
        assert_eq!(validate_api_key(Some(&header), &keys), Err(401));
    }

    #[tokio::test]
    async fn test_validate_basic_auth_valid() {
        // "user1:password1" -> bcrypt hash (cost 10 meets minimum)
        let hash = bcrypt::hash("password1", 10).unwrap();
        let mut creds = HashMap::new();
        creds.insert("user1".to_string(), hash);
        // "user1:password1" base64 = "dXNlcjE6cGFzc3dvcmQx"
        let header = HeaderValue::from_static("Basic dXNlcjE6cGFzc3dvcmQx");
        assert!(validate_basic_auth(Some(&header), &creds).await.is_ok());
    }

    #[tokio::test]
    async fn test_validate_basic_auth_wrong_password() {
        let hash = bcrypt::hash("password1", 10).unwrap();
        let mut creds = HashMap::new();
        creds.insert("user1".to_string(), hash);
        // "user1:wrongpass" base64 = "dXNlcjE6d3JvbmdwYXNz"
        let header = HeaderValue::from_static("Basic dXNlcjE6d3JvbmdwYXNz");
        assert_eq!(validate_basic_auth(Some(&header), &creds).await, Err(401));
    }

    #[tokio::test]
    async fn test_validate_basic_auth_missing_header() {
        let creds = HashMap::new();
        assert_eq!(validate_basic_auth(None, &creds).await, Err(401));
    }

    #[tokio::test]
    async fn test_validate_basic_auth_not_basic_scheme() {
        let creds = HashMap::new();
        let header = HeaderValue::from_static("Bearer some-token");
        assert_eq!(validate_basic_auth(Some(&header), &creds).await, Err(401));
    }

    #[test]
    fn test_base64_decode() {
        assert_eq!(base64_decode("dXNlcjE6cGFzc3dvcmQx").unwrap(), b"user1:password1");
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
    }

    // SEC-6: Username enumeration timing attack prevention
    #[tokio::test]
    async fn test_basic_auth_invalid_username_timing_safe() {
        // A valid user with a cost-12 bcrypt hash
        let hash = bcrypt::hash("password1", 12).unwrap();
        let mut creds = HashMap::new();
        creds.insert("validuser".to_string(), hash);

        // Time a request with a VALID username but wrong password
        let encoded_valid = base64_encode(b"validuser:wrongpass");
        let header_valid_user =
            HeaderValue::from_str(&format!("Basic {}", encoded_valid)).ok();
        let start_valid = std::time::Instant::now();
        let _ = validate_basic_auth(header_valid_user.as_ref(), &creds).await;
        let elapsed_valid = start_valid.elapsed();

        // Time a request with an INVALID username (should still take bcrypt time)
        let encoded_invalid = base64_encode(b"nonexistent:wrongpass");
        let header_invalid_user =
            HeaderValue::from_str(&format!("Basic {}", encoded_invalid)).ok();
        let start_invalid = std::time::Instant::now();
        let _ = validate_basic_auth(header_invalid_user.as_ref(), &creds).await;
        let elapsed_invalid = start_invalid.elapsed();

        // Both should take non-trivial time (bcrypt with cost 12 takes ~250ms+)
        // The invalid username path must NOT return instantly (< 1ms)
        assert!(
            elapsed_invalid.as_millis() > 10,
            "Invalid username returned too quickly ({}ms) — likely skipping bcrypt, enabling timing enumeration",
            elapsed_invalid.as_millis()
        );

        // The two times should be within 10x of each other (both do bcrypt)
        let ratio = elapsed_valid.as_millis().max(1) as f64
            / elapsed_invalid.as_millis().max(1) as f64;
        assert!(
            ratio < 10.0 && ratio > 0.1,
            "Timing ratio {:.2} between valid/invalid username too large — timing leak",
            ratio
        );
    }

    // SEC-7: Bcrypt minimum cost factor validation
    #[tokio::test]
    async fn test_basic_auth_rejects_low_cost_hash() {
        // Hash with cost 4 — trivially brute-forceable, must be rejected
        let low_cost_hash = bcrypt::hash("password1", 4).unwrap();
        let mut creds = HashMap::new();
        creds.insert("user1".to_string(), low_cost_hash);

        let encoded = base64_encode(b"user1:password1");
        let header = HeaderValue::from_str(&format!("Basic {}", encoded)).unwrap();
        // Even though the password is correct, the low-cost hash must be rejected
        assert_eq!(
            validate_basic_auth(Some(&header), &creds).await,
            Err(401),
            "Should reject bcrypt hash with cost < 10"
        );
    }

    #[tokio::test]
    async fn test_basic_auth_accepts_adequate_cost_hash() {
        // Hash with cost 10 — meets minimum, should be accepted
        let adequate_hash = bcrypt::hash("password1", 10).unwrap();
        let mut creds = HashMap::new();
        creds.insert("user1".to_string(), adequate_hash);

        let encoded = base64_encode(b"user1:password1");
        let header = HeaderValue::from_str(&format!("Basic {}", encoded)).unwrap();
        assert!(
            validate_basic_auth(Some(&header), &creds).await.is_ok(),
            "Should accept bcrypt hash with cost >= 10"
        );
    }

    #[test]
    fn test_extract_bcrypt_cost() {
        assert_eq!(extract_bcrypt_cost("$2b$12$abcdefghijklmnopqrstuuxxxxxxxxxxxxxxxxxxxxxxxxxx"), Some(12));
        assert_eq!(extract_bcrypt_cost("$2a$04$abcdefghijklmnopqrstuuxxxxxxxxxxxxxxxxxxxxxxxxxx"), Some(4));
        assert_eq!(extract_bcrypt_cost("$2y$10$abcdefghijklmnopqrstuuxxxxxxxxxxxxxxxxxxxxxxxxxx"), Some(10));
        assert_eq!(extract_bcrypt_cost("not-a-bcrypt-hash"), None);
        assert_eq!(extract_bcrypt_cost(""), None);
    }

    /// Simple base64 encoder for test use only.
    fn base64_encode(input: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut output = String::new();
        for chunk in input.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
            let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
            let triple = (b0 << 16) | (b1 << 8) | b2;
            output.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
            output.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
            if chunk.len() > 1 {
                output.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
            } else {
                output.push('=');
            }
            if chunk.len() > 2 {
                output.push(ALPHABET[(triple & 0x3F) as usize] as char);
            } else {
                output.push('=');
            }
        }
        output
    }
}
