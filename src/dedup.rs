//! Pure helpers for the Gmail duplicate-protection check: the identity of a message as far as a
//! provider's duplicate merging is concerned. No I/O, no allocation beyond the returned strings.
//!
//! What matters (see docs/GMAIL_DUPLICATE_MERGE_DESIGN.md): a provider such as Gmail merges an APPEND into
//! an existing message when their content matches, and in one observed case discarded the appended bytes
//! while reporting success. The check therefore needs a message's `Message-ID` and a hash of its body.
//!
//! Conservatism: the identifier is compared ASCII-case-insensitively and with or without angle
//! brackets, which can only make the check hold MORE than the provider merges, never less. A message with
//! no usable identifier (absent, duplicated, malformed) yields `None`, which is never a reason to hold.
use sha2::{Digest, Sha256};

/// Longest identifier accepted; anything longer is treated as malformed (no hold).
const MAX_ID: usize = 998;

/// Splits a raw message into (header block, body) at the first empty line (CRLF CRLF or LF LF).
/// Without an empty line the whole input is header and the body is empty.
pub fn split(raw: &[u8]) -> (&[u8], &[u8]) {
    // A message that begins with an empty line has an empty header.
    if raw.starts_with(b"\r\n") {
        return (&[], &raw[2..]);
    }
    if raw.starts_with(b"\n") {
        return (&[], &raw[1..]);
    }
    // Scan once; the earliest separator of either flavour wins.
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'\n' {
            if raw.get(i + 1) == Some(&b'\n') {
                return (&raw[..i + 1], &raw[i + 2..]);
            }
            if raw.get(i + 1) == Some(&b'\r') && raw.get(i + 2) == Some(&b'\n') {
                return (&raw[..i + 1], &raw[i + 3..]);
            }
        }
        i += 1;
    }
    (raw, &[])
}

/// Lowercase hex SHA-256 of the body part of a raw message.
pub fn body_hash(raw: &[u8]) -> String {
    let (_, body) = split(raw);
    hex(&Sha256::digest(body))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// The normalized `Message-ID` of a header block: lowercase, without angle brackets. `None` when the header is
/// absent, appears more than once, is empty or malformed, or is over-long. Never panics on arbitrary bytes.
pub fn message_id(header: &[u8]) -> Option<String> {
    let mut found: Option<Vec<u8>> = None;
    let mut line_start = 0;
    let mut lines: Vec<&[u8]> = Vec::new();
    // Logical (unfolded) header lines.
    let mut i = 0;
    while i <= header.len() {
        if i == header.len() || header[i] == b'\n' {
            lines.push(&header[line_start..i]);
            line_start = i + 1;
        }
        i += 1;
    }
    let mut logical: Vec<Vec<u8>> = Vec::new();
    for line in lines {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.first().is_some_and(|b| *b == b' ' || *b == b'\t') {
            if let Some(last) = logical.last_mut() {
                last.push(b' ');
                last.extend_from_slice(line);
            }
        } else if !line.is_empty() {
            logical.push(line.to_vec());
        }
    }
    for line in logical {
        let Some(colon) = line.iter().position(|b| *b == b':') else {
            continue;
        };
        if line[..colon].eq_ignore_ascii_case(b"message-id") {
            if found.is_some() {
                return None; // ambiguous: which one the provider uses is unknown
            }
            found = Some(line[colon + 1..].to_vec());
        }
    }
    normalize(&found?)
}

fn normalize(value: &[u8]) -> Option<String> {
    // Drop RFC 5322 comments ("(...)", nestable) that may surround the address.
    let mut cleaned = Vec::with_capacity(value.len());
    let mut depth = 0u32;
    for b in value {
        match *b {
            b'(' => depth += 1,
            b')' if depth > 0 => depth -= 1,
            _ if depth == 0 => cleaned.push(*b),
            _ => {}
        }
    }
    if depth != 0 {
        return None;
    }
    let text = std::str::from_utf8(&cleaned).ok()?.trim();
    let inner = match (text.find('<'), text.rfind('>')) {
        (Some(open), Some(close)) if open < close => {
            // Only whitespace may surround a single angle-addr.
            if !text[..open].trim().is_empty() || !text[close + 1..].trim().is_empty() {
                return None;
            }
            &text[open + 1..close]
        }
        (None, None) => text,
        _ => return None,
    };
    if inner.is_empty()
        || inner.len() > MAX_ID
        || inner
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '<' || c == '>')
    {
        return None;
    }
    Some(inner.to_ascii_lowercase())
}

/// What the duplicate check needs to know about one message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keys {
    /// Normalized Message-ID, if the message has a usable one.
    pub message_id: Option<String>,
    /// SHA-256 (hex) of the body part.
    pub body_sha256: String,
}

/// The duplicate-check identity of a whole raw message.
pub fn keys(raw: &[u8]) -> Keys {
    let (header, body) = split(raw);
    Keys {
        message_id: message_id(header),
        body_sha256: hex(&Sha256::digest(body)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(id: Option<&str>, extra: &str, body: &str) -> Vec<u8> {
        let mut h = String::new();
        if let Some(id) = id {
            h.push_str(&format!("Message-ID: {id}\r\n"));
        }
        h.push_str("From: a@example.invalid\r\nSubject: s\r\n");
        h.push_str(extra);
        format!("{h}\r\n{body}\r\n").into_bytes()
    }

    #[test]
    fn plain_bracketed_case_and_comment_forms_normalize_alike() {
        let a = keys(&msg(Some("<Exp-4@Example.Invalid>"), "", "x"));
        assert_eq!(a.message_id.as_deref(), Some("exp-4@example.invalid"));
        for v in [
            "exp-4@example.invalid",
            " <EXP-4@EXAMPLE.INVALID> ",
            "(c) <exp-4@example.invalid> (d)",
            "<exp-4@example.invalid>",
        ] {
            assert_eq!(keys(&msg(Some(v), "", "x")).message_id, a.message_id, "{v}");
        }
    }

    #[test]
    fn folded_header_and_lf_only_messages_are_read() {
        let raw = b"Subject: s\nMessage-ID:\n <folded@example.invalid>\n\nbody\n";
        let k = keys(raw);
        assert_eq!(k.message_id.as_deref(), Some("folded@example.invalid"));
        assert_eq!(k.body_sha256, body_hash(b"X: 1\n\nbody\n"));
    }

    #[test]
    fn absent_duplicate_empty_and_malformed_ids_are_none() {
        assert_eq!(keys(&msg(None, "", "x")).message_id, None);
        let two = msg(Some("<a@x>"), "Message-Id: <b@x>\r\n", "x");
        assert_eq!(keys(&two).message_id, None);
        for bad in [
            "",
            "<>",
            "<a b@x>",
            "<a@x",
            "a@x>",
            "<<a@x>>",
            "junk <a@x>",
            "<a@x> junk",
            "(unterminated <a@x>",
            "<a\u{7}@x>",
        ] {
            assert_eq!(keys(&msg(Some(bad), "", "x")).message_id, None, "{bad:?}");
        }
        let long = format!("<{}@x>", "a".repeat(MAX_ID));
        assert_eq!(keys(&msg(Some(&long), "", "x")).message_id, None);
    }

    #[test]
    fn the_body_hash_ignores_headers_and_follows_the_body_exactly() {
        // E7: an extra header changes the message but not the body hash.
        let a = msg(Some("<e7@x>"), "", "same body");
        let b = msg(Some("<e7@x>"), "X-Dup-Test: 1\r\n", "same body");
        assert_ne!(a, b);
        assert_eq!(keys(&a), keys(&b));
        // E2/E3: a different body is a different key.
        assert_ne!(
            keys(&a).body_sha256,
            keys(&msg(Some("<e7@x>"), "", "other body")).body_sha256
        );
        // One byte of body matters, including a trailing newline.
        assert_ne!(
            body_hash(b"H: 1\r\n\r\nabc"),
            body_hash(b"H: 1\r\n\r\nabc\r\n")
        );
    }

    #[test]
    fn the_first_empty_line_ends_the_header_for_both_line_endings() {
        assert_eq!(
            split(b"A: 1\r\n\r\nB: 2\r\n\r\nx"),
            (&b"A: 1\r\n"[..], &b"B: 2\r\n\r\nx"[..])
        );
        assert_eq!(split(b"A: 1\n\nbody"), (&b"A: 1\n"[..], &b"body"[..]));
        assert_eq!(split(b"A: 1\r\nB: 2"), (&b"A: 1\r\nB: 2"[..], &b""[..]));
        assert_eq!(split(b""), (&b""[..], &b""[..]));
        // A message that starts with the empty line has an empty header.
        assert_eq!(split(b"\r\nbody"), (&b""[..], &b"body"[..]));
    }

    #[test]
    fn a_message_id_in_the_body_is_never_used() {
        let raw = b"Subject: s\r\n\r\nMessage-ID: <fake@x>\r\n";
        assert_eq!(keys(raw).message_id, None);
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        let mut state = 0x9E37_79B9_7F4A_7C15_u64;
        let alphabet = b"Message-ID:<>@() \t\r\n\xff\x00aZ.";
        for len in 0..400 {
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                buf.push(alphabet[(state >> 33) as usize % alphabet.len()]);
            }
            let _ = keys(&buf);
            let _ = message_id(&buf);
            let _ = split(&buf);
        }
    }
}
