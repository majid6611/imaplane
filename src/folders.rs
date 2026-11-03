//! Folder encoding is session state, not a property inferred from a name.
use anyhow::{Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FolderEncoding {
    ModifiedUtf7,
    Utf8,
}

/// Call only after capabilities and the actual ENABLE response are available.
pub fn negotiated_encoding(
    rev1: bool,
    rev2: bool,
    rev2_enabled: bool,
    utf8_enabled: bool,
    utf8_only: bool,
) -> Result<FolderEncoding> {
    if !rev1 && !rev2 {
        bail!("server advertises neither IMAP4rev1 nor IMAP4rev2");
    }
    if rev2_enabled && !rev2 {
        bail!("IMAP4rev2 enabled without advertised capability");
    }
    if utf8_only && !utf8_enabled && !rev2_enabled && rev1 {
        bail!("UTF8=ONLY requires successful UTF8=ACCEPT negotiation");
    }
    Ok(if (rev2 && !rev1) || rev2_enabled || utf8_enabled {
        FolderEncoding::Utf8
    } else {
        FolderEncoding::ModifiedUtf7
    })
}

impl FolderEncoding {
    pub fn encode(self, name: &str) -> Result<String> {
        validate_name(name)?;
        if self == Self::Utf8 {
            return Ok(name.to_owned());
        }
        let mut out = String::new();
        let mut run = Vec::new();
        fn flush(run: &mut Vec<u8>, out: &mut String) {
            if !run.is_empty() {
                out.push('&');
                out.push_str(&STANDARD_NO_PAD.encode(&*run).replace('/', ","));
                out.push('-');
                run.clear();
            }
        }
        for ch in name.chars() {
            if (' '..='~').contains(&ch) {
                flush(&mut run, &mut out);
                if ch == '&' {
                    out.push_str("&-");
                } else {
                    out.push(ch);
                }
            } else {
                for unit in ch.encode_utf16(&mut [0; 2]) {
                    run.extend_from_slice(&unit.to_be_bytes());
                }
            }
        }
        flush(&mut run, &mut out);
        Ok(out)
    }

    pub fn decode(self, wire: &[u8]) -> Result<String> {
        let text = std::str::from_utf8(wire)?;
        if self == Self::Utf8 {
            validate_name(text)?;
            return Ok(text.to_owned());
        }
        let mut out = String::new();
        let mut rest = text;
        while !rest.is_empty() {
            if let Some(after) = rest.strip_prefix('&') {
                let end = after
                    .find('-')
                    .ok_or_else(|| anyhow::anyhow!("unterminated modified UTF-7 shift"))?;
                let encoded = &after[..end];
                if encoded.is_empty() {
                    out.push('&');
                } else {
                    if !encoded
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b',')
                    {
                        bail!("invalid modified UTF-7 alphabet");
                    }
                    let bytes = STANDARD_NO_PAD.decode(encoded.replace(',', "/"))?;
                    if bytes.len() % 2 != 0 {
                        bail!("odd UTF-16 byte count");
                    }
                    let units: Vec<_> = bytes
                        .chunks_exact(2)
                        .map(|b| u16::from_be_bytes([b[0], b[1]]))
                        .collect();
                    let decoded = String::from_utf16(&units)?;
                    if decoded.chars().any(|c| (' '..='~').contains(&c)) {
                        bail!("printable ASCII must not be shifted");
                    }
                    out.push_str(&decoded);
                }
                rest = &after[end + 1..];
            } else {
                let b = rest.as_bytes()[0];
                if !(0x20..=0x7e).contains(&b) {
                    bail!("non-ASCII byte outside modified UTF-7 shift");
                }
                out.push(b as char);
                rest = &rest[1..];
            }
        }
        validate_name(&out)?;
        if self.encode(&out)? != text {
            bail!("noncanonical modified UTF-7 name");
        }
        Ok(out)
    }
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() || name.chars().any(char::is_control) {
        bail!("folder name is empty or contains control characters");
    }
    Ok(())
}
