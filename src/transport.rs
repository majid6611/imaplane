//! Only this module holds the general IMAP Session. Source exposes no write API.
use crate::{
    config::{Auth, Endpoint, Security},
    folders::{FolderEncoding, negotiated_encoding},
};
use anyhow::{Context, Result, bail};
use chrono::{DateTime, FixedOffset};
use imap::{Session, types::Flag};
use imap_proto::{Capability, Response, UidSetMember};
use native_tls::{TlsConnector, TlsStream};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    cell::Cell,
    collections::HashSet,
    io::{self, BufRead, BufReader, Read, Write},
    net::{TcpStream, ToSocketAddrs},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const OVERHEAD: usize = 1024 * 1024;
#[derive(Clone, Debug)]
struct Control(Arc<Mutex<(usize, Instant)>>, Duration);
impl Control {
    fn reset(&self, limit: usize) {
        *self.0.lock().unwrap() = (limit, Instant::now() + self.1);
    }
    fn remaining(&self) -> io::Result<Duration> {
        let left = self
            .0
            .lock()
            .unwrap()
            .1
            .saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "IMAP idle timeout"));
        }
        Ok(left)
    }
    fn progress(&self, n: usize) {
        if n > 0 {
            self.0.lock().unwrap().1 = Instant::now() + self.1;
        }
    }
}
#[derive(Debug)]
struct HandshakeSocket {
    socket: TcpStream,
    deadline: Option<Instant>,
    control: Option<Control>,
}
impl HandshakeSocket {
    fn remaining(&self) -> io::Result<Option<Duration>> {
        if let Some(control) = &self.control {
            return control.remaining().map(Some);
        }
        match self.deadline {
            Some(d) => {
                let left = d.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "TLS handshake deadline exceeded",
                    ));
                }
                Ok(Some(left))
            }
            None => Ok(None),
        }
    }
}
impl Read for HandshakeSocket {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        loop {
            if let Some(left) = self.remaining()? {
                self.socket.set_read_timeout(Some(left))?;
            }
            match self.socket.read(b) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                result => {
                    if let (Some(c), Ok(n)) = (&self.control, &result) {
                        c.progress(*n);
                    }
                    return result;
                }
            }
        }
    }
}
impl Write for HandshakeSocket {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        loop {
            if let Some(left) = self.remaining()? {
                self.socket.set_write_timeout(Some(left))?;
            }
            match self.socket.write(b) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                result => {
                    if let (Some(c), Ok(n)) = (&self.control, &result) {
                        c.progress(*n);
                    }
                    return result;
                }
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }
}
struct BoundedTls {
    tls: TlsStream<HandshakeSocket>,
    control: Control,
}
impl Read for BoundedTls {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.control.remaining()?;
        let budget = self.control.0.lock().unwrap().0;
        if budget == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "IMAP response size limit exceeded",
            ));
        }
        let n = buf.len().min(budget);
        let read = loop {
            match self.tls.read(&mut buf[..n]) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                result => break result?,
            }
        };
        self.control.0.lock().unwrap().0 -= read;
        self.control.progress(read);
        Ok(read)
    }
}
impl Write for BoundedTls {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.control.remaining()?;
        let n = loop {
            match self.tls.write(buf) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                result => break result?,
            }
        };
        self.control.progress(n);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.tls.flush()
    }
}
struct Connection {
    session: Session<BoundedTls>,
    control: Control,
    encoding: FolderEncoding,
    caps: HashSet<String>,
    limit: usize,
}
#[derive(Clone, Debug, Serialize)]
pub struct Folder {
    pub name: String,
    pub delimiter: Option<String>,
    pub selectable: bool,
}
#[derive(Clone, Debug)]
pub struct Selected {
    pub exists: u32,
    pub validity: u32,
    pub next: Option<u32>,
    pub flags: Vec<String>,
    pub writable: bool,
}
#[derive(Clone, Debug)]
pub struct Message {
    pub body: Vec<u8>,
    pub date: DateTime<FixedOffset>,
    pub flags: Vec<String>,
}

/// What verification needs to know about a stored message without keeping its body.
/// `sha256` is lowercase hex, identical to `journal::fingerprint` of the same bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageDigest {
    pub sha256: String,
    pub size: u64,
    pub date: DateTime<FixedOffset>,
    pub flags: Vec<String>,
}
impl Message {
    pub fn digest(&self) -> MessageDigest {
        MessageDigest {
            sha256: crate::journal::fingerprint(&self.body),
            size: self.body.len() as u64,
            date: self.date,
            flags: self.flags.clone(),
        }
    }
}

#[derive(Debug)]
struct PermanentMessageError(&'static str);
impl std::fmt::Display for PermanentMessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for PermanentMessageError {}
pub fn is_permanent_message(e: &anyhow::Error) -> bool {
    e.is::<PermanentMessageError>()
        || e.downcast_ref::<ProtocolError>()
            .is_some_and(|p| p.permanent_message)
}

struct Plain<'a>(&'a str, &'a str);
impl imap::Authenticator for Plain<'_> {
    type Response = Vec<u8>;
    fn process(&self, _: &[u8]) -> Vec<u8> {
        format!("\0{}\0{}", self.0, self.1).into_bytes()
    }
}
struct Xoauth2<'a> {
    user: &'a str,
    token: &'a str,
    sent: Cell<bool>,
}
impl imap::Authenticator for Xoauth2<'_> {
    type Response = Vec<u8>;
    fn process(&self, challenge: &[u8]) -> Vec<u8> {
        // Gmail's JSON error challenge requires an EMPTY response, not another token.
        if self.sent.replace(true) || !challenge.is_empty() {
            return Vec::new();
        }
        format!("user={}\x01auth=Bearer {}\x01\x01", self.user, self.token).into_bytes()
    }
}

#[derive(Debug)]
struct ProtocolError {
    transient: bool,
    description: &'static str,
    rejection: Option<AppendRejection>,
    permanent_message: bool,
    /// Sanitized status/code summary, used only by opt-in diagnostics.
    wire: Option<Wire>,
}
/// Everything here is a fixed name or a strictly validated code atom; never server text.
#[derive(Clone, Debug)]
struct Wire {
    outcome: &'static str,
    code: &'static str,
    unlisted: Option<String>,
}
impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.description)
    }
}
impl std::error::Error for ProtocolError {}
pub fn is_transient(e: &anyhow::Error) -> bool {
    e.downcast_ref::<ProtocolError>()
        .is_some_and(|e| e.transient)
}
/// What a tagged APPEND rejection implies about the *next* message. This is a
/// statement about semantics, not a retry list: only `Transient` may be waited out,
/// only `Message`/`SizeDependent` may let later messages proceed, and everything
/// else stops the run so an operator decides. No variant authorizes a replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RejectionScope {
    /// Server-wide and expected to clear (rate limits, maintenance): bounded breaker.
    Transient,
    /// The content or size of this one message is the reason (RFC 5530/9051).
    Message,
    /// Depends on this message's size against remaining quota; a smaller one may fit.
    SizeDependent,
    /// The destination mailbox is missing, forbidden or unusable: every later
    /// message to it would fail the same way.
    Mailbox,
    /// Credentials, authorization or account policy: not recoverable by continuing.
    Account,
    /// Unknown, provider-specific, code-less or self-contradictory: stay conservative.
    Ambiguous,
}
impl RejectionScope {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Transient => "transient",
            Self::Message => "message",
            Self::SizeDependent => "size-dependent",
            Self::Mailbox => "mailbox",
            Self::Account => "account",
            Self::Ambiguous => "ambiguous",
        }
    }
}

/// Evidence is obtainable only from a parsed, matching tagged NO/BAD response.
#[derive(Clone, Debug)]
pub(crate) struct AppendRejection {
    pub code: &'static str,
    pub status: &'static str,
}
impl AppendRejection {
    pub(crate) fn scope(&self) -> RejectionScope {
        // BAD means the command itself was malformed or unsupported. A response
        // code on a BAD cannot make it a safe per-message or transient condition.
        if self.status != "NO" {
            return RejectionScope::Ambiguous;
        }
        match self.code {
            "UNAVAILABLE" | "THROTTLED" | "INUSE" | "LIMIT" => RejectionScope::Transient,
            "TOOBIG" | "CONTENTREJECTED" => RejectionScope::Message,
            "OVERQUOTA" => RejectionScope::SizeDependent,
            "NOPERM" | "NONEXISTENT" | "TRYCREATE" => RejectionScope::Mailbox,
            "AUTHENTICATIONFAILED" | "AUTHORIZATIONFAILED" | "EXPIRED" | "PRIVACYREQUIRED" => {
                RejectionScope::Account
            }
            _ => RejectionScope::Ambiguous,
        }
    }
}

pub(crate) fn append_rejection(error: &anyhow::Error) -> Option<AppendRejection> {
    error
        .downcast_ref::<ProtocolError>()
        .and_then(|e| e.rejection.clone())
}
/// Codes IMAPLANE can name in evidence. Anything else is reported only as
/// UNSPECIFIED, so server-controlled text never reaches the journal or reports.
const NAMED_CODES: &[&str] = &[
    "UNAVAILABLE",
    "THROTTLED",
    "INUSE",
    "LIMIT",
    "OVERQUOTA",
    "TOOBIG",
    "CONTENTREJECTED",
    "NOPERM",
    "NONEXISTENT",
    "TRYCREATE",
    "AUTHENTICATIONFAILED",
    "AUTHORIZATIONFAILED",
    "EXPIRED",
    "PRIVACYREQUIRED",
    "CANNOT",
    "SERVERBUG",
    "CLIENTBUG",
    "CONTACTADMIN",
    "UNKNOWN-CTE",
];
/// The vendored parser types only a few codes; the rest arrive as leading
/// `[ATOM ...]` text. Only a strict, bounded atom is considered, then matched
/// case-insensitively against the fixed allowlist above.
fn code_from_text(information: &str) -> &'static str {
    leading_atom(information)
        .and_then(|atom| {
            NAMED_CODES
                .iter()
                .find(|name| name.eq_ignore_ascii_case(atom))
                .copied()
        })
        .unwrap_or("UNSPECIFIED")
}
/// A leading `[ATOM` / `[ATOM ...]` token, only if it is a bounded protocol identifier.
fn leading_atom(information: &str) -> Option<&str> {
    let rest = information.strip_prefix('[')?;
    let end = rest.find([']', ' ']).unwrap_or(rest.len()).min(33);
    let atom = &rest[..end];
    (!atom.is_empty()
        && atom.len() <= 32
        && atom.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
    .then_some(atom)
}
/// Diagnostics only: the validated atom of a code IMAPLANE has no name for.
fn unlisted_atom(code: Option<&imap_proto::ResponseCode<'_>>, information: &str) -> Option<String> {
    use imap_proto::ResponseCode::*;
    match code {
        Some(Alert) => Some("ALERT".into()),
        Some(Parse) => Some("PARSE".into()),
        Some(ReadOnly) => Some("READ-ONLY".into()),
        Some(ReadWrite) => Some("READ-WRITE".into()),
        Some(BadCharset(_)) => Some("BADCHARSET".into()),
        Some(_) => None,
        None => leading_atom(information)
            .filter(|atom| !NAMED_CODES.iter().any(|n| n.eq_ignore_ascii_case(atom)))
            .map(str::to_ascii_uppercase),
    }
}
fn rejection_code(code: Option<&imap_proto::ResponseCode<'_>>, information: &str) -> &'static str {
    use imap_proto::ResponseCode::*;
    match code {
        Some(Unavailable) => "UNAVAILABLE",
        Some(Throttled) => "THROTTLED",
        Some(InUse) => "INUSE",
        Some(Limit) => "LIMIT",
        Some(OverQuota) => "OVERQUOTA",
        Some(TooBig) => "TOOBIG",
        Some(TryCreate) => "TRYCREATE",
        Some(_) => "UNSPECIFIED",
        None => code_from_text(information),
    }
}
fn stream_error_name(e: &imap::error::StreamError) -> &'static str {
    use imap::error::StreamError::*;
    match e {
        LiteralLengthMismatch => "LITERAL_LENGTH_MISMATCH",
        MalformedLiteralMarker => "MALFORMED_LITERAL_MARKER",
        LineTooLong => "LINE_TOO_LONG",
        ResponseTooLarge => "RESPONSE_TOO_LARGE",
        MalformedResponse => "MALFORMED_RESPONSE",
        _ => "STREAM",
    }
}
trait SafeImap<T> {
    fn safe(self) -> Result<T>;
}
impl<T> SafeImap<T> for imap::Result<T> {
    fn safe(self) -> Result<T> {
        self.map_err(|e| {
            // Do not attach the original error: Parse/Unexpected can contain mail
            // literals, and server NO/BAD text can echo credentials or message data.
            let permanent_message = matches!(&e, imap::Error::No(no) if matches!(no.code, Some(imap_proto::ResponseCode::TooBig)))
                // A streamed literal whose announced length differs from RFC822.SIZE is the
                // same permanent condition the buffered path reports as a size mismatch.
                || matches!(
                    &e,
                    imap::Error::Stream(imap::error::StreamError::LiteralLengthMismatch)
                );
            let rejection = match &e {
                imap::Error::No(no) => Some(AppendRejection {
                    code: rejection_code(no.code.as_ref(), &no.information),
                    status: "NO",
                }),
                imap::Error::Bad(bad) => Some(AppendRejection {
                    code: rejection_code(bad.code.as_ref(), &bad.information),
                    status: "BAD",
                }),
                _ => None,
            };
            let wire = Some(match &e {
                imap::Error::No(x) => Wire {
                    outcome: "NO",
                    code: rejection_code(x.code.as_ref(), &x.information),
                    unlisted: unlisted_atom(x.code.as_ref(), &x.information),
                },
                imap::Error::Bad(x) => Wire {
                    outcome: "BAD",
                    code: rejection_code(x.code.as_ref(), &x.information),
                    unlisted: unlisted_atom(x.code.as_ref(), &x.information),
                },
                imap::Error::Bye(x) => Wire {
                    outcome: "BYE",
                    code: rejection_code(x.code.as_ref(), &x.information),
                    unlisted: unlisted_atom(x.code.as_ref(), &x.information),
                },
                imap::Error::Io(_) | imap::Error::ConnectionLost => Wire {
                    outcome: "IO",
                    code: "-",
                    unlisted: None,
                },
                // Fixed names only; a streaming error never carries server data.
                imap::Error::Stream(x) => Wire {
                    outcome: "STREAM",
                    code: stream_error_name(x),
                    unlisted: None,
                },
                _ => Wire {
                    outcome: "INVALID",
                    code: "-",
                    unlisted: None,
                },
            });
            let (transient, description) = match e {
                imap::Error::Bye(bye) if bye.information == "no explanation given" => {
                    (false, "invalid IMAP response; session must be discarded")
                }
                imap::Error::Io(_) | imap::Error::ConnectionLost | imap::Error::Bye(_) => {
                    (true, "IMAP connection lost or I/O limit exceeded")
                }
                imap::Error::No(no) => (
                    matches!(
                        no.code,
                        Some(
                            imap_proto::ResponseCode::Unavailable
                                | imap_proto::ResponseCode::Throttled
                                | imap_proto::ResponseCode::InUse
                                | imap_proto::ResponseCode::Limit
                        )
                    ),
                    "IMAP server rejected command (NO); check permissions, quota and server limits",
                ),
                imap::Error::Bad(_) => (false, "IMAP server rejected command syntax (BAD)"),
                // The connection is desynchronized (it refuses further commands), so a
                // streamed response that violated a bound or the protocol is not retried.
                imap::Error::Stream(imap::error::StreamError::LiteralLengthMismatch) => (
                    false,
                    "streamed message size differs from RFC822.SIZE; session must be discarded",
                ),
                imap::Error::Stream(_) => (
                    false,
                    "invalid streamed IMAP response; session must be discarded",
                ),
                _ => (
                    false,
                    "invalid or unsupported IMAP response; session must be discarded",
                ),
            };
            anyhow::Error::new(ProtocolError {
                transient,
                description,
                rejection,
                permanent_message,
                wire,
            })
        })
    }
}

// Before STARTTLS, only greeting, CAPABILITY and STARTTLS are exchanged. Use
// the established typed parser and bounded reads; discard all plaintext state.
fn pre_tls_response(
    reader: &mut BufReader<TcpStream>,
    tag: Option<&str>,
    timeout: Duration,
) -> Result<Vec<Response<'static>>> {
    let deadline = Instant::now() + timeout;
    let mut remaining = 64 * 1024;
    let mut responses = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || remaining == 0 {
            bail!("STARTTLS negotiation size/time limit exceeded");
        }
        reader.get_ref().set_read_timeout(Some(left))?;
        let mut line = Vec::new();
        let read = reader.take(remaining as u64).read_until(b'\n', &mut line)?;
        if read == 0 {
            bail!("connection closed during STARTTLS negotiation");
        }
        remaining -= read;
        let (rest, response) = Response::from_bytes(&line)
            .map_err(|_| anyhow::anyhow!("invalid STARTTLS negotiation response"))?;
        if !rest.is_empty() {
            bail!("invalid STARTTLS response framing");
        }
        match &response {
            Response::Done {
                tag: actual,
                status,
                ..
            } => {
                if tag != Some(actual.0.as_str()) || *status != imap_proto::Status::Ok {
                    bail!("STARTTLS negotiation rejected or mismatched tag");
                }
                return Ok(responses);
            }
            Response::Data { status, .. } if *status != imap_proto::Status::Ok => {
                bail!("STARTTLS server rejected negotiation")
            }
            Response::Data {
                status: imap_proto::Status::Ok,
                ..
            } if tag.is_none() => return Ok(Vec::new()),
            _ if tag.is_none() => bail!("expected plaintext OK greeting before STARTTLS"),
            _ => {}
        }
        responses.push(response.into_owned());
    }
}
fn starttls(socket: TcpStream, timeout: Duration) -> Result<TcpStream> {
    let mut reader = BufReader::new(socket);
    pre_tls_response(&mut reader, None, timeout)?;
    reader.get_mut().write_all(b"ITLS1 CAPABILITY\r\n")?;
    let caps = pre_tls_response(&mut reader, Some("ITLS1"), timeout)?;
    let advertised = caps.iter().any(|r| matches!(r,Response::Capabilities(caps) if caps.iter().any(|c| matches!(c,Capability::Atom(s) if s.eq_ignore_ascii_case("STARTTLS")))));
    if !advertised {
        bail!("STARTTLS is required but not advertised; refusing plaintext authentication");
    }
    reader.get_mut().write_all(b"ITLS2 STARTTLS\r\n")?;
    pre_tls_response(&mut reader, Some("ITLS2"), timeout)?;
    // Any read-ahead plaintext is untrusted. It must never become authenticated
    // protocol data after TLS. The server cannot send TLS data before ClientHello.
    Ok(reader.into_inner())
}

fn capabilities(c: &imap::types::Capabilities) -> HashSet<String> {
    c.iter()
        .map(|c| match c {
            Capability::Imap4rev1 => "IMAP4REV1".to_string(),
            Capability::Auth(a) => format!("AUTH={a}").to_uppercase(),
            Capability::Atom(a) => a.to_uppercase(),
        })
        .collect()
}
impl Connection {
    fn connect(e: &Endpoint, password: &str, timeout: Duration, limit: usize) -> Result<Self> {
        let addresses: Vec<_> = (e.host.as_str(), e.port)
            .to_socket_addrs()
            .context("resolve IMAP host")?
            .collect();
        let mut socket = None;
        for addr in addresses {
            if let Ok(s) = TcpStream::connect_timeout(&addr, timeout) {
                socket = Some(s);
                break;
            }
        }
        let socket = socket.ok_or_else(|| {
            anyhow::Error::new(ProtocolError {
                transient: true,
                description: "could not connect to IMAP host",
                rejection: None,
                permanent_message: false,
                wire: None,
            })
        })?;
        socket.set_read_timeout(Some(timeout))?;
        socket.set_write_timeout(Some(timeout))?;
        let socket = if e.security == Security::Starttls {
            starttls(socket, timeout)?
        } else {
            socket
        };
        socket.set_read_timeout(Some(timeout))?;
        let mut tls = TlsConnector::builder();
        tls.min_protocol_version(Some(native_tls::Protocol::Tlsv12));
        if let Some(path) = &e.ca_file {
            tls.add_root_certificate(native_tls::Certificate::from_pem(
                &std::fs::read(path).context("read CA certificate")?,
            )?);
        }
        let mut tls = tls
            .build()?
            .connect(
                &e.host,
                HandshakeSocket {
                    socket,
                    deadline: Some(Instant::now() + timeout),
                    control: None,
                },
            )
            .context("TLS handshake failed (certificate and hostname validation required)")?;
        tls.get_mut().deadline = None;
        let control = Control(
            Arc::new(Mutex::new((OVERHEAD, Instant::now() + timeout))),
            timeout,
        );
        tls.get_mut().control = Some(control.clone());
        let mut client = imap::Client::new(BoundedTls {
            tls,
            control: control.clone(),
        });
        if e.security == Security::Tls {
            let greeting = client
                .read_greeting()
                .safe()
                .context("read IMAP greeting")?;
            if !matches!(
                Response::from_bytes(&greeting),
                Ok((
                    _,
                    Response::Data {
                        status: imap_proto::Status::Ok,
                        ..
                    }
                ))
            ) {
                bail!("expected an IMAP OK greeting");
            }
        }
        control.reset(OVERHEAD);
        let caps = capabilities(
            &client
                .capabilities()
                .safe()
                .context("pre-authentication CAPABILITY")?,
        );
        let use_plain = matches!(e.auth, Auth::Plain)
            || (matches!(e.auth, Auth::Auto) && caps.contains("AUTH=PLAIN"));
        if use_plain && !caps.contains("AUTH=PLAIN") {
            bail!("server does not advertise AUTH=PLAIN");
        }
        if !use_plain && !matches!(e.auth, Auth::Xoauth2) && caps.contains("LOGINDISABLED") {
            bail!("server disables LOGIN; select a supported authentication method");
        }
        control.reset(OVERHEAD);
        // Do not propagate server authentication diagnostics: they may echo credentials.
        let token = if matches!(e.auth, Auth::Xoauth2) {
            Some(e.password("Access token")?)
        } else {
            None
        };
        if token.is_some() && !caps.contains("AUTH=XOAUTH2") {
            bail!("server does not advertise AUTH=XOAUTH2; no password fallback");
        }
        let mut session = if let Some(token) = token.as_ref() {
            client.authenticate(
                "XOAUTH2",
                &Xoauth2 {
                    user: &e.username,
                    token,
                    sent: Cell::new(false),
                },
            )
        } else if use_plain {
            client.authenticate("PLAIN", &Plain(&e.username, password))
        } else {
            client.login(&e.username, password)
        }
        .map_err(|(error, _)| Err::<(), _>(error).safe().unwrap_err())
        .context("IMAP authentication failed; check credentials and authentication policy")?;
        control.reset(OVERHEAD);
        let caps = capabilities(
            &session
                .capabilities()
                .safe()
                .context("post-authentication CAPABILITY")?,
        );
        let rev1 = caps.contains("IMAP4REV1");
        let rev2 = caps.contains("IMAP4REV2");
        let mut rev2_enabled = false;
        let mut utf8_enabled = false;
        if rev1
            && caps.contains("ENABLE")
            && (rev2 || caps.contains("UTF8=ACCEPT") || caps.contains("UTF8=ONLY"))
        {
            let cap = if rev2 { "IMAP4rev2" } else { "UTF8=ACCEPT" };
            control.reset(OVERHEAD);
            let response = session
                .run_command_and_read_response(format!("ENABLE {cap}"))
                .safe()
                .context("ENABLE protocol mode")?;
            let mut rest = response.as_slice();
            while !rest.is_empty() {
                let (next, r) = Response::from_bytes(rest)
                    .map_err(|_| anyhow::anyhow!("invalid ENABLE response"))?;
                if let Response::Capabilities(enabled) = r {
                    for c in enabled {
                        if let Capability::Atom(c) = c {
                            rev2_enabled |= c.eq_ignore_ascii_case("IMAP4rev2");
                            utf8_enabled |= c.eq_ignore_ascii_case("UTF8=ACCEPT");
                        }
                    }
                }
                rest = next;
            }
        }
        let encoding = negotiated_encoding(
            rev1,
            rev2,
            rev2_enabled,
            utf8_enabled,
            caps.contains("UTF8=ONLY"),
        )?;
        Ok(Self {
            session,
            control,
            encoding,
            caps,
            limit,
        })
    }
    fn reset(&mut self, bytes: usize) {
        self.session.take_all_unsolicited().for_each(drop);
        self.control.reset(bytes);
    }
    fn list(&mut self) -> Result<Vec<Folder>> {
        self.reset(OVERHEAD * 16);
        let response = self
            .session
            .run_command_and_read_response("LIST \"\" \"*\"")
            .safe()?;
        decode_list(&response, self.encoding)
    }

    fn select_folder(&mut self, folder: &str, writable: bool) -> Result<Selected> {
        let folder = self.encoding.encode(folder)?;
        self.reset(OVERHEAD);
        let verb = if writable { "SELECT" } else { "EXAMINE" };
        let quoted = folder.replace('\\', "\\\\").replace('"', "\\\"");
        let (response, _) = self.session.run(format!("{verb} \"{quoted}\"")).safe()?;
        decode_selected(&response, writable)
    }

    fn uids(&mut self) -> Result<Vec<u32>> {
        self.uids_range("1:*")
    }
    fn uids_range(&mut self, range: &str) -> Result<Vec<u32>> {
        self.reset(OVERHEAD * 16);
        // UID FETCH also works in rev2, where SEARCH can return ESEARCH instead
        // of the legacy SEARCH response understood by this client version.
        let data = self.session.uid_fetch(range, "(UID)").safe()?;
        let mut uids: Vec<_> = data
            .iter()
            .filter_map(|m| m.uid)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        uids.sort_unstable();
        if uids.contains(&0) {
            bail!("server returned invalid UID zero");
        }
        Ok(uids)
    }
    /// RFC822.SIZE of one message, checked against the configured cap. `None` if absent.
    fn size_of(&mut self, uid: u32) -> Result<Option<usize>> {
        // Inspect size first, but also enforce a wire budget in case the server lies.
        self.reset(OVERHEAD);
        let size = self
            .session
            .uid_fetch(uid.to_string(), "(UID RFC822.SIZE)")
            .safe()?;
        let mut matching = size
            .iter()
            .filter(|m| m.uid == Some(uid) && m.size.is_some());
        let Some(s) = matching.next() else {
            return Ok(None);
        };
        if matching.next().is_some() {
            bail!("ambiguous RFC822.SIZE for requested UID");
        }
        let expected = s.size.unwrap() as usize;
        if expected > self.limit {
            return Err(
                PermanentMessageError("message exceeds configured max_message_bytes").into(),
            );
        }
        Ok(Some(expected))
    }
    fn message(&mut self, uid: u32) -> Result<Option<Message>> {
        match self.size_of(uid)? {
            None => Ok(None),
            Some(expected) => self.fetch_buffered(uid, expected),
        }
    }
    fn fetch_buffered(&mut self, uid: u32, expected: usize) -> Result<Option<Message>> {
        self.reset(expected.saturating_add(OVERHEAD));
        let (data, _) = self
            .session
            .run(format!(
                "UID FETCH {uid} (UID FLAGS INTERNALDATE BODY.PEEK[])"
            ))
            .safe()?;
        decode_message(&data, uid, expected)
    }
    /// A source message for transfer. Above `stream_above` bytes it is streamed into a
    /// verified spool; otherwise it is fetched whole, exactly as before. The flag says whether
    /// the spool path ran.
    fn read_for_transfer(
        &mut self,
        uid: u32,
        stream_above: Option<usize>,
        spool: &SpoolConfig,
    ) -> Result<(Option<Transfer>, bool)> {
        let Some(expected) = self.size_of(uid)? else {
            return Ok((None, false));
        };
        if stream_above.is_some_and(|threshold| expected > threshold) {
            // Directory, filesystem and free-space checks happen before anything is read.
            let target =
                crate::spool::Spool::create(&spool.dir, expected as u64, spool.allow_memory_backed)
                    .map_err(anyhow::Error::new)?;
            self.reset(expected.saturating_add(OVERHEAD));
            Ok((
                spool_message_into(
                    &mut self.session,
                    uid,
                    expected,
                    target,
                    &crate::interrupted,
                )?
                .map(Transfer::Spooled),
                true,
            ))
        } else {
            Ok((
                self.fetch_buffered(uid, expected)?.map(Transfer::Buffered),
                false,
            ))
        }
    }
    /// Digest of one message. Above `stream_above` bytes the body is streamed through the
    /// hasher and never held in memory; otherwise it is fetched whole, exactly as before,
    /// and digested. The two paths must (and are tested to) give the same answer.
    /// The returned flag says whether the streaming path ran.
    fn digest(
        &mut self,
        uid: u32,
        stream_above: Option<usize>,
        chunk_point: &'static str,
    ) -> Result<(Option<MessageDigest>, bool)> {
        let Some(expected) = self.size_of(uid)? else {
            return Ok((None, false));
        };
        if stream_above.is_some_and(|threshold| expected > threshold) {
            self.reset(expected.saturating_add(OVERHEAD));
            Ok((
                stream_digest(&mut self.session, uid, expected, chunk_point)?,
                true,
            ))
        } else {
            let message = self.fetch_buffered(uid, expected)?;
            Ok((message.map(|m| m.digest()), false))
        }
    }
}

/// What a streamed FETCH established about one message. The body itself went to the sink.
struct StreamedMeta {
    sha256: String,
    size: u64,
    date: DateTime<FixedOffset>,
    flags: Vec<String>,
    /// Non-empty only for a short body sent as a quoted string rather than a literal: it is
    /// already in the response skeleton and was NOT passed to the sink.
    inline: Vec<u8>,
}

/// Stream one message body through SHA-256 into `sink`, validated by the same `parse_fetch`
/// as the buffered path. Nothing is returned unless the whole literal was read, matched the
/// expected size and was followed by a complete tagged OK, so a truncated, short or failed
/// read can never yield a result. The sink may fail (for example a full disk); that aborts
/// the stream and the error comes back as `Error::Io`.
fn stream_message<T: Read + Write>(
    session: &mut imap::Session<T>,
    uid: u32,
    expected: usize,
    chunk_point: &'static str,
    sink: &mut dyn FnMut(&[u8]) -> io::Result<()>,
) -> Result<Option<StreamedMeta>> {
    let mut hasher = Sha256::new();
    let mut seen = 0u64;
    let fetched = session
        .uid_fetch_body_stream(uid, expected as u64, &mut |chunk| {
            hasher.update(chunk);
            seen += chunk.len() as u64;
            // Crash-test hook (absent in default builds): die part-way through the body.
            crate::fault::point(chunk_point);
            sink(chunk)
        })
        .safe()?;
    let streamed_len = fetched.body_len.map(|n| n as usize);
    let Some(parsed) = parse_fetch(&fetched.skeleton, uid, expected, streamed_len)? else {
        return Ok(None);
    };
    let (sha256, size, inline) = match fetched.body_len {
        Some(n) => {
            if seen != n || !parsed.body.is_empty() {
                bail!("streamed body does not match its FETCH response");
            }
            (format!("{:x}", hasher.finalize()), n, Vec::new())
        }
        None => (
            crate::journal::fingerprint(&parsed.body),
            parsed.body.len() as u64,
            parsed.body,
        ),
    };
    Ok(Some(StreamedMeta {
        sha256,
        size,
        date: parsed.date,
        flags: parsed.flags,
        inline,
    }))
}

/// Digest of one message, streamed and not kept.
fn stream_digest<T: Read + Write>(
    session: &mut imap::Session<T>,
    uid: u32,
    expected: usize,
    chunk_point: &'static str,
) -> Result<Option<MessageDigest>> {
    Ok(
        stream_message(session, uid, expected, chunk_point, &mut |_| Ok(()))?.map(|m| {
            MessageDigest {
                sha256: m.sha256,
                size: m.size,
                date: m.date,
                flags: m.flags,
            }
        }),
    )
}

/// A stop request (SIGTERM, SIGINT, SIGHUP) arrived while a source message was being streamed into
/// the spool. Nothing durable exists at that point (no journal row, nothing sent), so abandoning the
/// download is safe; it is deliberately NOT done once a literal is authorized.
#[derive(Debug)]
pub struct StopRequested;
impl std::fmt::Display for StopRequested {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("stop requested during the source download")
    }
}
impl std::error::Error for StopRequested {}

/// Where and how large source messages are spooled.
#[derive(Clone, Debug)]
pub struct SpoolConfig {
    pub dir: std::path::PathBuf,
    pub allow_memory_backed: bool,
}
/// A source message that was streamed into a verified spool instead of memory.
pub struct SpooledMessage {
    pub spool: crate::spool::SealedSpool,
    pub date: DateTime<FixedOffset>,
    pub flags: Vec<String>,
}
impl SpooledMessage {
    pub fn size(&self) -> u64 {
        self.spool.size
    }
    /// Lowercase hex SHA-256, identical to `journal::fingerprint` of the same bytes.
    pub fn sha256(&self) -> &str {
        &self.spool.sha256
    }
}
/// A source message ready to transfer: whole in memory (small) or in a verified spool (large).
pub enum Transfer {
    Buffered(Message),
    Spooled(SpooledMessage),
}

/// Stream a source message into `spool`, then verify it. Everything that can go wrong here
/// (truncation, size or length mismatch, malformed or failed reads, a full disk) happens
/// BEFORE the caller writes anything to the journal or the destination, so a failure leaves
/// nothing behind but the error. A spool write failure is returned as the typed, non-retryable
/// `SpoolError`, never disguised as a transient network error.
fn spool_message_into<T: Read + Write>(
    session: &mut imap::Session<T>,
    uid: u32,
    expected: usize,
    mut spool: crate::spool::Spool,
    should_stop: &dyn Fn() -> bool,
) -> Result<Option<SpooledMessage>> {
    let mut sink_error: Option<crate::spool::SpoolError> = None;
    let mut stopped = false;
    let streamed = stream_message(
        session,
        uid,
        expected,
        "source_stream_chunk",
        &mut |chunk| {
            // Safe to abandon: nothing durable exists yet. Checked once per chunk.
            if should_stop() {
                stopped = true;
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            spool.write_chunk(chunk).inspect_err(|e| {
                sink_error = Some(crate::spool::classify(e));
            })
        },
    );
    let meta = match streamed {
        Ok(meta) => meta,
        Err(e) => {
            return Err(if stopped {
                anyhow::Error::new(StopRequested)
            } else {
                match sink_error {
                    Some(spool_error) => anyhow::Error::new(spool_error),
                    None => e,
                }
            });
        }
    };
    let Some(meta) = meta else {
        return Ok(None);
    };
    if !meta.inline.is_empty() {
        spool
            .write_chunk(&meta.inline)
            .map_err(|e| anyhow::Error::new(crate::spool::classify(&e)))?;
    }
    if spool.written() != meta.size {
        bail!("spooled length differs from the streamed length");
    }
    crate::fault::point("spool_after_fetch");
    let sealed = spool.seal().map_err(anyhow::Error::new)?;
    if sealed.sha256 != meta.sha256 {
        return Err(anyhow::Error::new(crate::spool::SpoolError::Corrupt));
    }
    crate::fault::point("spool_sealed");
    Ok(Some(SpooledMessage {
        spool: sealed,
        date: meta.date,
        flags: meta.flags,
    }))
}

/// Outcome of a streaming APPEND. `phase` says how far the literal got, so the caller can
/// tell a provably unsent APPEND from an uncertain one; the conservative recovery rules do
/// not change because of it.
pub struct StreamedOutcome {
    pub result: Result<(u32, u32)>,
    pub phase: imap::AppendPhase,
    pub body_bytes_sent: u64,
}
fn appended_identity(appended: imap::types::Appended) -> Result<(u32, u32)> {
    let uid = match appended.uids.as_deref() {
        Some([UidSetMember::Uid(u)]) => *u,
        Some([UidSetMember::UidRange(r)]) if r.start() == r.end() => *r.start(),
        _ => bail!("APPEND succeeded without a single APPENDUID; transfer remains uncertain"),
    };
    Ok((
        appended
            .uid_validity
            .filter(|v| *v != 0)
            .context("missing APPENDUID validity")?,
        uid,
    ))
}
/// APPEND a spooled message. The guard (durable authorization) runs after the `+` continuation
/// and before the first body byte, exactly as for the buffered APPEND, and the literal is read
/// from the spool and re-hashed on the way out.
fn append_from_spool<T: Read + Write>(
    session: &mut imap::Session<T>,
    name: &str,
    flags: &[String],
    spooled: &mut SpooledMessage,
    guard: impl FnOnce() -> io::Result<()>,
) -> StreamedOutcome {
    let (size, date) = (spooled.size(), spooled.date);
    let mut reader = match spooled.spool.reader("append_stream_chunk") {
        Ok(reader) => reader,
        Err(e) => {
            return StreamedOutcome {
                result: Err(anyhow::Error::new(crate::spool::classify(&e))),
                phase: imap::AppendPhase::NotAuthorized,
                body_bytes_sent: 0,
            };
        }
    };
    let mut command = session.append_stream(name);
    command
        .flags(flags.iter().map(|f| Flag::from(f.as_str())))
        .internal_date(date);
    let out = command.finish_streaming(size, &mut reader, guard);
    let result = out
        .result
        .safe()
        .context("APPEND did not provide a usable confirmation; transfer remains uncertain")
        .and_then(appended_identity);
    StreamedOutcome {
        result,
        phase: out.phase,
        body_bytes_sent: out.body_bytes_sent,
    }
}
pub(crate) fn phase_name(phase: imap::AppendPhase) -> &'static str {
    use imap::AppendPhase::*;
    match phase {
        NotAuthorized => "not_authorized",
        Authorized => "authorized",
        BodyStarted => "body_started",
        BodyComplete => "body_complete",
        Responded => "responded",
    }
}

pub struct Source(Connection);
impl Source {
    pub fn connect(e: &Endpoint, password: &str, timeout: Duration, limit: usize) -> Result<Self> {
        let result = Connection::connect(e, password, timeout, limit);
        diag_connect("source", &result);
        Ok(Self(result?))
    }
    pub fn folders(&mut self) -> Result<Vec<Folder>> {
        observed("source", "list", count_detail, || self.0.list())
    }
    pub fn examine(&mut self, folder: &str) -> Result<Selected> {
        observed("source", "examine", selected_detail, || {
            self.0.select_folder(folder, false)
        })
    }
    pub fn uids(&mut self) -> Result<Vec<u32>> {
        observed("source", "uid_search", count_detail, || self.0.uids())
    }
    pub fn snapshot_uids(&mut self, next: u32) -> Result<Vec<u32>> {
        if next <= 1 {
            return Ok(Vec::new());
        }
        observed("source", "uid_search_range", count_detail, || {
            let uids = self.0.uids_range(&format!("1:{}", next - 1))?;
            if uids.iter().any(|u| *u >= next) {
                bail!("server returned UID outside snapshot horizon");
            }
            Ok(uids)
        })
    }
    pub fn message(&mut self, uid: u32) -> Result<Option<Message>> {
        observed("source", "uid_fetch", message_detail, || {
            self.0.message(uid)
        })
    }
    /// Read one message for transfer: whole in memory when small, streamed into a verified
    /// spool above `stream_above` bytes. Nothing is durable until the caller writes the journal.
    pub fn read_for_transfer(
        &mut self,
        uid: u32,
        stream_above: Option<usize>,
        spool: &SpoolConfig,
    ) -> Result<Option<Transfer>> {
        if !crate::diagnostics::enabled() {
            return Ok(self.0.read_for_transfer(uid, stream_above, spool)?.0);
        }
        let started = Instant::now();
        let result = self.0.read_for_transfer(uid, stream_above, spool);
        let mut fields = diag_object([
            ("role", "source".into()),
            ("op", "uid_fetch_transfer".into()),
            ("ms", (started.elapsed().as_millis() as u64).into()),
        ]);
        match &result {
            Ok((transfer, spooled)) => {
                fields.insert("outcome".into(), "OK".into());
                fields.insert("found".into(), transfer.is_some().into());
                fields.insert("spooled".into(), (*spooled).into());
                let bytes = match transfer {
                    Some(Transfer::Buffered(m)) => Some(m.body.len() as u64),
                    Some(Transfer::Spooled(s)) => Some(s.size()),
                    None => None,
                };
                fields.insert("bytes".into(), bytes.into());
            }
            Err(e) => {
                fields.extend(diag_failure(e));
                if let Some(spool_error) = e.downcast_ref::<crate::spool::SpoolError>() {
                    fields.insert("outcome".into(), "SPOOL".into());
                    fields.insert("code".into(), spool_error_name(spool_error).into());
                }
            }
        }
        crate::diagnostics::event("command", fields);
        Ok(result?.0)
    }
}
fn spool_error_name(e: &crate::spool::SpoolError) -> &'static str {
    use crate::spool::SpoolError::*;
    match e {
        Unsupported => "SPOOL_UNSUPPORTED",
        MemoryBacked => "SPOOL_MEMORY_BACKED",
        NoSpace => "SPOOL_NO_SPACE",
        BadDirectory(_) => "SPOOL_BAD_DIRECTORY",
        Corrupt => "SPOOL_CORRUPT",
        Io(_) => "SPOOL_IO",
    }
}

/// Fixed capability names that may appear in diagnostics; everything else is only counted.
const DIAG_CAPS: &[&str] = &[
    "IMAP4REV1",
    "IMAP4REV2",
    "UIDPLUS",
    "AUTH=PLAIN",
    "AUTH=XOAUTH2",
    "AUTH=LOGIN",
    "LOGINDISABLED",
    "STARTTLS",
    "ENABLE",
    "UTF8=ACCEPT",
    "UTF8=ONLY",
    "MOVE",
    "LITERAL+",
    "LITERAL-",
    "IDLE",
    "NAMESPACE",
    "ID",
    "UNSELECT",
    "CHILDREN",
    "SASL-IR",
    "CONDSTORE",
    "QRESYNC",
    "MULTIAPPEND",
    "SPECIAL-USE",
    "XLIST",
    "LIST-EXTENDED",
    "X-GM-EXT-1",
    "BINARY",
    "COMPRESS=DEFLATE",
];
fn diag_object(
    pairs: impl IntoIterator<Item = (&'static str, serde_json::Value)>,
) -> serde_json::Map<String, serde_json::Value> {
    pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
}
fn diag_connect(role: &'static str, result: &Result<Connection>) {
    use serde_json::json;
    let mut fields = diag_object([("role", json!(role))]);
    match result {
        Ok(c) => {
            let mut names: Vec<_> = c
                .caps
                .iter()
                .filter(|c| DIAG_CAPS.contains(&c.as_str()))
                .cloned()
                .collect();
            names.sort();
            let limit = c.caps.iter().find_map(|c| {
                c.strip_prefix("APPENDLIMIT=")
                    .and_then(|n| n.parse::<u64>().ok())
            });
            fields.extend(diag_object([
                ("outcome", json!("OK")),
                ("capabilities", json!(names)),
                ("other_capability_count", json!(c.caps.len() - names.len())),
                ("appendlimit", json!(limit)),
            ]));
        }
        Err(e) => fields.extend(diag_failure(e)),
    }
    crate::diagnostics::event("connect", fields);
}
fn diag_failure(e: &anyhow::Error) -> serde_json::Map<String, serde_json::Value> {
    use serde_json::json;
    match e.downcast_ref::<ProtocolError>() {
        Some(p) => {
            let wire = p.wire.clone();
            diag_object([
                (
                    "outcome",
                    json!(wire.as_ref().map_or("LOCAL", |w| w.outcome)),
                ),
                ("code", json!(wire.as_ref().map_or("-", |w| w.code))),
                (
                    "unlisted_code",
                    json!(wire.as_ref().and_then(|w| w.unlisted.clone())),
                ),
                (
                    "scope",
                    json!(p.rejection.as_ref().map(|r| r.scope().name())),
                ),
                ("transient", json!(p.transient)),
            ])
        }
        None => diag_object([("outcome", json!("LOCAL_ERROR"))]),
    }
}
/// Run one wire operation; when diagnostics are off this is exactly `f()`.
fn observed<T>(
    role: &'static str,
    op: &'static str,
    detail: impl FnOnce(&T) -> Vec<(&'static str, serde_json::Value)>,
    f: impl FnOnce() -> Result<T>,
) -> Result<T> {
    if !crate::diagnostics::enabled() {
        return f();
    }
    let started = Instant::now();
    let result = f();
    let mut fields = diag_object([
        ("role", role.into()),
        ("op", op.into()),
        ("ms", (started.elapsed().as_millis() as u64).into()),
    ]);
    match &result {
        Ok(value) => {
            fields.insert("outcome".into(), "OK".into());
            fields.extend(diag_object(detail(value)));
        }
        Err(e) => fields.extend(diag_failure(e)),
    }
    crate::diagnostics::event("command", fields);
    result
}
// Must take `&Vec<T>` to fit the `FnOnce(&T)` callback with `T = Vec<_>`.
#[allow(clippy::ptr_arg)]
fn count_detail<T>(v: &Vec<T>) -> Vec<(&'static str, serde_json::Value)> {
    vec![("count", v.len().into())]
}
fn message_detail(m: &Option<Message>) -> Vec<(&'static str, serde_json::Value)> {
    vec![
        ("found", m.is_some().into()),
        ("bytes", m.as_ref().map(|m| m.body.len()).into()),
    ]
}
fn selected_detail(s: &Selected) -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    const SYSTEM: [&str; 6] = [
        "\\Seen",
        "\\Answered",
        "\\Flagged",
        "\\Deleted",
        "\\Draft",
        "\\*",
    ];
    let system: Vec<_> = s
        .flags
        .iter()
        .filter(|f| SYSTEM.iter().any(|k| k.eq_ignore_ascii_case(f)))
        .cloned()
        .collect();
    vec![
        ("writable", json!(s.writable)),
        ("exists", json!(s.exists)),
        ("has_uidnext", json!(s.next.is_some())),
        ("system_flags", json!(system)),
        ("custom_flag_count", json!(s.flags.len() - system.len())),
    ]
}

pub struct Destination(Connection);
impl Destination {
    pub fn connect(e: &Endpoint, password: &str, timeout: Duration, limit: usize) -> Result<Self> {
        let result = Connection::connect(e, password, timeout, limit);
        diag_connect("destination", &result);
        let c = result?;
        // Without this, a routine successful upload may have no durable identity.
        if !c.caps.contains("UIDPLUS") && !c.caps.contains("IMAP4REV2") {
            bail!("destination must support UIDPLUS or IMAP4rev2 for APPENDUID tracking");
        }
        Ok(Self(c))
    }
    pub fn folders(&mut self) -> Result<Vec<Folder>> {
        observed("destination", "list", count_detail, || self.0.list())
    }
    pub fn examine(&mut self, folder: &str) -> Result<Selected> {
        observed("destination", "examine", selected_detail, || {
            self.0.select_folder(folder, false)
        })
    }
    pub fn uids(&mut self) -> Result<Vec<u32>> {
        observed("destination", "uid_search", count_detail, || self.0.uids())
    }
    pub fn message(&mut self, uid: u32) -> Result<Option<Message>> {
        observed("destination", "uid_fetch", message_detail, || {
            self.0.message(uid)
        })
    }
    /// Digest of one destination message for verification and candidate scans. Above
    /// `stream_above` bytes the body is streamed and never held in memory.
    pub fn message_digest(
        &mut self,
        uid: u32,
        stream_above: Option<usize>,
        chunk_point: &'static str,
    ) -> Result<Option<MessageDigest>> {
        if !crate::diagnostics::enabled() {
            return Ok(self.0.digest(uid, stream_above, chunk_point)?.0);
        }
        let started = Instant::now();
        let result = self.0.digest(uid, stream_above, chunk_point);
        let mut fields = diag_object([
            ("role", "destination".into()),
            ("op", "uid_fetch_digest".into()),
            ("ms", (started.elapsed().as_millis() as u64).into()),
        ]);
        match &result {
            Ok((digest, streamed)) => {
                fields.insert("outcome".into(), "OK".into());
                fields.insert("found".into(), digest.is_some().into());
                fields.insert("bytes".into(), digest.as_ref().map(|d| d.size).into());
                fields.insert("streamed".into(), (*streamed).into());
            }
            Err(e) => fields.extend(diag_failure(e)),
        }
        crate::diagnostics::event("command", fields);
        Ok(result?.0)
    }
    pub fn select(&mut self, folder: &str) -> Result<Selected> {
        observed("destination", "select", selected_detail, || {
            self.0.select_folder(folder, true)
        })
    }
    /// Destination-only liveness probe. It carries no message data and, being
    /// a read of connection state, never takes part in an uncertain transfer.
    pub fn noop(&mut self) -> Result<()> {
        observed(
            "destination",
            "noop",
            |_| Vec::new(),
            || {
                self.0.reset(OVERHEAD);
                self.0
                    .session
                    .noop()
                    .safe()
                    .context("destination NOOP liveness probe")
            },
        )
    }
    pub fn create(&mut self, folder: &str) -> Result<()> {
        observed(
            "destination",
            "create",
            |_| Vec::new(),
            || {
                let name = self.0.encoding.encode(folder)?;
                self.0.reset(OVERHEAD);
                self.0
                    .session
                    .create(name)
                    .safe()
                    .context("create destination folder")
            },
        )
    }
    pub fn append(
        &mut self,
        folder: &str,
        message: &Message,
        flags: &[String],
        guard: impl FnOnce() -> io::Result<()>,
    ) -> Result<(u32, u32)> {
        let bytes = message.body.len();
        observed(
            "destination",
            "append",
            |_| vec![("bytes", bytes.into()), ("appenduid", true.into())],
            || self.append_inner(folder, message, flags, guard),
        )
    }
    fn append_inner(
        &mut self,
        folder: &str,
        message: &Message,
        flags: &[String],
        guard: impl FnOnce() -> io::Result<()>,
    ) -> Result<(u32, u32)> {
        let name = self.0.encoding.encode(folder)?;
        // imap 3 alpha's APPEND builder wraps but does not escape this argument.
        let name = name.replace('\\', "\\\\").replace('"', "\\\"");
        if flags.iter().any(|f| !valid_flag(f)) {
            bail!("unsafe IMAP flag");
        }
        self.0.reset(OVERHEAD);
        let appended = self
            .0
            .session
            .append(&name, &message.body)
            .flags(flags.iter().map(|f| Flag::from(f.as_str())))
            .internal_date(message.date)
            .finish_with_literal_guard(guard)
            .safe()
            .context("APPEND did not provide a usable confirmation; transfer remains uncertain")?;
        appended_identity(appended)
    }
    /// APPEND a message that lives in a verified spool, streaming the literal. The guard
    /// (durable authorization) runs after the continuation and before any body byte.
    pub fn append_spooled(
        &mut self,
        folder: &str,
        spooled: &mut SpooledMessage,
        flags: &[String],
        guard: impl FnOnce() -> io::Result<()>,
    ) -> StreamedOutcome {
        let refused = |e: anyhow::Error| StreamedOutcome {
            result: Err(e),
            phase: imap::AppendPhase::NotAuthorized,
            body_bytes_sent: 0,
        };
        let name = match self.0.encoding.encode(folder) {
            // imap 3 alpha's APPEND builder wraps but does not escape this argument.
            Ok(name) => name.replace('\\', "\\\\").replace('"', "\\\""),
            Err(e) => return refused(e),
        };
        if flags.iter().any(|f| !valid_flag(f)) {
            return refused(anyhow::anyhow!("unsafe IMAP flag"));
        }
        self.0.reset(OVERHEAD);
        let started = Instant::now();
        let out = append_from_spool(&mut self.0.session, &name, flags, spooled, guard);
        if crate::diagnostics::enabled() {
            let mut fields = diag_object([
                ("role", "destination".into()),
                ("op", "append".into()),
                ("ms", (started.elapsed().as_millis() as u64).into()),
                ("phase", phase_name(out.phase).into()),
                ("streamed", true.into()),
                ("bytes", spooled.size().into()),
            ]);
            match &out.result {
                Ok(_) => {
                    fields.insert("outcome".into(), "OK".into());
                    fields.insert("appenduid".into(), true.into());
                }
                Err(e) => fields.extend(diag_failure(e)),
            }
            crate::diagnostics::event("command", fields);
        }
        out
    }
}
pub fn valid_flag(flag: &str) -> bool {
    let atom = flag.strip_prefix('\\').unwrap_or(flag);
    !atom.is_empty()
        && atom
            .bytes()
            .all(|b| (0x21..=0x7e).contains(&b) && !b"(){%*\"\\]".contains(&b))
}

/// What one FETCH response says about one message, after every structural check.
/// `body` is empty when the body literal was streamed out of the response.
struct ParsedFetch {
    body: Vec<u8>,
    date: DateTime<FixedOffset>,
    flags: Vec<String>,
}
/// The single place that validates a message FETCH response, used by both the buffered
/// path and the streaming path so they cannot diverge.
///
/// `streamed_len` is `Some` when the body literal was streamed out and replaced by an empty
/// literal in `response`; the size check then uses that length. The size check happens as
/// soon as the matching body is found, before later responses are examined, exactly as the
/// original decoder did, so the same error is reported for the same input.
fn parse_fetch(
    response: &[u8],
    uid: u32,
    expected: usize,
    streamed_len: Option<usize>,
) -> Result<Option<ParsedFetch>> {
    use imap_proto::AttributeValue as A;
    let mut rest = response;
    let mut message = None;
    // Streaming only: some other message's response also carried a body section.
    let mut foreign_body = false;
    while !rest.is_empty() {
        let (next, r) = Response::from_bytes(rest)
            .map_err(|_| anyhow::anyhow!("invalid message FETCH response"))?;
        if let Response::Fetch(_, attributes) = r {
            let ids: Vec<_> = attributes
                .iter()
                .filter_map(|a| if let A::Uid(u) = a { Some(*u) } else { None })
                .collect();
            if streamed_len.is_some()
                && !ids.contains(&uid)
                && attributes.iter().any(|a| {
                    matches!(
                        a,
                        A::BodySection {
                            section: None,
                            index: None,
                            data: Some(_)
                        }
                    )
                })
            {
                foreign_body = true;
            }
            if ids.contains(&uid) {
                let bodies: Vec<_> = attributes
                    .iter()
                    .filter_map(|a| {
                        if let A::BodySection {
                            section: None,
                            index: None,
                            data: Some(b),
                        } = a
                        {
                            Some(b)
                        } else {
                            None
                        }
                    })
                    .collect();
                if !bodies.is_empty() {
                    if ids.len() != 1 || bodies.len() != 1 || message.is_some() {
                        bail!("ambiguous or duplicate UID FETCH content");
                    }
                    let dates: Vec<_> = attributes
                        .iter()
                        .filter_map(|a| {
                            if let A::InternalDate(d) = a {
                                Some(d)
                            } else {
                                None
                            }
                        })
                        .collect();
                    let flags: Vec<_> = attributes
                        .iter()
                        .filter_map(|a| if let A::Flags(f) = a { Some(f) } else { None })
                        .collect();
                    if dates.len() != 1 || flags.len() != 1 {
                        bail!("FETCH omitted or duplicated INTERNALDATE/FLAGS");
                    }
                    let actual = match streamed_len {
                        Some(n) if bodies[0].is_empty() => n,
                        _ => bodies[0].len(),
                    };
                    if actual != expected {
                        return Err(
                            PermanentMessageError("message size differs from RFC822.SIZE").into(),
                        );
                    }
                    let date = DateTime::parse_from_str(dates[0], "%d-%b-%Y %H:%M:%S %z")
                        .context("invalid INTERNALDATE")?;
                    message = Some(ParsedFetch {
                        body: bodies[0].to_vec(),
                        date,
                        flags: flags[0].iter().map(ToString::to_string).collect(),
                    });
                }
            }
        }
        rest = next;
    }
    if foreign_body && message.is_some() {
        // The streamed literal is the first BODY[] on the wire. With bodies for two
        // messages present it cannot be attributed to this one, so fail closed; the
        // buffered path would have ignored the other message's body.
        bail!("streamed FETCH body may belong to a different UID");
    }
    Ok(message)
}

fn decode_message(response: &[u8], uid: u32, expected: usize) -> Result<Option<Message>> {
    Ok(
        parse_fetch(response, uid, expected, None)?.map(|parsed| Message {
            body: parsed.body,
            date: parsed.date,
            flags: parsed.flags,
        }),
    )
}

// Parse selection with the established protocol parser rather than imap's
// convenience parser, which panics on untagged NO (including UIDNOTSTICKY).
fn decode_selected(response: &[u8], requested_write: bool) -> Result<Selected> {
    use imap_proto::{ResponseCode as C, Status};
    let mut rest = response;
    let mut exists = None;
    let mut validity = None;
    let mut next_uid = None;
    let mut flags = None;
    let mut permanent = None;
    let mut mode = None;
    while !rest.is_empty() {
        let (next, r) = Response::from_bytes(rest)
            .map_err(|_| anyhow::anyhow!("invalid folder-selection response"))?;
        let code = match r {
            Response::Data { code, status, .. } => {
                if matches!(code, Some(C::UidNotSticky)) {
                    bail!("server reports UIDNOTSTICKY; durable migration requires stable UIDs");
                }
                if status != Status::Ok {
                    bail!("server reported an unsuccessful untagged selection response");
                }
                code
            }
            Response::Done { code, status, .. } => {
                if status != Status::Ok {
                    bail!("folder selection rejected");
                }
                mode = match code {
                    Some(C::ReadOnly) => Some(false),
                    Some(C::ReadWrite) => Some(true),
                    _ => None,
                };
                code
            }
            Response::MailboxData(imap_proto::MailboxDatum::Exists(n)) => {
                exists = Some(n);
                None
            }
            Response::MailboxData(imap_proto::MailboxDatum::Flags(f)) => {
                flags = Some(f.iter().map(ToString::to_string).collect::<Vec<_>>());
                None
            }
            _ => None,
        };
        match code {
            Some(C::UidValidity(v)) => {
                if v == 0 || validity.is_some_and(|old| old != v) {
                    bail!("invalid or conflicting UIDVALIDITY");
                }
                validity = Some(v);
            }
            Some(C::UidNext(v)) => {
                if v == 0 {
                    bail!("invalid UIDNEXT zero");
                }
                next_uid = Some(v);
            }
            Some(C::PermanentFlags(f)) => {
                permanent = Some(f.iter().map(ToString::to_string).collect::<Vec<_>>())
            }
            Some(C::UidNotSticky) => bail!("server reports UIDNOTSTICKY"),
            _ => {}
        }
        rest = next;
    }
    let writable = mode.context("server omitted explicit READ-ONLY/READ-WRITE selection mode")?;
    if !requested_write && writable {
        bail!("server did not honor read-only EXAMINE");
    }
    // RFC3501: when PERMANENTFLAGS is omitted all flags may be changed.
    let supported = permanent.unwrap_or_else(|| {
        let mut all = flags.unwrap_or_else(|| {
            ["\\Seen", "\\Answered", "\\Flagged", "\\Draft", "\\Deleted"]
                .map(str::to_owned)
                .to_vec()
        });
        all.push("\\*".into());
        all
    });
    Ok(Selected {
        exists: exists.context("server omitted EXISTS in folder selection")?,
        validity: validity.context("server omitted stable UIDVALIDITY")?,
        next: next_uid,
        flags: supported,
        writable,
    })
}

// imap-proto 0.16 preserves quoted-string escapes. Keep literal bytes unchanged:
// only unescape a value whose borrowed span is immediately preceded by DQUOTE.
fn list_string(value: &str, frame: &[u8]) -> Result<String> {
    if !value.contains('\\') {
        return Ok(value.to_owned());
    }
    let offset = (value.as_ptr() as usize)
        .checked_sub(frame.as_ptr() as usize)
        .filter(|o| *o <= frame.len())
        .context("LIST parser returned a non-borrowed escaped name")?;
    if offset == 0 || frame.get(offset - 1) != Some(&b'"') {
        return Ok(value.to_owned());
    }
    let mut out = String::new();
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let escaped = chars.next().context("incomplete quoted escape")?;
            if escaped != '\\' && escaped != '"' {
                bail!("invalid quoted escape");
            }
            out.push(escaped);
        } else {
            out.push(c);
        }
    }
    Ok(out)
}
fn decode_list(response: &[u8], encoding: FolderEncoding) -> Result<Vec<Folder>> {
    let mut rest = response;
    let mut folders = Vec::new();
    while !rest.is_empty() {
        let (next, r) =
            Response::from_bytes(rest).map_err(|_| anyhow::anyhow!("invalid LIST response"))?;
        if let Response::MailboxData(imap_proto::MailboxDatum::List {
            name_attributes,
            delimiter,
            name,
        }) = r
        {
            let name = list_string(&name, rest)?;
            // Empty hierarchy roots are not selectable mailboxes.
            if !name.is_empty() {
                folders.push(Folder {
                    name: encoding.decode(name.as_bytes())?,
                    delimiter: delimiter.map(|d| list_string(&d, rest)).transpose()?,
                    selectable: !name_attributes.contains(&imap_proto::NameAttribute::NoSelect),
                });
            }
        }
        rest = next;
    }
    Ok(folders)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    #[test]
    fn interrupted_socket_read_retries_without_losing_bytes() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static SIGNALS: AtomicUsize = AtomicUsize::new(0);
        extern "C" fn handler(_: libc::c_int) {
            SIGNALS.fetch_add(1, Ordering::Relaxed);
        }
        // Target only the worker thread and explicitly disable SA_RESTART so
        // this exercises an interrupted recv rather than a restarted syscall.
        let mut previous = unsafe { std::mem::zeroed::<libc::sigaction>() };
        let mut action = unsafe { std::mem::zeroed::<libc::sigaction>() };
        action.sa_sigaction = handler as *const () as usize;
        unsafe {
            libc::sigemptyset(&mut action.sa_mask);
            assert_eq!(libc::sigaction(libc::SIGUSR1, &action, &mut previous), 0);
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let socket = listener.accept().unwrap().0;
        let (send, receive) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let mut socket = HandshakeSocket {
                socket,
                deadline: Some(Instant::now() + Duration::from_secs(3)),
                control: None,
            };
            send.send(unsafe { libc::pthread_self() }).unwrap();
            let mut bytes = [0; 4];
            let result = socket.read(&mut bytes);
            (result, bytes)
        });
        let thread = receive.recv().unwrap();
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(unsafe { libc::pthread_kill(thread, libc::SIGUSR1) }, 0);
        std::thread::sleep(Duration::from_millis(50));
        peer.write_all(b"mail").unwrap();
        let (result, bytes) = worker.join().unwrap();
        unsafe {
            assert_eq!(
                libc::sigaction(libc::SIGUSR1, &previous, std::ptr::null_mut()),
                0
            );
        }
        assert!(SIGNALS.load(Ordering::Relaxed) > 0);
        assert_eq!(result.unwrap(), 4);
        assert_eq!(&bytes, b"mail");
    }
    #[test]
    fn idle_deadline_advances_only_on_positive_progress_without_resetting_budget() {
        let control = Control(
            Arc::new(Mutex::new((123, Instant::now() - Duration::from_secs(1)))),
            Duration::from_secs(2),
        );
        assert!(control.remaining().is_err());
        control.progress(0);
        assert!(control.remaining().is_err());
        control.progress(1);
        assert!(control.remaining().unwrap() > Duration::from_secs(1));
        assert_eq!(control.0.lock().unwrap().0, 123);
    }
    #[test]
    fn missing_flags_duplicate_content_and_size_discrepancies_are_not_confirmed() {
        let valid = b"* 1 FETCH (UID 7 FLAGS () INTERNALDATE \"02-Jan-2020 03:04:05 +0000\" BODY[] {3}\r\nabc)\r\na1 OK done\r\n";
        assert_eq!(decode_message(valid, 7, 3).unwrap().unwrap().body, b"abc");
        assert!(decode_message(valid, 7, 4).is_err());
        let missing = String::from_utf8(valid.to_vec())
            .unwrap()
            .replace("FLAGS () ", "");
        assert!(decode_message(missing.as_bytes(), 7, 3).is_err());
        let mut duplicate = valid.to_vec();
        duplicate.extend(valid);
        assert!(decode_message(&duplicate, 7, 3).is_err());
    }
    /// Outcome class of a decode, for pinning behavior across refactors.
    fn decode_outcome(response: &[u8], uid: u32, expected: usize) -> String {
        match decode_message(response, uid, expected) {
            Ok(None) => "none".into(),
            Ok(Some(m)) => format!(
                "ok body={} date={} flags={:?}",
                String::from_utf8_lossy(&m.body),
                m.date.timestamp(),
                m.flags
            ),
            Err(e) if e.is::<PermanentMessageError>() => "permanent".into(),
            Err(_) => "error".into(),
        }
    }
    const D: &str = "INTERNALDATE \"02-Jan-2020 03:04:05 +0000\"";
    #[test]
    fn decode_message_behavior_is_pinned_for_valid_and_malformed_responses() {
        let ok = format!("* 1 FETCH (UID 7 FLAGS (\\Seen) {D} BODY[] {{3}}\r\nabc)\r\n");
        let ts = chrono::DateTime::parse_from_rfc3339("2020-01-02T03:04:05+00:00")
            .unwrap()
            .timestamp();
        let good = format!("ok body=abc date={ts} flags=[\"\\\\Seen\"]");
        let case = |response: &str, uid: u32, expected: usize| {
            decode_outcome(response.as_bytes(), uid, expected)
        };
        assert_eq!(case(&ok, 7, 3), good);
        // Attribute order must not matter.
        let body_first = format!("* 1 FETCH (BODY[] {{3}}\r\nabc UID 7 FLAGS (\\Seen) {D})\r\n");
        assert_eq!(case(&body_first, 7, 3), good);
        // Size mismatch is a permanent-message error, whichever way it differs.
        assert_eq!(case(&ok, 7, 4), "permanent");
        assert_eq!(case(&ok, 7, 2), "permanent");
        // A different UID, or a response without a body, is "no message", not an error.
        assert_eq!(case(&ok, 8, 3), "none");
        assert_eq!(
            case(
                &format!("* 1 FETCH (UID 7 FLAGS () {D} BODY[] NIL)\r\n"),
                7,
                3
            ),
            "none"
        );
        assert_eq!(
            case(&format!("* 1 FETCH (UID 7 FLAGS () {D})\r\n"), 7, 3),
            "none"
        );
        assert_eq!(case("", 7, 3), "none");
        // Quoted-string body (legal for small data) is accepted like a literal.
        assert!(
            case(
                &format!("* 1 FETCH (UID 7 FLAGS () {D} BODY[] \"abc\")\r\n"),
                7,
                3
            )
            .starts_with("ok body=abc")
        );
        // Structural problems are errors.
        let no_flags = format!("* 1 FETCH (UID 7 {D} BODY[] {{3}}\r\nabc)\r\n");
        let no_date = "* 1 FETCH (UID 7 FLAGS () BODY[] {3}\r\nabc)\r\n";
        let two_flags = format!("* 1 FETCH (UID 7 FLAGS () FLAGS () {D} BODY[] {{3}}\r\nabc)\r\n");
        let two_dates = format!("* 1 FETCH (UID 7 FLAGS () {D} {D} BODY[] {{3}}\r\nabc)\r\n");
        let two_uids = format!("* 1 FETCH (UID 7 UID 7 FLAGS () {D} BODY[] {{3}}\r\nabc)\r\n");
        let two_bodies =
            format!("* 1 FETCH (UID 7 FLAGS () {D} BODY[] {{3}}\r\nabc BODY[] {{3}}\r\nabc)\r\n");
        let bad_date = "* 1 FETCH (UID 7 FLAGS () INTERNALDATE \"nonsense\" BODY[] {3}\r\nabc)\r\n";
        for (name, r) in [
            ("no flags", no_flags.as_str()),
            ("no date", no_date),
            ("two flags", two_flags.as_str()),
            ("two dates", two_dates.as_str()),
            ("two uids", two_uids.as_str()),
            ("two bodies", two_bodies.as_str()),
            ("bad date", bad_date),
            ("garbage", "not an imap response\r\n"),
        ] {
            assert_eq!(case(r, 7, 3), "error", "{name}");
        }
        // The same message twice is ambiguous.
        assert_eq!(case(&format!("{ok}{ok}"), 7, 3), "error");
        // Ordering of failures is part of the behavior: the size check happens when the body
        // is found, before a later duplicate is seen.
        assert_eq!(case(&format!("{ok}{ok}"), 7, 4), "permanent");
        // Unrelated FETCH responses (other UIDs, even with bodies) are ignored.
        let other = format!("* 2 FETCH (UID 9 FLAGS () {D} BODY[] {{2}}\r\nzz)\r\n{ok}");
        assert_eq!(case(&other, 7, 3), good);
    }
    // ------------------------------------------------------------ streaming digest (3b)
    /// Duplex stream that replays a script with fragmented reads and records what is written.
    struct Replay {
        incoming: Vec<u8>,
        pos: usize,
        max_read: usize,
        step: usize,
        written: std::rc::Rc<std::cell::RefCell<Vec<u8>>>,
    }
    impl Read for Replay {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.pos >= self.incoming.len() {
                return Ok(0);
            }
            self.step = self.step.wrapping_mul(1103515245).wrapping_add(12345);
            let take = 1 + (self.step >> 8) % self.max_read;
            let n = take.min(buf.len()).min(self.incoming.len() - self.pos);
            buf[..n].copy_from_slice(&self.incoming[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }
    impl Write for Replay {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written.borrow_mut().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    #[derive(Debug, PartialEq, Eq)]
    enum Outcome {
        Absent,
        Found {
            sha256: String,
            size: u64,
            date: i64,
            flags: Vec<String>,
        },
        Permanent,
        Failed,
    }
    fn found(d: &MessageDigest) -> Outcome {
        Outcome::Found {
            sha256: d.sha256.clone(),
            size: d.size,
            date: d.date.timestamp(),
            flags: d.flags.clone(),
        }
    }
    fn classify(e: &anyhow::Error) -> Outcome {
        if is_permanent_message(e) {
            Outcome::Permanent
        } else {
            Outcome::Failed
        }
    }
    fn buffered_outcome(response: &[u8], uid: u32, expected: usize) -> Outcome {
        match decode_message(response, uid, expected) {
            Ok(None) => Outcome::Absent,
            Ok(Some(m)) => found(&m.digest()),
            Err(e) => classify(&e),
        }
    }
    /// Run the REAL streaming reader and digest over a script (greeting, login, `response`, tagged OK).
    fn streaming_outcome(response: &[u8], uid: u32, expected: usize, max_read: usize) -> Outcome {
        let mut script = b"* OK hello\r\na1 OK logged in\r\n".to_vec();
        script.extend_from_slice(response);
        script.extend_from_slice(b"a2 OK UID FETCH completed\r\n");
        streaming_outcome_raw(script, uid, expected, max_read)
    }
    fn streaming_outcome_raw(
        script: Vec<u8>,
        uid: u32,
        expected: usize,
        max_read: usize,
    ) -> Outcome {
        let mut client = imap::Client::new(Replay {
            incoming: script,
            pos: 0,
            max_read,
            step: 7,
            written: Default::default(),
        });
        client.read_greeting().unwrap();
        let mut session = client.login("u", "p").map_err(|e| e.0).unwrap();
        match stream_digest(&mut session, uid, expected, "") {
            Ok(None) => Outcome::Absent,
            Ok(Some(d)) => found(&d),
            Err(e) => classify(&e),
        }
    }
    fn fetch(body: &[u8], body_first: bool) -> Vec<u8> {
        let attrs = format!("UID 7 FLAGS (\\Seen \\Flagged) {D}");
        let mut r = b"* 1 FETCH (".to_vec();
        if body_first {
            r.extend_from_slice(format!("BODY[] {{{}}}\r\n", body.len()).as_bytes());
            r.extend_from_slice(body);
            r.extend_from_slice(format!(" {attrs})\r\n").as_bytes());
        } else {
            r.extend_from_slice(format!("{attrs} BODY[] {{{}}}\r\n", body.len()).as_bytes());
            r.extend_from_slice(body);
            r.extend_from_slice(b")\r\n");
        }
        r
    }
    fn pseudo(seed: u64, n: usize) -> Vec<u8> {
        let mut x = seed | 1;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect()
    }

    #[test]
    fn streaming_and_buffered_paths_agree_on_valid_and_malformed_responses() {
        let ok = format!("* 1 FETCH (UID 7 FLAGS (\\Seen) {D} BODY[] {{3}}\r\nabc)\r\n");
        let body_first = format!("* 1 FETCH (BODY[] {{3}}\r\nabc UID 7 FLAGS (\\Seen) {D})\r\n");
        let quoted = format!("* 1 FETCH (UID 7 FLAGS () {D} BODY[] \"abc\")\r\n");
        let empty = format!("* 1 FETCH (UID 7 FLAGS () {D} BODY[] {{0}}\r\n)\r\n");
        let no_flags = format!("* 1 FETCH (UID 7 {D} BODY[] {{3}}\r\nabc)\r\n");
        let no_date = "* 1 FETCH (UID 7 FLAGS () BODY[] {3}\r\nabc)\r\n".to_string();
        let two_flags = format!("* 1 FETCH (UID 7 FLAGS () FLAGS () {D} BODY[] {{3}}\r\nabc)\r\n");
        let two_dates = format!("* 1 FETCH (UID 7 FLAGS () {D} {D} BODY[] {{3}}\r\nabc)\r\n");
        let two_uids = format!("* 1 FETCH (UID 7 UID 7 FLAGS () {D} BODY[] {{3}}\r\nabc)\r\n");
        let two_bodies =
            format!("* 1 FETCH (UID 7 FLAGS () {D} BODY[] {{3}}\r\nabc BODY[] {{3}}\r\nabc)\r\n");
        let bad_date = "* 1 FETCH (UID 7 FLAGS () INTERNALDATE \"nonsense\" BODY[] {3}\r\nabc)\r\n"
            .to_string();
        let nil_body = format!("* 1 FETCH (UID 7 FLAGS () {D} BODY[] NIL)\r\n");
        let no_body = format!("* 1 FETCH (UID 7 FLAGS () {D})\r\n");
        let duplicate = format!("{ok}{ok}");
        let cases: Vec<(&str, String, u32, usize)> = vec![
            ("valid", ok.clone(), 7, 3),
            ("body first", body_first, 7, 3),
            ("quoted body", quoted, 7, 3),
            ("empty literal", empty, 7, 0),
            ("size larger than expected", ok.clone(), 7, 4),
            ("size smaller than expected", ok.clone(), 7, 2),
            ("other uid", ok.clone(), 8, 3),
            ("nil body", nil_body, 7, 3),
            ("no body", no_body, 7, 3),
            ("no flags", no_flags, 7, 3),
            ("no date", no_date, 7, 3),
            ("two flags", two_flags, 7, 3),
            ("two dates", two_dates, 7, 3),
            ("two uids", two_uids, 7, 3),
            ("two bodies", two_bodies, 7, 3),
            ("bad date", bad_date, 7, 3),
            ("duplicate response", duplicate.clone(), 7, 3),
            ("duplicate with size mismatch", duplicate, 7, 4),
        ];
        for (name, response, uid, expected) in &cases {
            let want = buffered_outcome(response.as_bytes(), *uid, *expected);
            for max_read in [1, 3, 64, 1 << 20] {
                assert_eq!(
                    streaming_outcome(response.as_bytes(), *uid, *expected, max_read),
                    want,
                    "{name} (max_read {max_read})"
                );
            }
        }
        // Sanity that the table is not vacuous: both outcomes occur.
        assert!(matches!(
            buffered_outcome(ok.as_bytes(), 7, 3),
            Outcome::Found { .. }
        ));
        assert_eq!(buffered_outcome(ok.as_bytes(), 7, 4), Outcome::Permanent);
        assert_eq!(buffered_outcome(ok.as_bytes(), 8, 3), Outcome::Absent);
        assert_eq!(buffered_outcome(b"junk\r\n", 7, 3), Outcome::Failed);
    }

    #[test]
    fn streaming_is_deliberately_stricter_when_a_body_may_belong_to_another_uid() {
        let ours = String::from_utf8(fetch(b"abc", false)).unwrap();
        // The buffered path ignores another message's body and finds ours.
        // Streaming can hash only the FIRST body on the wire, so it must never return a digest here.
        for (name, other_len, want) in [
            // Different length: the announced length cannot match, a permanent refusal.
            ("foreign body of another length", 2usize, Outcome::Permanent),
            // Same length: it WOULD be hashed, so attribution must be refused outright.
            ("foreign body of the same length", 3, Outcome::Failed),
        ] {
            let foreign = format!(
                "* 2 FETCH (UID 9 FLAGS () {D} BODY[] {{{other_len}}}\r\n{})\r\n",
                "z".repeat(other_len)
            );
            let response = format!("{foreign}{ours}");
            assert!(
                matches!(
                    buffered_outcome(response.as_bytes(), 7, 3),
                    Outcome::Found { .. }
                ),
                "{name}"
            );
            for max_read in [1, 64, 1 << 20] {
                assert_eq!(
                    streaming_outcome(response.as_bytes(), 7, 3, max_read),
                    want,
                    "{name} ({max_read})"
                );
            }
        }
        // If the requested UID has no body, a foreign body is simply "not found", as when buffered.
        let only_foreign = format!("* 2 FETCH (UID 9 FLAGS () {D} BODY[] {{3}}\r\nzzz)\r\n");
        assert_eq!(
            buffered_outcome(only_foreign.as_bytes(), 7, 3),
            Outcome::Absent
        );
        assert_eq!(
            streaming_outcome(only_foreign.as_bytes(), 7, 3, 5),
            Outcome::Absent
        );
        // A body-less unrelated FETCH (flag updates) is harmless in both.
        let noise = format!("* 3 FETCH (UID 11 FLAGS (\\Seen))\r\n{ours}");
        assert_eq!(
            streaming_outcome(noise.as_bytes(), 7, 3, 5),
            buffered_outcome(noise.as_bytes(), 7, 3)
        );
    }

    #[test]
    fn streaming_digest_matches_the_journal_fingerprint_for_all_sizes_and_fragmentations() {
        for (i, len) in [
            0usize,
            1,
            2,
            4095,
            4096,
            4097,
            128 * 1024 - 1,
            128 * 1024,
            128 * 1024 + 1,
            300_000,
        ]
        .into_iter()
        .enumerate()
        {
            let body = pseudo(i as u64 + 1, len);
            for body_first in [false, true] {
                let response = fetch(&body, body_first);
                let want = buffered_outcome(&response, 7, len);
                assert!(
                    matches!(&want, Outcome::Found { sha256, .. } if *sha256 == crate::journal::fingerprint(&body))
                );
                for max_read in [1, 7, 1024, 1 << 20] {
                    if len > 5000 && max_read < 100 {
                        continue; // the byte-at-a-time cases are covered by the small sizes
                    }
                    assert_eq!(
                        streaming_outcome(&response, 7, len, max_read),
                        want,
                        "len {len} first {body_first} read {max_read}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_large_message_that_differs_only_in_its_final_byte_has_a_different_digest() {
        let mut body = pseudo(42, 400_000);
        let original = streaming_outcome(&fetch(&body, false), 7, body.len(), 4096);
        *body.last_mut().unwrap() ^= 0x01;
        let altered = streaming_outcome(&fetch(&body, false), 7, body.len(), 4096);
        let (
            Outcome::Found {
                sha256: a,
                size: sa,
                ..
            },
            Outcome::Found {
                sha256: b,
                size: sb,
                ..
            },
        ) = (&original, &altered)
        else {
            panic!("both must be found: {original:?} {altered:?}");
        };
        assert_eq!(sa, sb);
        assert_ne!(a, b, "a single flipped final byte must change the digest");
        // And it still equals the buffered answer for that altered message.
        assert_eq!(
            altered,
            buffered_outcome(&fetch(&body, false), 7, body.len())
        );
    }

    #[test]
    fn a_truncated_or_failed_streaming_read_never_yields_a_digest() {
        let body = pseudo(5, 50_000);
        let mut script = b"* OK hello\r\na1 OK logged in\r\n".to_vec();
        let header = script.len();
        script.extend_from_slice(&fetch(&body, false));
        script.extend_from_slice(b"a2 OK UID FETCH completed\r\n");
        // Cut the stream at many points: inside the header, mid-literal, before and inside the tagged OK.
        let mut cuts: Vec<usize> = (0..60)
            .map(|i| header + i * (script.len() - header) / 60)
            .collect();
        cuts.extend([script.len() - 1, script.len() - 10, script.len() - 28]);
        for cut in cuts {
            for max_read in [1usize, 97, 1 << 20] {
                let o = streaming_outcome_raw(script[..cut].to_vec(), 7, body.len(), max_read);
                assert_eq!(
                    o,
                    Outcome::Failed,
                    "cut at {cut} of {} (max_read {max_read})",
                    script.len()
                );
            }
        }
        // The complete script is accepted, so the loop above really exercises truncation.
        assert!(matches!(
            streaming_outcome_raw(script.clone(), 7, body.len(), 1 << 20),
            Outcome::Found { .. }
        ));
        // A tagged NO instead of OK after the literal is a failure, never a digest.
        let mut no = b"* OK hello\r\na1 OK logged in\r\n".to_vec();
        no.extend_from_slice(&fetch(&body, false));
        no.extend_from_slice(b"a2 NO [SERVERBUG] read failed\r\n");
        assert_eq!(
            streaming_outcome_raw(no, 7, body.len(), 4096),
            Outcome::Failed
        );
    }

    #[test]
    fn stream_errors_are_classified_explicitly_and_carry_no_server_data() {
        // Announced length differs from RFC822.SIZE: the same permanent condition as the buffered path.
        let body = vec![b'x'; 100];
        let mismatch = streaming_outcome(&fetch(&body, false), 7, 99, 64);
        assert_eq!(mismatch, buffered_outcome(&fetch(&body, false), 7, 99));
        assert_eq!(mismatch, Outcome::Permanent);
        // Every other stream failure is a non-permanent, non-transient failure with a fixed name.
        use imap::error::StreamError as E;
        for (error, name) in [
            (E::MalformedLiteralMarker, "MALFORMED_LITERAL_MARKER"),
            (E::LineTooLong, "LINE_TOO_LONG"),
            (E::ResponseTooLarge, "RESPONSE_TOO_LARGE"),
            (E::MalformedResponse, "MALFORMED_RESPONSE"),
        ] {
            let e = Err::<(), _>(imap::Error::Stream(error)).safe().unwrap_err();
            let p = e.downcast_ref::<ProtocolError>().unwrap();
            assert!(!p.transient && !p.permanent_message, "{name}");
            assert_eq!(
                p.wire.as_ref().map(|w| (w.outcome, w.code)),
                Some(("STREAM", name))
            );
            assert!(!format!("{e:#}").contains("PRIVATE"));
        }
        let e = Err::<(), _>(imap::Error::Stream(E::LiteralLengthMismatch))
            .safe()
            .unwrap_err();
        assert!(is_permanent_message(&e));
        // A stream failure produced by a real malformed response (bare-LF literal marker).
        let bad = b"* 1 FETCH (UID 7 FLAGS () INTERNALDATE \"02-Jan-2020 03:04:05 +0000\" BODY[] {3}\nabc)\r\n";
        assert_eq!(streaming_outcome(bad, 7, 3, 64), Outcome::Failed);
    }

    // ------------------------------------------------------------ spool transfer (4.2)
    type Log = std::rc::Rc<std::cell::RefCell<Vec<u8>>>;
    fn private_spool_dir() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }
    fn session_over(script: Vec<u8>, max_read: usize) -> (imap::Session<Replay>, Log) {
        let wire = Replay {
            incoming: script,
            pos: 0,
            max_read,
            step: 7,
            written: Default::default(),
        };
        let log = wire.written.clone();
        let mut client = imap::Client::new(wire);
        client.read_greeting().unwrap();
        (client.login("u", "p").map_err(|e| e.0).unwrap(), log)
    }
    fn fetch_script(response: &[u8]) -> Vec<u8> {
        let mut script = b"* OK hello\r\na1 OK logged in\r\n".to_vec();
        script.extend_from_slice(response);
        script.extend_from_slice(b"a2 OK UID FETCH completed\r\n");
        script
    }
    fn read_all(spooled: &mut SpooledMessage) -> Vec<u8> {
        let mut out = Vec::new();
        let mut reader = spooled.spool.reader("").unwrap();
        let mut buf = vec![0u8; 7001];
        loop {
            let n = reader.read(&mut buf).unwrap();
            if n == 0 {
                return out;
            }
            out.extend_from_slice(&buf[..n]);
        }
    }
    fn spool_of(bytes: &[u8], dir: &std::path::Path) -> SpooledMessage {
        let mut spool = crate::spool::Spool::create(dir, bytes.len() as u64, true).unwrap();
        spool.write_chunk(bytes).unwrap();
        SpooledMessage {
            spool: spool.seal().unwrap(),
            date: DateTime::parse_from_str("02-Jan-2020 03:04:05 +0000", "%d-%b-%Y %H:%M:%S %z")
                .unwrap(),
            flags: vec!["\\Seen".into()],
        }
    }

    #[test]
    fn a_spooled_source_read_is_exact_and_matches_the_buffered_decode() {
        let dir = private_spool_dir();
        for (i, len) in [0usize, 1, 4095, 128 * 1024, 128 * 1024 + 1, 300_000]
            .into_iter()
            .enumerate()
        {
            let body = pseudo(i as u64 + 11, len);
            for body_first in [false, true] {
                let response = fetch(&body, body_first);
                let want = decode_message(&response, 7, len).unwrap().unwrap();
                for max_read in [3, 1000, 1 << 20] {
                    let (mut session, _) = session_over(fetch_script(&response), max_read);
                    let target = crate::spool::Spool::create(dir.path(), len as u64, true).unwrap();
                    let mut got = spool_message_into(&mut session, 7, len, target, &|| false)
                        .unwrap()
                        .unwrap();
                    assert_eq!(
                        got.sha256(),
                        crate::journal::fingerprint(&body),
                        "len {len}"
                    );
                    assert_eq!(
                        (got.size(), got.date, &got.flags),
                        (len as u64, want.date, &want.flags)
                    );
                    assert_eq!(
                        read_all(&mut got),
                        body,
                        "len {len} first {body_first} read {max_read}"
                    );
                }
            }
        }
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            0,
            "the spool is anonymous"
        );
    }

    #[test]
    fn a_missing_message_and_a_quoted_body_spool_correctly() {
        let dir = private_spool_dir();
        let none = format!("* 1 FETCH (UID 9 FLAGS () {D} BODY[] NIL)\r\n");
        let (mut session, _) = session_over(fetch_script(none.as_bytes()), 64);
        let target = crate::spool::Spool::create(dir.path(), 3, true).unwrap();
        assert!(
            spool_message_into(&mut session, 7, 3, target, &|| false)
                .unwrap()
                .is_none()
        );
        let quoted = format!("* 1 FETCH (UID 7 FLAGS () {D} BODY[] \"abc\")\r\n");
        let (mut session, _) = session_over(fetch_script(quoted.as_bytes()), 64);
        let target = crate::spool::Spool::create(dir.path(), 3, true).unwrap();
        let mut got = spool_message_into(&mut session, 7, 3, target, &|| false)
            .unwrap()
            .unwrap();
        assert_eq!(read_all(&mut got), b"abc");
        assert_eq!(got.sha256(), crate::journal::fingerprint(b"abc"));
    }

    #[test]
    fn a_truncated_source_stream_never_yields_a_spooled_message() {
        let dir = private_spool_dir();
        let body = pseudo(3, 60_000);
        let script = fetch_script(&fetch(&body, false));
        let header = b"* OK hello\r\na1 OK logged in\r\n".len();
        let mut cuts: Vec<usize> = (0..50)
            .map(|i| header + i * (script.len() - header) / 50)
            .collect();
        cuts.extend([script.len() - 1, script.len() - 10, script.len() - 28]);
        for cut in cuts {
            for max_read in [1usize, 97, 1 << 20] {
                let (mut session, _) = session_over(script[..cut].to_vec(), max_read);
                let target =
                    crate::spool::Spool::create(dir.path(), body.len() as u64, true).unwrap();
                let err = spool_message_into(&mut session, 7, body.len(), target, &|| false)
                    .err()
                    .unwrap_or_else(|| panic!("cut {cut} must fail"));
                assert!(
                    err.downcast_ref::<crate::spool::SpoolError>().is_none(),
                    "a network failure is not a spool failure"
                );
            }
        }
        let (mut session, _) = session_over(script, 4096);
        let target = crate::spool::Spool::create(dir.path(), body.len() as u64, true).unwrap();
        assert!(
            spool_message_into(&mut session, 7, body.len(), target, &|| false)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn a_full_disk_is_a_typed_non_transient_failure_not_a_network_error() {
        let dir = private_spool_dir();
        let body = pseudo(8, 300_000);
        let (mut session, _) = session_over(fetch_script(&fetch(&body, false)), 4096);
        let mut target = crate::spool::Spool::create(dir.path(), body.len() as u64, true).unwrap();
        target.fail_after = Some(100_000);
        let err = spool_message_into(&mut session, 7, body.len(), target, &|| false)
            .err()
            .unwrap();
        assert!(matches!(
            err.downcast_ref::<crate::spool::SpoolError>(),
            Some(crate::spool::SpoolError::NoSpace)
        ));
        assert!(
            !is_transient(&err),
            "a full disk must not be retried as a connection problem"
        );
        assert!(
            !is_permanent_message(&err),
            "and it is not a property of the message"
        );
        assert!(
            session.is_desynced(),
            "the interrupted response poisons the connection"
        );
        assert!(
            !format!("{err:#}").contains(dir.path().to_str().unwrap()),
            "no path in the error"
        );
    }

    #[test]
    fn a_stop_request_abandons_the_source_download_with_nothing_kept() {
        let dir = private_spool_dir();
        let body = pseudo(4, 600_000);
        let (mut session, _) = session_over(fetch_script(&fetch(&body, false)), 4096);
        let target = crate::spool::Spool::create(dir.path(), body.len() as u64, true).unwrap();
        // The request arrives after a few chunks have already been spooled.
        let checks = std::cell::Cell::new(0);
        let err = spool_message_into(&mut session, 7, body.len(), target, &|| {
            checks.set(checks.get() + 1);
            checks.get() > 3
        })
        .err()
        .expect("a stop request must abandon the download");
        assert!(err.is::<StopRequested>(), "{err:#}");
        assert!(
            !is_transient(&err) && !is_permanent_message(&err),
            "neither a retry nor a message verdict"
        );
        assert!(err.downcast_ref::<crate::spool::SpoolError>().is_none());
        assert!(
            session.is_desynced(),
            "the unread rest of the response poisons the connection"
        );
        assert!(
            checks.get() <= 4,
            "it must stop at the next chunk, not read on"
        );
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            0,
            "the spool is anonymous and gone with it"
        );
        // Without a request the same download completes.
        let (mut session, _) = session_over(fetch_script(&fetch(&body, false)), 4096);
        let target = crate::spool::Spool::create(dir.path(), body.len() as u64, true).unwrap();
        assert!(
            spool_message_into(&mut session, 7, body.len(), target, &|| false)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn a_wrong_announced_length_is_refused_before_anything_is_spooled() {
        let dir = private_spool_dir();
        let body = vec![b'x'; 100];
        let (mut session, _) = session_over(fetch_script(&fetch(&body, false)), 64);
        let target = crate::spool::Spool::create(dir.path(), 99, true).unwrap();
        let err = spool_message_into(&mut session, 7, 99, target, &|| false)
            .err()
            .unwrap();
        assert!(is_permanent_message(&err));
    }

    #[test]
    fn a_cut_off_response_with_a_wrong_announced_length_is_transient_on_both_paths() {
        // A server that dies mid-FETCH after announcing a length that does not match RFC822.SIZE:
        // read whole, the truncation is noticed first (a connection loss, retried); the streaming
        // path must classify it the same way, not as a permanent size mismatch.
        let cut = format!("* 1 FETCH (UID 7 FLAGS () {D} BODY[] {{999}}\r\npartial").into_bytes();
        let mut script = b"* OK hello\r\na1 OK logged in\r\n".to_vec();
        script.extend_from_slice(&cut);
        let (mut buffered, _) = session_over(script.clone(), 64);
        let buffered_error = buffered
            .run("UID FETCH 7 (UID FLAGS INTERNALDATE BODY.PEEK[])")
            .safe()
            .expect_err("a cut-off response cannot succeed");
        let (mut streaming, _) = session_over(script, 64);
        let streaming_error = stream_digest(&mut streaming, 7, 10, "").err().unwrap();
        assert!(is_transient(&buffered_error) && is_transient(&streaming_error));
        assert!(!is_permanent_message(&buffered_error) && !is_permanent_message(&streaming_error));
        // Once the whole response arrives, the mismatch is permanent on both paths.
        let mut whole = cut.clone();
        whole.extend(std::iter::repeat_n(b'x', 999 - b"partial".len()));
        whole.extend_from_slice(b")\r\n");
        assert_eq!(streaming_outcome(&whole, 7, 10, 64), Outcome::Permanent);
        assert_eq!(buffered_outcome(&whole, 7, 10), Outcome::Permanent);
    }

    fn append_script(response: &str) -> Vec<u8> {
        let mut script = b"* OK hello\r\na1 OK logged in\r\n".to_vec();
        script.extend_from_slice(response.as_bytes());
        script
    }
    fn command_line(len: usize) -> Vec<u8> {
        format!("a2 APPEND \"INBOX\" (\\Seen) \"02-Jan-2020 03:04:05 +0000\" {{{len}}}\r\n")
            .into_bytes()
    }
    const FLAGS: [&str; 1] = ["\\Seen"];

    #[test]
    fn a_spooled_append_authorizes_before_any_body_byte_and_sends_the_exact_literal() {
        let dir = private_spool_dir();
        let body = pseudo(5, 400_000);
        let mut spooled = spool_of(&body, dir.path());
        let (mut session, log) = session_over(
            append_script("+ ready\r\na2 OK [APPENDUID 5 9] done\r\n"),
            7,
        );
        let base = log.borrow().len(); // the LOGIN exchange precedes the APPEND
        let at_guard = std::cell::Cell::new(None);
        let probe = log.clone();
        let flags: Vec<String> = FLAGS.iter().map(ToString::to_string).collect();
        let out = append_from_spool(&mut session, "INBOX", &flags, &mut spooled, || {
            at_guard.set(Some(probe.borrow().len()));
            Ok(())
        });
        assert_eq!(out.result.unwrap(), (5, 9));
        assert_eq!(
            (out.phase, out.body_bytes_sent),
            (imap::AppendPhase::Responded, body.len() as u64)
        );
        let cmd = command_line(body.len());
        assert_eq!(
            at_guard.get(),
            Some(base + cmd.len()),
            "only the command line may precede authorization"
        );
        let mut want = cmd;
        want.extend_from_slice(&body);
        want.extend_from_slice(b"\r\n");
        assert_eq!(log.borrow()[base..], want[..]);
    }

    #[test]
    fn a_failing_guard_sends_no_spooled_byte() {
        let dir = private_spool_dir();
        let mut spooled = spool_of(b"PRIVATE_SPOOLED_BODY", dir.path());
        let (mut session, log) = session_over(append_script("+ ready\r\n"), 64);
        let flags: Vec<String> = FLAGS.iter().map(ToString::to_string).collect();
        let out = append_from_spool(&mut session, "INBOX", &flags, &mut spooled, || {
            Err(io::Error::other("journal failure"))
        });
        assert!(out.result.is_err());
        assert_eq!(
            (out.phase, out.body_bytes_sent),
            (imap::AppendPhase::NotAuthorized, 0)
        );
        assert!(
            !log.borrow()
                .windows(20)
                .any(|w| w == b"PRIVATE_SPOOLED_BODY")
        );
        assert!(session.is_desynced());
    }

    #[test]
    fn a_spool_that_changed_after_sealing_cannot_complete_a_literal() {
        let dir = private_spool_dir();
        let body = pseudo(9, 500_000);
        let mut spooled = spool_of(&body, dir.path());
        {
            use std::io::Seek;
            let f = spooled.spool.file_for_test();
            f.seek(io::SeekFrom::Start(body.len() as u64 - 1)).unwrap();
            f.write_all(&[body[body.len() - 1] ^ 1]).unwrap();
        }
        let (mut session, log) = session_over(
            append_script("+ ready\r\na2 OK [APPENDUID 5 9] done\r\n"),
            64,
        );
        let base = log.borrow().len();
        let flags: Vec<String> = FLAGS.iter().map(ToString::to_string).collect();
        let out = append_from_spool(&mut session, "INBOX", &flags, &mut spooled, || Ok(()));
        assert!(out.result.is_err());
        assert_eq!(
            out.phase,
            imap::AppendPhase::BodyStarted,
            "bytes were sent, so the outcome is uncertain"
        );
        let sent = log.borrow().len() - base - command_line(body.len()).len();
        assert!(
            sent < body.len(),
            "the final chunk must be withheld ({sent} of {})",
            body.len()
        );
        assert!(
            !log.borrow().ends_with(b"\r\n") || sent < body.len(),
            "never terminated"
        );
        assert!(session.is_desynced());
    }

    #[test]
    fn spooled_append_rejections_keep_their_codes_for_the_existing_classification() {
        let dir = private_spool_dir();
        let flags: Vec<String> = FLAGS.iter().map(ToString::to_string).collect();
        // Rejected after the literal (size-dependent) and before it (mailbox): same errors as the buffered path.
        for (script, scope, phase) in [
            (
                "+ ready\r\na2 NO [TOOBIG] too big\r\n",
                "message",
                imap::AppendPhase::Responded,
            ),
            (
                "a2 NO [NONEXISTENT] no such mailbox\r\n",
                "mailbox",
                imap::AppendPhase::NotAuthorized,
            ),
        ] {
            let mut spooled = spool_of(b"hello world", dir.path());
            let (mut session, _) = session_over(append_script(script), 64);
            let out = append_from_spool(&mut session, "INBOX", &flags, &mut spooled, || Ok(()));
            let error = out.result.err().unwrap();
            assert_eq!(
                append_rejection(&error).map(|r| r.scope().name()),
                Some(scope),
                "{script}"
            );
            assert_eq!(out.phase, phase);
            assert!(
                !session.is_desynced(),
                "a consumed tagged rejection keeps the connection usable"
            );
        }
    }

    #[test]
    fn xoauth_error_challenge_never_repeats_token() {
        use imap::Authenticator;
        let a = Xoauth2 {
            user: "user",
            token: "secret",
            sent: Cell::new(false),
        };
        assert_eq!(a.process(b""), b"user=user\x01auth=Bearer secret\x01\x01");
        assert!(a.process(b"{error}").is_empty());
        assert!(a.process(b"").is_empty());
    }
    #[test]
    fn untyped_rejection_codes_are_classified_by_scope_not_retry_lists() {
        use RejectionScope::*;
        for (text, code, scope) in [
            ("[NOPERM] PRIVATE", "NOPERM", Mailbox),
            ("[nonexistent] x", "NONEXISTENT", Mailbox),
            ("[AUTHENTICATIONFAILED]", "AUTHENTICATIONFAILED", Account),
            ("[EXPIRED] x", "EXPIRED", Account),
            ("[CONTENTREJECTED] spam", "CONTENTREJECTED", Message),
            ("[CANNOT] x", "CANNOT", Ambiguous),
            ("[SERVERBUG] x", "SERVERBUG", Ambiguous),
            ("[X-PROVIDER-QUIRK] x", "UNSPECIFIED", Ambiguous),
            ("APPEND failed", "UNSPECIFIED", Ambiguous),
        ] {
            let rejection = AppendRejection {
                code: rejection_code(None, text),
                status: "NO",
            };
            assert_eq!((rejection.code, rejection.scope()), (code, scope), "{text}");
        }
    }
    #[test]
    fn diagnostics_only_ever_name_validated_atoms_or_fixed_names() {
        use imap_proto::ResponseCode as C;
        // A vendor code is reported as a bounded atom, upper-cased, never with its text.
        assert_eq!(
            unlisted_atom(None, "[x-vendor-odd] PRIVATE secret sentence").as_deref(),
            Some("X-VENDOR-ODD")
        );
        // Named codes are not "unlisted"; hostile or oversized atoms yield nothing.
        assert_eq!(unlisted_atom(None, "[NOPERM] x"), None);
        for hostile in [
            "[a/b] x",
            "plain text",
            "[]",
            &format!("[{}]", "A".repeat(33)),
        ] {
            assert_eq!(unlisted_atom(None, hostile), None, "{hostile:?}");
        }
        // Typed codes IMAPLANE has no journal name for map to fixed protocol names.
        assert_eq!(
            unlisted_atom(Some(&C::Alert), "PRIVATE").as_deref(),
            Some("ALERT")
        );
        assert_eq!(
            unlisted_atom(Some(&C::ReadOnly), "").as_deref(),
            Some("READ-ONLY")
        );
        assert_eq!(unlisted_atom(Some(&C::TooBig), ""), None);
        // The journal-facing code stays on the allowlist regardless.
        assert_eq!(rejection_code(Some(&C::Alert), "PRIVATE"), "UNSPECIFIED");
        assert_eq!(
            rejection_code(None, "[x-vendor-odd] PRIVATE"),
            "UNSPECIFIED"
        );
    }
    #[test]
    fn code_extraction_is_strict_and_bounded() {
        for hostile in [
            "[",
            "[]",
            "[ NOPERM]",
            "NOPERM]",
            " [NOPERM]",
            "[NOPERM\r\nX] x",
            "[NOP\u{0}ERM]",
            "[NOPERMNOPERMNOPERMNOPERMNOPERMNOPERMNOPERM]",
            "[NOPERM-] x",
        ] {
            assert_eq!(code_from_text(hostile), "UNSPECIFIED", "{hostile:?}");
        }
        assert_eq!(code_from_text("[NoPerm]"), "NOPERM");
        assert_eq!(code_from_text("[UNKNOWN-CTE] x"), "UNKNOWN-CTE");
    }
    #[test]
    fn typed_codes_keep_existing_scopes_and_bad_is_never_trusted() {
        use RejectionScope::*;
        let scope = |code, status| AppendRejection { code, status }.scope();
        for (code, expected) in [
            ("UNAVAILABLE", Transient),
            ("THROTTLED", Transient),
            ("INUSE", Transient),
            ("LIMIT", Transient),
            ("TOOBIG", Message),
            ("OVERQUOTA", SizeDependent),
            ("TRYCREATE", Mailbox),
        ] {
            assert_eq!(scope(code, "NO"), expected, "{code}");
            // A BAD cannot be a benign per-message or transient condition.
            assert_eq!(scope(code, "BAD"), Ambiguous, "BAD {code}");
        }
    }
    #[test]
    fn protocol_diagnostics_discard_untrusted_payload() {
        let err = Err::<(), _>(imap::Error::Parse(imap::error::ParseError::Invalid(
            b"PRIVATE-MAIL-TOKEN".to_vec(),
        )))
        .safe()
        .unwrap_err();
        assert!(!format!("{err:#}").contains("PRIVATE"));
    }
    #[test]
    fn unstable_uids_and_write_access_on_examine_fail_without_panicking() {
        let unstable =
            b"* NO [UIDNOTSTICKY] unstable\r\n* OK [UIDVALIDITY 1] v\r\na1 OK [READ-ONLY] done\r\n";
        assert!(decode_selected(unstable, false).is_err());
        let writable = b"* 0 EXISTS\r\n* OK [UIDVALIDITY 1] v\r\na1 OK [READ-WRITE] done\r\n";
        assert!(decode_selected(writable, false).is_err());
        assert!(
            decode_selected(writable, true)
                .unwrap()
                .flags
                .contains(&"\\*".into())
        );
    }
    #[test]
    fn rev2_only_capability_response_is_accepted() {
        let (_, r) =
            Response::from_bytes(b"* CAPABILITY IMAP4rev2 UIDPLUS AUTH=PLAIN\r\n").unwrap();
        let Response::Capabilities(caps) = r else {
            panic!("not a capability response");
        };
        assert!(
            caps.iter()
                .any(|c| matches!(c,Capability::Atom(s) if s.eq_ignore_ascii_case("IMAP4rev2")))
        );
        assert!(Response::from_bytes(b"* CAPABILITY UIDPLUS AUTH=PLAIN\r\n").is_err());
    }
    #[test]
    fn quoted_and_literal_list_names_do_not_confuse_escapes() {
        let quoted = br#"* LIST () "/" "a\"b\\c"
"#;
        let quoted = String::from_utf8(quoted.to_vec())
            .unwrap()
            .replace('\n', "\r\n");
        let names = decode_list(quoted.as_bytes(), FolderEncoding::ModifiedUtf7).unwrap();
        assert_eq!(names[0].name, "a\"b\\c");
        let literal = b"* LIST () \"/\" {5}\r\na\\b\"c\r\n";
        let names = decode_list(literal, FolderEncoding::ModifiedUtf7).unwrap();
        assert_eq!(names[0].name, "a\\b\"c");
    }
}
