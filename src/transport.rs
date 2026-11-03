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
/// Evidence is obtainable only from a parsed, matching tagged NO/BAD response.
#[derive(Clone, Debug)]
pub(crate) struct AppendRejection {
    pub code: &'static str,
    pub status: &'static str,
}
pub(crate) fn append_rejection(error: &anyhow::Error) -> Option<AppendRejection> {
    error
        .downcast_ref::<ProtocolError>()
        .and_then(|e| e.rejection.clone())
}
fn rejection_code(code: Option<&imap_proto::ResponseCode<'_>>) -> &'static str {
    use imap_proto::ResponseCode::*;
    match code {
        Some(Unavailable) => "UNAVAILABLE",
        Some(Throttled) => "THROTTLED",
        Some(InUse) => "INUSE",
        Some(Limit) => "LIMIT",
        Some(OverQuota) => "OVERQUOTA",
        Some(TooBig) => "TOOBIG",
        _ => "UNSPECIFIED",
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
            let permanent_message = matches!(&e, imap::Error::No(no) if matches!(no.code, Some(imap_proto::ResponseCode::TooBig)));
            let rejection = match &e {
                imap::Error::No(no) => Some(AppendRejection {
                    code: rejection_code(no.code.as_ref()),
                    status: "NO",
                }),
                imap::Error::Bad(bad) => Some(AppendRejection {
                    code: rejection_code(bad.code.as_ref()),
                    status: "BAD",
                }),
                _ => None,
            };
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
    fn message(&mut self, uid: u32) -> Result<Option<Message>> {
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
        drop(size);
        self.reset(expected.saturating_add(OVERHEAD));
        let (data, _) = self
            .session
            .run(format!(
                "UID FETCH {uid} (UID FLAGS INTERNALDATE BODY.PEEK[])"
            ))
            .safe()?;
        decode_message(&data, uid, expected)
    }
}

pub struct Source(Connection);
impl Source {
    pub fn connect(e: &Endpoint, password: &str, timeout: Duration, limit: usize) -> Result<Self> {
        Ok(Self(Connection::connect(e, password, timeout, limit)?))
    }
    pub fn folders(&mut self) -> Result<Vec<Folder>> {
        self.0.list()
    }
    pub fn examine(&mut self, folder: &str) -> Result<Selected> {
        self.0.select_folder(folder, false)
    }
    pub fn uids(&mut self) -> Result<Vec<u32>> {
        self.0.uids()
    }
    pub fn snapshot_uids(&mut self, next: u32) -> Result<Vec<u32>> {
        if next <= 1 {
            return Ok(Vec::new());
        }
        let uids = self.0.uids_range(&format!("1:{}", next - 1))?;
        if uids.iter().any(|u| *u >= next) {
            bail!("server returned UID outside snapshot horizon");
        }
        Ok(uids)
    }
    pub fn message(&mut self, uid: u32) -> Result<Option<Message>> {
        self.0.message(uid)
    }
}

pub struct Destination(Connection);
impl Destination {
    pub fn connect(e: &Endpoint, password: &str, timeout: Duration, limit: usize) -> Result<Self> {
        let c = Connection::connect(e, password, timeout, limit)?;
        // Without this, a routine successful upload may have no durable identity.
        if !c.caps.contains("UIDPLUS") && !c.caps.contains("IMAP4REV2") {
            bail!("destination must support UIDPLUS or IMAP4rev2 for APPENDUID tracking");
        }
        Ok(Self(c))
    }
    pub fn folders(&mut self) -> Result<Vec<Folder>> {
        self.0.list()
    }
    pub fn examine(&mut self, folder: &str) -> Result<Selected> {
        self.0.select_folder(folder, false)
    }
    pub fn uids(&mut self) -> Result<Vec<u32>> {
        self.0.uids()
    }
    pub fn message(&mut self, uid: u32) -> Result<Option<Message>> {
        self.0.message(uid)
    }
    pub fn select(&mut self, folder: &str) -> Result<Selected> {
        self.0.select_folder(folder, true)
    }
    pub fn create(&mut self, folder: &str) -> Result<()> {
        let name = self.0.encoding.encode(folder)?;
        self.0.reset(OVERHEAD);
        self.0
            .session
            .create(name)
            .safe()
            .context("create destination folder")
    }
    pub fn append(
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
}
pub fn valid_flag(flag: &str) -> bool {
    let atom = flag.strip_prefix('\\').unwrap_or(flag);
    !atom.is_empty()
        && atom
            .bytes()
            .all(|b| (0x21..=0x7e).contains(&b) && !b"(){%*\"\\]".contains(&b))
}

fn decode_message(response: &[u8], uid: u32, expected: usize) -> Result<Option<Message>> {
    use imap_proto::AttributeValue as A;
    let mut rest = response;
    let mut message = None;
    while !rest.is_empty() {
        let (next, r) = Response::from_bytes(rest)
            .map_err(|_| anyhow::anyhow!("invalid message FETCH response"))?;
        if let Response::Fetch(_, attributes) = r {
            let ids: Vec<_> = attributes
                .iter()
                .filter_map(|a| if let A::Uid(u) = a { Some(*u) } else { None })
                .collect();
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
                    if bodies[0].len() != expected {
                        return Err(
                            PermanentMessageError("message size differs from RFC822.SIZE").into(),
                        );
                    }
                    let date = DateTime::parse_from_str(dates[0], "%d-%b-%Y %H:%M:%S %z")
                        .context("invalid INTERNALDATE")?;
                    message = Some(Message {
                        body: bodies[0].to_vec(),
                        date,
                        flags: flags[0].iter().map(ToString::to_string).collect(),
                    });
                }
            }
        }
        rest = next;
    }
    Ok(message)
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
