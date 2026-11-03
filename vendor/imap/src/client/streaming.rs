//! IMAPLANE patch: bounded-memory streaming of one FETCH literal and one APPEND literal.
//!
//! Neither operation ever holds the message in a `Vec`. Memory is a fixed copy buffer
//! (`STREAM_CHUNK`) plus a "skeleton" of everything that is not the streamed literal
//! (capped at `MAX_SKELETON`). Existing APIs are untouched; this module only adds.
//!
//! Failure model. After any error that is not a fully consumed tagged NO/BAD/BYE the
//! protocol stream is at an unknown position, so the connection is marked desynced and
//! every later command is refused; the caller must drop it.
use super::*;
use crate::error::StreamError;
use std::cmp::min;
use std::io::{self, BufRead};

/// Size of the one reusable copy buffer used for literals.
pub const STREAM_CHUNK: usize = 128 * 1024;
/// Bound for every non-literal response line.
const MAX_LINE: usize = 64 * 1024;
/// Bound for everything in a streamed FETCH response except the streamed literal.
const MAX_SKELETON: usize = 1024 * 1024;

/// Result of [`Session::uid_fetch_body_stream`].
#[derive(Debug)]
pub struct StreamedFetch {
    /// The response with the body literal replaced by an empty one (`{0}`), and without the
    /// tagged completion. It can be given to the usual response parser to obtain UID,
    /// FLAGS and INTERNALDATE; it never contains any of the streamed bytes.
    pub skeleton: Vec<u8>,
    /// Length of the streamed body, or `None` if the response held no `BODY[]` literal
    /// (for example, the message no longer exists).
    pub body_len: Option<u64>,
}

/// How far a streaming APPEND got. Ordered: each phase implies the earlier ones.
///
/// `NotAuthorized` and `Authorized` prove that no message-body byte was handed to the
/// connection, so the server cannot have appended anything. From `BodyStarted` on, bytes
/// may have reached the server and only a tagged response settles the outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AppendPhase {
    /// The authorization guard has not succeeded: the command was not sent, was refused
    /// before the continuation, or the guard failed. No body byte was sent.
    NotAuthorized,
    /// The guard succeeded; no body byte has been handed to the connection yet.
    Authorized,
    /// The first body write was attempted (set BEFORE the write, because a failed write
    /// may still have delivered bytes). The outcome is uncertain until a tagged response.
    BodyStarted,
    /// The whole literal and its terminator were written and flushed.
    BodyComplete,
    /// A tagged OK, NO or BAD completion for this command was received.
    Responded,
}

/// Outcome of [`StreamAppendCmd::finish_streaming`]. The phase is reported even on failure.
#[derive(Debug)]
pub struct StreamedAppend {
    /// The furthest phase reached.
    pub phase: AppendPhase,
    /// Informational only: body bytes whose `write_all` into the client's buffered stream
    /// completed. It is **not** a bound on what the server received, because bytes may still
    /// sit in the client's write buffer and a failed write may have delivered part of a
    /// chunk. Decide safety from `phase`, never from this count. It never exceeds the
    /// declared length and equals it after a successful APPEND.
    pub body_bytes_sent: u64,
    /// The usual APPEND result: `Ok` on tagged OK, `Err(No/Bad)` on a tagged rejection.
    pub result: Result<Appended>,
}

impl StreamedAppend {
    /// True if any body byte may have reached the server.
    pub fn body_possibly_sent(&self) -> bool {
        self.phase >= AppendPhase::BodyStarted
    }
}

/// Whether an error means a tagged completion was fully consumed (stream still in sync).
fn completion_consumed(e: &Error) -> bool {
    matches!(e, Error::No(_) | Error::Bad(_))
}

/// `{digits}` at the very end of a CRLF-terminated line: (index of `{`, length).
/// `Ok(None)` if the line has no literal marker. A marker with a bare LF is refused.
fn literal_marker(line: &[u8]) -> std::result::Result<Option<(usize, u64)>, StreamError> {
    let (body, crlf) = match line {
        [rest @ .., CR, LF] => (rest, true),
        [rest @ .., LF] => (rest, false),
        _ => return Ok(None),
    };
    let Some(inner) = body.strip_suffix(b"}") else {
        return Ok(None);
    };
    let Some(open) = inner.iter().rposition(|b| *b == b'{') else {
        return Ok(None);
    };
    let digits = &inner[open + 1..];
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return Ok(None);
    }
    if !crlf || digits.len() > 20 {
        return Err(StreamError::MalformedLiteralMarker);
    }
    let n = digits
        .iter()
        .try_fold(0u64, |n, d| {
            n.checked_mul(10)?.checked_add(u64::from(d - b'0'))
        })
        .ok_or(StreamError::MalformedLiteralMarker)?;
    Ok(Some((open, n)))
}

fn ends_with_ignore_case(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.len() >= needle.len()
        && haystack[haystack.len() - needle.len()..].eq_ignore_ascii_case(needle)
}

/// Map a tagged completion exactly as `read_response_onto` does.
fn completion(
    status: imap_proto::Status,
    information: Option<std::borrow::Cow<'_, str>>,
    code: Option<imap_proto::ResponseCode<'_>>,
) -> Result<()> {
    use imap_proto::Status;
    let information = || {
        information
            .clone()
            .map_or_else(|| "no explanation given".to_string(), |v| v.into_owned())
    };
    let code = code.map(|v| v.into_owned());
    match status {
        Status::Ok => Ok(()),
        Status::Bad => Err(Error::Bad(Bad {
            code,
            information: information(),
        })),
        Status::No => Err(Error::No(No {
            code,
            information: information(),
        })),
        Status::Bye => Err(Error::Bye(Bye {
            code,
            information: information(),
        })),
        _ => Err(Error::Stream(StreamError::MalformedResponse)),
    }
}

impl<T: Read + Write> Connection<T> {
    /// One CRLF- or LF-terminated line into `into`, never more than `max` bytes.
    fn read_bounded_line(&mut self, into: &mut Vec<u8>, max: usize) -> Result<()> {
        loop {
            let available = match self.stream.fill_buf() {
                Ok(b) => b,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            };
            if available.is_empty() {
                return Err(Error::ConnectionLost);
            }
            let (take, done) = match available.iter().position(|b| *b == LF) {
                Some(i) => (i + 1, true),
                None => (available.len(), false),
            };
            if into.len() + take > max {
                return Err(Error::Stream(StreamError::LineTooLong));
            }
            into.extend_from_slice(&available[..take]);
            self.stream.consume(take);
            if done {
                return Ok(());
            }
        }
    }

    /// Copy exactly `n` bytes from the connection into `sink` through `buf`.
    fn copy_literal(
        &mut self,
        n: u64,
        sink: &mut dyn FnMut(&[u8]) -> io::Result<()>,
        buf: &mut [u8],
    ) -> Result<()> {
        let mut left = n;
        while left > 0 {
            let want = min(left, buf.len() as u64) as usize;
            let got = match self.stream.read(&mut buf[..want]) {
                Ok(0) => return Err(Error::ConnectionLost), // truncated literal
                Ok(got) => got,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            };
            sink(&buf[..got])?;
            left -= got as u64;
        }
        Ok(())
    }

    /// Small non-body literal, kept in the skeleton. The caller has already bounded `n`.
    fn read_small_literal(&mut self, n: u64, into: &mut Vec<u8>) -> Result<()> {
        let start = into.len();
        into.resize(start + n as usize, 0);
        let mut filled = start;
        while filled < into.len() {
            match self.stream.read(&mut into[filled..]) {
                Ok(0) => return Err(Error::ConnectionLost),
                Ok(got) => filled += got,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    fn read_streamed_fetch(
        &mut self,
        marker: &[u8],
        expected: u64,
        sink: &mut dyn FnMut(&[u8]) -> io::Result<()>,
    ) -> Result<StreamedFetch> {
        let tag = format!("{}{}", TAG_PREFIX, self.tag);
        let mut skeleton: Vec<u8> = Vec::new();
        let mut line: Vec<u8> = Vec::new();
        let mut streamed: Option<u64> = None;
        let mut buf: Vec<u8> = Vec::new();
        loop {
            line.clear();
            self.read_bounded_line(&mut line, MAX_LINE)?;
            if let Some((open, n)) = literal_marker(&line).map_err(Error::Stream)? {
                if streamed.is_none() && ends_with_ignore_case(&line[..open], marker) {
                    if n != expected {
                        // Refuse before consuming any body byte.
                        return Err(Error::Stream(StreamError::LiteralLengthMismatch));
                    }
                    if skeleton.len() + open + 5 > MAX_SKELETON {
                        return Err(Error::Stream(StreamError::ResponseTooLarge));
                    }
                    skeleton.extend_from_slice(&line[..open]);
                    skeleton.extend_from_slice(b"{0}\r\n");
                    if buf.is_empty() {
                        buf.resize(STREAM_CHUNK, 0);
                    }
                    self.copy_literal(n, sink, &mut buf)?;
                    streamed = Some(n);
                } else {
                    let room = (MAX_SKELETON - skeleton.len().min(MAX_SKELETON)) as u64;
                    if n.saturating_add(line.len() as u64) > room {
                        return Err(Error::Stream(StreamError::ResponseTooLarge));
                    }
                    skeleton.extend_from_slice(&line);
                    self.read_small_literal(n, &mut skeleton)?;
                }
                continue;
            }
            // Only lines that can be tagged completions are parsed as such. Untagged,
            // continuation and literal-continuation lines go to the skeleton.
            if !matches!(
                line.first(),
                None | Some(b'*') | Some(b'+') | Some(b' ') | Some(b')')
            ) {
                match imap_proto::parser::parse_response(&line) {
                    Ok((
                        _,
                        Response::Done {
                            tag: done_tag,
                            status,
                            information,
                            code,
                            ..
                        },
                    )) => {
                        if done_tag.as_bytes() != tag.as_bytes() {
                            let expect = self.tag;
                            let actual = done_tag
                                .0
                                .trim_start_matches(TAG_PREFIX)
                                .parse::<u32>()
                                .map_err(|_| done_tag.as_bytes().to_vec());
                            return Err(Error::TagMismatch(TagMismatch { expect, actual }));
                        }
                        completion(status, information, code)?;
                        return Ok(StreamedFetch {
                            skeleton,
                            body_len: streamed,
                        });
                    }
                    _ => return Err(Error::Stream(StreamError::MalformedResponse)),
                }
            }
            if skeleton.len() + line.len() > MAX_SKELETON {
                return Err(Error::Stream(StreamError::ResponseTooLarge));
            }
            skeleton.extend_from_slice(&line);
        }
    }
}

impl<T: Read + Write> Session<T> {
    /// Stream the body of one message into `sink` without ever holding it in memory.
    ///
    /// Sends `UID FETCH <uid> (UID FLAGS INTERNALDATE BODY.PEEK[])`. **`BODY.PEEK` is fixed:**
    /// a plain `BODY[]` would set `\Seen`, so this method cannot modify the mailbox.
    ///
    /// `expected_len` is the message size the caller already established (for example from
    /// `RFC822.SIZE`). The announced literal must equal it, or the call fails before any body
    /// byte is read. `sink` receives the body in chunks of at most [`STREAM_CHUNK`] bytes; a
    /// sink error aborts the call.
    ///
    /// On any error other than a tagged `No`/`Bad`, the connection is desynchronized and
    /// must be dropped (`is_desynced()` is true and further commands are refused).
    pub fn uid_fetch_body_stream(
        &mut self,
        uid: u32,
        expected_len: u64,
        sink: &mut dyn FnMut(&[u8]) -> io::Result<()>,
    ) -> Result<StreamedFetch> {
        let command = format!("UID FETCH {uid} (UID FLAGS INTERNALDATE BODY.PEEK[])");
        self.conn.run_command(&command)?;
        let result = self
            .conn
            .read_streamed_fetch(b"BODY[] ", expected_len, sink);
        if let Err(e) = &result {
            if !completion_consumed(e) {
                self.conn.desynced = true;
            }
        }
        result
    }

    /// Begin an `APPEND` whose literal is streamed from a reader. See [`StreamAppendCmd`].
    pub fn append_stream<'a>(&'a mut self, mailbox: &'a str) -> StreamAppendCmd<'a, T> {
        StreamAppendCmd {
            session: self,
            mailbox,
            flags: Vec::new(),
            date: None,
        }
    }
}

/// Builder for a streaming `APPEND`. Mirrors [`AppendCmd`]'s builder methods.
#[derive(Debug)]
pub struct StreamAppendCmd<'a, T: Read + Write> {
    session: &'a mut Session<T>,
    mailbox: &'a str,
    flags: Vec<Flag<'a>>,
    date: Option<DateTime<FixedOffset>>,
}

/// The exact command line `AppendCmd::finish_with_literal_guard` sends, for a literal of `len`.
fn append_command_line(
    mailbox: &str,
    flags: &[Flag<'_>],
    date: Option<DateTime<FixedOffset>>,
    len: u64,
) -> String {
    let flagstr = iter_join(flags.iter().filter(|f| **f != Flag::Recent), " ");
    let datestr = if let Some(date) = date {
        format!(" \"{}\"", date.format("%d-%h-%Y %T %z"))
    } else {
        "".to_string()
    };
    format!("APPEND \"{mailbox}\" ({flagstr}){datestr} {{{len}}}")
}

impl<'a, T: Read + Write> StreamAppendCmd<'a, T> {
    /// Add one flag (`\Recent` is filtered out, as for [`AppendCmd`]).
    pub fn flag(&mut self, flag: Flag<'a>) -> &mut Self {
        self.flags.push(flag);
        self
    }

    /// Add several flags.
    pub fn flags(&mut self, flags: impl IntoIterator<Item = Flag<'a>>) -> &mut Self {
        self.flags.extend(flags);
        self
    }

    /// Set the INTERNALDATE of the new message.
    pub fn internal_date(&mut self, date: DateTime<FixedOffset>) -> &mut Self {
        self.date = Some(date);
        self
    }

    /// Run the APPEND, sending exactly `len` bytes read from `reader`.
    ///
    /// Order, which preserves the pre-literal authorization fence:
    /// 1. send `APPEND ... {len}` and wait for the `+` continuation;
    /// 2. call `guard()`. If it fails, **no body byte is sent**;
    /// 3. only then copy `len` bytes in chunks of at most [`STREAM_CHUNK`], then CRLF;
    /// 4. read the tagged response.
    ///
    /// The returned [`StreamedAppend`] always reports the furthest [`AppendPhase`], even on
    /// failure, so the caller can tell a provably-unsent APPEND from an uncertain one.
    /// A short or failing `reader`, a short or failing write, a timeout or a disconnect
    /// never retries anything: the connection is marked desynced and must be dropped.
    pub fn finish_streaming<R: Read>(
        &mut self,
        len: u64,
        reader: &mut R,
        guard: impl FnOnce() -> io::Result<()>,
    ) -> StreamedAppend {
        let mut out = StreamedAppend {
            phase: AppendPhase::NotAuthorized,
            body_bytes_sent: 0,
            result: Err(Error::Append),
        };
        out.result = self.run(len, reader, guard, &mut out.phase, &mut out.body_bytes_sent);
        if let Err(e) = &out.result {
            if !completion_consumed(e) {
                self.session.conn.desynced = true;
            }
        }
        out
    }

    fn run<R: Read>(
        &mut self,
        len: u64,
        reader: &mut R,
        guard: impl FnOnce() -> io::Result<()>,
        phase: &mut AppendPhase,
        sent: &mut u64,
    ) -> Result<Appended> {
        let command = append_command_line(self.mailbox, &self.flags, self.date, len);
        self.session.run_command(&command)?;
        let mut first = Vec::new();
        self.session.readline(&mut first)?;
        if !first.starts_with(b"+") {
            // A matching tagged rejection is preserved with its code; an early OK or any
            // other reply cannot establish success and no body was sent.
            self.session.read_response_onto(&mut first)?;
            return Err(Error::Append);
        }
        guard()?;
        *phase = AppendPhase::Authorized;

        let mut buf = vec![0u8; STREAM_CHUNK];
        let mut left = len;
        while left > 0 {
            let want = min(left, buf.len() as u64) as usize;
            let got = match reader.read(&mut buf[..want]) {
                Ok(0) => {
                    return Err(Error::Io(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "streaming APPEND source ended before the declared length",
                    )));
                }
                Ok(got) => got,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            };
            // Before the write: a failed write may still have delivered bytes.
            *phase = AppendPhase::BodyStarted;
            self.session.stream.write_all(&buf[..got])?;
            *sent += got as u64;
            left -= got as u64;
        }
        *phase = AppendPhase::BodyStarted;
        self.session.stream.write_all(b"\r\n")?;
        self.session.stream.flush()?;
        *phase = AppendPhase::BodyComplete;

        match self.session.read_response() {
            Ok((lines, _)) => {
                *phase = AppendPhase::Responded;
                parse_append(&lines, &mut self.session.unsolicited_responses)
            }
            Err(e) => {
                if completion_consumed(&e) {
                    *phase = AppendPhase::Responded;
                }
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::mock_stream::MockStream;
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    /// xorshift64*: deterministic, dependency-free randomness.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn below(&mut self, n: u64) -> u64 {
            if n == 0 {
                0
            } else {
                self.next() % n
            }
        }
        fn bytes(&mut self, n: usize) -> Vec<u8> {
            // Random bytes salted with protocol-looking fragments that must never be misread.
            let mut v = Vec::with_capacity(n);
            while v.len() < n {
                match self.below(12) {
                    0 => v.extend_from_slice(b"\r\n"),
                    1 => v.extend_from_slice(b"{5}\r\n"),
                    2 => v.extend_from_slice(b"a1 OK done\r\n"),
                    3 => v.extend_from_slice(b"* 1 FETCH (UID 9)\r\n"),
                    4 => v.extend_from_slice(b"a1 NO [TOOBIG] x\r\n"),
                    5 => v.extend_from_slice(b"BODY[] {7}\r\n"),
                    _ => v.push(self.next() as u8),
                }
            }
            v.truncate(n);
            v
        }
    }

    /// Duplex stream with randomly fragmented reads and writes and optional failures.
    struct Wire {
        incoming: Vec<u8>,
        pos: usize,
        rng: Rng,
        max_read: usize,
        max_write: usize,
        written: Rc<RefCell<Vec<u8>>>,
        fail_write_at: Option<usize>,
        eof_is_error: bool,
    }
    impl Wire {
        fn new(incoming: Vec<u8>, seed: u64, max_read: usize) -> Wire {
            Wire {
                incoming,
                pos: 0,
                rng: Rng(seed | 1),
                max_read,
                max_write: usize::MAX / 2,
                written: Rc::default(),
                fail_write_at: None,
                eof_is_error: false,
            }
        }
    }
    impl Read for Wire {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.pos >= self.incoming.len() {
                return if self.eof_is_error {
                    Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof"))
                } else {
                    Ok(0)
                };
            }
            let n = min(
                min(buf.len(), self.incoming.len() - self.pos),
                1 + self.rng.below(self.max_read as u64) as usize,
            );
            buf[..n].copy_from_slice(&self.incoming[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }
    impl Write for Wire {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let mut log = self.written.borrow_mut();
            let mut n = min(
                buf.len(),
                1 + self.rng.below(self.max_write.min(1 << 20) as u64) as usize,
            );
            if let Some(at) = self.fail_write_at {
                if log.len() >= at {
                    return Err(io::Error::other("write failed"));
                }
                n = min(n, at - log.len());
            }
            log.extend_from_slice(&buf[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn session<S: Read + Write>(stream: S) -> Session<S> {
        Session::new(Client::new(stream).conn)
    }

    const DATE: &str = "02-Jan-2020 03:04:05 +0000";
    fn fetch_response(body: &[u8], body_first: bool) -> Vec<u8> {
        let mut r = b"* 1 FETCH (".to_vec();
        let attrs = format!("UID 7 FLAGS (\\Seen) INTERNALDATE \"{DATE}\"");
        if body_first {
            r.extend_from_slice(format!("BODY[] {{{}}}\r\n", body.len()).as_bytes());
            r.extend_from_slice(body);
            r.extend_from_slice(format!(" {attrs})\r\n").as_bytes());
        } else {
            r.extend_from_slice(format!("{attrs} BODY[] {{{}}}\r\n", body.len()).as_bytes());
            r.extend_from_slice(body);
            r.extend_from_slice(b")\r\n");
        }
        r.extend_from_slice(b"a1 OK UID FETCH completed\r\n");
        r
    }

    fn stream_fetch(
        wire: Wire,
        expected: u64,
    ) -> (Result<StreamedFetch>, Vec<u8>, Rc<RefCell<Vec<u8>>>, bool) {
        let written = wire.written.clone();
        let mut s = session(wire);
        let mut body = Vec::new();
        let r = s.uid_fetch_body_stream(7, expected, &mut |c| {
            assert!(c.len() <= STREAM_CHUNK);
            body.extend_from_slice(c);
            Ok(())
        });
        (r, body, written, s.is_desynced())
    }

    // ---------------------------------------------------------------- streaming FETCH
    #[test]
    fn fetch_streams_exact_bytes_in_either_attribute_order_and_uses_peek_only() {
        let body = Rng(5).bytes(20_000);
        for body_first in [false, true] {
            let wire = Wire::new(fetch_response(&body, body_first), 1, 4096);
            let (r, got, written, desynced) = stream_fetch(wire, body.len() as u64);
            let r = r.unwrap();
            assert_eq!(got, body);
            assert_eq!(r.body_len, Some(body.len() as u64));
            assert!(!desynced);
            assert_eq!(
                written.borrow().as_slice(),
                b"a1 UID FETCH 7 (UID FLAGS INTERNALDATE BODY.PEEK[])\r\n"
            );
            // The skeleton parses with the normal parser and holds no body bytes.
            assert!(r.skeleton.len() < 200, "{}", r.skeleton.len());
            let mut rest = r.skeleton.as_slice();
            let mut saw = false;
            while !rest.is_empty() {
                let (next, resp) = Response::from_bytes(rest).expect("skeleton must parse");
                if let Response::Fetch(_, attrs) = resp {
                    saw = true;
                    use imap_proto::AttributeValue as A;
                    assert!(attrs.iter().any(|a| matches!(a, A::Uid(7))));
                    assert!(attrs.iter().any(|a| matches!(a, A::Flags(_))));
                    assert!(attrs
                        .iter()
                        .any(|a| matches!(a, A::InternalDate(d) if d == DATE)));
                    assert!(attrs.iter().any(|a| matches!(
                        a,
                        A::BodySection { section: None, index: None, data: Some(b) } if b.is_empty()
                    )));
                }
                rest = next;
            }
            assert!(saw);
        }
    }

    #[test]
    fn fetch_result_is_identical_under_arbitrary_fragmentation() {
        let mut rng = Rng(99);
        for seed in 0..300u64 {
            let len = match rng.below(8) {
                0 => 0,
                1 => 1,
                2 => STREAM_CHUNK as u64 + rng.below(3), // chunk boundary
                _ => rng.below(40_000),
            } as usize;
            let body = rng.bytes(len);
            let reference = stream_fetch(
                Wire::new(fetch_response(&body, seed % 2 == 0), 3, 1 << 20),
                len as u64,
            );
            let max_read = [1, 2, 3, 7, 64, 4096, 1 << 20][rng.below(7) as usize];
            let (r, got, _, desynced) = stream_fetch(
                Wire::new(fetch_response(&body, seed % 2 == 0), seed, max_read),
                len as u64,
            );
            let (r, reference_r) = (r.unwrap(), reference.0.unwrap());
            assert_eq!(got, body, "seed {seed} max_read {max_read}");
            assert_eq!(got, reference.1);
            assert_eq!(r.skeleton, reference_r.skeleton);
            assert_eq!(r.body_len, Some(len as u64));
            assert!(!desynced);
        }
    }

    #[test]
    fn fetch_zero_length_literal_never_calls_the_sink() {
        let wire = Wire::new(fetch_response(b"", false), 4, 3);
        let (r, got, _, desynced) = stream_fetch(wire, 0);
        assert_eq!(r.unwrap().body_len, Some(0));
        assert!(got.is_empty() && !desynced);
    }

    #[test]
    fn fetch_length_mismatch_is_refused_before_any_body_byte_is_read() {
        for (announced, expected) in [(11usize, 10u64), (10, 11), (0, 1)] {
            let wire = Wire::new(fetch_response(&vec![b'x'; announced], false), 6, 1 << 20);
            let (r, got, _, desynced) = stream_fetch(wire, expected);
            assert!(matches!(
                r,
                Err(Error::Stream(StreamError::LiteralLengthMismatch))
            ));
            assert!(got.is_empty(), "no body byte may reach the sink");
            assert!(desynced);
        }
    }

    #[test]
    fn fetch_truncated_literal_fails_and_desyncs_whether_eof_or_error() {
        let body = Rng(8).bytes(5000);
        let full = fetch_response(&body, false);
        let header_end = full.windows(2).position(|w| w == b"}\r").unwrap();
        for cut in [
            header_end + 4,
            header_end + 100,
            full.len() / 2,
            full.len() - 30,
        ] {
            for eof_is_error in [false, true] {
                let mut wire = Wire::new(full[..cut].to_vec(), 9, 97);
                wire.eof_is_error = eof_is_error;
                let (r, got, _, desynced) = stream_fetch(wire, body.len() as u64);
                assert!(r.is_err(), "cut {cut}");
                assert!(got.len() < body.len() || r.is_err());
                assert!(desynced, "a failed stream must poison the connection");
            }
        }
    }

    #[test]
    fn fetch_desynced_connection_refuses_every_later_command() {
        let wire = Wire::new(fetch_response(b"0123456789", false), 2, 8);
        let written = wire.written.clone();
        let mut s = session(wire);
        assert!(s.uid_fetch_body_stream(7, 99, &mut |_| Ok(())).is_err());
        let before = written.borrow().len();
        assert!(matches!(s.run_command("NOOP"), Err(Error::ConnectionLost)));
        assert!(matches!(s.noop(), Err(Error::ConnectionLost)));
        assert_eq!(
            written.borrow().len(),
            before,
            "nothing may be written after desync"
        );
    }

    #[test]
    fn fetch_sink_failure_aborts_and_desyncs() {
        let body = vec![b'z'; 300_000];
        let mut s = session(Wire::new(fetch_response(&body, false), 3, 1 << 20));
        let mut calls = 0;
        let r = s.uid_fetch_body_stream(7, body.len() as u64, &mut |_| {
            calls += 1;
            if calls == 2 {
                Err(io::Error::other("disk full"))
            } else {
                Ok(())
            }
        });
        assert!(matches!(r, Err(Error::Io(_))));
        assert_eq!(calls, 2, "no chunk after the failing one");
        assert!(s.is_desynced());
    }

    #[test]
    fn fetch_bounds_lines_and_non_body_literals() {
        // A line with no LF beyond the bound.
        let mut r = b"* OK ".to_vec();
        r.extend(std::iter::repeat(b'a').take(MAX_LINE + 10));
        let (res, ..) = stream_fetch(Wire::new(r, 1, 1 << 20), 1);
        assert!(matches!(res, Err(Error::Stream(StreamError::LineTooLong))));
        // A huge literal that is not the requested body section is refused, not buffered.
        let (res, got, ..) = stream_fetch(
            Wire::new(
                b"* 1 FETCH (RFC822.TEXT {2097152}\r\nxx".to_vec(),
                1,
                1 << 20,
            ),
            1,
        );
        assert!(matches!(
            res,
            Err(Error::Stream(StreamError::ResponseTooLarge))
        ));
        assert!(got.is_empty());
        // A small other literal is kept in the skeleton; a second BODY[] literal is too, so the
        // caller's ambiguity checks still see it.
        let r =
            b"* 1 FETCH (UID 7 X {3}\r\nabc BODY[] {2}\r\nhi BODY[] {2}\r\nyo)\r\na1 OK done\r\n"
                .to_vec();
        let (res, got, ..) = stream_fetch(Wire::new(r, 1, 5), 2);
        let res = res.unwrap();
        assert_eq!(got, b"hi");
        assert!(
            res.skeleton.windows(3).any(|w| w == b"abc")
                && res.skeleton.windows(2).any(|w| w == b"yo")
        );
    }

    #[test]
    fn fetch_malformed_markers_and_completions_fail_safely() {
        // Bare-LF literal marker: the body would be misread as lines, so refuse.
        let (res, ..) = stream_fetch(
            Wire::new(b"* 1 FETCH (BODY[] {5}\nhello)\r\n".to_vec(), 1, 64),
            5,
        );
        assert!(matches!(
            res,
            Err(Error::Stream(StreamError::MalformedLiteralMarker))
        ));
        // Overflowing and over-long digit strings.
        for marker in ["{99999999999999999999999}", "{184467440737095516160}"] {
            let (res, ..) = stream_fetch(
                Wire::new(
                    format!("* 1 FETCH (BODY[] {marker}\r\n").into_bytes(),
                    1,
                    64,
                ),
                5,
            );
            assert!(
                matches!(res, Err(Error::Stream(StreamError::MalformedLiteralMarker))),
                "{marker}"
            );
        }
        // Text that merely ends in a brace is not a literal and is passed through.
        let (res, got, ..) = stream_fetch(
            Wire::new(b"* OK see {x}\r\n* OK {}\r\na1 OK done\r\n".to_vec(), 1, 64),
            5,
        );
        assert_eq!(res.unwrap().body_len, None);
        assert!(got.is_empty());
        // Garbage that looks like a tagged line.
        let (res, ..) = stream_fetch(Wire::new(b"a1 \x00\x01 garbage\r\n".to_vec(), 1, 64), 5);
        assert!(res.is_err());
    }

    #[test]
    fn fetch_tagged_completions_are_reported_and_only_consumed_ones_keep_sync() {
        let (res, _, _, desynced) =
            stream_fetch(Wire::new(b"a1 NO [TOOBIG] too big\r\n".to_vec(), 1, 3), 5);
        assert!(
            matches!(&res, Err(Error::No(n)) if matches!(n.code, Some(imap_proto::ResponseCode::TooBig)))
        );
        assert!(
            !desynced,
            "a fully consumed tagged NO leaves the stream in sync"
        );
        let (res, _, _, desynced) = stream_fetch(Wire::new(b"a1 BAD nope\r\n".to_vec(), 1, 3), 5);
        assert!(matches!(res, Err(Error::Bad(_))) && !desynced);
        let (res, _, _, desynced) = stream_fetch(Wire::new(b"a9 OK done\r\n".to_vec(), 1, 3), 5);
        assert!(matches!(res, Err(Error::TagMismatch(_))) && desynced);
        let (res, _, _, _) = stream_fetch(Wire::new(b"a1 OK done\r\n".to_vec(), 1, 3), 5);
        assert_eq!(res.unwrap().body_len, None, "no literal: message absent");
    }

    #[test]
    fn fetch_is_bounded_for_a_large_body() {
        // 6 MiB streamed; the skeleton stays tiny and the sink only ever sees bounded chunks.
        let body = vec![0xA5u8; 6 << 20];
        let mut s = session(Wire::new(fetch_response(&body, false), 11, 1 << 20));
        let (mut total, mut max_chunk) = (0usize, 0usize);
        let r = s
            .uid_fetch_body_stream(7, body.len() as u64, &mut |c| {
                total += c.len();
                max_chunk = max_chunk.max(c.len());
                Ok(())
            })
            .unwrap();
        assert_eq!(total, body.len());
        assert!(max_chunk <= STREAM_CHUNK && r.skeleton.len() < 200);
    }

    // ---------------------------------------------------------------- streaming APPEND
    fn date() -> DateTime<FixedOffset> {
        DateTime::parse_from_str(DATE, "%d-%b-%Y %H:%M:%S %z").unwrap()
    }

    struct Attempt {
        out: StreamedAppend,
        written: Vec<u8>,
        guard_calls: u32,
        written_at_guard: Option<usize>,
        desynced: bool,
    }
    fn append(wire: Wire, body: &[u8], reader: &mut dyn Read, len: u64) -> Attempt {
        let log = wire.written.clone();
        let mut s = session(wire);
        let calls = Cell::new(0u32);
        let at_guard = Cell::new(None);
        let probe = log.clone();
        let out = {
            let mut cmd = s.append_stream("INBOX");
            cmd.flag(Flag::Seen)
                .flag(Flag::Recent)
                .internal_date(date());
            let mut r = reader;
            cmd.finish_streaming(len, &mut r, || {
                calls.set(calls.get() + 1);
                at_guard.set(Some(probe.borrow().len()));
                Ok(())
            })
        };
        let _ = body;
        let written = log.borrow().clone();
        Attempt {
            out,
            written,
            guard_calls: calls.get(),
            written_at_guard: at_guard.get(),
            desynced: s.is_desynced(),
        }
    }
    fn command_bytes(len: u64) -> Vec<u8> {
        let mut c = append_command_line("INBOX", &[Flag::Seen, Flag::Recent], Some(date()), len)
            .into_bytes();
        c.extend_from_slice(b"\r\n");
        c.insert(0, b' ');
        c.splice(0..1, b"a1 ".iter().copied());
        c
    }
    const OK: &[u8] = b"+ ready\r\na1 OK [APPENDUID 77 5] done\r\n";

    #[test]
    fn append_command_line_is_identical_to_the_existing_builder() {
        let body = b"hello".to_vec();
        let mut old = session(MockStream::new(b"+ ready\r\n".to_vec()));
        let _ = old
            .append("INBOX", &body)
            .flag(Flag::Seen)
            .flag(Flag::Recent)
            .flag(Flag::Custom("$X".into()))
            .internal_date(date())
            .finish_with_literal_guard(|| Ok(()));
        let old_cmd: Vec<u8> = old
            .stream
            .get_ref()
            .written_buf
            .split_inclusive(|b| *b == LF)
            .next()
            .unwrap()
            .to_vec();
        let new = append_command_line(
            "INBOX",
            &[Flag::Seen, Flag::Recent, Flag::Custom("$X".into())],
            Some(date()),
            5,
        );
        assert_eq!(old_cmd, format!("a1 {new}\r\n").into_bytes());
        // And without flags or date.
        let mut old = session(MockStream::new(b"+ ready\r\n".to_vec()));
        let _ = old
            .append("INBOX", &body)
            .finish_with_literal_guard(|| Ok(()));
        let old_cmd: Vec<u8> = old
            .stream
            .get_ref()
            .written_buf
            .split_inclusive(|b| *b == LF)
            .next()
            .unwrap()
            .to_vec();
        assert_eq!(
            old_cmd,
            format!("a1 {}\r\n", append_command_line("INBOX", &[], None, 5)).into_bytes()
        );
    }

    #[test]
    fn append_success_authorizes_before_any_body_byte() {
        let body = Rng(21).bytes(3 * STREAM_CHUNK + 17);
        let mut wire = Wire::new(OK.to_vec(), 1, 7);
        wire.max_write = 5; // short writes
        let a = append(wire, &body, &mut body.as_slice(), body.len() as u64);
        let cmd = command_bytes(body.len() as u64);
        assert_eq!(a.guard_calls, 1);
        assert_eq!(
            a.written_at_guard,
            Some(cmd.len()),
            "only the command line may precede authorization"
        );
        let mut expect = cmd;
        expect.extend_from_slice(&body);
        expect.extend_from_slice(b"\r\n");
        assert_eq!(a.written, expect);
        assert_eq!(
            (a.out.phase, a.out.body_bytes_sent),
            (AppendPhase::Responded, body.len() as u64)
        );
        let ok = a.out.result.unwrap();
        assert_eq!(ok.uid_validity, Some(77));
        assert!(!a.desynced);
    }

    #[test]
    fn append_zero_length_literal() {
        let a = append(Wire::new(OK.to_vec(), 2, 3), b"", &mut io::empty(), 0);
        let mut expect = command_bytes(0);
        expect.extend_from_slice(b"\r\n");
        assert_eq!(a.written, expect);
        assert_eq!(
            (a.out.phase, a.out.body_bytes_sent),
            (AppendPhase::Responded, 0)
        );
        assert!(a.out.result.is_ok() && a.guard_calls == 1);
    }

    #[test]
    fn append_guard_failure_sends_no_body_and_is_not_authorized() {
        let body = b"PRIVATE_BODY".to_vec();
        let wire = Wire::new(OK.to_vec(), 3, 64);
        let log = wire.written.clone();
        let mut s = session(wire);
        let out = {
            let mut cmd = s.append_stream("INBOX");
            cmd.finish_streaming(body.len() as u64, &mut body.as_slice(), || {
                Err(io::Error::other("journal failure"))
            })
        };
        assert!(matches!(out.result, Err(Error::Io(_))));
        assert_eq!(
            (out.phase, out.body_bytes_sent),
            (AppendPhase::NotAuthorized, 0)
        );
        assert!(!out.body_possibly_sent());
        assert!(!log.borrow().windows(12).any(|w| w == b"PRIVATE_BODY"));
        assert!(s.is_desynced(), "the server is still waiting for a literal");
    }

    #[test]
    fn append_rejection_before_continuation_never_calls_the_guard_and_keeps_sync() {
        for response in [&b"a1 NO [OVERQUOTA] full\r\n"[..], b"a1 BAD no\r\n"] {
            let a = append(Wire::new(response.to_vec(), 4, 5), b"x", &mut &b"x"[..], 1);
            assert_eq!(a.guard_calls, 0);
            assert_eq!(a.out.phase, AppendPhase::NotAuthorized);
            assert!(matches!(a.out.result, Err(Error::No(_) | Error::Bad(_))));
            assert!(
                !a.desynced,
                "a consumed tagged rejection leaves the connection usable"
            );
            assert_eq!(a.written, command_bytes(1));
        }
        // An early OK, or any non-continuation reply, cannot be a success and sends no body.
        for response in [&b"a1 OK done\r\n"[..], b"* weird\r\na1 OK done\r\n"] {
            let a = append(Wire::new(response.to_vec(), 4, 5), b"x", &mut &b"x"[..], 1);
            assert_eq!(a.guard_calls, 0);
            assert_eq!(a.out.phase, AppendPhase::NotAuthorized);
            assert!(a.out.result.is_err() && a.written == command_bytes(1));
        }
    }

    #[test]
    fn append_reader_ending_early_is_reported_by_phase() {
        let body = vec![b'q'; 100_000];
        // Source empty: authorized but nothing sent, so provably nothing was appended.
        let a = append(
            Wire::new(OK.to_vec(), 5, 64),
            &body,
            &mut io::empty(),
            body.len() as u64,
        );
        assert_eq!(
            (a.out.phase, a.out.body_bytes_sent),
            (AppendPhase::Authorized, 0)
        );
        assert!(!a.out.body_possibly_sent() && a.written.len() == command_bytes(100_000).len());
        // Source ends after 40 000 bytes: body started, uncertain, no terminator.
        let a = append(
            Wire::new(OK.to_vec(), 5, 64),
            &body,
            &mut &body[..40_000],
            body.len() as u64,
        );
        assert_eq!(a.out.phase, AppendPhase::BodyStarted);
        assert_eq!(a.out.body_bytes_sent, 40_000);
        assert!(a.out.body_possibly_sent() && a.desynced);
        assert!(
            !a.written.ends_with(b"\r\n")
                || a.written.len() == command_bytes(100_000).len() + 40_000
        );
        assert!(
            matches!(a.out.result, Err(Error::Io(ref e)) if e.kind() == io::ErrorKind::UnexpectedEof)
        );
    }

    struct FailingReader(usize, usize);
    impl Read for FailingReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.0 >= self.1 {
                return Err(io::Error::other("spool read failed"));
            }
            let n = min(buf.len(), self.1 - self.0);
            buf[..n].fill(b'r');
            self.0 += n;
            Ok(n)
        }
    }

    #[test]
    fn append_reader_error_mid_way_is_uncertain() {
        let a = append(
            Wire::new(OK.to_vec(), 6, 64),
            b"",
            &mut FailingReader(0, 200_000),
            400_000,
        );
        assert_eq!(a.out.phase, AppendPhase::BodyStarted);
        assert!(a.out.body_possibly_sent() && a.desynced && a.out.result.is_err());
    }

    #[test]
    fn append_write_failures_are_reported_conservatively() {
        let body = vec![b'w'; 50_000];
        let cmd_len = command_bytes(body.len() as u64).len();
        // The very first body write fails: the attempt counts as started even though no byte is confirmed.
        let mut wire = Wire::new(OK.to_vec(), 7, 64);
        wire.fail_write_at = Some(cmd_len);
        let a = append(wire, &body, &mut body.as_slice(), body.len() as u64);
        assert_eq!(a.out.phase, AppendPhase::BodyStarted);
        assert!(a.out.body_possibly_sent() && a.out.result.is_err() && a.desynced);
        // Failure partway through the body.
        let mut wire = Wire::new(OK.to_vec(), 7, 64);
        wire.fail_write_at = Some(cmd_len + 20_000);
        let a = append(wire, &body, &mut body.as_slice(), body.len() as u64);
        assert_eq!(a.out.phase, AppendPhase::BodyStarted);
        assert!(a.out.body_bytes_sent <= body.len() as u64);
        // Failure while writing the terminator: the whole body was sent but the command is unterminated.
        let mut wire = Wire::new(OK.to_vec(), 7, 64);
        wire.fail_write_at = Some(cmd_len + body.len());
        let a = append(wire, &body, &mut body.as_slice(), body.len() as u64);
        assert_eq!(
            (a.out.phase, a.out.body_bytes_sent),
            (AppendPhase::BodyStarted, body.len() as u64)
        );
        // The command line itself cannot be written: nothing is authorized.
        let mut wire = Wire::new(OK.to_vec(), 7, 64);
        wire.fail_write_at = Some(5);
        let a = append(wire, &body, &mut body.as_slice(), body.len() as u64);
        assert_eq!(a.out.phase, AppendPhase::NotAuthorized);
        assert_eq!(a.guard_calls, 0);
    }

    #[test]
    fn append_server_outcomes_after_the_body() {
        let body = b"abcdef".to_vec();
        // Disconnect after the body: complete but unanswered, so uncertain.
        let a = append(
            Wire::new(b"+ ready\r\n".to_vec(), 8, 64),
            &body,
            &mut body.as_slice(),
            6,
        );
        assert_eq!(a.out.phase, AppendPhase::BodyComplete);
        assert!(
            a.out.body_possibly_sent()
                && matches!(a.out.result, Err(Error::ConnectionLost))
                && a.desynced
        );
        // A tagged rejection after the body is a definite answer and keeps the stream in sync.
        let a = append(
            Wire::new(b"+ ready\r\na1 NO [TOOBIG] big\r\n".to_vec(), 8, 64),
            &body,
            &mut body.as_slice(),
            6,
        );
        assert_eq!(a.out.phase, AppendPhase::Responded);
        assert!(
            matches!(&a.out.result, Err(Error::No(n)) if matches!(n.code, Some(imap_proto::ResponseCode::TooBig)))
        );
        assert!(!a.desynced);
        // OK without APPENDUID is answered; the caller decides what a missing UID means.
        let a = append(
            Wire::new(b"+ ready\r\na1 OK done\r\n".to_vec(), 8, 64),
            &body,
            &mut body.as_slice(),
            6,
        );
        assert_eq!(a.out.phase, AppendPhase::Responded);
        assert_eq!(a.out.result.unwrap().uids, None);
        // A wrong tag is not a completion of this command.
        let a = append(
            Wire::new(b"+ ready\r\na9 OK done\r\n".to_vec(), 8, 64),
            &body,
            &mut body.as_slice(),
            6,
        );
        assert_eq!(a.out.phase, AppendPhase::BodyComplete);
        assert!(matches!(a.out.result, Err(Error::TagMismatch(_))) && a.desynced);
    }

    #[test]
    fn append_randomized_failures_preserve_the_fence_and_phase_invariants() {
        let mut rng = Rng(0xC0FFEE);
        for case in 0..400u64 {
            let len = match rng.below(10) {
                0 => 0,
                1 => 1,
                2 => STREAM_CHUNK as u64 + rng.below(3),
                3 => 2 * STREAM_CHUNK as u64 + rng.below(40_000),
                _ => rng.below(30_000),
            } as usize;
            let body = rng.bytes(len);
            let cmd = command_bytes(len as u64);
            let response: Vec<u8> = match rng.below(5) {
                0 => OK.to_vec(),
                1 => b"+ ready\r\na1 NO [TOOBIG] x\r\n".to_vec(),
                2 => b"+ ready\r\n".to_vec(),
                3 => b"a1 NO [OVERQUOTA] pre\r\n".to_vec(),
                _ => OK.to_vec(),
            };
            let mut wire = Wire::new(
                response,
                case,
                [1usize, 3, 64, 1 << 16][rng.below(4) as usize],
            );
            wire.max_write = [1usize, 5, 4096, usize::MAX / 4][rng.below(4) as usize];
            let write_failure = rng.below(3) == 0;
            if write_failure {
                wire.fail_write_at = Some(rng.below((cmd.len() + len + 3) as u64) as usize);
            }
            let reader_cut = if rng.below(4) == 0 {
                Some(rng.below(len as u64 + 1) as usize)
            } else {
                None
            };
            let mut reader = &body[..reader_cut.unwrap_or(len)];
            let a = append(wire, &body, &mut reader, len as u64);
            let (w, o) = (&a.written, &a.out);
            // Written bytes always follow the command, then the body, then CRLF, never more.
            let mut full = cmd.clone();
            full.extend_from_slice(&body);
            full.extend_from_slice(b"\r\n");
            assert!(
                full.starts_with(w),
                "case {case}: unexpected bytes on the wire"
            );
            // The fence: nothing past the command line unless the guard ran and phase says so.
            if o.phase < AppendPhase::BodyStarted {
                assert!(
                    w.len() <= cmd.len(),
                    "case {case}: body bytes sent in phase {:?}",
                    o.phase
                );
            }
            if o.phase == AppendPhase::Authorized {
                assert_eq!(a.guard_calls, 1, "case {case}");
                assert_eq!(w.len(), cmd.len(), "case {case}");
            }
            if w.len() > cmd.len() {
                assert_eq!(
                    a.guard_calls, 1,
                    "case {case}: body written without authorization"
                );
                assert!(o.phase >= AppendPhase::BodyStarted, "case {case}");
                assert_eq!(a.written_at_guard, Some(cmd.len()), "case {case}");
            }
            assert!(a.guard_calls <= 1);
            // The count is informational (see its docs): bounded by the length, zero before any
            // body write, and the wire never carries more than the declared literal.
            assert!(o.body_bytes_sent <= len as u64, "case {case}");
            if o.phase < AppendPhase::BodyStarted {
                assert_eq!(o.body_bytes_sent, 0, "case {case}");
            }
            assert!(w.len() <= cmd.len() + len + 2, "case {case}");
            if o.result.is_ok() {
                assert_eq!(o.phase, AppendPhase::Responded);
                assert_eq!(
                    w, &full,
                    "case {case}: success must mean the exact literal was sent"
                );
                assert_eq!(o.body_bytes_sent, len as u64);
                assert!(!a.desynced);
            }
            if o.phase == AppendPhase::Responded && o.result.is_err() {
                assert!(matches!(o.result, Err(Error::No(_) | Error::Bad(_))));
            }
            if o.result.is_err() && !matches!(o.result, Err(Error::No(_) | Error::Bad(_))) {
                assert!(
                    a.desynced,
                    "case {case}: an unsettled failure must poison the connection"
                );
            }
        }
    }
}
