//! Real-socket checks of the vendored client's streaming FETCH and APPEND (phase 2).
//!
//! A loopback TCP server generates and consumes the literal on the fly, so no thread but
//! the client ever holds the message. A tracking allocator counts allocation made by the
//! CLIENT THREAD ONLY, which proves the memory bound directly instead of estimating it.
//! The migration engine does not use these methods yet.
use imap::{AppendPhase, Client, STREAM_CHUNK};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    io::{self, BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex},
    thread,
};

// ---------------------------------------------------------------- tracking allocator
thread_local! {
    static ON: Cell<bool> = const { Cell::new(false) };
    static CURRENT: Cell<isize> = const { Cell::new(0) };
    static PEAK: Cell<isize> = const { Cell::new(0) };
}
struct Tracking;
fn note(delta: isize) {
    let _ = ON.try_with(|on| {
        if on.get() {
            let _ = CURRENT.try_with(|c| {
                c.set(c.get() + delta);
                let _ = PEAK.try_with(|p| p.set(p.get().max(c.get())));
            });
        }
    });
}
unsafe impl GlobalAlloc for Tracking {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(l) };
        if !p.is_null() {
            note(l.size() as isize);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) };
        note(-(l.size() as isize));
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        let q = unsafe { System.realloc(p, l, new) };
        if !q.is_null() {
            note(new as isize - l.size() as isize);
        }
        q
    }
}
#[global_allocator]
static ALLOCATOR: Tracking = Tracking;

/// Peak bytes allocated by this thread while `f` ran, above what was live when it started.
fn peak_during<R>(f: impl FnOnce() -> R) -> (R, isize) {
    CURRENT.with(|c| c.set(0));
    PEAK.with(|p| p.set(0));
    ON.with(|on| on.set(true));
    let r = f();
    ON.with(|on| on.set(false));
    (r, PEAK.with(Cell::get))
}

// ---------------------------------------------------------------- deterministic content
fn byte_at(i: u64) -> u8 {
    (i.wrapping_mul(31) ^ (i >> 8).wrapping_mul(17) ^ (i >> 20)) as u8
}
fn fill(offset: u64, buf: &mut [u8]) {
    for (k, b) in buf.iter_mut().enumerate() {
        *b = byte_at(offset + k as u64);
    }
}
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
struct Fnv(u64);
impl Fnv {
    fn new() -> Fnv {
        Fnv(0xcbf29ce484222325)
    }
    fn update(&mut self, data: &[u8]) {
        for b in data {
            self.0 = (self.0 ^ u64::from(*b)).wrapping_mul(0x100000001b3);
        }
    }
}
fn expected_hash(len: u64) -> Fnv {
    let (mut h, mut buf, mut off) = (Fnv::new(), vec![0u8; 64 * 1024], 0u64);
    while off < len {
        let n = (len - off).min(buf.len() as u64) as usize;
        fill(off, &mut buf[..n]);
        h.update(&buf[..n]);
        off += n as u64;
    }
    h
}
struct PatternReader(u64, u64);
impl Read for PatternReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = (self.1 - self.0).min(buf.len() as u64) as usize;
        fill(self.0, &mut buf[..n]);
        self.0 += n as u64;
        Ok(n)
    }
}

// ---------------------------------------------------------------- loopback server
#[derive(Clone, Default)]
struct Received(Arc<Mutex<Option<(u64, Fnv)>>>);
struct Server {
    port: u16,
    received: Received,
}
/// `cut_fetch_at`: close the connection after that many literal bytes.
fn serve(fetch_len: u64, cut_fetch_at: Option<u64>) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let received = Received::default();
    let got = received.clone();
    thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut out = stream.try_clone().unwrap();
        let mut input = BufReader::new(stream);
        out.write_all(b"* OK ready\r\n").unwrap();
        let mut line = String::new();
        loop {
            line.clear();
            if input.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
            let mut parts = line.trim_end().splitn(3, ' ');
            let (tag, verb) = (
                parts.next().unwrap().to_string(),
                parts.next().unwrap_or("").to_ascii_uppercase(),
            );
            let rest = parts.next().unwrap_or("").to_string();
            match verb.as_str() {
                "LOGIN" | "NOOP" => out
                    .write_all(format!("{tag} OK done\r\n").as_bytes())
                    .unwrap(),
                "LOGOUT" => {
                    out.write_all(format!("* BYE\r\n{tag} OK bye\r\n").as_bytes())
                        .unwrap();
                    return;
                }
                "UID" => {
                    assert!(
                        rest.contains("BODY.PEEK[]") && !rest.contains(" BODY[]"),
                        "source must only be PEEKed: {rest}"
                    );
                    out.write_all(format!("* 1 FETCH (UID 1 FLAGS (\\Seen) INTERNALDATE \"02-Jan-2020 03:04:05 +0000\" BODY[] {{{fetch_len}}}\r\n").as_bytes())
                        .unwrap();
                    let (mut off, mut buf) = (0u64, vec![0u8; 37_777]); // odd size: fragmentation
                    let limit = cut_fetch_at.unwrap_or(fetch_len);
                    while off < limit {
                        let n = (limit - off).min(buf.len() as u64) as usize;
                        fill(off, &mut buf[..n]);
                        out.write_all(&buf[..n]).unwrap();
                        off += n as u64;
                    }
                    if cut_fetch_at.is_some() {
                        return; // drop the socket mid-literal
                    }
                    out.write_all(format!(")\r\n{tag} OK UID FETCH completed\r\n").as_bytes())
                        .unwrap();
                }
                "APPEND" => {
                    let n: u64 = rest
                        .rsplit('{')
                        .next()
                        .unwrap()
                        .trim_end_matches('}')
                        .parse()
                        .unwrap();
                    out.write_all(b"+ ready\r\n").unwrap();
                    let (mut h, mut left, mut buf) = (Fnv::new(), n, vec![0u8; 64 * 1024]);
                    while left > 0 {
                        let want = left.min(buf.len() as u64) as usize;
                        let k = input.read(&mut buf[..want]).unwrap();
                        assert!(k > 0, "client closed mid-literal");
                        h.update(&buf[..k]);
                        left -= k as u64;
                    }
                    let mut crlf = [0u8; 2];
                    input.read_exact(&mut crlf).unwrap();
                    assert_eq!(&crlf, b"\r\n");
                    *got.0.lock().unwrap() = Some((n, h));
                    out.write_all(
                        format!("{tag} OK [APPENDUID 5 9] APPEND completed\r\n").as_bytes(),
                    )
                    .unwrap();
                }
                other => panic!("unexpected command {other}"),
            }
        }
    });
    Server { port, received }
}
fn session(port: u16) -> imap::Session<TcpStream> {
    let mut client = Client::new(TcpStream::connect(("127.0.0.1", port)).unwrap());
    client.read_greeting().unwrap();
    client.login("u", "p").map_err(|e| e.0).unwrap()
}

const BIG: u64 = 24 << 20;
/// Chunk buffer + two 8 KiB stream buffers + skeleton and small vectors, with headroom.
const BOUND: isize = 1 << 20;

#[test]
fn streaming_fetch_over_a_real_socket_is_exact_and_bounded() {
    let server = serve(BIG, None);
    let mut s = session(server.port);
    let mut hash = Fnv::new();
    let mut seen = 0u64;
    let (fetched, peak) = peak_during(|| {
        s.uid_fetch_body_stream(1, BIG, &mut |c| {
            hash.update(c);
            seen += c.len() as u64;
            Ok(())
        })
    });
    let fetched = fetched.unwrap();
    assert_eq!((fetched.body_len, seen), (Some(BIG), BIG));
    assert_eq!(hash, expected_hash(BIG), "streamed bytes must be exact");
    assert!(fetched.skeleton.len() < 256);
    eprintln!(
        "MEASURED streaming FETCH of {} MiB: client thread peak allocation {} KiB",
        BIG >> 20,
        peak / 1024
    );
    assert!(
        peak < BOUND,
        "client allocated {peak} bytes while streaming {BIG}"
    );
    assert!(!s.is_desynced());
    s.noop().unwrap(); // the connection is in sync and reusable afterwards
}

#[test]
fn control_a_buffered_fetch_is_visibly_unbounded_so_the_measurement_is_meaningful() {
    let small = 8u64 << 20;
    let server = serve(small, None);
    let mut s = session(server.port);
    let (r, peak) = peak_during(|| s.run("UID FETCH 1 (UID FLAGS INTERNALDATE BODY.PEEK[])"));
    r.unwrap();
    eprintln!(
        "MEASURED control (buffered run) of {} MiB: client thread peak allocation {} KiB",
        small >> 20,
        peak / 1024
    );
    assert!(
        peak >= small as isize,
        "the allocator must see a buffered transfer ({peak})"
    );
}

#[test]
fn streaming_append_over_a_real_socket_is_exact_authorized_first_and_bounded() {
    let server = serve(0, None);
    let mut s = session(server.port);
    let guard_calls = Cell::new(0);
    let (out, peak) = peak_during(|| {
        let mut cmd = s.append_stream("INBOX");
        cmd.finish_streaming(BIG, &mut PatternReader(0, BIG), || {
            guard_calls.set(guard_calls.get() + 1);
            Ok(())
        })
    });
    assert_eq!(
        (out.phase, out.body_bytes_sent, guard_calls.get()),
        (AppendPhase::Responded, BIG, 1)
    );
    let appended = out.result.unwrap();
    assert_eq!(
        (appended.uid_validity, appended.uids.is_some()),
        (Some(5), true)
    );
    eprintln!(
        "MEASURED streaming APPEND of {} MiB: client thread peak allocation {} KiB",
        BIG >> 20,
        peak / 1024
    );
    assert!(
        peak < BOUND,
        "client allocated {peak} bytes while streaming {BIG}"
    );
    let (n, h) = server.received.0.lock().unwrap().unwrap();
    assert_eq!(
        (n, h),
        (BIG, expected_hash(BIG)),
        "the server must have received the exact literal"
    );
    assert!(STREAM_CHUNK < BOUND as usize);
}

#[test]
fn a_server_that_drops_mid_literal_fails_safely_and_poisons_the_connection() {
    let server = serve(10 << 20, Some(3 << 20));
    let mut s = session(server.port);
    let mut seen = 0u64;
    let r = s.uid_fetch_body_stream(1, 10 << 20, &mut |c| {
        seen += c.len() as u64;
        Ok(())
    });
    assert!(r.is_err(), "a truncated literal must never succeed");
    assert!(seen < 10 << 20);
    assert!(s.is_desynced());
    assert!(
        s.noop().is_err(),
        "no further command may be sent on a poisoned connection"
    );
}

#[test]
fn a_length_the_caller_did_not_expect_is_refused_before_any_body_is_read() {
    let server = serve(1000, None);
    let mut s = session(server.port);
    let mut seen = 0u64;
    let r = s.uid_fetch_body_stream(1, 999, &mut |c| {
        seen += c.len() as u64;
        Ok(())
    });
    assert!(matches!(
        r,
        Err(imap::Error::Stream(
            imap::error::StreamError::LiteralLengthMismatch
        ))
    ));
    assert_eq!(seen, 0);
    assert!(s.is_desynced());
}
