//! Hardened TLS ClientHello parsing and record-level fragmentation.
//!
//! Everything here operates on caller-provided byte slices, never panics on
//! malformed input, and has hard upper bounds on the amount of data it will
//! ever consider (see [`MAX_HANDSHAKE_LEN`] and [`MAX_STREAM_BYTES`]).
//! Nothing is decrypted: a ClientHello is plaintext by design.

use std::ops::Range;

/// TLS record header length.
pub const RECORD_HEADER_LEN: usize = 5;
/// Maximum TLS record payload length (RFC 8446 §5.1).
pub const MAX_RECORD_PAYLOAD: usize = 16 * 1024;
/// Upper bound on a ClientHello handshake message we are willing to buffer.
pub const MAX_HANDSHAKE_LEN: usize = 32 * 1024;
/// Upper bound on the raw stream bytes needed to hold a ClientHello and its record headers.
pub const MAX_STREAM_BYTES: usize = MAX_HANDSHAKE_LEN + 8 * RECORD_HEADER_LEN + MAX_RECORD_PAYLOAD;

const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const EXT_SERVER_NAME: u16 = 0;

/// Parsed facts about a ClientHello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHelloInfo {
    /// Validated, lower-cased SNI host name, if present and well-formed.
    pub sni: Option<String>,
    /// Byte range of the host name inside the reassembled handshake message
    /// (offsets include the 4-byte handshake header).
    pub sni_range: Option<Range<usize>>,
    /// Length of the handshake message including its 4-byte header.
    pub handshake_len: usize,
    /// Number of stream bytes occupied by the records carrying the hello.
    pub consumed: usize,
    /// Number of handshake bytes following the ClientHello inside the last record.
    pub trailing: usize,
    /// Legacy record-layer version bytes of the first record.
    pub record_version: [u8; 2],
    /// Number of TLS records the hello was spread over.
    pub record_count: usize,
}

/// Result of inspecting the start of a client byte stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    /// More bytes are required; the hello is still plausible.
    NeedMore,
    /// A complete ClientHello. `handshake` is the reassembled handshake message.
    Hello {
        info: ClientHelloInfo,
        handshake: Vec<u8>,
    },
    /// The stream is not a TLS handshake that starts with a ClientHello.
    NotClientHello,
    /// Looks like a ClientHello but is structurally invalid or too large.
    Malformed(&'static str),
}

/// Inspect `buf` (the first bytes the client sent on a connection).
///
/// Handles ClientHellos split over several TCP segments (call again with the
/// grown buffer after [`Parsed::NeedMore`]) and over several TLS records.
pub fn parse_client_hello(buf: &[u8]) -> Parsed {
    if buf.len() > MAX_STREAM_BYTES {
        return Parsed::Malformed("stream prefix too large");
    }
    let mut pos = 0usize;
    let mut hs: Vec<u8> = Vec::new();
    let mut record_version = [0u8; 2];
    let mut records = 0usize;
    loop {
        let rest = &buf[pos..];
        // Early rejection so non-TLS streams never make us wait for more data.
        if !rest.is_empty() && rest[0] != CONTENT_TYPE_HANDSHAKE {
            return Parsed::NotClientHello;
        }
        if rest.len() >= 2 && rest[1] != 0x03 {
            return Parsed::NotClientHello;
        }
        if rest.len() >= 3 && rest[2] > 0x04 {
            return Parsed::NotClientHello;
        }
        if rest.len() < RECORD_HEADER_LEN {
            return Parsed::NeedMore;
        }
        let len = u16::from_be_bytes([rest[3], rest[4]]) as usize;
        if len == 0 || len > MAX_RECORD_PAYLOAD {
            return Parsed::Malformed("bad record length");
        }
        if rest.len() < RECORD_HEADER_LEN + len {
            // Validate what we can of the handshake header already available.
            return Parsed::NeedMore;
        }
        if records == 0 {
            record_version = [rest[1], rest[2]];
        }
        records += 1;
        if records > 16 {
            return Parsed::Malformed("too many records");
        }
        hs.extend_from_slice(&rest[RECORD_HEADER_LEN..RECORD_HEADER_LEN + len]);
        pos += RECORD_HEADER_LEN + len;

        if !hs.is_empty() && hs[0] != HANDSHAKE_CLIENT_HELLO {
            return Parsed::NotClientHello;
        }
        if hs.len() >= 4 {
            let hs_len = u32::from_be_bytes([0, hs[1], hs[2], hs[3]]) as usize;
            if hs_len > MAX_HANDSHAKE_LEN {
                return Parsed::Malformed("handshake too large");
            }
            let total = 4 + hs_len;
            if hs.len() >= total {
                let trailing = hs.len() - total;
                hs.truncate(total);
                return match parse_body(&hs) {
                    Some((sni, sni_range)) => Parsed::Hello {
                        info: ClientHelloInfo {
                            sni,
                            sni_range,
                            handshake_len: total,
                            consumed: pos,
                            trailing,
                            record_version,
                            record_count: records,
                        },
                        handshake: hs,
                    },
                    None => Parsed::Malformed("invalid client hello body"),
                };
            }
        }
        // Handshake incomplete: loop to read the next record (or ask for more).
    }
}

/// Bounds-checked cursor.
struct Cur<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.p.checked_add(n)?;
        let s = self.b.get(self.p..end)?;
        self.p = end;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|s| u16::from_be_bytes([s[0], s[1]]))
    }
}

/// Returns `(sni, sni_range)` or `None` if the body is structurally invalid.
fn parse_body(hs: &[u8]) -> Option<(Option<String>, Option<Range<usize>>)> {
    let mut c = Cur { b: hs, p: 4 };
    c.take(2)?; // legacy_version
    c.take(32)?; // random
    let sid = c.u8()? as usize;
    if sid > 32 {
        return None;
    }
    c.take(sid)?;
    let cs = c.u16()? as usize;
    if cs < 2 || cs % 2 != 0 {
        return None;
    }
    c.take(cs)?;
    let comp = c.u8()? as usize;
    if comp == 0 {
        return None;
    }
    c.take(comp)?;
    if c.p == hs.len() {
        // No extensions at all (TLS ≤1.1 style hello): valid, but no SNI.
        return Some((None, None));
    }
    let ext_total = c.u16()? as usize;
    let ext_end = c.p.checked_add(ext_total)?;
    if ext_end != hs.len() {
        return None;
    }
    let mut sni = None;
    let mut range = None;
    while c.p < ext_end {
        let ty = c.u16()?;
        let len = c.u16()? as usize;
        let data_start = c.p;
        let data = c.take(len)?;
        if data_start + len > ext_end {
            return None;
        }
        if ty == EXT_SERVER_NAME && sni.is_none() {
            let mut e = Cur { b: data, p: 0 };
            let list_len = e.u16()? as usize;
            if e.p + list_len != data.len() {
                return None;
            }
            while e.p < data.len() {
                let name_type = e.u8()?;
                let nlen = e.u16()? as usize;
                let off = e.p;
                let name = e.take(nlen)?;
                if name_type == 0 {
                    if let Some(h) = sanitize_host(name) {
                        sni = Some(h);
                        range = Some(data_start + off..data_start + off + nlen);
                    }
                    break;
                }
            }
        }
    }
    Some((sni, range))
}

/// Accept only plain DNS host names (LDH + underscore + dots), 1..=253 bytes.
pub fn sanitize_host(raw: &[u8]) -> Option<String> {
    if raw.is_empty() || raw.len() > 253 {
        return None;
    }
    let mut s = String::with_capacity(raw.len());
    for &b in raw {
        match b {
            b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' => s.push(b as char),
            b'A'..=b'Z' => s.push(b.to_ascii_lowercase() as char),
            _ => return None,
        }
    }
    if s.starts_with('.') || s.contains("..") {
        return None;
    }
    Some(s.trim_end_matches('.').to_string()).filter(|h| !h.is_empty())
}

/// How a ClientHello is put on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitMode {
    /// Two TLS records written back-to-back in a single write.
    Records,
    /// Two TLS records, each written (and flushed) separately so they leave in separate TCP segments.
    RecordsTcp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitError {
    NoSni,
    Unsplittable,
}

/// Re-encode `handshake` as two TLS records split inside the SNI host name.
///
/// Returns the chunks to write; each chunk must be written with a flush after it.
/// The concatenation of record payloads equals the original handshake message, so TLS
/// semantics (and the transcript hash) are untouched.
pub fn split_client_hello(
    handshake: &[u8],
    info: &ClientHelloInfo,
    mode: SplitMode,
) -> Result<Vec<Vec<u8>>, SplitError> {
    if info.trailing != 0 || handshake.len() != info.handshake_len {
        return Err(SplitError::Unsplittable);
    }
    let range = info.sni_range.clone().ok_or(SplitError::NoSni)?;
    if range.end > handshake.len() || range.is_empty() {
        return Err(SplitError::Unsplittable);
    }
    let at = split_point(&range);
    if at == 0 || at >= handshake.len() {
        return Err(SplitError::Unsplittable);
    }
    let r1 = encode_record(info.record_version, &handshake[..at]);
    let r2 = encode_record(info.record_version, &handshake[at..]);
    match mode {
        SplitMode::Records => {
            let mut one = r1;
            one.extend_from_slice(&r2);
            Ok(vec![one])
        }
        SplitMode::RecordsTcp => Ok(vec![r1, r2]),
    }
}

/// Deterministic split position: the middle of the host name (always strictly inside it for len ≥ 2).
pub fn split_point(range: &Range<usize>) -> usize {
    range.start + ((range.end - range.start) / 2).max(1)
}

fn encode_record(version: [u8; 2], payload: &[u8]) -> Vec<u8> {
    debug_assert!(payload.len() <= MAX_RECORD_PAYLOAD);
    let mut v = Vec::with_capacity(RECORD_HEADER_LEN + payload.len());
    v.push(CONTENT_TYPE_HANDSHAKE);
    v.extend_from_slice(&version);
    v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// Helpers for building synthetic ClientHellos in tests and the integration harness.
#[cfg(any(test, feature = "testutil"))]
pub mod testutil {
    /// Build a plausible TLS 1.3 ClientHello handshake message (with 4-byte header) for `sni`.
    pub fn client_hello_handshake(sni: Option<&str>, pad_to: usize) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x42; 32]);
        body.push(32);
        body.extend_from_slice(&[0x07; 32]);
        let suites: [u16; 4] = [0x1301, 0x1302, 0x1303, 0xc02b];
        body.extend_from_slice(&((suites.len() * 2) as u16).to_be_bytes());
        for s in suites {
            body.extend_from_slice(&s.to_be_bytes());
        }
        body.extend_from_slice(&[1, 0]);
        let mut ext = Vec::new();
        if let Some(h) = sni {
            let hb = h.as_bytes();
            let mut e = Vec::new();
            e.extend_from_slice(&((hb.len() + 3) as u16).to_be_bytes());
            e.push(0);
            e.extend_from_slice(&(hb.len() as u16).to_be_bytes());
            e.extend_from_slice(hb);
            ext.extend_from_slice(&0u16.to_be_bytes());
            ext.extend_from_slice(&(e.len() as u16).to_be_bytes());
            ext.extend_from_slice(&e);
        }
        // supported_versions, supported_groups, key_share (x25519)
        ext.extend_from_slice(&[0, 43, 0, 3, 2, 3, 4]);
        ext.extend_from_slice(&[0, 10, 0, 4, 0, 2, 0, 29]);
        ext.extend_from_slice(&[0, 51, 0, 38, 0, 36, 0, 29, 0, 32]);
        ext.extend_from_slice(&[0x55; 32]);
        if pad_to > 0 {
            let cur = 4 + body.len() + 2 + ext.len() + 4;
            if pad_to > cur {
                let n = pad_to - cur;
                ext.extend_from_slice(&[0, 21]);
                ext.extend_from_slice(&(n as u16).to_be_bytes());
                ext.extend(std::iter::repeat_n(0u8, n));
            }
        }
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut hs = vec![1];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        hs
    }

    /// Wrap a handshake message in one TLS record.
    pub fn one_record(hs: &[u8]) -> Vec<u8> {
        let mut v = vec![0x16, 0x03, 0x01];
        v.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        v.extend_from_slice(hs);
        v
    }

    /// Wrap a handshake message in records of at most `chunk` payload bytes.
    pub fn many_records(hs: &[u8], chunk: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for c in hs.chunks(chunk) {
            out.extend_from_slice(&one_record(c));
        }
        out
    }

    /// A complete single-record ClientHello for `sni`.
    pub fn client_hello(sni: &str) -> Vec<u8> {
        one_record(&client_hello_handshake(Some(sni), 0))
    }

    pub fn from_hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;
    use proptest::prelude::*;

    fn hello(buf: &[u8]) -> (ClientHelloInfo, Vec<u8>) {
        match parse_client_hello(buf) {
            Parsed::Hello { info, handshake } => (info, handshake),
            other => panic!("expected hello, got {other:?}"),
        }
    }

    #[test]
    fn parses_sni_single_record() {
        let raw = client_hello("Discord.COM");
        let (info, hs) = hello(&raw);
        assert_eq!(info.sni.as_deref(), Some("discord.com"));
        assert_eq!(info.consumed, raw.len());
        assert_eq!(info.record_count, 1);
        let r = info.sni_range.unwrap();
        assert_eq!(&hs[r], b"Discord.COM");
    }

    #[test]
    fn every_prefix_needs_more_never_panics() {
        let raw = client_hello("example.org");
        for n in 0..raw.len() {
            assert_eq!(
                parse_client_hello(&raw[..n]),
                Parsed::NeedMore,
                "prefix {n}"
            );
        }
        assert!(matches!(parse_client_hello(&raw), Parsed::Hello { .. }));
    }

    #[test]
    fn multi_record_hello_is_reassembled() {
        let hs = client_hello_handshake(Some("multi.example.net"), 600);
        for chunk in [1usize, 7, 64, 200] {
            let raw = many_records(&hs, chunk);
            if raw.len() / (chunk + 5) > 16 {
                continue;
            }
            let (info, got) = hello(&raw);
            assert_eq!(got, hs);
            assert_eq!(info.sni.as_deref(), Some("multi.example.net"));
            assert!(info.record_count > 1);
            assert_eq!(info.consumed, raw.len());
        }
    }

    #[test]
    fn too_many_records_rejected() {
        let hs = client_hello_handshake(Some("a.example"), 0);
        let raw = many_records(&hs, 1);
        assert!(matches!(parse_client_hello(&raw), Parsed::Malformed(_)));
    }

    #[test]
    fn non_tls_is_rejected_immediately() {
        assert_eq!(
            parse_client_hello(b"GET / HTTP/1.1\r\n"),
            Parsed::NotClientHello
        );
        assert_eq!(parse_client_hello(&[0x16, 0x04]), Parsed::NotClientHello);
        assert_eq!(
            parse_client_hello(&[0x17, 0x03, 0x03, 0, 5]),
            Parsed::NotClientHello
        );
        // Handshake but ServerHello (type 2)
        assert_eq!(
            parse_client_hello(&[0x16, 3, 3, 0, 4, 2, 0, 0, 0]),
            Parsed::NotClientHello
        );
    }

    #[test]
    fn hello_without_sni() {
        let raw = one_record(&client_hello_handshake(None, 0));
        let (info, _) = hello(&raw);
        assert_eq!(info.sni, None);
        assert_eq!(info.sni_range, None);
    }

    #[test]
    fn rejects_bad_sni_characters() {
        let raw = client_hello("evil host");
        let (info, _) = hello(&raw);
        assert_eq!(info.sni, None);
        for bad in ["a..b", ".a", "a/b", "a\u{e9}"] {
            assert_eq!(sanitize_host(bad.as_bytes()), None, "{bad}");
        }
        assert_eq!(sanitize_host(b"EXAMPLE.com."), Some("example.com".into()));
    }

    #[test]
    fn oversized_handshake_is_malformed() {
        let mut raw = vec![0x16, 3, 1, 0, 8, 1, 0xff, 0xff, 0xff];
        raw.extend_from_slice(&[0; 4]);
        assert!(matches!(parse_client_hello(&raw), Parsed::Malformed(_)));
    }

    #[test]
    fn zero_length_record_is_malformed() {
        assert!(matches!(
            parse_client_hello(&[0x16, 3, 1, 0, 0]),
            Parsed::Malformed(_)
        ));
    }

    #[test]
    fn extension_length_lies_are_malformed() {
        let mut hs = client_hello_handshake(Some("a.example"), 0);
        let n = hs.len();
        // corrupt the extensions total length
        let ext_len_pos = 4 + 2 + 32 + 1 + 32 + 2 + 8 + 2;
        hs[ext_len_pos] = hs[ext_len_pos].wrapping_add(1);
        assert!(n > ext_len_pos);
        assert!(matches!(
            parse_client_hello(&one_record(&hs)),
            Parsed::Malformed(_)
        ));
    }

    #[test]
    fn real_openssl_client_hello_sample() {
        // Captured from `openssl s_client -servername discord.com` (OpenSSL 3.x, TLS 1.3).
        let raw = from_hex(include_str!("../testdata/openssl_discord.hex"));
        let (info, _) = hello(&raw);
        assert_eq!(info.sni.as_deref(), Some("discord.com"));
        assert_eq!(info.consumed, raw.len());
    }

    #[test]
    fn real_curl_client_hello_sample() {
        let raw = from_hex(include_str!("../testdata/curl_example.hex"));
        let (info, _) = hello(&raw);
        assert_eq!(info.sni.as_deref(), Some("example.com"));
    }

    #[test]
    fn split_records_is_lossless_and_inside_sni() {
        let raw = client_hello("blocked.example.com");
        let (info, hs) = hello(&raw);
        for mode in [SplitMode::Records, SplitMode::RecordsTcp] {
            let chunks = split_client_hello(&hs, &info, mode).unwrap();
            assert_eq!(chunks.len(), if mode == SplitMode::Records { 1 } else { 2 });
            let wire: Vec<u8> = chunks.concat();
            // Must still be parseable as a (two-record) ClientHello with identical content.
            let (info2, hs2) = hello(&wire);
            assert_eq!(hs2, hs);
            assert_eq!(info2.record_count, 2);
            assert_eq!(info2.sni, info.sni);
            // Split is strictly inside the host name: neither record contains it whole.
            let host = b"blocked.example.com";
            let first = &wire[RECORD_HEADER_LEN..];
            let len1 = u16::from_be_bytes([wire[3], wire[4]]) as usize;
            let p1 = &first[..len1];
            assert!(!p1.windows(host.len()).any(|w| w == host));
            let p2 = &wire[RECORD_HEADER_LEN + len1 + RECORD_HEADER_LEN..];
            assert!(!p2.windows(host.len()).any(|w| w == host));
            assert_eq!(wire[0], 0x16);
            assert_eq!(&wire[1..3], &[3, 1]);
        }
    }

    #[test]
    fn split_refuses_without_sni_or_with_trailing() {
        let raw = one_record(&client_hello_handshake(None, 0));
        let (info, hs) = hello(&raw);
        assert_eq!(
            split_client_hello(&hs, &info, SplitMode::Records),
            Err(SplitError::NoSni)
        );
        let mut hs2 = client_hello_handshake(Some("a.example"), 0);
        hs2.extend_from_slice(&[0, 0, 0, 0]);
        let (info2, hs3) = hello(&one_record(&hs2));
        assert_eq!(info2.trailing, 4);
        assert_eq!(
            split_client_hello(&hs3, &info2, SplitMode::Records),
            Err(SplitError::Unsplittable)
        );
    }

    #[test]
    fn split_of_multi_record_hello_reassembles_first() {
        let hs = client_hello_handshake(Some("multi.example.net"), 900);
        let raw = many_records(&hs, 300);
        let (info, got) = hello(&raw);
        let chunks = split_client_hello(&got, &info, SplitMode::RecordsTcp).unwrap();
        let (info2, hs2) = hello(&chunks.concat());
        assert_eq!(hs2, hs);
        assert_eq!(info2.record_count, 2);
    }

    #[test]
    fn split_point_edge_cases() {
        assert_eq!(split_point(&(10..12)), 11);
        assert_eq!(split_point(&(10..11)), 11); // degenerate 1-byte host: caller bounds-checks
        assert_eq!(split_point(&(10..30)), 20);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn arbitrary_bytes_never_panic(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let _ = parse_client_hello(&data);
        }

        #[test]
        fn mutated_valid_hello_never_panics(
            idx in 0usize..400, val in any::<u8>(), cut in 0usize..400,
        ) {
            let mut raw = client_hello("fuzz.example.org");
            let i = idx % raw.len();
            raw[i] = val;
            raw.truncate(raw.len().saturating_sub(cut % 8));
            let _ = parse_client_hello(&raw);
        }

        #[test]
        fn split_roundtrips_for_any_host(label in "[a-z0-9]{2,30}", pad in 0usize..2000) {
            let host = format!("{label}.example.com");
            let hs = client_hello_handshake(Some(&host), pad);
            let raw = one_record(&hs);
            let (info, got) = hello(&raw);
            prop_assert_eq!(&got, &hs);
            let chunks = split_client_hello(&got, &info, SplitMode::RecordsTcp).unwrap();
            let (info2, hs2) = hello(&chunks.concat());
            prop_assert_eq!(hs2, hs);
            prop_assert_eq!(info2.sni.as_deref(), Some(host.as_str()));
        }

        #[test]
        fn chunked_arrival_is_equivalent(split in 1usize..300) {
            let raw = client_hello("chunk.example.com");
            let split = split.min(raw.len() - 1);
            prop_assert_eq!(parse_client_hello(&raw[..split]), Parsed::NeedMore);
            let is_hello = matches!(parse_client_hello(&raw), Parsed::Hello { .. });
            prop_assert!(is_hello);
        }
    }
}
