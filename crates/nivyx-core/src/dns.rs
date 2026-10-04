//! Minimal, bounds-checked DNS wire helpers, a bounded response cache, and
//! classification of names that must never leave the local network.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
pub const MAX_DNS_MESSAGE: usize = 4096;

const HEADER_LEN: usize = 12;
const MAX_NAME_JUMPS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub id: u16,
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    pub recursion_desired: bool,
}

/// Read a (possibly compressed) name. Returns the dotted lower-case name and the
/// position just after the name field at `start`.
fn read_name(msg: &[u8], start: usize) -> Option<(String, usize)> {
    let mut out = String::new();
    let mut pos = start;
    let mut end: Option<usize> = None;
    let mut jumps = 0;
    loop {
        let len = *msg.get(pos)? as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        match len & 0xC0 {
            0x00 => {
                let label = msg.get(pos + 1..pos + 1 + len)?;
                if !out.is_empty() {
                    out.push('.');
                }
                if out.len() + len > 253 {
                    return None;
                }
                for &b in label {
                    out.push(b.to_ascii_lowercase() as char);
                }
                pos += 1 + len;
            }
            0xC0 => {
                let lo = *msg.get(pos + 1)? as usize;
                let ptr = ((len & 0x3F) << 8) | lo;
                if end.is_none() {
                    end = Some(pos + 2);
                }
                jumps += 1;
                if jumps > MAX_NAME_JUMPS || ptr >= msg.len() {
                    return None;
                }
                pos = ptr;
            }
            _ => return None,
        }
    }
    Some((out, end.unwrap_or(pos)))
}

/// Parse the first question of a DNS message.
pub fn parse_question(msg: &[u8]) -> Option<Question> {
    if msg.len() < HEADER_LEN || msg.len() > MAX_DNS_MESSAGE {
        return None;
    }
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    let qd = u16::from_be_bytes([msg[4], msg[5]]);
    if qd == 0 {
        return None;
    }
    let (name, p) = read_name(msg, HEADER_LEN)?;
    let t = msg.get(p..p + 4)?;
    Some(Question {
        id: u16::from_be_bytes([msg[0], msg[1]]),
        name,
        qtype: u16::from_be_bytes([t[0], t[1]]),
        qclass: u16::from_be_bytes([t[2], t[3]]),
        recursion_desired: flags & 0x0100 != 0,
    })
}

pub fn is_response(msg: &[u8]) -> bool {
    msg.len() >= HEADER_LEN && msg[2] & 0x80 != 0
}

pub fn rcode(msg: &[u8]) -> Option<u8> {
    (msg.len() >= HEADER_LEN).then(|| msg[3] & 0x0F)
}

/// Overwrite the transaction id.
pub fn set_id(msg: &mut [u8], id: u16) {
    if msg.len() >= 2 {
        msg[..2].copy_from_slice(&id.to_be_bytes());
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Answers {
    pub rcode: u8,
    pub addrs: Vec<IpAddr>,
    /// Smallest TTL over all answer records (any type), if any.
    pub min_ttl: Option<u32>,
    pub answer_count: usize,
}

/// Extract A/AAAA addresses and TTLs from a response.
pub fn parse_answers(msg: &[u8]) -> Option<Answers> {
    if msg.len() < HEADER_LEN || msg.len() > MAX_DNS_MESSAGE || !is_response(msg) {
        return None;
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut pos = HEADER_LEN;
    for _ in 0..qd.min(16) {
        let (_, p) = read_name(msg, pos)?;
        pos = p.checked_add(4)?;
        if pos > msg.len() {
            return None;
        }
    }
    let mut out = Answers {
        rcode: msg[3] & 0x0F,
        ..Default::default()
    };
    for _ in 0..an.min(256) {
        let (_, p) = read_name(msg, pos)?;
        let h = msg.get(p..p + 10)?;
        let ty = u16::from_be_bytes([h[0], h[1]]);
        let ttl = u32::from_be_bytes([h[4], h[5], h[6], h[7]]);
        let rdlen = u16::from_be_bytes([h[8], h[9]]) as usize;
        let rd = msg.get(p + 10..p + 10 + rdlen)?;
        out.answer_count += 1;
        out.min_ttl = Some(out.min_ttl.map_or(ttl, |m| m.min(ttl)));
        match (ty, rdlen) {
            (TYPE_A, 4) => out
                .addrs
                .push(IpAddr::V4(Ipv4Addr::new(rd[0], rd[1], rd[2], rd[3]))),
            (TYPE_AAAA, 16) => {
                let mut o = [0u8; 16];
                o.copy_from_slice(rd);
                out.addrs.push(IpAddr::V6(Ipv6Addr::from(o)));
            }
            _ => {}
        }
        pos = p + 10 + rdlen;
    }
    Some(out)
}

/// Build a response to `query` carrying `rcode` and no answers (NOERROR+empty = NODATA).
pub fn build_empty_response(query: &[u8], rcode: u8) -> Option<Vec<u8>> {
    let q = parse_question(query)?;
    let (_, qend) = read_name(query, HEADER_LEN)?;
    let qend = qend + 4;
    let mut r = Vec::with_capacity(qend);
    r.extend_from_slice(&q.id.to_be_bytes());
    let rd = if q.recursion_desired { 0x01 } else { 0x00 };
    r.push(0x80 | rd);
    r.push(0x80 | (rcode & 0x0F)); // RA + rcode
    r.extend_from_slice(&1u16.to_be_bytes());
    r.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    r.extend_from_slice(query.get(HEADER_LEN..qend)?);
    Some(r)
}

/// Build a query for tests and diagnostics.
pub fn build_query(id: u16, name: &str, qtype: u16) -> Option<Vec<u8>> {
    let mut m = Vec::new();
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.push(0);
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes());
    Some(m)
}

/// Names that belong to the local network and must be answered by the system resolver,
/// never sent to a public DoH resolver.
pub fn is_local_name(name: &str) -> bool {
    let n = name.trim_end_matches('.').to_ascii_lowercase();
    if n.is_empty() || !n.contains('.') {
        return true; // single-label names are search-domain / LAN names
    }
    const LOCAL_SUFFIXES: [&str; 11] = [
        "local",
        "localdomain",
        "localhost",
        "lan",
        "home",
        "home.arpa",
        "internal",
        "intranet",
        "corp",
        "private",
        "invalid",
    ];
    if LOCAL_SUFFIXES
        .iter()
        .any(|s| n == *s || n.ends_with(&format!(".{s}")))
    {
        return true;
    }
    if let Some(rest) = n.strip_suffix(".in-addr.arpa") {
        // reverse of an IPv4 address: d.c.b.a
        let o: Vec<u8> = rest.split('.').filter_map(|p| p.parse().ok()).collect();
        if o.len() == rest.split('.').count() && !o.is_empty() {
            // The LAST label is the first octet.
            let first = *o.last().unwrap();
            let second = if o.len() >= 2 {
                Some(o[o.len() - 2])
            } else {
                None
            };
            return match first {
                10 | 127 => true,
                192 => second == Some(168) || second.is_none(),
                172 => second.is_none_or(|s| (16..=31).contains(&s)),
                169 => second == Some(254) || second.is_none(),
                _ => false,
            };
        }
        return false;
    }
    if let Some(rest) = n.strip_suffix(".ip6.arpa") {
        // Nibble-reversed: the most significant nibbles are the LAST labels.
        let nibs: Vec<&str> = rest.split('.').collect();
        if nibs
            .iter()
            .any(|l| l.len() != 1 || !l.chars().all(|c| c.is_ascii_hexdigit()))
        {
            return false;
        }
        let top: String = nibs.iter().rev().take(3).copied().collect();
        // fc00::/7 (ULA), fe80::/10 (link-local); a full 32-nibble name for ::1 is loopback.
        let loopback = nibs.len() == 32 && nibs[0] == "1" && nibs[1..].iter().all(|l| *l == "0");
        return loopback
            || top.starts_with("fc")
            || top.starts_with("fd")
            || ["fe8", "fe9", "fea", "feb"]
                .iter()
                .any(|p| top.starts_with(p));
    }
    false
}

/// Addresses that a public name should never legitimately resolve to; seeing one in a
/// plain-DNS answer while the encrypted resolver disagrees is the classic sign of DNS tampering.
pub fn is_bogus_answer_for_public_name(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            a.is_unspecified()
                || a.is_loopback()
                || a.is_private()
                || a.is_link_local()
                || a.is_broadcast()
        }
        IpAddr::V6(a) => {
            a.is_unspecified() || a.is_loopback() || (a.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

/// Verdict of comparing a plain-DNS answer with an encrypted-DNS answer for the same public name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoisonVerdict {
    Clean,
    /// Plain answer contains an address a public name should not resolve to.
    Bogus,
    /// Answers are disjoint (can be legitimate geo/CDN variance, so only "possible").
    Disjoint,
    /// Not enough data.
    Unknown,
}

pub fn compare_answers(plain: &[IpAddr], encrypted: &[IpAddr]) -> PoisonVerdict {
    if plain.is_empty() || encrypted.is_empty() {
        return PoisonVerdict::Unknown;
    }
    if plain.iter().any(is_bogus_answer_for_public_name)
        && !encrypted.iter().any(is_bogus_answer_for_public_name)
    {
        return PoisonVerdict::Bogus;
    }
    if plain.iter().any(|a| encrypted.contains(a)) {
        PoisonVerdict::Clean
    } else {
        PoisonVerdict::Disjoint
    }
}

/// Bounded cache of whole DNS responses.
pub struct DnsCache {
    cap: usize,
    min_ttl: u32,
    max_ttl: u32,
    neg_ttl: u32,
    map: HashMap<(String, u16), (Vec<u8>, u64)>,
}

impl DnsCache {
    pub fn new(cap: usize) -> DnsCache {
        DnsCache {
            cap: cap.max(1),
            min_ttl: 10,
            max_ttl: 300,
            neg_ttl: 30,
            map: HashMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn clear(&mut self) {
        self.map.clear();
    }

    /// Returns a copy of the cached response (transaction id is the cached one; caller patches it).
    pub fn get(&mut self, name: &str, qtype: u16, now: u64) -> Option<Vec<u8>> {
        let k = (name.to_ascii_lowercase(), qtype);
        match self.map.get(&k) {
            Some((resp, exp)) if *exp > now => Some(resp.clone()),
            Some(_) => {
                self.map.remove(&k);
                None
            }
            None => None,
        }
    }

    /// Cache `resp` if it is a cacheable answer. Lifetime is clamped to 10..=300 s; NXDOMAIN/NODATA 30 s.
    pub fn put(&mut self, name: &str, qtype: u16, resp: &[u8], now: u64) {
        let Some(a) = parse_answers(resp) else { return };
        let ttl = match a.rcode {
            0 if a.answer_count > 0 => a.min_ttl.unwrap_or(0).clamp(self.min_ttl, self.max_ttl),
            0 | 3 => self.neg_ttl,
            _ => return,
        };
        if self.map.len() >= self.cap {
            self.map.retain(|_, (_, exp)| *exp > now);
            while self.map.len() >= self.cap {
                let victim = self
                    .map
                    .iter()
                    .min_by_key(|(k, (_, e))| (*e, (*k).clone()))
                    .map(|(k, _)| k.clone());
                match victim {
                    Some(k) => {
                        self.map.remove(&k);
                    }
                    None => break,
                }
            }
        }
        self.map.insert(
            (name.to_ascii_lowercase(), qtype),
            (resp.to_vec(), now + ttl as u64),
        );
    }
}

/// Build a synthetic response for tests: one A/AAAA record per address.
#[cfg(any(test, feature = "testutil"))]
pub fn build_response(query: &[u8], addrs: &[IpAddr], ttl: u32) -> Vec<u8> {
    let mut r = build_empty_response(query, 0).unwrap();
    r[6..8].copy_from_slice(&(addrs.len() as u16).to_be_bytes());
    for a in addrs {
        r.extend_from_slice(&[0xC0, 0x0C]);
        match a {
            IpAddr::V4(v) => {
                r.extend_from_slice(&[0, 1, 0, 1]);
                r.extend_from_slice(&ttl.to_be_bytes());
                r.extend_from_slice(&[0, 4]);
                r.extend_from_slice(&v.octets());
            }
            IpAddr::V6(v) => {
                r.extend_from_slice(&[0, 28, 0, 1]);
                r.extend_from_slice(&ttl.to_be_bytes());
                r.extend_from_slice(&[0, 16]);
                r.extend_from_slice(&v.octets());
            }
        }
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn question_roundtrip() {
        let q = build_query(0xBEEF, "Discord.com", TYPE_AAAA).unwrap();
        let p = parse_question(&q).unwrap();
        assert_eq!(p.id, 0xBEEF);
        assert_eq!(p.name, "discord.com");
        assert_eq!(p.qtype, TYPE_AAAA);
        assert!(p.recursion_desired);
    }

    #[test]
    fn response_parsing_with_compression() {
        let q = build_query(1, "example.com", TYPE_A).unwrap();
        let r = build_response(&q, &[ip("93.184.216.34"), ip("2606:2800::1")], 120);
        let a = parse_answers(&r).unwrap();
        assert_eq!(a.addrs, vec![ip("93.184.216.34"), ip("2606:2800::1")]);
        assert_eq!(a.min_ttl, Some(120));
        assert_eq!(a.rcode, 0);
    }

    #[test]
    fn compression_loops_are_rejected() {
        // header + a name that points to itself
        let mut m = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1]);
        assert_eq!(parse_question(&m), None);
    }

    #[test]
    fn truncated_messages_are_rejected_not_panicking() {
        let q = build_query(1, "example.com", TYPE_A).unwrap();
        let r = build_response(&q, &[ip("1.2.3.4")], 60);
        for n in 0..r.len() {
            let _ = parse_answers(&r[..n]);
            let _ = parse_question(&r[..n]);
        }
    }

    #[test]
    fn empty_response_builder() {
        let q = build_query(7, "v6only.example", TYPE_AAAA).unwrap();
        let r = build_empty_response(&q, 0).unwrap();
        let a = parse_answers(&r).unwrap();
        assert_eq!((a.rcode, a.answer_count), (0, 0));
        assert_eq!(r[..2], [0, 7]);
        let s = build_empty_response(&q, 2).unwrap();
        assert_eq!(rcode(&s), Some(2));
    }

    #[test]
    fn local_name_classification() {
        for n in [
            "printer.local",
            "nas",
            "router.lan",
            "x.home.arpa",
            "foo.internal",
            "localhost",
            "5.1.168.192.in-addr.arpa",
            "1.0.0.10.in-addr.arpa",
            "9.0.16.172.in-addr.arpa",
            "1.0.0.127.in-addr.arpa",
            "Host.LOCAL.",
        ] {
            assert!(is_local_name(n), "{n}");
        }
        for n in [
            "discord.com",
            "example.co.uk",
            "8.8.8.8.in-addr.arpa",
            "1.0.0.1.in-addr.arpa",
            "9.0.15.172.in-addr.arpa",
            "locally.example.com",
            "notlocal.com",
        ] {
            assert!(!is_local_name(n), "{n}");
        }
    }

    #[test]
    fn poison_comparison() {
        assert_eq!(
            compare_answers(&[ip("0.0.0.0")], &[ip("1.2.3.4")]),
            PoisonVerdict::Bogus
        );
        assert_eq!(
            compare_answers(&[ip("10.0.0.1")], &[ip("1.2.3.4")]),
            PoisonVerdict::Bogus
        );
        assert_eq!(
            compare_answers(&[ip("1.2.3.4")], &[ip("1.2.3.4"), ip("5.6.7.8")]),
            PoisonVerdict::Clean
        );
        assert_eq!(
            compare_answers(&[ip("9.9.9.9")], &[ip("1.2.3.4")]),
            PoisonVerdict::Disjoint
        );
        assert_eq!(
            compare_answers(&[], &[ip("1.2.3.4")]),
            PoisonVerdict::Unknown
        );
        // Both bogus (e.g. genuinely internal) is not poisoning.
        assert_ne!(
            compare_answers(&[ip("10.0.0.1")], &[ip("10.0.0.1")]),
            PoisonVerdict::Bogus
        );
    }

    #[test]
    fn cache_ttl_clamping_expiry_and_bound() {
        let q = build_query(1, "a.example", TYPE_A).unwrap();
        let mut c = DnsCache::new(2);
        c.put(
            "a.example",
            TYPE_A,
            &build_response(&q, &[ip("1.1.1.1")], 1),
            1000,
        );
        assert!(c.get("A.example", TYPE_A, 1009).is_some()); // clamped up to 10s
        assert!(c.get("a.example", TYPE_A, 1010).is_none());
        c.put(
            "a.example",
            TYPE_A,
            &build_response(&q, &[ip("1.1.1.1")], 86_400),
            1000,
        );
        assert!(c.get("a.example", TYPE_A, 1299).is_some()); // clamped down to 300s
        assert!(c.get("a.example", TYPE_A, 1300).is_none());
        for (i, n) in ["b", "c", "d"].iter().enumerate() {
            let q = build_query(1, &format!("{n}.example"), TYPE_A).unwrap();
            c.put(
                &format!("{n}.example"),
                TYPE_A,
                &build_response(&q, &[ip("1.1.1.1")], 100),
                2000 + i as u64,
            );
            assert!(c.len() <= 2);
        }
    }

    #[test]
    fn servfail_is_not_cached_but_nxdomain_is_briefly() {
        let q = build_query(1, "n.example", TYPE_A).unwrap();
        let mut c = DnsCache::new(8);
        c.put(
            "n.example",
            TYPE_A,
            &build_empty_response(&q, 2).unwrap(),
            100,
        );
        assert!(c.is_empty());
        c.put(
            "n.example",
            TYPE_A,
            &build_empty_response(&q, 3).unwrap(),
            100,
        );
        assert!(c.get("n.example", TYPE_A, 129).is_some());
        assert!(c.get("n.example", TYPE_A, 130).is_none());
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(data in proptest::collection::vec(any::<u8>(), 0..600)) {
            let _ = parse_question(&data);
            let _ = parse_answers(&data);
            let _ = build_empty_response(&data, 0);
        }
    }
}
