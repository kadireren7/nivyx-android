//! QUIC awareness: recognising QUIC Initial datagrams and mapping destination IPs back to the
//! host names that resolved to them, so QUIC can be rejected *only* for destinations whose hosts
//! are known to need bypass (forcing the app to fall back to TCP/TLS, where bypass works).

use std::collections::HashMap;
use std::net::IpAddr;

/// QUIC long-header packet of type Initial for a known version (v1, v2, or drafts 29..).
pub fn is_quic_initial(payload: &[u8]) -> bool {
    if payload.len() < 1200 || payload[0] & 0xC0 != 0xC0 {
        return false;
    }
    let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
    let ptype = (payload[0] >> 4) & 0x03;
    match version {
        0x0000_0001 => ptype == 0x00,               // QUIC v1: Initial = 0
        0x6b33_43cf => ptype == 0x01,               // QUIC v2: Initial = 1
        0xff00_001d..=0xff00_0020 => ptype == 0x00, // drafts 29-32
        _ => false,
    }
}

/// Any datagram that looks like QUIC at all (long header with a known version, or short header on 443).
pub fn looks_like_quic(payload: &[u8]) -> bool {
    !payload.is_empty() && payload[0] & 0x40 != 0
}

/// Bounded, short-lived IP → host mapping fed by DNS answers.
pub struct NameMap {
    cap: usize,
    map: HashMap<IpAddr, Vec<(String, u64)>>,
}

const MAX_NAMES_PER_IP: usize = 8;
pub const MAX_MAPPING_TTL: u64 = 300;

impl NameMap {
    pub fn new(cap: usize) -> NameMap {
        NameMap {
            cap: cap.max(1),
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

    /// Remember that `host` resolved to `ip` for at most `ttl` seconds (capped at 5 minutes so
    /// stale CDN addresses stop influencing decisions quickly).
    pub fn record(&mut self, ip: IpAddr, host: &str, ttl: u64, now: u64) {
        let expires = now + ttl.clamp(1, MAX_MAPPING_TTL);
        if !self.map.contains_key(&ip) && self.map.len() >= self.cap {
            self.map.retain(|_, v| v.iter().any(|(_, e)| *e > now));
            if self.map.len() >= self.cap {
                if let Some(victim) = self
                    .map
                    .iter()
                    .min_by_key(|(k, v)| (v.iter().map(|(_, e)| *e).max().unwrap_or(0), **k))
                    .map(|(k, _)| *k)
                {
                    self.map.remove(&victim);
                }
            }
        }
        let v = self.map.entry(ip).or_default();
        v.retain(|(_, e)| *e > now);
        if let Some(x) = v.iter_mut().find(|(h, _)| h == host) {
            x.1 = expires;
            return;
        }
        if v.len() >= MAX_NAMES_PER_IP {
            v.remove(0);
        }
        v.push((host.to_string(), expires));
    }

    /// Hosts that resolved to `ip` and whose mapping is still fresh.
    pub fn hosts_for(&self, ip: &IpAddr, now: u64) -> Vec<&str> {
        self.map
            .get(ip)
            .map(|v| {
                v.iter()
                    .filter(|(_, e)| *e > now)
                    .map(|(h, _)| h.as_str())
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn detects_quic_v1_initial() {
        let mut p = vec![0u8; 1252];
        p[0] = 0xC3; // long, fixed, type 0
        p[4] = 1; // version 1
        assert!(is_quic_initial(&p));
        p[0] = 0xE3; // type 2 = handshake
        assert!(!is_quic_initial(&p));
        let mut small = vec![0u8; 100];
        small[0] = 0xC3;
        small[4] = 1;
        assert!(!is_quic_initial(&small));
        assert!(!is_quic_initial(b"\x16\x03\x01"));
        let mut v2 = vec![0u8; 1250];
        v2[..5].copy_from_slice(&[0xD3, 0x6b, 0x33, 0x43, 0xcf]);
        assert!(is_quic_initial(&v2));
    }

    #[test]
    fn mapping_expires_and_is_capped_at_five_minutes() {
        let mut m = NameMap::new(10);
        m.record(ip("1.2.3.4"), "a.example", 86_400, 1000);
        assert_eq!(m.hosts_for(&ip("1.2.3.4"), 1299), vec!["a.example"]);
        assert!(m.hosts_for(&ip("1.2.3.4"), 1300).is_empty());
    }

    #[test]
    fn shared_cdn_ip_lists_all_fresh_hosts() {
        let mut m = NameMap::new(10);
        m.record(ip("1.2.3.4"), "a.example", 60, 1000);
        m.record(ip("1.2.3.4"), "b.example", 600, 1010);
        let mut h = m.hosts_for(&ip("1.2.3.4"), 1020);
        h.sort();
        assert_eq!(h, vec!["a.example", "b.example"]);
        assert_eq!(m.hosts_for(&ip("1.2.3.4"), 1065), vec!["b.example"]); // a expired, b stays
    }

    #[test]
    fn bounded_in_ips_and_names_per_ip() {
        let mut m = NameMap::new(3);
        for i in 0..10u8 {
            m.record(
                ip(&format!("10.0.0.{i}")),
                "h.example",
                100,
                1000 + i as u64,
            );
            assert!(m.len() <= 3);
        }
        for i in 0..20 {
            m.record(ip("9.9.9.9"), &format!("h{i}.example"), 100, 2000);
        }
        assert!(m.hosts_for(&ip("9.9.9.9"), 2001).len() <= MAX_NAMES_PER_IP);
    }
}
