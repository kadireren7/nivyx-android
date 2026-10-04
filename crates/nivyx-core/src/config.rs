//! Engine configuration: strictly validated, size-bounded JSON.

use crate::strategy::Params;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub const MAX_CONFIG_BYTES: usize = 128 * 1024;
pub const MAX_RULES_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resolver {
    pub name: String,
    /// `https://host[:port]/path` DNS-over-HTTPS endpoint (RFC 8484, POST).
    pub url: String,
    /// Addresses used to reach `url` when its host is a name. Empty when the host is an IP literal.
    #[serde(default)]
    pub bootstrap: Vec<IpAddr>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Ipv6Mode {
    /// Tunnel IPv6 only when the underlying network has working IPv6.
    #[default]
    Auto,
    On,
    Off,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub resolvers: Vec<Resolver>,
    /// When false, DNS is passed to the system resolver untouched.
    pub encrypted_dns: bool,
    pub strategy: Params,
    pub manual_rules: String,
    pub ipv6: Ipv6Mode,
    /// Reject QUIC to destinations whose hosts need bypass, forcing TCP/TLS fallback.
    pub quic_fallback: bool,
    /// Allow host names in logs and diagnostics (off by default).
    pub verbose_hosts: bool,
    /// TCP ports whose first client flight is inspected as TLS.
    pub tls_ports: Vec<u16>,
    /// How long to wait for the first server byte on a direct attempt before escalating.
    pub first_byte_timeout_ms: u64,
    pub connect_timeout_ms: u64,
    pub max_flows: usize,
    pub dns_cache_entries: usize,
    /// Per-install random salt (hex) used to hash host names and network identifiers.
    pub salt: String,
    /// Network fingerprint for the currently active underlying network.
    pub network_id: u64,
    /// Whether the underlying network currently has working global IPv6.
    pub has_ipv6: bool,
    /// DNS servers of the underlying network (used for local names and as a last-resort fallback).
    pub system_dns: Vec<IpAddr>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            resolvers: default_resolvers(),
            encrypted_dns: true,
            strategy: Params::default(),
            manual_rules: String::new(),
            ipv6: Ipv6Mode::Auto,
            quic_fallback: true,
            verbose_hosts: false,
            tls_ports: vec![443],
            first_byte_timeout_ms: 3000,
            connect_timeout_ms: 8000,
            max_flows: 1024,
            dns_cache_entries: 512,
            salt: String::new(),
            network_id: 0,
            has_ipv6: false,
            system_dns: Vec::new(),
        }
    }
}

pub fn default_resolvers() -> Vec<Resolver> {
    let r = |n: &str, u: &str| Resolver {
        name: n.into(),
        url: u.into(),
        bootstrap: vec![],
    };
    vec![
        r("Cloudflare", "https://1.1.1.1/dns-query"),
        r("Google", "https://8.8.8.8/dns-query"),
        r("Quad9", "https://9.9.9.9/dns-query"),
    ]
}

/// Parsed form of a DoH URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DohUrl {
    pub host: String,
    pub port: u16,
    pub path: String,
}

pub fn parse_doh_url(url: &str) -> Option<DohUrl> {
    let rest = url.strip_prefix("https://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/dns-query"),
    };
    if authority.is_empty()
        || authority.contains('@')
        || path.contains(['\r', '\n', ' '])
        || path.len() > 256
    {
        return None;
    }
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        let (h, tail) = inner.split_once(']')?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None if tail.is_empty() => 443,
            None => return None,
        };
        (h.to_string(), port)
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        (h.to_string(), p.parse().ok()?)
    } else {
        (authority.to_string(), 443)
    };
    if host.is_empty() || port == 0 {
        return None;
    }
    if host.parse::<IpAddr>().is_err() && crate::tls::sanitize_host(host.as_bytes()).is_none() {
        return None;
    }
    Some(DohUrl {
        host,
        port,
        path: path.to_string(),
    })
}

impl Config {
    /// Parse and validate. Unknown fields are ignored; every numeric field is clamped to a sane range.
    pub fn from_json(s: &str) -> Result<Config, String> {
        if s.len() > MAX_CONFIG_BYTES {
            return Err("config too large".into());
        }
        let mut c: Config = serde_json::from_str(s).map_err(|e| format!("invalid config: {e}"))?;
        c.validate()?;
        Ok(c)
    }

    pub fn validate(&mut self) -> Result<(), String> {
        if self.manual_rules.len() > MAX_RULES_BYTES {
            return Err("manual rules too large".into());
        }
        if self.resolvers.len() > 8 {
            return Err("too many resolvers".into());
        }
        for r in &self.resolvers {
            let u = parse_doh_url(&r.url)
                .ok_or_else(|| format!("invalid resolver URL for {}", r.name.escape_debug()))?;
            if u.host.parse::<IpAddr>().is_err() && r.bootstrap.is_empty() {
                return Err(format!(
                    "resolver {} needs bootstrap addresses",
                    r.name.escape_debug()
                ));
            }
        }
        if self.resolvers.is_empty() {
            self.resolvers = default_resolvers();
        }
        if self.tls_ports.len() > 16 {
            return Err("too many TLS ports".into());
        }
        self.tls_ports.retain(|p| *p != 0);
        self.first_byte_timeout_ms = self.first_byte_timeout_ms.clamp(500, 15_000);
        self.connect_timeout_ms = self.connect_timeout_ms.clamp(1_000, 30_000);
        self.max_flows = self.max_flows.clamp(16, 8192);
        self.dns_cache_entries = self.dns_cache_entries.clamp(16, 4096);
        self.strategy.max_entries = self.strategy.max_entries.clamp(16, 16_384);
        for ttl in [
            &mut self.strategy.direct_good_ttl,
            &mut self.strategy.direct_bad_ttl,
            &mut self.strategy.tlsrec_good_ttl,
            &mut self.strategy.tlsrec_bad_ttl,
            &mut self.strategy.tlsrec_tcp_good_ttl,
            &mut self.strategy.tlsrec_tcp_bad_ttl,
        ] {
            *ttl = (*ttl).clamp(30, 7 * 24 * 3600);
        }
        if self.salt.len() > 128 {
            return Err("salt too long".into());
        }
        if self.system_dns.len() > 8 {
            self.system_dns.truncate(8);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_validate_and_have_multiple_providers() {
        let mut c = Config::default();
        c.validate().unwrap();
        assert!(c.resolvers.len() >= 2);
        let names: Vec<_> = c.resolvers.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"Cloudflare") && names.contains(&"Google"));
    }

    #[test]
    fn partial_json_uses_defaults_and_clamps() {
        let c = Config::from_json(
            r#"{"first_byte_timeout_ms": 1, "max_flows": 999999, "future_field": 1}"#,
        )
        .unwrap();
        assert_eq!(c.first_byte_timeout_ms, 500);
        assert_eq!(c.max_flows, 8192);
        assert!(c.encrypted_dns);
    }

    #[test]
    fn rejects_garbage_and_oversize() {
        assert!(Config::from_json("not json").is_err());
        assert!(Config::from_json(&" ".repeat(MAX_CONFIG_BYTES + 1)).is_err());
        assert!(Config::from_json(
            r#"{"resolvers":[{"name":"x","url":"http://1.1.1.1/dns-query"}]}"#
        )
        .is_err());
        assert!(Config::from_json(
            r#"{"resolvers":[{"name":"x","url":"https://dns.example/dns-query"}]}"#
        )
        .is_err());
        let ok = Config::from_json(
            r#"{"resolvers":[{"name":"x","url":"https://dns.example/dns-query","bootstrap":["192.0.2.1"]}]}"#,
        );
        assert!(ok.is_ok());
    }

    #[test]
    fn doh_url_parsing() {
        let u = parse_doh_url("https://1.1.1.1/dns-query").unwrap();
        assert_eq!(
            (u.host.as_str(), u.port, u.path.as_str()),
            ("1.1.1.1", 443, "/dns-query")
        );
        let u = parse_doh_url("https://dns.google:8443/resolve").unwrap();
        assert_eq!((u.host.as_str(), u.port), ("dns.google", 8443));
        let u = parse_doh_url("https://[2606:4700:4700::1111]/dns-query").unwrap();
        assert_eq!(u.host, "2606:4700:4700::1111");
        assert_eq!(
            parse_doh_url("https://dns.example").unwrap().path,
            "/dns-query"
        );
        for bad in [
            "http://x/",
            "https://",
            "https://u@h/",
            "https://h:0/",
            "https://h:99999/",
            "https://bad host/",
            "ftp://h/",
        ] {
            assert!(parse_doh_url(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn roundtrips_through_json() {
        let c = Config::default();
        let j = serde_json::to_string(&c).unwrap();
        assert_eq!(Config::from_json(&j).unwrap(), c);
    }
}
