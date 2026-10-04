//! Deterministic, explainable per-host strategy engine.
//!
//! Every decision is scoped by `(network fingerprint, address family, host)`.
//! For each scope the engine remembers, per strategy, whether it recently worked
//! ("good") or failed ("bad") together with an expiry. Nothing is permanent:
//! every slot expires, and failures act as a cooldown rather than a verdict.
//! Manual rules always win over anything learned. There is no randomness and no ML.
//!
//! Host names are only ever stored as salted 64-bit hashes, so neither memory
//! dumps of the cache nor its persisted form reveal a browsing history.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// A way of putting a connection's first flight on the wire.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum Strategy {
    Direct,
    TlsRec,
    TlsRecTcp,
}

impl Strategy {
    pub const ALL: [Strategy; 3] = [Strategy::Direct, Strategy::TlsRec, Strategy::TlsRecTcp];

    pub fn name(self) -> &'static str {
        match self {
            Strategy::Direct => "direct",
            Strategy::TlsRec => "tlsrec",
            Strategy::TlsRecTcp => "tlsrec-tcp",
        }
    }

    pub fn parse(s: &str) -> Option<Strategy> {
        match s.trim().to_ascii_lowercase().as_str() {
            "direct" => Some(Strategy::Direct),
            "tlsrec" | "tls-record-split" => Some(Strategy::TlsRec),
            "tlsrec-tcp" | "tlsrec+tcp" => Some(Strategy::TlsRecTcp),
            _ => None,
        }
    }

    fn idx(self) -> usize {
        self as usize
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    pub fn of(ip: &std::net::IpAddr) -> Family {
        if ip.is_ipv4() {
            Family::V4
        } else {
            Family::V6
        }
    }
}

/// Scope of a learned decision.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Key {
    pub network: u64,
    pub family: Family,
    pub host: u64,
}

impl Key {
    pub fn new(salt: &[u8], network: u64, family: Family, host: &str) -> Key {
        Key {
            network,
            family,
            host: hash_host(salt, host),
        }
    }
}

/// Salted, truncated SHA-256 of a lower-cased host name (or IP literal).
pub fn hash_host(salt: &[u8], host: &str) -> u64 {
    let mut h = Sha256::new();
    h.update(b"nivyx.host.v1");
    h.update((salt.len() as u32).to_be_bytes());
    h.update(salt);
    h.update(host.to_ascii_lowercase().as_bytes());
    let d = h.finalize();
    u64::from_be_bytes(d[..8].try_into().expect("8 bytes"))
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum State {
    Unknown,
    DirectGood,
    DirectBad,
    TlsRecGood,
    TlsRecBad,
    TlsRecTcpGood,
    TlsRecTcpBad,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Source {
    Manual,
    Learned,
    Default,
}

/// Lifetimes (seconds) and switches for the engine.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Params {
    pub direct_good_ttl: u64,
    pub direct_bad_ttl: u64,
    pub tlsrec_good_ttl: u64,
    pub tlsrec_bad_ttl: u64,
    pub tlsrec_tcp_good_ttl: u64,
    pub tlsrec_tcp_bad_ttl: u64,
    /// Whether the optional `tlsrec-tcp` strategy may be tried.
    pub allow_tlsrec_tcp: bool,
    /// Hard cap on remembered scopes.
    pub max_entries: usize,
}

impl Default for Params {
    fn default() -> Self {
        Params {
            direct_good_ttl: 60 * 60,
            direct_bad_ttl: 30 * 60,
            tlsrec_good_ttl: 6 * 60 * 60,
            tlsrec_bad_ttl: 10 * 60,
            tlsrec_tcp_good_ttl: 6 * 60 * 60,
            tlsrec_tcp_bad_ttl: 10 * 60,
            allow_tlsrec_tcp: false,
            max_entries: 4096,
        }
    }
}

impl Params {
    fn ttl(&self, s: Strategy, good: bool) -> u64 {
        match (s, good) {
            (Strategy::Direct, true) => self.direct_good_ttl,
            (Strategy::Direct, false) => self.direct_bad_ttl,
            (Strategy::TlsRec, true) => self.tlsrec_good_ttl,
            (Strategy::TlsRec, false) => self.tlsrec_bad_ttl,
            (Strategy::TlsRecTcp, true) => self.tlsrec_tcp_good_ttl,
            (Strategy::TlsRecTcp, false) => self.tlsrec_tcp_bad_ttl,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Slot {
    good: bool,
    at: u64,
    expires: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Entry {
    slots: [Option<Slot>; 3],
}

impl Entry {
    fn live(&self, s: Strategy, now: u64) -> Option<Slot> {
        self.slots[s.idx()].filter(|x| x.expires > now)
    }

    fn expires(&self) -> u64 {
        self.slots
            .iter()
            .flatten()
            .map(|s| s.expires)
            .max()
            .unwrap_or(0)
    }

    fn decided_at(&self, now: u64) -> Option<u64> {
        Strategy::ALL
            .iter()
            .filter_map(|s| self.live(*s, now))
            .map(|s| s.at)
            .max()
    }

    pub fn state(&self, now: u64) -> State {
        let l = |s| self.live(s, now);
        if l(Strategy::Direct).is_some_and(|s| s.good) {
            State::DirectGood
        } else if l(Strategy::TlsRec).is_some_and(|s| s.good) {
            State::TlsRecGood
        } else if l(Strategy::TlsRecTcp).is_some_and(|s| s.good) {
            State::TlsRecTcpGood
        } else if l(Strategy::TlsRec).is_some() {
            State::TlsRecBad
        } else if l(Strategy::TlsRecTcp).is_some() {
            State::TlsRecTcpBad
        } else if l(Strategy::Direct).is_some() {
            State::DirectBad
        } else {
            State::Unknown
        }
    }

    /// True when the live data says this scope needs more than plain direct.
    fn needs_bypass(&self, now: u64) -> bool {
        let direct = self.live(Strategy::Direct, now);
        if direct.is_some_and(|s| s.good) {
            return false;
        }
        direct.is_some()
            || self.live(Strategy::TlsRec, now).is_some_and(|s| s.good)
            || self.live(Strategy::TlsRecTcp, now).is_some_and(|s| s.good)
    }
}

/// Manual rules: exact hosts and `*.suffix` wildcards. A plain `example.com` rule never
/// applies to `www.example.com` or `example.org` (no implicit sibling/child inheritance).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ManualRules {
    exact: HashMap<String, Option<Strategy>>,
    wildcard: Vec<(String, Option<Strategy>)>,
}

impl ManualRules {
    /// Parse `host = strategy` lines. `#` starts a comment. `auto` removes manual control.
    /// Returns the rules and a list of `(line_number, message)` problems; bad lines are skipped.
    pub fn parse(text: &str) -> (ManualRules, Vec<(usize, String)>) {
        let mut r = ManualRules::default();
        let mut errs = Vec::new();
        for (i, raw) in text.lines().enumerate().take(10_000) {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let Some((host, strat)) = line.split_once('=') else {
                errs.push((i + 1, "expected `host = strategy`".into()));
                continue;
            };
            let host = host.trim().to_ascii_lowercase();
            let strat = strat.trim().to_ascii_lowercase();
            let value = if strat == "auto" {
                None
            } else if let Some(s) = Strategy::parse(&strat) {
                Some(s)
            } else {
                errs.push((i + 1, format!("unknown strategy `{strat}`")));
                continue;
            };
            let (is_wild, bare) = match host.strip_prefix("*.") {
                Some(rest) => (true, rest),
                None => (false, host.as_str()),
            };
            if crate::tls::sanitize_host(bare.as_bytes()).as_deref() != Some(bare) {
                errs.push((i + 1, format!("invalid host `{host}`")));
                continue;
            }
            if is_wild {
                r.wildcard.retain(|(h, _)| h != bare);
                r.wildcard.push((bare.to_string(), value));
            } else {
                r.exact.insert(bare.to_string(), value);
            }
        }
        // Longest suffix first so the most specific wildcard wins.
        r.wildcard
            .sort_by(|a, b| b.0.len().cmp(&a.0.len()).then(a.0.cmp(&b.0)));
        (r, errs)
    }

    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.wildcard.is_empty()
    }

    pub fn len(&self) -> usize {
        self.exact.len() + self.wildcard.len()
    }

    /// `Some(Some(s))`: forced strategy. `Some(None)`: explicit `auto`. `None`: no rule.
    pub fn lookup(&self, host: &str) -> Option<Option<Strategy>> {
        let host = host.to_ascii_lowercase();
        if let Some(v) = self.exact.get(&host) {
            return Some(*v);
        }
        for (suffix, v) in &self.wildcard {
            if host.len() > suffix.len()
                && host.ends_with(suffix.as_str())
                && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
            {
                return Some(*v);
            }
        }
        None
    }
}

/// The outcome of asking the engine what to do for a connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    /// Strategies to attempt in order. Never empty.
    pub ladder: Vec<Strategy>,
    pub source: Source,
    pub state: State,
    /// Seconds until the governing learned data expires (0 for manual/default).
    pub ttl_remaining: u64,
    pub decided_at: Option<u64>,
}

impl Decision {
    pub fn primary(&self) -> Strategy {
        self.ladder[0]
    }
}

pub struct Engine {
    params: Params,
    entries: HashMap<Key, Entry>,
}

impl Engine {
    pub fn new(params: Params) -> Engine {
        Engine {
            params,
            entries: HashMap::new(),
        }
    }

    pub fn params(&self) -> &Params {
        &self.params
    }

    pub fn set_params(&mut self, params: Params) {
        self.params = params;
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn enabled(&self) -> Vec<Strategy> {
        Strategy::ALL
            .into_iter()
            .filter(|s| *s != Strategy::TlsRecTcp || self.params.allow_tlsrec_tcp)
            .collect()
    }

    /// Decide how to connect. `manual` is the result of [`ManualRules::lookup`].
    pub fn decide(&self, key: &Key, manual: Option<Option<Strategy>>, now: u64) -> Decision {
        if let Some(Some(s)) = manual {
            return Decision {
                ladder: vec![s],
                source: Source::Manual,
                state: State::Unknown,
                ttl_remaining: 0,
                decided_at: None,
            };
        }
        let entry = self.entries.get(key);
        let empty = Entry::default();
        let e = entry.unwrap_or(&empty);
        let enabled = self.enabled();
        let mut ladder: Vec<Strategy> = enabled
            .iter()
            .copied()
            .filter(|s| e.live(*s, now).is_none_or(|slot| slot.good))
            .collect();
        // Known-good strategies go first, in canonical (least intrusive first) order.
        ladder.sort_by_key(|s| (!e.live(*s, now).is_some_and(|x| x.good), s.idx()));
        if ladder.is_empty() {
            // Everything is cooling down: fail open to plain direct.
            ladder.push(Strategy::Direct);
        }
        let learned = e.decided_at(now).is_some();
        Decision {
            ladder,
            source: if learned {
                Source::Learned
            } else {
                Source::Default
            },
            state: e.state(now),
            ttl_remaining: e.expires().saturating_sub(now),
            decided_at: e.decided_at(now),
        }
    }

    /// Record the outcome of attempting `strategy`.
    pub fn report(&mut self, key: Key, strategy: Strategy, success: bool, now: u64) {
        let ttl = self.params.ttl(strategy, success);
        if !self.entries.contains_key(&key) && self.entries.len() >= self.params.max_entries {
            self.evict(now);
        }
        let e = self.entries.entry(key).or_default();
        e.slots[strategy.idx()] = Some(Slot {
            good: success,
            at: now,
            expires: now.saturating_add(ttl),
        });
    }

    /// Whether QUIC to this scope should be rejected so the app falls back to TCP/TLS.
    pub fn needs_bypass(&self, key: &Key, manual: Option<Option<Strategy>>, now: u64) -> bool {
        match manual {
            Some(Some(Strategy::Direct)) => false,
            Some(Some(_)) => true,
            _ => self.entries.get(key).is_some_and(|e| e.needs_bypass(now)),
        }
    }

    fn evict(&mut self, now: u64) {
        self.entries.retain(|_, e| e.expires() > now);
        while self.entries.len() >= self.params.max_entries {
            let victim = self
                .entries
                .iter()
                .min_by_key(|(k, e)| (e.expires(), k.host))
                .map(|(k, _)| *k);
            match victim {
                Some(k) => {
                    self.entries.remove(&k);
                }
                None => break,
            }
        }
    }

    /// Drop expired entries. Cheap enough to call periodically.
    pub fn sweep(&mut self, now: u64) {
        self.entries.retain(|_, e| e.expires() > now);
    }

    /// Forget everything learned for one network (e.g. its DNS or gateway changed).
    pub fn invalidate_network(&mut self, network: u64) {
        self.entries.retain(|k, _| k.network != network);
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Entries worth persisting: only scopes where plain direct is known not to work, still live.
    /// Direct-good scopes are the default and are intentionally never written to disk.
    pub fn export(&self, now: u64, limit: usize) -> Vec<(Key, Entry)> {
        let mut v: Vec<(Key, Entry)> = self
            .entries
            .iter()
            .filter(|(_, e)| e.expires() > now && e.needs_bypass(now))
            .map(|(k, e)| (*k, e.clone()))
            .collect();
        v.sort_by_key(|(k, e)| (std::cmp::Reverse(e.expires()), k.host));
        v.truncate(limit);
        v
    }

    pub fn import(&mut self, items: Vec<(Key, Entry)>, now: u64) {
        for (k, e) in items {
            if e.expires() > now && self.entries.len() < self.params.max_entries {
                self.entries.insert(k, e);
            }
        }
    }

    /// Counts of live scopes by state, for status display. No host information.
    pub fn summary(&self, now: u64) -> HashMap<&'static str, usize> {
        let mut m = HashMap::new();
        for e in self.entries.values() {
            let name = match e.state(now) {
                State::Unknown => continue,
                State::DirectGood => "direct-good",
                State::DirectBad => "direct-bad",
                State::TlsRecGood => "tlsrec-good",
                State::TlsRecBad => "tlsrec-bad",
                State::TlsRecTcpGood => "tlsrec-tcp-good",
                State::TlsRecTcpBad => "tlsrec-tcp-bad",
            };
            *m.entry(name).or_insert(0) += 1;
        }
        m
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: &[u8] = b"test-salt";
    fn key(host: &str) -> Key {
        Key::new(SALT, 1, Family::V4, host)
    }
    fn eng() -> Engine {
        Engine::new(Params::default())
    }

    #[test]
    fn unknown_host_is_direct_first() {
        let e = eng();
        let d = e.decide(&key("a.example"), None, 100);
        assert_eq!(d.ladder, vec![Strategy::Direct, Strategy::TlsRec]);
        assert_eq!(d.source, Source::Default);
        assert_eq!(d.state, State::Unknown);
    }

    #[test]
    fn direct_success_avoids_bypass() {
        let mut e = eng();
        let k = key("ok.example");
        e.report(k, Strategy::Direct, true, 100);
        let d = e.decide(&k, None, 200);
        assert_eq!(d.primary(), Strategy::Direct);
        assert_eq!(d.state, State::DirectGood);
        assert_eq!(d.source, Source::Learned);
        assert!(!e.needs_bypass(&k, None, 200));
    }

    #[test]
    fn failed_direct_promotes_tlsrec_and_success_is_cached() {
        let mut e = eng();
        let k = key("blocked.example");
        e.report(k, Strategy::Direct, false, 100);
        let d = e.decide(&k, None, 101);
        assert_eq!(d.ladder, vec![Strategy::TlsRec]);
        assert_eq!(d.state, State::DirectBad);
        e.report(k, Strategy::TlsRec, true, 102);
        let d = e.decide(&k, None, 103);
        assert_eq!(d.primary(), Strategy::TlsRec);
        assert_eq!(d.state, State::TlsRecGood);
        assert!(e.needs_bypass(&k, None, 103));
    }

    #[test]
    fn good_strategy_keeps_direct_as_last_resort_ladder() {
        let mut e = eng();
        let k = key("b.example");
        e.report(k, Strategy::TlsRec, true, 100);
        let d = e.decide(&k, None, 101);
        // TlsRec is known good so it leads, Direct (unknown) follows.
        assert_eq!(d.ladder, vec![Strategy::TlsRec, Strategy::Direct]);
    }

    #[test]
    fn failures_expire_and_good_decisions_are_not_permanent() {
        let p = Params::default();
        let mut e = Engine::new(p.clone());
        let k = key("x.example");
        e.report(k, Strategy::Direct, false, 1000);
        assert_eq!(
            e.decide(&k, None, 1000 + p.direct_bad_ttl - 1).state,
            State::DirectBad
        );
        let d = e.decide(&k, None, 1000 + p.direct_bad_ttl);
        assert_eq!(d.state, State::Unknown);
        assert_eq!(d.primary(), Strategy::Direct); // re-probe direct after cooldown
        e.report(k, Strategy::TlsRec, true, 2000);
        let d = e.decide(&k, None, 2000 + p.tlsrec_good_ttl);
        assert_eq!(d.state, State::Unknown);
        assert_eq!(d.source, Source::Default);
    }

    #[test]
    fn cooldown_after_total_failure_fails_open_to_direct() {
        let mut e = eng();
        let k = key("dead.example");
        e.report(k, Strategy::Direct, false, 100);
        e.report(k, Strategy::TlsRec, false, 101);
        let d = e.decide(&k, None, 102);
        assert_eq!(d.ladder, vec![Strategy::Direct]);
        assert_eq!(d.state, State::TlsRecBad);
    }

    #[test]
    fn tlsrec_tcp_only_when_enabled() {
        let mut e = Engine::new(Params {
            allow_tlsrec_tcp: true,
            ..Params::default()
        });
        let k = key("t.example");
        e.report(k, Strategy::Direct, false, 100);
        e.report(k, Strategy::TlsRec, false, 101);
        assert_eq!(e.decide(&k, None, 102).ladder, vec![Strategy::TlsRecTcp]);
        e.report(k, Strategy::TlsRecTcp, true, 103);
        let d = e.decide(&k, None, 104);
        assert_eq!(d.state, State::TlsRecTcpGood);
        assert_eq!(d.primary(), Strategy::TlsRecTcp);
        let off = eng();
        assert!(!off
            .decide(&k, None, 1)
            .ladder
            .contains(&Strategy::TlsRecTcp));
    }

    #[test]
    fn manual_rule_always_wins() {
        let mut e = eng();
        let k = key("m.example");
        e.report(k, Strategy::Direct, false, 100);
        let (rules, errs) = ManualRules::parse("m.example = direct\n");
        assert!(errs.is_empty());
        let d = e.decide(&k, rules.lookup("m.example"), 101);
        assert_eq!(d.ladder, vec![Strategy::Direct]);
        assert_eq!(d.source, Source::Manual);
        let (rules, _) = ManualRules::parse("m.example = tlsrec");
        let d = e.decide(&k, rules.lookup("m.example"), 101);
        assert_eq!(d.ladder, vec![Strategy::TlsRec]);
        assert!(e.needs_bypass(&k, rules.lookup("m.example"), 101));
        // explicit auto yields to learning
        let (rules, _) = ManualRules::parse("m.example = auto");
        let d = e.decide(&k, rules.lookup("m.example"), 101);
        assert_eq!(d.source, Source::Learned);
    }

    #[test]
    fn manual_rules_do_not_inherit_to_siblings_or_children() {
        let (r, errs) = ManualRules::parse(
            "# comment\nexample.com = tlsrec\n*.cdn.example.com = direct  # wildcard\n*.example.com=tlsrec\n",
        );
        assert!(errs.is_empty(), "{errs:?}");
        assert_eq!(r.lookup("example.com"), Some(Some(Strategy::TlsRec)));
        assert_eq!(r.lookup("EXAMPLE.com"), Some(Some(Strategy::TlsRec)));
        assert_eq!(r.lookup("www.example.com"), Some(Some(Strategy::TlsRec))); // via *.example.com
        assert_eq!(r.lookup("a.cdn.example.com"), Some(Some(Strategy::Direct))); // longest wildcard wins
        assert_eq!(r.lookup("example.org"), None);
        assert_eq!(r.lookup("notexample.com"), None);
        let (only_exact, _) = ManualRules::parse("example.com = tlsrec");
        assert_eq!(only_exact.lookup("www.example.com"), None);
        assert_eq!(only_exact.lookup("evilexample.com"), None);
    }

    #[test]
    fn manual_rule_parse_errors_are_reported_and_skipped() {
        let (r, errs) = ManualRules::parse(
            "good.example = direct\nnonsense\nbad.example = warp\nbad host = direct\n",
        );
        assert_eq!(r.len(), 1);
        assert_eq!(errs.iter().map(|e| e.0).collect::<Vec<_>>(), vec![2, 3, 4]);
    }

    #[test]
    fn learned_data_is_scoped_by_network_and_family() {
        let mut e = eng();
        let home = Key::new(SALT, 10, Family::V4, "h.example");
        let other = Key::new(SALT, 11, Family::V4, "h.example");
        let v6 = Key::new(SALT, 10, Family::V6, "h.example");
        e.report(home, Strategy::Direct, false, 100);
        assert_eq!(e.decide(&home, None, 101).state, State::DirectBad);
        assert_eq!(e.decide(&other, None, 101).state, State::Unknown);
        assert_eq!(e.decide(&v6, None, 101).state, State::Unknown);
        e.invalidate_network(10);
        assert_eq!(e.decide(&home, None, 101).state, State::Unknown);
    }

    #[test]
    fn learned_data_never_leaks_to_sibling_hosts() {
        let mut e = eng();
        e.report(key("a.example.com"), Strategy::Direct, false, 100);
        assert_eq!(
            e.decide(&key("b.example.com"), None, 101).state,
            State::Unknown
        );
        assert_eq!(
            e.decide(&key("example.com"), None, 101).state,
            State::Unknown
        );
    }

    #[test]
    fn cache_is_bounded_and_evicts_soonest_to_expire() {
        let mut e = Engine::new(Params {
            max_entries: 3,
            ..Params::default()
        });
        for (i, h) in ["a", "b", "c", "d", "e"].iter().enumerate() {
            e.report(key(h), Strategy::Direct, true, 100 + i as u64);
            assert!(e.len() <= 3);
        }
        assert_eq!(e.len(), 3);
        // Oldest (soonest expiring) were evicted; newest survive.
        assert_eq!(e.decide(&key("e"), None, 200).state, State::DirectGood);
        assert_eq!(e.decide(&key("a"), None, 200).state, State::Unknown);
    }

    #[test]
    fn export_skips_direct_good_and_expired_and_roundtrips() {
        let mut e = eng();
        e.report(key("fine.example"), Strategy::Direct, true, 100);
        e.report(key("blocked.example"), Strategy::Direct, false, 100);
        e.report(key("blocked.example"), Strategy::TlsRec, true, 101);
        e.report(key("old.example"), Strategy::TlsRec, true, 100);
        let now = 101 + Params::default().tlsrec_good_ttl; // every entry has expired by now
        assert!(e.export(now, 10).is_empty());
        let items = e.export(200, 10);
        assert_eq!(items.len(), 2);
        let json = serde_json::to_string(&items).unwrap();
        assert!(
            !json.contains("blocked.example"),
            "hosts must not be persisted in clear"
        );
        let back: Vec<(Key, Entry)> = serde_json::from_str(&json).unwrap();
        let mut e2 = eng();
        e2.import(back, 200);
        assert_eq!(
            e2.decide(&key("blocked.example"), None, 201).state,
            State::TlsRecGood
        );
        assert_eq!(
            e2.decide(&key("fine.example"), None, 201).state,
            State::Unknown
        );
    }

    #[test]
    fn host_hash_depends_on_salt_and_ignores_case() {
        assert_eq!(
            hash_host(b"s", "Example.COM"),
            hash_host(b"s", "example.com")
        );
        assert_ne!(
            hash_host(b"s", "example.com"),
            hash_host(b"t", "example.com")
        );
        assert_ne!(
            hash_host(b"s", "example.com"),
            hash_host(b"s", "example.org")
        );
    }

    #[test]
    fn summary_has_no_host_information() {
        let mut e = eng();
        e.report(key("a"), Strategy::Direct, true, 100);
        e.report(key("b"), Strategy::Direct, false, 100);
        let s = e.summary(101);
        assert_eq!(s["direct-good"], 1);
        assert_eq!(s["direct-bad"], 1);
    }
}
