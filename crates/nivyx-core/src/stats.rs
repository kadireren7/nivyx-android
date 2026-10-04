//! Local-only counters. Nothing here records host names or any history.

use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

#[derive(Default)]
pub struct Stats {
    pub connections_total: AtomicU64,
    pub connections_direct: AtomicU64,
    pub connections_bypassed: AtomicU64,
    pub connections_failed: AtomicU64,
    pub strategy_tlsrec: AtomicU64,
    pub strategy_tlsrec_tcp: AtomicU64,
    pub escalations: AtomicU64,
    pub flows_active: AtomicU64,
    pub udp_flows: AtomicU64,
    pub dns_queries: AtomicU64,
    pub dns_failures: AtomicU64,
    pub dns_cache_hits: AtomicU64,
    pub dns_poison_suspected: AtomicU64,
    pub quic_rejected: AtomicU64,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
    pub protect_failures: AtomicU64,
}

#[derive(Serialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct StatsSnapshot {
    pub connections_total: u64,
    pub connections_direct: u64,
    pub connections_bypassed: u64,
    pub connections_failed: u64,
    pub strategy_tlsrec: u64,
    pub strategy_tlsrec_tcp: u64,
    pub escalations: u64,
    pub flows_active: u64,
    pub udp_flows: u64,
    pub dns_queries: u64,
    pub dns_failures: u64,
    pub dns_cache_hits: u64,
    pub dns_poison_suspected: u64,
    pub quic_rejected: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub protect_failures: u64,
}

impl Stats {
    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            connections_total: self.connections_total.load(Relaxed),
            connections_direct: self.connections_direct.load(Relaxed),
            connections_bypassed: self.connections_bypassed.load(Relaxed),
            connections_failed: self.connections_failed.load(Relaxed),
            strategy_tlsrec: self.strategy_tlsrec.load(Relaxed),
            strategy_tlsrec_tcp: self.strategy_tlsrec_tcp.load(Relaxed),
            escalations: self.escalations.load(Relaxed),
            flows_active: self.flows_active.load(Relaxed),
            udp_flows: self.udp_flows.load(Relaxed),
            dns_queries: self.dns_queries.load(Relaxed),
            dns_failures: self.dns_failures.load(Relaxed),
            dns_cache_hits: self.dns_cache_hits.load(Relaxed),
            dns_poison_suspected: self.dns_poison_suspected.load(Relaxed),
            quic_rejected: self.quic_rejected.load(Relaxed),
            bytes_up: self.bytes_up.load(Relaxed),
            bytes_down: self.bytes_down.load(Relaxed),
            protect_failures: self.protect_failures.load(Relaxed),
        }
    }
}

pub fn inc(c: &AtomicU64) {
    c.fetch_add(1, Relaxed);
}

pub fn add(c: &AtomicU64, n: u64) {
    c.fetch_add(n, Relaxed);
}

pub fn dec(c: &AtomicU64) {
    let mut cur = c.load(Relaxed);
    while cur > 0 {
        match c.compare_exchange_weak(cur, cur - 1, Relaxed, Relaxed) {
            Ok(_) => break,
            Err(v) => cur = v,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_and_saturating_dec() {
        let s = Stats::default();
        inc(&s.flows_active);
        dec(&s.flows_active);
        dec(&s.flows_active);
        add(&s.bytes_up, 10);
        let snap = s.snapshot();
        assert_eq!(snap.flows_active, 0);
        assert_eq!(snap.bytes_up, 10);
    }
}
