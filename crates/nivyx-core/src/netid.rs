//! Network fingerprinting. Raw identifiers (SSID, gateway, ...) are hashed together with a
//! per-install salt immediately; only the 64-bit hash is ever stored or compared.

use sha2::{Digest, Sha256};

/// Inputs describing the underlying (non-VPN) network. Empty strings mean "unknown/unavailable".
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetworkInfo<'a> {
    /// "wifi", "cellular", "ethernet", "other"
    pub transport: &'a str,
    /// Wi-Fi network name when the platform exposes it (optional; Nivyx does not request location
    /// permission, so this is normally empty). Hashed, never stored raw.
    pub ssid: &'a str,
    /// Default gateway address.
    pub gateway: &'a str,
    /// Local subnet in CIDR form (e.g. `192.168.1.0/24`).
    pub subnet: &'a str,
    /// The network's DNS servers, comma separated, sorted by the caller.
    pub dns: &'a str,
    /// Coarse carrier identity (MCC+MNC) for cellular. No cell-level/location data.
    pub carrier: &'a str,
    /// Whether the network has global IPv6 connectivity.
    pub has_ipv6: bool,
}

pub fn fingerprint(salt: &[u8], n: &NetworkInfo<'_>) -> u64 {
    let mut h = Sha256::new();
    h.update(b"nivyx.net.v1");
    h.update((salt.len() as u32).to_be_bytes());
    h.update(salt);
    let mut field = |label: &str, v: &str| {
        h.update((label.len() as u32).to_be_bytes());
        h.update(label.as_bytes());
        h.update((v.len() as u32).to_be_bytes());
        h.update(v.as_bytes());
    };
    field("transport", n.transport);
    field("ssid", n.ssid);
    field("gateway", n.gateway);
    field("subnet", n.subnet);
    field("dns", n.dns);
    field("carrier", n.carrier);
    // IPv6 availability is deliberately NOT part of the id: the strategy engine already scopes by family.
    u64::from_be_bytes(h.finalize()[..8].try_into().expect("8 bytes"))
}

pub fn to_hex(id: u64) -> String {
    format!("{id:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n<'a>(t: &'a str, ssid: &'a str, gw: &'a str, car: &'a str) -> NetworkInfo<'a> {
        NetworkInfo {
            transport: t,
            ssid,
            gateway: gw,
            carrier: car,
            ..Default::default()
        }
    }

    #[test]
    fn distinguishes_networks() {
        let s = b"salt";
        let home = fingerprint(s, &n("wifi", "HomeNet", "192.168.1.1", ""));
        let cafe = fingerprint(s, &n("wifi", "Cafe", "192.168.1.1", ""));
        let hotspot = fingerprint(s, &n("wifi", "", "192.168.43.1", ""));
        let mobile = fingerprint(s, &n("cellular", "", "", "28603"));
        let mobile2 = fingerprint(s, &n("cellular", "", "", "28601"));
        let all = [home, cafe, hotspot, mobile, mobile2];
        for i in 0..all.len() {
            for j in i + 1..all.len() {
                assert_ne!(all[i], all[j]);
            }
        }
        assert_eq!(
            home,
            fingerprint(s, &n("wifi", "HomeNet", "192.168.1.1", ""))
        );
    }

    #[test]
    fn salt_changes_everything_and_fields_cannot_alias() {
        let a = fingerprint(b"a", &n("wifi", "x", "", ""));
        assert_ne!(a, fingerprint(b"b", &n("wifi", "x", "", "")));
        // length-prefixed fields: ("ab","") must differ from ("a","b")
        assert_ne!(
            fingerprint(b"s", &n("wifi", "ab", "", "")),
            fingerprint(b"s", &n("wifi", "a", "b", ""))
        );
    }

    #[test]
    fn same_gateway_different_subnet_or_dns_is_a_different_network() {
        let base = NetworkInfo {
            transport: "wifi",
            gateway: "192.168.1.1",
            subnet: "192.168.1.0/24",
            dns: "192.168.1.1",
            ..Default::default()
        };
        let other_dns = NetworkInfo {
            dns: "9.9.9.9",
            ..base.clone()
        };
        let other_subnet = NetworkInfo {
            subnet: "192.168.0.0/16",
            ..base.clone()
        };
        let a = fingerprint(b"s", &base);
        assert_ne!(a, fingerprint(b"s", &other_dns));
        assert_ne!(a, fingerprint(b"s", &other_subnet));
    }

    #[test]
    fn ipv6_availability_does_not_change_id() {
        let mut x = n("wifi", "x", "g", "");
        let a = fingerprint(b"s", &x);
        x.has_ipv6 = true;
        assert_eq!(a, fingerprint(b"s", &x));
    }

    #[test]
    fn hex_is_fixed_width() {
        assert_eq!(to_hex(1), "0000000000000001");
    }
}
