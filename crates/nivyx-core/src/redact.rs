//! Privacy-preserving redaction for logs and support bundles.
//!
//! Works on whitespace/punctuation separated words; no regex engine, no allocation
//! beyond the output string. By default host names are removed too, since a log of
//! host names is a browsing history.

use std::net::IpAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RedactOptions {
    pub keep_hosts: bool,
}

const SENSITIVE_KEYS: [&str; 14] = [
    "token",
    "access_token",
    "refresh_token",
    "key",
    "apikey",
    "api_key",
    "auth",
    "authorization",
    "password",
    "passwd",
    "secret",
    "cookie",
    "sid",
    "session",
];

const FILE_EXTENSIONS: [&str; 16] = [
    "so", "rs", "kt", "java", "json", "apk", "txt", "log", "jar", "dex", "xml", "kts", "toml",
    "md", "png", "zip",
];

fn is_word_sep(c: char) -> bool {
    c.is_whitespace()
        || matches!(
            c,
            ',' | ';' | '(' | ')' | '[' | ']' | '"' | '\'' | '<' | '>' | '{' | '}'
        )
}

fn strip_port_and_brackets(w: &str) -> &str {
    w.trim_start_matches('[').split(']').next().unwrap_or(w)
}

fn looks_like_ip(w: &str) -> bool {
    let t = strip_port_and_brackets(w);
    if t.parse::<IpAddr>().is_ok() {
        return true;
    }
    // ip:port
    if let Some((h, p)) = t.rsplit_once(':') {
        if p.chars().all(|c| c.is_ascii_digit()) && h.parse::<std::net::Ipv4Addr>().is_ok() {
            return true;
        }
    }
    false
}

fn looks_like_host(w: &str) -> bool {
    let w = w.trim_end_matches(['.', ':', '!', '?']);
    if !w.contains('.') || w.starts_with('.') || w.contains("..") {
        return false;
    }
    let labels: Vec<&str> = w.split('.').collect();
    if !labels.iter().all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && l.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    }) {
        return false;
    }
    let tld = labels[labels.len() - 1];
    tld.len() >= 2
        && tld.chars().all(|c| c.is_ascii_alphabetic())
        && !FILE_EXTENSIONS.contains(&tld.to_ascii_lowercase().as_str())
}

fn looks_like_token(w: &str) -> bool {
    w.len() >= 32
        && w.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '+' | '/' | '=' | '.'))
        && w.chars().any(|c| c.is_ascii_digit())
}

fn redact_word(w: &str, opts: RedactOptions, prev_auth: &mut bool) -> String {
    if w.is_empty() {
        return String::new();
    }
    let lower = w.to_ascii_lowercase();
    if *prev_auth {
        if matches!(lower.as_str(), "bearer" | "basic") {
            return w.to_string(); // keep the scheme word, redact the credential after it
        }
        *prev_auth = false;
        return "[redacted]".into();
    }
    if matches!(
        lower.trim_end_matches(':'),
        "bearer" | "basic" | "authorization" | "cookie" | "set-cookie"
    ) {
        *prev_auth = true;
        return w.to_string();
    }
    if let Some(i) = w.find("://") {
        let scheme = &w[..i];
        let rest = &w[i + 3..];
        let hostpart = rest.split(['/', '?', '#']).next().unwrap_or("");
        let hostpart = hostpart.rsplit('@').next().unwrap_or(hostpart);
        let shown = if opts.keep_hosts && !looks_like_ip(hostpart) {
            hostpart
        } else {
            "<host>"
        };
        let tail = if rest.len() > hostpart.len() {
            "/…"
        } else {
            ""
        };
        return format!("{scheme}://{shown}{tail}");
    }
    if let Some((k, _)) = w.split_once('=') {
        if SENSITIVE_KEYS.contains(&k.to_ascii_lowercase().as_str()) {
            return format!("{k}=[redacted]");
        }
    }
    if w.contains('?') && w.contains('=') {
        let base = w.split('?').next().unwrap_or("");
        return format!("{}?[redacted]", redact_word(base, opts, &mut false));
    }
    if w.contains('@') && w.rsplit('@').next().is_some_and(looks_like_host) {
        return "<email>".into();
    }
    if looks_like_ip(w) {
        return "<ip>".into();
    }
    if looks_like_token(w) {
        return "<token>".into();
    }
    if !opts.keep_hosts && looks_like_host(w) {
        let trail: String = w
            .chars()
            .rev()
            .take_while(|c| matches!(c, '.' | ':' | '!' | '?'))
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        return format!("<host>{trail}");
    }
    w.to_string()
}

/// Redact one text blob (any number of lines), preserving whitespace layout.
pub fn redact(text: &str, opts: RedactOptions) -> String {
    let mut out = String::with_capacity(text.len());
    for (li, line) in text.lines().enumerate() {
        if li > 0 {
            out.push('\n');
        }
        let mut prev_auth = false;
        let mut word = String::new();
        let flush = |word: &mut String, out: &mut String, prev_auth: &mut bool| {
            if !word.is_empty() {
                out.push_str(&redact_word(word, opts, prev_auth));
                word.clear();
            }
        };
        for c in line.chars() {
            if is_word_sep(c) {
                flush(&mut word, &mut out, &mut prev_auth);
                out.push(c);
            } else {
                word.push(c);
            }
        }
        flush(&mut word, &mut out, &mut prev_auth);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const STRICT: RedactOptions = RedactOptions { keep_hosts: false };
    const HOSTS: RedactOptions = RedactOptions { keep_hosts: true };

    #[test]
    fn urls_lose_path_query_and_credentials() {
        let r = redact(
            "GET https://user:pw@example.com/a/b?token=abc&x=1 failed",
            STRICT,
        );
        assert_eq!(r, "GET https://<host>/… failed");
        let r = redact("fetch https://api.example.com/v1/items?q=secret", HOSTS);
        assert_eq!(r, "fetch https://api.example.com/…");
        assert!(!r.contains("secret"));
    }

    #[test]
    fn ips_hosts_emails_are_removed() {
        let r = redact(
            "conn 192.168.1.20:5555 -> 93.184.216.34:443 for discord.com, mail bob@example.org",
            STRICT,
        );
        assert!(
            !r.contains("192.168")
                && !r.contains("93.184")
                && !r.contains("discord")
                && !r.contains("bob")
        );
        assert!(r.contains("<ip>") && r.contains("<host>") && r.contains("<email>"));
        assert_eq!(redact("peer 2606:4700::1111 up", STRICT), "peer <ip> up");
        assert_eq!(redact("[2606:4700::1111]:443", STRICT), "[<ip>]:443");
    }

    #[test]
    fn keep_hosts_keeps_names_but_never_ips() {
        let r = redact("resolved discord.com to 162.159.135.232", HOSTS);
        assert_eq!(r, "resolved discord.com to <ip>");
    }

    #[test]
    fn secrets_are_redacted() {
        assert_eq!(
            redact("Authorization: Bearer abc.def.ghi", STRICT),
            "Authorization: Bearer [redacted]"
        );
        assert_eq!(redact("Cookie: sid123", STRICT), "Cookie: [redacted]");
        assert_eq!(
            redact("password=hunter2 ok", STRICT),
            "password=[redacted] ok"
        );
        assert_eq!(redact("session_id=1", STRICT), "session_id=1"); // not a listed key: untouched
        let t = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6";
        assert_eq!(redact(&format!("key blob {t}"), STRICT), "key blob <token>");
    }

    #[test]
    fn versions_files_and_plain_text_survive() {
        let s = "Nivyx 0.1.0 loaded libnivyx_jni.so state=Active uptime=12s Android 14 (API 34)";
        assert_eq!(redact(s, STRICT), s);
        assert_eq!(
            redact("see build.gradle.kts and Cargo.toml", STRICT),
            "see build.gradle.kts and Cargo.toml"
        );
    }

    #[test]
    fn multiline_layout_preserved() {
        let r = redact("a 1.2.3.4\n\nb example.com", STRICT);
        assert_eq!(r, "a <ip>\n\nb <host>");
    }

    #[test]
    fn query_without_scheme() {
        assert_eq!(
            redact("path /search?q=cats&tok=1", STRICT),
            "path /search?[redacted]"
        );
    }

    #[test]
    fn trailing_punctuation_on_hosts() {
        assert_eq!(
            redact("failed for discord.com.", STRICT),
            "failed for <host>."
        );
    }
}
