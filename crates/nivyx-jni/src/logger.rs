//! Bounded, privacy-aware logging: an in-memory ring buffer (for the support bundle) plus logcat.
//! Hostnames never appear at the default level; debug logging is opt-in.

use log::{LevelFilter, Log, Metadata, Record};
use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::Once;

const MAX_LINES: usize = 400;
const MAX_LINE_LEN: usize = 240;

static RING: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());
static INIT: Once = Once::new();
static LOGGER: RingLogger = RingLogger;

struct RingLogger;

impl Log for RingLogger {
    fn enabled(&self, m: &Metadata) -> bool {
        m.level() <= log::max_level()
    }

    fn log(&self, r: &Record) {
        if !self.enabled(r.metadata()) {
            return;
        }
        let mut line = format!("{} {}: {}", r.level(), short_target(r.target()), r.args());
        if line.len() > MAX_LINE_LEN {
            let mut cut = MAX_LINE_LEN;
            while !line.is_char_boundary(cut) {
                cut -= 1;
            }
            line.truncate(cut);
        }
        #[cfg(target_os = "android")]
        android_write(r.level(), &line);
        let mut g = RING.lock().unwrap_or_else(|e| e.into_inner());
        if g.len() >= MAX_LINES {
            g.pop_front();
        }
        g.push_back(line);
    }

    fn flush(&self) {}
}

fn short_target(t: &str) -> &str {
    t.rsplit("::").next().unwrap_or(t)
}

#[cfg(target_os = "android")]
fn android_write(level: log::Level, msg: &str) {
    use log::Level;
    use std::ffi::CString;
    extern "C" {
        fn __android_log_write(
            prio: i32,
            tag: *const std::os::raw::c_char,
            text: *const std::os::raw::c_char,
        ) -> i32;
    }
    let prio = match level {
        Level::Error => 6,
        Level::Warn => 5,
        Level::Info => 4,
        Level::Debug => 3,
        Level::Trace => 2,
    };
    if let (Ok(tag), Ok(text)) = (CString::new("nivyx"), CString::new(msg.replace('\0', " "))) {
        // SAFETY: both pointers are valid NUL-terminated strings for the duration of the call.
        unsafe { __android_log_write(prio, tag.as_ptr(), text.as_ptr()) };
    }
}

pub fn init() {
    INIT.call_once(|| {
        let _ = log::set_logger(&LOGGER);
        log::set_max_level(LevelFilter::Info);
    });
}

pub fn set_debug(on: bool) {
    log::set_max_level(if on {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    });
}

pub fn recent() -> String {
    RING.lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .cloned()
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_is_bounded_and_lines_are_truncated() {
        init();
        for i in 0..(MAX_LINES + 50) {
            log::warn!("line {i} {}", "x".repeat(500));
        }
        let all = recent();
        let lines: Vec<&str> = all.lines().collect();
        assert!(lines.len() <= MAX_LINES);
        assert!(lines.iter().all(|l| l.len() <= MAX_LINE_LEN));
        assert!(lines
            .last()
            .unwrap()
            .contains(&format!("line {}", MAX_LINES + 49)));
    }
}
