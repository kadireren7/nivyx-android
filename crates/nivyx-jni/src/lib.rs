//! JNI surface. Deliberately small:
//! * engine handles are opaque ids into a registry (never raw pointers), so stale or doubled
//!   calls cannot cause use-after-free;
//! * every entry point is wrapped in `catch_unwind` — a Rust panic can never unwind into the JVM;
//! * all inputs are length-bounded and validated before use.

mod logger;

use jni::objects::{GlobalRef, JClass, JObject, JString, JValue};
use jni::sys::{jboolean, jint, jlong, jstring, JNI_FALSE, JNI_TRUE};
use jni::{JNIEnv, JavaVM};
use nivyx_core::config::Config;
use nivyx_core::netid::{fingerprint, NetworkInfo};
use nivyx_core::redact::{redact, RedactOptions};
use nivyx_core::strategy::ManualRules;
use nivyx_engine::connector::Protector;
use nivyx_engine::Engine;
use std::collections::HashMap;
use std::net::IpAddr;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex, OnceLock};

const MAX_TEXT: usize = 256 * 1024;

type Registry = Mutex<HashMap<u64, Arc<Mutex<Engine>>>>;

fn registry() -> &'static Registry {
    static R: OnceLock<Registry> = OnceLock::new();
    R.get_or_init(|| Mutex::new(HashMap::new()))
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static LAST_ERROR: Mutex<String> = Mutex::new(String::new());

fn set_error(msg: impl Into<String>) {
    *LAST_ERROR.lock().unwrap_or_else(|e| e.into_inner()) = msg.into();
}

fn get_engine(h: jlong) -> Option<Arc<Mutex<Engine>>> {
    registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&(h as u64))
        .cloned()
}

/// Calls `VpnService.protect(int)` on the Kotlin service object.
struct JniProtector {
    vm: JavaVM,
    service: GlobalRef,
}

impl Protector for JniProtector {
    fn protect(&self, fd: i32) -> bool {
        let Ok(mut env) = self.vm.attach_current_thread() else {
            return false;
        };
        let r = env.call_method(self.service.as_obj(), "protect", "(I)Z", &[JValue::Int(fd)]);
        if env.exception_check().unwrap_or(true) {
            let _ = env.exception_clear();
            return false;
        }
        matches!(r.and_then(|v| v.z()), Ok(true))
    }
}

fn read_string(env: &mut JNIEnv, s: &JString) -> Option<String> {
    let s: String = env.get_string(s).ok()?.into();
    (s.len() <= MAX_TEXT).then_some(s)
}

fn to_jstring(env: &mut JNIEnv, s: &str) -> jstring {
    env.new_string(s)
        .map(|j| j.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

fn guarded<T>(default: T, f: impl FnOnce() -> T) -> T {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|_| {
        set_error("internal error (panic caught at JNI boundary)");
        default
    })
}

#[no_mangle]
pub extern "system" fn Java_app_nivyx_android_core_NivyxNative_version(
    mut env: JNIEnv,
    _c: JClass,
) -> jstring {
    to_jstring(&mut env, env!("CARGO_PKG_VERSION"))
}

/// Start the engine. Returns a handle (>0) or 0 on failure (see `lastError`).
#[no_mangle]
pub extern "system" fn Java_app_nivyx_android_core_NivyxNative_start(
    mut env: JNIEnv,
    _c: JClass,
    tun_fd: jint,
    config: JString,
    network_id: jlong,
    has_ipv6: jboolean,
    dns_csv: JString,
    service: JObject,
) -> jlong {
    logger::init();
    let Some(cfg_json) = read_string(&mut env, &config) else {
        set_error("config unreadable or too large");
        return 0;
    };
    let dns_csv = read_string(&mut env, &dns_csv).unwrap_or_default();
    let (Ok(vm), Ok(service)) = (env.get_java_vm(), env.new_global_ref(&service)) else {
        set_error("cannot capture JVM/service reference");
        return 0;
    };
    guarded(0, || {
        let mut cfg = match Config::from_json(&cfg_json) {
            Ok(c) => c,
            Err(e) => {
                set_error(e);
                return 0;
            }
        };
        // Network identity is applied before the first packet is processed (no race with flows).
        cfg.network_id = network_id as u64;
        cfg.has_ipv6 = has_ipv6 != 0;
        cfg.system_dns = dns_csv
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .take(8)
            .collect();
        if tun_fd < 0 {
            set_error("invalid TUN descriptor");
            return 0;
        }
        match Engine::start(tun_fd, cfg, Arc::new(JniProtector { vm, service })) {
            Ok(e) => {
                let id = NEXT_ID.fetch_add(1, Relaxed);
                registry()
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(id, Arc::new(Mutex::new(e)));
                log::info!("engine {id} started (core {})", env!("CARGO_PKG_VERSION"));
                id as jlong
            }
            Err(e) => {
                set_error(format!("engine start failed: {e}"));
                0
            }
        }
    })
}

/// Stop and release an engine. Safe to call repeatedly or with a stale handle.
#[no_mangle]
pub extern "system" fn Java_app_nivyx_android_core_NivyxNative_stop(
    _env: JNIEnv,
    _c: JClass,
    handle: jlong,
) {
    guarded((), || {
        let e = registry()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&(handle as u64));
        if let Some(e) = e {
            e.lock().unwrap_or_else(|e| e.into_inner()).stop();
            log::info!("engine {handle} stopped");
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_app_nivyx_android_core_NivyxNative_statsJson(
    mut env: JNIEnv,
    _c: JClass,
    handle: jlong,
) -> jstring {
    let s = guarded(String::from("{}"), || match get_engine(handle) {
        Some(e) => e.lock().unwrap_or_else(|e| e.into_inner()).stats_json(),
        None => "{}".into(),
    });
    to_jstring(&mut env, &s)
}

#[no_mangle]
pub extern "system" fn Java_app_nivyx_android_core_NivyxNative_updateConfig(
    mut env: JNIEnv,
    _c: JClass,
    handle: jlong,
    config: JString,
) -> jboolean {
    let Some(json) = read_string(&mut env, &config) else {
        return JNI_FALSE;
    };
    guarded(JNI_FALSE, || {
        let mut cfg = match Config::from_json(&json) {
            Ok(c) => c,
            Err(e) => {
                set_error(e);
                return JNI_FALSE;
            }
        };
        let Some(e) = get_engine(handle) else {
            return JNI_FALSE;
        };
        let e = e.lock().unwrap_or_else(|e| e.into_inner());
        // Network identity is owned by `networkChanged`, not by settings updates.
        let cur = e.shared.cfg();
        cfg.network_id = cur.network_id;
        cfg.has_ipv6 = cur.has_ipv6;
        cfg.system_dns = cur.system_dns.clone();
        e.shared.set_config(cfg);
        JNI_TRUE
    })
}

/// `dns_csv`: comma separated IP literals of the underlying network's DNS servers.
#[no_mangle]
pub extern "system" fn Java_app_nivyx_android_core_NivyxNative_networkChanged(
    mut env: JNIEnv,
    _c: JClass,
    handle: jlong,
    network_id: jlong,
    has_ipv6: jboolean,
    dns_csv: JString,
) -> jboolean {
    let Some(csv) = read_string(&mut env, &dns_csv) else {
        return JNI_FALSE;
    };
    guarded(JNI_FALSE, || {
        let dns: Vec<IpAddr> = csv
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .take(8)
            .collect();
        match get_engine(handle) {
            Some(e) => {
                e.lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .shared
                    .network_changed(network_id as u64, has_ipv6 != 0, dns);
                JNI_TRUE
            }
            None => JNI_FALSE,
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_app_nivyx_android_core_NivyxNative_diagnose(
    mut env: JNIEnv,
    _c: JClass,
    handle: jlong,
    host: JString,
) -> jstring {
    let host = read_string(&mut env, &host).unwrap_or_default();
    let out = guarded(r#"{"error":"internal error"}"#.to_string(), || {
        // Take what we need and release the engine lock: a probe can run for many seconds and
        // must not block stats polling or `stop`.
        let ctx = get_engine(handle)
            .and_then(|e| e.lock().unwrap_or_else(|e| e.into_inner()).diag_context());
        match ctx {
            Some((h, shared)) => nivyx_engine::diagnose_blocking(&h, shared, &host),
            None => r#"{"error":"not running"}"#.into(),
        }
    });
    to_jstring(&mut env, &out)
}

#[no_mangle]
pub extern "system" fn Java_app_nivyx_android_core_NivyxNative_exportLearned(
    mut env: JNIEnv,
    _c: JClass,
    handle: jlong,
) -> jstring {
    let s = guarded("[]".to_string(), || match get_engine(handle) {
        Some(e) => e.lock().unwrap_or_else(|e| e.into_inner()).export_learned(),
        None => "[]".into(),
    });
    to_jstring(&mut env, &s)
}

#[no_mangle]
pub extern "system" fn Java_app_nivyx_android_core_NivyxNative_importLearned(
    mut env: JNIEnv,
    _c: JClass,
    handle: jlong,
    json: JString,
) -> jint {
    let Some(json) = read_string(&mut env, &json) else {
        return 0;
    };
    guarded(0, || match get_engine(handle) {
        Some(e) => e
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .import_learned(&json) as jint,
        None => 0,
    })
}

#[no_mangle]
pub extern "system" fn Java_app_nivyx_android_core_NivyxNative_resetLearned(
    _env: JNIEnv,
    _c: JClass,
    handle: jlong,
) {
    guarded((), || {
        if let Some(e) = get_engine(handle) {
            e.lock().unwrap_or_else(|e| e.into_inner()).reset_learned();
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_app_nivyx_android_core_NivyxNative_lastError(
    mut env: JNIEnv,
    _c: JClass,
) -> jstring {
    let s = LAST_ERROR.lock().unwrap_or_else(|e| e.into_inner()).clone();
    to_jstring(&mut env, &s)
}

#[no_mangle]
pub extern "system" fn Java_app_nivyx_android_core_NivyxNative_setDebug(
    _env: JNIEnv,
    _c: JClass,
    on: jboolean,
) {
    logger::init();
    logger::set_debug(on != 0);
}

/// Salted hash of the (already coarse) network identity. Raw values never leave this call.
#[no_mangle]
pub extern "system" fn Java_app_nivyx_android_core_NivyxNative_fingerprint(
    mut env: JNIEnv,
    _c: JClass,
    salt: JString,
    transport: JString,
    gateway: JString,
    subnet: JString,
    dns: JString,
    carrier: JString,
) -> jlong {
    let (Some(salt), Some(t), Some(g), Some(s), Some(d), Some(c)) = (
        read_string(&mut env, &salt),
        read_string(&mut env, &transport),
        read_string(&mut env, &gateway),
        read_string(&mut env, &subnet),
        read_string(&mut env, &dns),
        read_string(&mut env, &carrier),
    ) else {
        return 0;
    };
    guarded(0, || {
        let info = NetworkInfo {
            transport: &t,
            gateway: &g,
            subnet: &s,
            dns: &d,
            carrier: &c,
            ..Default::default()
        };
        fingerprint(salt.as_bytes(), &info) as jlong
    })
}

#[no_mangle]
pub extern "system" fn Java_app_nivyx_android_core_NivyxNative_redact(
    mut env: JNIEnv,
    _c: JClass,
    text: JString,
    keep_hosts: jboolean,
) -> jstring {
    let text = read_string(&mut env, &text).unwrap_or_default();
    let out = guarded(String::new(), || {
        redact(
            &text,
            RedactOptions {
                keep_hosts: keep_hosts != 0,
            },
        )
    });
    to_jstring(&mut env, &out)
}

/// Empty string when valid, otherwise a human-readable error.
#[no_mangle]
pub extern "system" fn Java_app_nivyx_android_core_NivyxNative_validateConfig(
    mut env: JNIEnv,
    _c: JClass,
    json: JString,
) -> jstring {
    let json = read_string(&mut env, &json).unwrap_or_default();
    let out = guarded("internal error".to_string(), || {
        Config::from_json(&json).err().unwrap_or_default()
    });
    to_jstring(&mut env, &out)
}

/// `{"rules": n, "errors": [{"line": 3, "message": "..."}]}`
#[no_mangle]
pub extern "system" fn Java_app_nivyx_android_core_NivyxNative_parseRules(
    mut env: JNIEnv,
    _c: JClass,
    text: JString,
) -> jstring {
    let text = read_string(&mut env, &text).unwrap_or_default();
    let out = guarded("{}".to_string(), || {
        let (rules, errs) = ManualRules::parse(&text);
        serde_json::json!({
            "rules": rules.len(),
            "errors": errs.iter().map(|(l, m)| serde_json::json!({"line": l, "message": m})).collect::<Vec<_>>(),
        })
        .to_string()
    });
    to_jstring(&mut env, &out)
}

#[no_mangle]
pub extern "system" fn Java_app_nivyx_android_core_NivyxNative_recentLogs(
    mut env: JNIEnv,
    _c: JClass,
) -> jstring {
    let out = guarded(String::new(), logger::recent);
    to_jstring(&mut env, &out)
}
