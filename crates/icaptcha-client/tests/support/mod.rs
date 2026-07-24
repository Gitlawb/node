use std::ffi::OsString;

const PROXY_VARS: &[&str] = &[
    "NO_PROXY",
    "no_proxy",
    "ALL_PROXY",
    "all_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "REQUEST_METHOD",
];

/// Captures the current values of a set of env vars and restores them on drop.
pub struct EnvSnapshot(Vec<(String, Option<OsString>)>);

impl EnvSnapshot {
    pub fn capture(vars: &[&str]) -> Self {
        EnvSnapshot(
            vars.iter()
                .map(|v| (v.to_string(), std::env::var_os(v)))
                .collect(),
        )
    }
}

impl Drop for EnvSnapshot {
    fn drop(&mut self) {
        for (var, val) in &self.0 {
            match val {
                Some(v) => std::env::set_var(var, v),
                None => std::env::remove_var(var),
            }
        }
    }
}

/// Guard that restores env vars captured at construction time.
pub struct EnvGuard {
    _prev: EnvSnapshot,
}

/// Override every proxy-related env var so that non-loopback destinations are
/// forced through `proxy_url`, with NO_PROXY covering loopback.  Also clears
/// REQUEST_METHOD, which causes hyper-util to ignore all proxy variables when
/// set.  Restores prior values on drop.
pub fn arm_blackhole(proxy_url: &str) -> EnvGuard {
    let prev = EnvSnapshot::capture(PROXY_VARS);

    std::env::set_var("NO_PROXY", "127.0.0.1,localhost");
    std::env::set_var("no_proxy", "127.0.0.1,localhost");
    for var in [
        "ALL_PROXY",
        "all_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
    ] {
        std::env::set_var(var, proxy_url);
    }
    std::env::remove_var("REQUEST_METHOD");

    EnvGuard { _prev: prev }
}

/// Clear every proxy-related env var so connections go direct.  Restores
/// prior values on drop.
#[allow(dead_code)]
pub fn disarm_proxy_env() -> EnvGuard {
    let prev = EnvSnapshot::capture(PROXY_VARS);

    for var in PROXY_VARS {
        std::env::remove_var(var);
    }

    EnvGuard { _prev: prev }
}
