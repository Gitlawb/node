/// Set every proxy env var to point at `proxy_url`, with NO_PROXY covering
/// loopback so the mock is reached directly.
pub fn arm_blackhole(proxy_url: &str) {
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
}
