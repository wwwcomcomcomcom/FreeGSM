//! Runtime configuration. Mirrors `dohproxy/config.py`.
//!
//! Priority: environment variables -> built-in defaults. (The Python build also
//! read an optional `config.yml`; that is out of scope here per the migration
//! plan, which lists only the `FREEGSM_*` env vars.)
//!
//! Built once at startup into a global accessed via [`get`]. Read this module
//! first to understand the WinDivert capture filter.

use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::OnceLock;
use std::time::Duration;

// --- TCP transparent proxy ---------------------------------------------------
pub const TCP_BIND_HOST: &str = "0.0.0.0";
pub const TCP_PROXY_PORT: u16 = 53533;

// --- DPI / SNI-blocking bypass ----------------------------------------------
pub const HTTPS_PROXY_PORT: u16 = 53444;
// Relay upstream sockets bind to ports in [BASE, BASE+COUNT); the filter excludes
// this range so those packets are never re-captured. Sits below Windows'
// ephemeral range (49152-65535).
pub const UPSTREAM_PORT_BASE: u16 = 30000;
pub const UPSTREAM_PORT_COUNT: u16 = 2048;

// TLS-record split bounds (bytes, including the 5-byte header), matching Intra.
pub const SPLIT_MIN: usize = 6;
pub const SPLIT_MAX: usize = 64;

pub const DOH_TIMEOUT: Duration = Duration::from_secs(5);
pub const HTTPS_CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
pub const HTTPS_FIRST_READ_TIMEOUT: Duration = Duration::from_secs(8);

// Fail-closed: on DoH error, drop the query rather than leak plaintext.
pub const FAIL_OPEN: bool = false;
pub const WORKER_THREADS: usize = 32;

pub struct Config {
    pub doh_url: String,
    /// Host part of `doh_url` when it is a literal IPv4 (so the DPI layer can
    /// leave our own DoH channel alone). `None` if the URL uses a hostname.
    /// Consumed when building [`Config::divert_filter`]; kept for introspection.
    #[allow(dead_code)]
    pub doh_server_ip: Option<Ipv4Addr>,
    pub dpi_bypass: bool,
    pub divert_filter: String,
}

static CONFIG: OnceLock<Config> = OnceLock::new();

/// Initialise the global config from the environment. Call once at startup.
pub fn init() -> &'static Config {
    CONFIG.get_or_init(Config::from_env)
}

/// Access the global config. Panics if [`init`] has not been called.
pub fn get() -> &'static Config {
    CONFIG.get().expect("config::init() not called")
}

impl Config {
    fn from_env() -> Self {
        let doh_url = std::env::var("FREEGSM_DOH_URL")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "https://1.0.0.1/dns-query".to_string());

        let doh_server_ip = literal_ipv4_host(&doh_url);
        let dpi_bypass = env_flag("FREEGSM_DPI", true);
        let divert_filter = build_filter(dpi_bypass, doh_server_ip);

        Config {
            doh_url,
            doh_server_ip,
            dpi_bypass,
            divert_filter,
        }
    }
}

/// Parse a boolean env var with the same truthiness rules as the Python
/// `_env_flag`: present and not in {"0","false","no","off",""} -> true;
/// absent -> `default`.
fn env_flag(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(val) => {
            let v = val.trim().to_ascii_lowercase();
            !matches!(v.as_str(), "0" | "false" | "no" | "off" | "")
        }
        Err(_) => default,
    }
}

/// Return the host of `url` if (and only if) it is a literal dotted-quad IPv4.
fn literal_ipv4_host(url: &str) -> Option<Ipv4Addr> {
    let parsed = url::Url::parse(url).ok()?;
    let host = parsed.host_str()?;
    // Match the Python check: four dotted, all-numeric parts.
    if host.split('.').count() == 4 && host.split('.').all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())) {
        Ipv4Addr::from_str(host).ok()
    } else {
        None
    }
}

/// Build the WinDivert filter string, byte-for-byte matching `config.py`.
fn build_filter(dpi_bypass: bool, doh_ip: Option<Ipv4Addr>) -> String {
    // DNS clauses:
    //   1. outbound UDP/53  -> synthesized DoH responses
    //   2. outbound TCP/53  -> redirected to the local DoH proxy
    //   3. packets the proxy emits (src == TCP_PROXY_PORT) -> rewritten as if
    //      from the real server. No `outbound` qualifier so it also matches
    //      same-host (loopback-flagged) replies.
    let dns_clauses = format!(
        "(outbound and udp.DstPort == 53) or (outbound and tcp.DstPort == 53) or (tcp.SrcPort == {TCP_PROXY_PORT})"
    );

    let mut filter = format!("ip and ({dns_clauses}");

    if dpi_bypass {
        let upstream_hi = UPSTREAM_PORT_BASE + UPSTREAM_PORT_COUNT - 1;
        let doh_excl = match doh_ip {
            Some(ip) => format!(" and ip.DstAddr != {ip}"),
            None => String::new(),
        };
        // DPI clauses:
        //   * outbound TCP/443, EXCEPT our DoH upstream and the relay's reserved
        //     upstream source-port range -> redirected to the splitting relay.
        //   * packets the relay emits (src == HTTPS_PROXY_PORT) -> rewritten back
        //     to look like they came from the real server:443.
        let dpi_clauses = format!(
            "(outbound and tcp.DstPort == 443{doh_excl} and (tcp.SrcPort < {UPSTREAM_PORT_BASE} or tcp.SrcPort > {upstream_hi})) or (tcp.SrcPort == {HTTPS_PROXY_PORT})"
        );
        filter.push_str(&format!(" or {dpi_clauses}"));
    }
    filter.push(')');
    filter
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_matches_python_default() {
        let ip = Some(Ipv4Addr::new(1, 0, 0, 1));
        let f = build_filter(true, ip);
        assert_eq!(
            f,
            "ip and ((outbound and udp.DstPort == 53) or (outbound and tcp.DstPort == 53) or (tcp.SrcPort == 53533) or (outbound and tcp.DstPort == 443 and ip.DstAddr != 1.0.0.1 and (tcp.SrcPort < 30000 or tcp.SrcPort > 32047)) or (tcp.SrcPort == 53444))"
        );
    }

    #[test]
    fn filter_dpi_off() {
        let f = build_filter(false, Some(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(
            f,
            "ip and ((outbound and udp.DstPort == 53) or (outbound and tcp.DstPort == 53) or (tcp.SrcPort == 53533))"
        );
    }

    #[test]
    fn filter_hostname_upstream_has_no_doh_exclusion() {
        let f = build_filter(true, None);
        assert!(f.contains("outbound and tcp.DstPort == 443 and (tcp.SrcPort"));
        assert!(!f.contains("ip.DstAddr !="));
    }

    #[test]
    fn detects_literal_ipv4() {
        assert_eq!(literal_ipv4_host("https://1.0.0.1/dns-query"), Some(Ipv4Addr::new(1, 0, 0, 1)));
        assert_eq!(literal_ipv4_host("https://8.8.8.8/dns-query"), Some(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(literal_ipv4_host("https://dns.google/dns-query"), None);
    }
}
