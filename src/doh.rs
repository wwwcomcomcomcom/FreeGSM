//! DoH client. A DNS query and a DoH request body are the *same* bytes (RFC 8484
//! `application/dns-message` == the UDP DNS wire format), so resolving is just:
//! POST the query bytes, return the response bytes. No DNS parsing.
//!
//! One shared blocking client over HTTP/2 + a kept-alive TLS connection. We
//! connect to the literal upstream IP (the URL host), so resolving the DoH host
//! never itself needs DNS; rustls verifies the connection against the cert's IP
//! SAN. `resolve` raises on any failure so callers can fail closed.

use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use reqwest::blocking::Client;
use reqwest::header::{HeaderValue, ACCEPT, CONTENT_TYPE};

use crate::config;

static CLIENT: OnceLock<Client> = OnceLock::new();

const DNS_MESSAGE: &str = "application/dns-message";

/// Build the shared client. Call once at startup (before [`resolve`]).
pub fn start() -> Result<()> {
    let client = Client::builder()
        .use_rustls_tls()
        .timeout(config::DOH_TIMEOUT)
        // Keep the connection pool small but warm.
        .pool_max_idle_per_host(8)
        .pool_idle_timeout(Duration::from_secs(90))
        .build()
        .context("building DoH HTTP client")?;
    let _ = CLIENT.set(client);
    Ok(())
}

fn client() -> Result<&'static Client> {
    CLIENT.get().ok_or_else(|| anyhow!("DoH client not started"))
}

/// A minimal DNS query for `example.com A`, used to probe upstream reachability.
const PROBE_QUERY: &[u8] = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\
\x07example\x03com\x00\x00\x01\x00\x01";

/// Check the DoH upstream is reachable. Returns `(ok, detail)`.
pub fn probe() -> (bool, String) {
    match resolve(PROBE_QUERY) {
        Ok(_) => (true, "ok".to_string()),
        Err(e) => (false, format!("{e:#}")),
    }
}

/// Resolve a raw DNS query (wire format) via DoH; return the raw response.
/// Errors on any failure so callers can fail closed (drop the query).
pub fn resolve(query: &[u8]) -> Result<Vec<u8>> {
    let client = client()?;
    let resp = client
        .post(&config::get().doh_url)
        .header(CONTENT_TYPE, HeaderValue::from_static(DNS_MESSAGE))
        .header(ACCEPT, HeaderValue::from_static(DNS_MESSAGE))
        .body(query.to_vec())
        .send()
        .context("DoH request failed")?
        .error_for_status()
        .context("DoH upstream returned an error status")?;
    let body = resp.bytes().context("reading DoH response body")?;
    if body.is_empty() {
        return Err(anyhow!("empty DoH response"));
    }
    Ok(body.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Live check of the critical risk: connecting to a *literal IP* DoH URL and
    /// having rustls accept it via the cert's IP SAN, over HTTP/2. Network-bound,
    /// so #[ignore]'d by default. Run with: `cargo test -- --ignored live_probe`.
    #[test]
    #[ignore]
    fn live_probe() {
        // The user's network blocks 1.1.1.1; 8.8.8.8 is the agreed upstream.
        std::env::set_var("FREEGSM_DOH_URL", "https://8.8.8.8/dns-query");
        config::init();
        start().unwrap();
        let answer = resolve(PROBE_QUERY).expect("DoH resolve against literal IP failed");
        // A valid DNS response echoes the query id and has the QR bit set.
        assert!(answer.len() > 12, "short DoH answer: {} bytes", answer.len());
        assert_eq!(answer[0..2], PROBE_QUERY[0..2], "response id mismatch");
    }
}
