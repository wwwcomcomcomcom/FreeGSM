//! UDP/53 handling: stateless DoH response synthesis.
//!
//! An outbound UDP DNS query is captured, its payload resolved over DoH, and the
//! same packet turned into the reply by swapping addresses/ports and replacing
//! the payload, then injected back inbound. Runs on the thread pool (the DoH
//! round-trip is blocking).

use windivert::prelude::*;

use crate::config;
use crate::divert::{inject_inbound, Injector};
use crate::dnsutil::describe_query;
use crate::{doh, netpkt};

/// Resolve one captured outbound UDP/53 query and inject the reply. On any DoH
/// failure the query is dropped (fail-closed) unless `FAIL_OPEN`, in which case
/// the original query is forwarded in plaintext.
pub fn handle(mut packet: WinDivertPacket<NetworkLayer>, inj: &Injector) {
    let Some(off) = netpkt::udp_payload_offset(&packet.data) else {
        return;
    };
    let query = packet.data[off..].to_vec();
    if query.is_empty() {
        return;
    }

    let desc = describe_query(&query);
    let src = netpkt::src_addr(&packet.data)
        .map(|a| a.to_string())
        .unwrap_or_else(|| "?".to_string());
    log::info!(target: "freegsm.udp", "[INTERCEPT] UDP  {desc}  (from {src})");

    let answer = match doh::resolve(&query) {
        Ok(a) => a,
        Err(e) => {
            if config::FAIL_OPEN {
                log::warn!(target: "freegsm.udp",
                    "[FAILED]    UDP  {desc}  -> DoH error: {e:#}; forwarding plaintext");
                inj.send(&packet);
            } else {
                log::warn!(target: "freegsm.udp",
                    "[FAILED]    UDP  {desc}  -> DoH error: {e:#}; dropped");
            }
            return;
        }
    };

    log::info!(target: "freegsm.udp", "[RESOLVED]  UDP  {desc}  -> {} bytes", answer.len());

    // Turn the captured query into its reply, in place.
    let data = packet.data.to_mut();
    netpkt::swap_endpoints(data);
    if !netpkt::set_udp_payload(data, &answer) {
        return;
    }
    inject_inbound(inj, &mut packet);
}
