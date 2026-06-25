//! TCP/53 handling: transparent redirect to a local DoH-terminating proxy.
//!
//! A single synthesized packet cannot answer a DNS-over-TCP query (it is a
//! length-prefixed stream), so we redirect the connection to a local server and
//! let it speak real TCP.
//!
//! Redirect recipe:
//!   * Outbound client->server packet (dst 53): remember the original server
//!     keyed by (src_addr, src_port), rewrite the destination to
//!     `src_addr:PROXY_PORT`, and inject it INBOUND. Aiming at the packet's own
//!     source IP (a real interface address) makes the local stack deliver it to
//!     our listener; aiming at 127.0.0.1 does not work.
//!   * Proxy->client packet (src == PROXY_PORT): look the server up by
//!     (dst_addr, dst_port) and rewrite the source back to `server:53`.
//!
//! The rewriting runs inline on the capture thread, so the connection map needs
//! no locking.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};

use anyhow::{Context, Result};
use windivert::prelude::*;

use crate::config;
use crate::divert::{inject_inbound, Injector};
use crate::dnsutil::describe_query;
use crate::netpkt::{self, TCP_FIN, TCP_RST};
use crate::doh;

/// (src_addr, src_port) -> (orig_dst_addr, orig_dst_port). Capture-thread-only.
pub type ConnMap = HashMap<(Ipv4Addr, u16), (Ipv4Addr, u16)>;

// --------------------------------------------------------------------------- //
// Packet rewriting (capture thread)
// --------------------------------------------------------------------------- //
pub fn handle_packet(conn: &mut ConnMap, packet: &mut WinDivertPacket<NetworkLayer>, inj: &Injector) {
    let outbound = packet.address.outbound();
    let dst_port = netpkt::l4_dst_port(&packet.data);
    let src_port = netpkt::l4_src_port(&packet.data);

    if dst_port == Some(53) && outbound {
        redirect_to_proxy(conn, packet, inj);
    } else if src_port == Some(config::TCP_PROXY_PORT) {
        rewrite_reply(conn, packet, inj);
    } else {
        // Shouldn't happen given the filter; pass it through untouched.
        inj.send(packet);
    }
}

fn redirect_to_proxy(conn: &mut ConnMap, packet: &mut WinDivertPacket<NetworkLayer>, inj: &Injector) {
    let (Some(src), Some(sport)) = (netpkt::src_addr(&packet.data), netpkt::l4_src_port(&packet.data))
    else {
        return;
    };
    let (Some(dst), Some(dport)) = (netpkt::dst_addr(&packet.data), netpkt::l4_dst_port(&packet.data))
    else {
        return;
    };
    let key = (src, sport);
    conn.insert(key, (dst, dport));
    // Forget the mapping once the client tears the connection down.
    if netpkt::tcp_flags(&packet.data) & TCP_RST != 0 {
        conn.remove(&key);
    }

    let data = packet.data.to_mut();
    netpkt::set_dst_addr(data, src);
    netpkt::set_l4_dst_port(data, config::TCP_PROXY_PORT);
    inject_inbound(inj, packet);
}

fn rewrite_reply(conn: &mut ConnMap, packet: &mut WinDivertPacket<NetworkLayer>, inj: &Injector) {
    let (Some(dst), Some(dport)) = (netpkt::dst_addr(&packet.data), netpkt::l4_dst_port(&packet.data))
    else {
        return;
    };
    let key = (dst, dport);
    let Some(&(sip, sport)) = conn.get(&key) else {
        return; // unknown connection (stray packet); drop it
    };

    let flags = netpkt::tcp_flags(&packet.data);
    let data = packet.data.to_mut();
    netpkt::set_src_addr(data, sip);
    netpkt::set_l4_src_port(data, sport);
    inject_inbound(inj, packet);

    if flags & (TCP_RST | TCP_FIN) != 0 {
        conn.remove(&key);
    }
}

// --------------------------------------------------------------------------- //
// Local DoH-terminating TCP server
// --------------------------------------------------------------------------- //
fn recv_exactly(sock: &mut TcpStream, n: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    let mut got = 0;
    while got < n {
        match sock.read(&mut buf[got..]) {
            Ok(0) => {
                buf.truncate(got);
                return Ok(buf);
            }
            Ok(k) => got += k,
            Err(e) => return Err(e),
        }
    }
    Ok(buf)
}

fn serve_client(mut sock: TcpStream) {
    // Only ever serve the local host itself. Redirected connections always have
    // peer IP == local IP, so this rejects any real external client and prevents
    // acting as an open resolver.
    let (Ok(peer), Ok(local)) = (sock.peer_addr(), sock.local_addr()) else {
        return;
    };
    if peer.ip() != local.ip() {
        return;
    }
    let peer_ip = peer.ip();

    loop {
        let header = match recv_exactly(&mut sock, 2) {
            Ok(h) if h.len() == 2 => h,
            _ => return,
        };
        let length = u16::from_be_bytes([header[0], header[1]]) as usize;
        let query = match recv_exactly(&mut sock, length) {
            Ok(q) if q.len() == length => q,
            _ => return,
        };

        let desc = describe_query(&query);
        log::info!(target: "freegsm.tcp", "[INTERCEPT] TCP  {desc}  (from {peer_ip})");

        let answer = match doh::resolve(&query) {
            Ok(a) => a,
            Err(e) => {
                log::warn!(target: "freegsm.tcp",
                    "[FAILED]    TCP  {desc}  -> DoH error: {e:#}; closing");
                return; // closing the socket = fail-closed for this query
            }
        };
        log::info!(target: "freegsm.tcp", "[RESOLVED]  TCP  {desc}  -> {} bytes", answer.len());

        let mut framed = Vec::with_capacity(2 + answer.len());
        framed.extend_from_slice(&(answer.len() as u16).to_be_bytes());
        framed.extend_from_slice(&answer);
        if sock.write_all(&framed).is_err() {
            return;
        }
    }
}

/// Start the local DoH-terminating TCP server on its own thread.
pub fn start_server() -> Result<()> {
    let addr = (config::TCP_BIND_HOST, config::TCP_PROXY_PORT);
    let listener = TcpListener::bind(addr)
        .with_context(|| format!("binding TCP DoH proxy on {}:{}", config::TCP_BIND_HOST, config::TCP_PROXY_PORT))?;
    log::info!(target: "freegsm.tcp",
        "TCP DoH proxy listening on {}:{}", config::TCP_BIND_HOST, config::TCP_PROXY_PORT);
    std::thread::Builder::new()
        .name("tcp-proxy".into())
        .spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(s) => {
                        std::thread::spawn(move || serve_client(s));
                    }
                    Err(e) => log::debug!(target: "freegsm.tcp", "accept error: {e}"),
                }
            }
        })
        .context("spawning tcp-proxy thread")?;
    Ok(())
}
