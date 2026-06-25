//! Transparent TLS-splitting relay for outbound TCP/443 (SNI/DPI bypass).
//!
//! Defeating an SNI filter that reassembles the TCP stream requires TLS
//! *record-layer* fragmentation, which inserts a second 5-byte record header into
//! the byte stream. You cannot insert bytes on the raw WinDivert path without
//! desyncing the client kernel's TCP sequence numbers, so -- exactly like Intra --
//! we terminate each :443 connection at a tiny local relay (the same redirect
//! trick as tcp_proxy) and reframe the ClientHello from a process that owns both
//! sockets.
//!
//! The relay's upstream sockets bind to a reserved source-port range the kernel
//! filter excludes, so they travel normally and are never re-captured.
//!
//! Packet rewriting runs on the capture thread; the connection map is shared with
//! handler threads, so it is behind a Mutex (the Python relied on the GIL).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, OnceLock};

use anyhow::{anyhow, Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use windivert::prelude::*;

use crate::config;
use crate::divert::{inject_inbound, Injector};
use crate::netpkt::{self, TCP_FIN, TCP_RST};
use crate::tcp_proxy::ConnMap;
use crate::dpi;

// (src_addr, src_port) -> (orig_dst_addr, orig_dst_port). Written by the capture
// thread, read by handler threads -> Mutex.
static CONN: OnceLock<Mutex<ConnMap>> = OnceLock::new();

fn conn() -> &'static Mutex<ConnMap> {
    CONN.get_or_init(|| Mutex::new(HashMap::new()))
}

// --------------------------------------------------------------------------- //
// Packet rewriting (capture thread)
// --------------------------------------------------------------------------- //
pub fn handle_packet(packet: &mut WinDivertPacket<NetworkLayer>, inj: &Injector) {
    let outbound = packet.address.outbound();
    let dst_port = netpkt::l4_dst_port(&packet.data);
    let src_port = netpkt::l4_src_port(&packet.data);

    if outbound && dst_port == Some(443) {
        redirect(packet, inj);
    } else if src_port == Some(config::HTTPS_PROXY_PORT) {
        rewrite_reply(packet, inj);
    } else {
        inj.send(packet);
    }
}

fn redirect(packet: &mut WinDivertPacket<NetworkLayer>, inj: &Injector) {
    let (Some(src), Some(sport)) = (netpkt::src_addr(&packet.data), netpkt::l4_src_port(&packet.data))
    else {
        return;
    };
    let (Some(dst), Some(dport)) = (netpkt::dst_addr(&packet.data), netpkt::l4_dst_port(&packet.data))
    else {
        return;
    };
    let key = (src, sport);
    {
        let mut map = conn().lock().unwrap();
        map.insert(key, (dst, dport));
        if netpkt::tcp_flags(&packet.data) & TCP_RST != 0 {
            map.remove(&key);
        }
    }

    let data = packet.data.to_mut();
    netpkt::set_dst_addr(data, src);
    netpkt::set_l4_dst_port(data, config::HTTPS_PROXY_PORT);
    inject_inbound(inj, packet);
}

fn rewrite_reply(packet: &mut WinDivertPacket<NetworkLayer>, inj: &Injector) {
    let (Some(dst), Some(dport)) = (netpkt::dst_addr(&packet.data), netpkt::l4_dst_port(&packet.data))
    else {
        return;
    };
    let key = (dst, dport);
    let server = conn().lock().unwrap().get(&key).copied();
    let Some((sip, sport)) = server else {
        return; // unknown/teardown stray; drop
    };

    let flags = netpkt::tcp_flags(&packet.data);
    let data = packet.data.to_mut();
    netpkt::set_src_addr(data, sip);
    netpkt::set_l4_src_port(data, sport);
    inject_inbound(inj, packet);

    if flags & (TCP_RST | TCP_FIN) != 0 {
        conn().lock().unwrap().remove(&key);
    }
}

// --------------------------------------------------------------------------- //
// Reserved upstream source ports (so the relay's upstream leg is never captured)
// --------------------------------------------------------------------------- //
static NEXT_PORT: AtomicU32 = AtomicU32::new(0);

fn connect_upstream(server_ip: Ipv4Addr, server_port: u16) -> Result<TcpStream> {
    let base = config::UPSTREAM_PORT_BASE;
    let count = config::UPSTREAM_PORT_COUNT as u32;
    let mut last_err: Option<std::io::Error> = None;

    for _ in 0..count {
        let n = NEXT_PORT.fetch_add(1, Ordering::Relaxed);
        let port = base + (n % count) as u16;

        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
            .context("creating upstream socket")?;
        let _ = socket.set_reuse_address(true);
        let bind_addr: SocketAddr = (Ipv4Addr::UNSPECIFIED, port).into();
        if let Err(e) = socket.bind(&bind_addr.into()) {
            last_err = Some(e); // port busy -> try the next one
            continue;
        }
        let _ = socket.set_nodelay(true);
        let server: SocketAddr = (server_ip, server_port).into();
        // Connect failures propagate immediately (mirrors the Python relay).
        socket
            .connect_timeout(&server.into(), config::HTTPS_CONNECT_TIMEOUT)
            .with_context(|| format!("connecting upstream {server_ip}:{server_port}"))?;
        return Ok(socket.into());
    }

    Err(anyhow!(
        "no free upstream port in reserved range ({last_err:?})"
    ))
}

// --------------------------------------------------------------------------- //
// Local relay server
// --------------------------------------------------------------------------- //
fn pump(mut src: TcpStream, mut dst: TcpStream) {
    let mut buf = vec![0u8; 65535];
    loop {
        match src.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if dst.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = dst.shutdown(std::net::Shutdown::Write);
}

fn serve_client(client: TcpStream) {
    let (Ok(peer), Ok(local)) = (client.peer_addr(), client.local_addr()) else {
        return;
    };
    // Redirected connections always have peer IP == this host's IP. Reject
    // anything else so we never act as an open proxy.
    if peer.ip() != local.ip() {
        return;
    }

    let key = match peer {
        SocketAddr::V4(a) => (*a.ip(), a.port()),
        _ => return,
    };
    let Some((server_ip, server_port)) = conn().lock().unwrap().get(&key).copied() else {
        return;
    };

    let _ = client.set_nodelay(true);

    let upstream = match connect_upstream(server_ip, server_port) {
        Ok(u) => u,
        Err(e) => {
            log::warn!(target: "freegsm.https",
                "[HTTPS] upstream {server_ip}:{server_port} failed: {e:#}");
            return;
        }
    };

    relay(client, upstream, server_ip, server_port);
}

fn relay(mut client: TcpStream, mut upstream: TcpStream, server_ip: Ipv4Addr, server_port: u16) {
    // Read the first client segment -- the TLS ClientHello -- and re-emit it
    // fragmented across two TLS records.
    let _ = client.set_read_timeout(Some(config::HTTPS_FIRST_READ_TIMEOUT));
    let mut buf = vec![0u8; 65535];
    let first_len = match client.read(&mut buf) {
        Ok(0) | Err(_) => return,
        Ok(n) => n,
    };
    let _ = client.set_read_timeout(None);
    let first = &buf[..first_len];

    if first[0] == dpi::TLS_HANDSHAKE {
        let segs = dpi::split_hello(first, config::SPLIT_MIN, config::SPLIT_MAX);
        log::info!(target: "freegsm.https",
            "[HTTPS] {server_ip}:{server_port}  SNI={}  ClientHello {}B -> {} TLS records",
            dpi::sni_name(first), first.len(), segs.len());
        for seg in &segs {
            if upstream.write_all(seg).is_err() {
                return;
            }
        }
    } else {
        // Not TLS (e.g. plaintext on 443): forward untouched.
        if upstream.write_all(first).is_err() {
            return;
        }
    }

    // Dumb bidirectional pipe for the rest of the connection.
    let (Ok(client_rx), Ok(upstream_rx)) = (client.try_clone(), upstream.try_clone()) else {
        return;
    };
    let reverse = std::thread::Builder::new()
        .name("https-pump".into())
        .spawn(move || pump(upstream_rx, client_rx));
    pump(client, upstream);
    if let Ok(handle) = reverse {
        let _ = handle.join();
    }
}

/// Start the HTTPS splitting relay on its own thread.
pub fn start_server() -> Result<()> {
    let listener = TcpListener::bind((config::TCP_BIND_HOST, config::HTTPS_PROXY_PORT))
        .with_context(|| {
            format!(
                "binding HTTPS relay on {}:{}",
                config::TCP_BIND_HOST,
                config::HTTPS_PROXY_PORT
            )
        })?;
    log::info!(target: "freegsm.https",
        "HTTPS splitting relay listening on {}:{} (upstream ports {}-{})",
        config::TCP_BIND_HOST, config::HTTPS_PROXY_PORT,
        config::UPSTREAM_PORT_BASE,
        config::UPSTREAM_PORT_BASE + config::UPSTREAM_PORT_COUNT - 1);
    std::thread::Builder::new()
        .name("https-proxy".into())
        .spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(s) => {
                        std::thread::spawn(move || serve_client(s));
                    }
                    Err(e) => log::debug!(target: "freegsm.https", "accept error: {e}"),
                }
            }
        })
        .context("spawning https-proxy thread")?;
    Ok(())
}
