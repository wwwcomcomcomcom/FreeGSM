//! WinDivert capture loop and dispatch.
//!
//! One WinDivert handle drives everything. The capture thread classifies each
//! packet and either:
//!   * offloads UDP/53 queries to a thread pool (each does a blocking DoH
//!     round-trip before injecting the reply), or
//!   * handles TCP inline (fast, non-blocking address/port rewriting).
//!
//! The handle is shared (`Arc`) so pool workers and the capture thread can both
//! inject. Injection (`send`) is serialised behind a lock, mirroring the Python
//! `_send_lock`; `recv` runs lock-free on the capture thread (WinDivert handles
//! are thread-safe for concurrent recv/send).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use threadpool::ThreadPool;
use windivert::prelude::*;
use windivert_sys::ChecksumFlags;

use crate::netpkt::{self, PROTO_TCP, PROTO_UDP};
use crate::{config, https_proxy, tcp_proxy, udp};

/// Set by the Ctrl+C handler; the capture loop checks it and exits.
static STOP: AtomicBool = AtomicBool::new(false);

pub fn request_stop() {
    STOP.store(true, Ordering::SeqCst);
}

fn stopped() -> bool {
    STOP.load(Ordering::SeqCst)
}

/// Whether a stop has been requested (Ctrl+C or a fatal capture error).
pub fn is_stopped() -> bool {
    stopped()
}

/// The single WinDivert handle, plus the injection lock. `unsafe impl Send/Sync`
/// is sound because WinDivert handles are documented thread-safe for concurrent
/// `recv`/`send`.
struct Handle {
    wd: WinDivert<NetworkLayer>,
    send_lock: Mutex<()>,
}

unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}

/// Thread-safe packet injector handed to every handler.
#[derive(Clone)]
pub struct Injector(Arc<Handle>);

impl Injector {
    /// Inject a packet (thread-safe). Errors are swallowed at debug level, like
    /// the Python `_send`.
    pub fn send(&self, packet: &WinDivertPacket<NetworkLayer>) {
        let _guard = self.0.send_lock.lock().unwrap();
        if let Err(e) = self.0.wd.send(packet) {
            log::debug!("send failed: {e}");
        }
    }
}

/// Flip a (mutated) packet to inbound, recompute checksums, and inject it. This
/// is the shared tail of every redirect/reply-rewrite/UDP-reply path.
pub fn inject_inbound(inj: &Injector, packet: &mut WinDivertPacket<NetworkLayer>) {
    packet.address.set_outbound(false);
    // No-op unless the packet data is owned (handlers mutate via to_mut(), which
    // makes it owned), so this only runs on packets we actually changed.
    if let Err(e) = packet.recalculate_checksums(ChecksumFlags::new()) {
        log::debug!("checksum recalc failed: {e}");
    }
    inj.send(packet);
}

pub struct Diverter {
    handle: Arc<Handle>,
    injector: Injector,
    pool: ThreadPool,
}

impl Diverter {
    pub fn new() -> Result<Self> {
        let cfg = config::get();
        let wd = WinDivert::network(&cfg.divert_filter, 0, WinDivertFlags::new())
            .context("opening WinDivert handle (needs Administrator + the driver)")?;
        let handle = Arc::new(Handle {
            wd,
            send_lock: Mutex::new(()),
        });
        let injector = Injector(handle.clone());
        let pool = ThreadPool::with_name("doh".into(), config::WORKER_THREADS);
        log::info!(target: "freegsm.divert", "WinDivert open; filter: {}", cfg.divert_filter);
        Ok(Self {
            handle,
            injector,
            pool,
        })
    }

    /// Run the blocking capture loop until [`request_stop`] is called or a recv
    /// error occurs. Consumes `self` so it can be moved onto its own thread.
    pub fn run(self) {
        let mut buf = vec![0u8; 65535];
        let mut tcp_conn: tcp_proxy::ConnMap = HashMap::new();
        while !stopped() {
            let packet = match self.handle.wd.recv(Some(&mut buf)) {
                Ok(p) => p,
                Err(e) => {
                    if stopped() {
                        break;
                    }
                    log::error!(target: "freegsm.divert", "recv error: {e}");
                    break;
                }
            };
            self.dispatch(packet, &mut tcp_conn);
        }
    }

    fn dispatch(&self, packet: WinDivertPacket<NetworkLayer>, tcp_conn: &mut tcp_proxy::ConnMap) {
        // Read everything we need into Copy locals so no borrow of packet.data
        // survives into the match arms (which move the packet).
        let proto = netpkt::protocol(&packet.data);
        let outbound = packet.address.outbound();
        let dst_port = netpkt::l4_dst_port(&packet.data);
        let src_port = netpkt::l4_src_port(&packet.data);

        match proto {
            Some(PROTO_UDP) if outbound && dst_port == Some(53) => {
                let owned = packet.into_owned();
                let inj = self.injector.clone();
                self.pool.execute(move || udp::handle(owned, &inj));
            }
            Some(PROTO_TCP) => {
                let cfg = config::get();
                let to_https = cfg.dpi_bypass
                    && ((outbound && dst_port == Some(443))
                        || src_port == Some(config::HTTPS_PROXY_PORT));
                let mut packet = packet;
                if to_https {
                    https_proxy::handle_packet(&mut packet, &self.injector);
                } else {
                    tcp_proxy::handle_packet(tcp_conn, &mut packet, &self.injector);
                }
            }
            // Shouldn't happen given the filter; pass it through untouched.
            _ => self.injector.send(&packet),
        }
    }
}
