//! FreeGSM: transparent DNS-over-HTTPS + SNI/DPI bypass for Windows.
//!
//! Run from an elevated context (WinDivert needs Administrator to load its
//! driver). Leaving the process running == DNS is upgraded to DoH. Ctrl+C stops
//! it and restores normal DNS (no system setting is ever changed).

// A console app; no Windows subsystem flag so logs go to the terminal.

mod config;
mod divert;
mod dnsutil;
mod doh;
mod dpi;
mod https_proxy;
mod logging;
mod netpkt;
mod rng;
mod tcp_proxy;
mod udp;

use std::time::Duration;

use anyhow::Result;

use crate::divert::Diverter;

#[link(name = "shell32")]
extern "system" {
    fn IsUserAnAdmin() -> i32;
}

fn is_admin() -> bool {
    // SAFETY: IsUserAnAdmin takes no args and returns a BOOL.
    unsafe { IsUserAnAdmin() != 0 }
}

fn run() -> Result<i32> {
    logging::init();

    if !is_admin() {
        log::error!(target: "freegsm",
            "Administrator privileges required (WinDivert loads a kernel driver). \
             Re-run this from an elevated terminal, or use the packaged .exe.");
        return Ok(1);
    }

    let cfg = config::init();

    log::info!(target: "freegsm",
        "FreeGSM starting. Upstream: {}  (fail-{})",
        cfg.doh_url,
        if config::FAIL_OPEN { "open" } else { "closed" });
    if cfg.dpi_bypass {
        log::info!(target: "freegsm",
            "SNI/DPI bypass: ON (TLS record fragmentation via local relay on TCP/443)");
    } else {
        log::info!(target: "freegsm", "SNI/DPI bypass: OFF (set FREEGSM_DPI=1 to enable)");
    }

    doh::start()?;

    // Probe the upstream BEFORE touching DNS. With fail-closed, starting against
    // an unreachable upstream would kill all DNS; refusing to start keeps the
    // machine's DNS untouched and tells the user how to fix it.
    log::info!(target: "freegsm", "Probing DoH upstream...");
    let (ok, detail) = doh::probe();
    if !ok {
        log::error!(target: "freegsm", "DoH upstream {} is unreachable ({detail}).", cfg.doh_url);
        log::error!(target: "freegsm",
            "Not starting (fail-closed would break all DNS). Some networks block \
             1.1.1.1 specifically. Set a reachable upstream and retry, e.g.:");
        log::error!(target: "freegsm", "    set FREEGSM_DOH_URL=https://8.8.8.8/dns-query");
        log::error!(target: "freegsm", "    set FREEGSM_DOH_URL=https://9.9.9.9/dns-query");
        return Ok(1);
    }
    log::info!(target: "freegsm", "DoH upstream reachable.");

    tcp_proxy::start_server()?;
    if cfg.dpi_bypass {
        https_proxy::start_server()?;
    }

    let diverter = Diverter::new()?;
    // Run the (blocking) capture loop off the main thread so Ctrl+C stays
    // responsive. When it returns (stop or fatal recv error) it flips the stop
    // flag so the main loop below wakes up.
    let _capture = std::thread::Builder::new()
        .name("capture".into())
        .spawn(move || {
            diverter.run();
            divert::request_stop();
        })?;

    let _ = ctrlc::set_handler(|| {
        log::info!(target: "freegsm", "Shutting down...");
        divert::request_stop();
    });

    log::info!(target: "freegsm", "Running. DNS is now upgraded to DoH. Press Ctrl+C to stop.");
    while !divert::is_stopped() {
        std::thread::sleep(Duration::from_millis(200));
    }

    log::info!(target: "freegsm", "Stopped. Normal DNS restored.");
    Ok(0)
}

fn main() {
    let code = run().unwrap_or_else(|e| {
        log::error!(target: "freegsm", "fatal: {e:#}");
        1
    });
    std::process::exit(code);
}
