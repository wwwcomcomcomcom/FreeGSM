//! Minimal logger reproducing the Python format
//! `"%(asctime)s %(levelname)-7s %(name)s: %(message)s"` with `%H:%M:%S` local
//! time. A hand-rolled `log::Log` keeps the binary small (no tracing stack).

use log::{Level, LevelFilter, Log, Metadata, Record};

#[repr(C)]
struct SystemTime {
    w_year: u16,
    w_month: u16,
    w_day_of_week: u16,
    w_day: u16,
    w_hour: u16,
    w_minute: u16,
    w_second: u16,
    w_milliseconds: u16,
}

extern "system" {
    fn GetLocalTime(out: *mut SystemTime);
}

fn local_hms() -> (u16, u16, u16) {
    // SAFETY: GetLocalTime fills the provided SYSTEMTIME; no failure mode.
    let mut st = SystemTime {
        w_year: 0,
        w_month: 0,
        w_day_of_week: 0,
        w_day: 0,
        w_hour: 0,
        w_minute: 0,
        w_second: 0,
        w_milliseconds: 0,
    };
    unsafe { GetLocalTime(&mut st) };
    (st.w_hour, st.w_minute, st.w_second)
}

struct Logger;

impl Log for Logger {
    fn enabled(&self, _meta: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let (h, m, s) = local_hms();
        // Python logging maps WARNING (not "WARN"); align level names accordingly.
        let level = match record.level() {
            Level::Error => "ERROR",
            Level::Warn => "WARNING",
            Level::Info => "INFO",
            Level::Debug => "DEBUG",
            Level::Trace => "TRACE",
        };
        // levelname left-justified to width 7, like Python's `%(levelname)-7s`.
        println!(
            "{h:02}:{m:02}:{s:02} {level:<7} {}: {}",
            record.target(),
            record.args()
        );
    }

    fn flush(&self) {}
}

static LOGGER: Logger = Logger;

/// Install the global logger at INFO level. Idempotent-ish: a second call is a
/// no-op error that we ignore.
pub fn init() {
    let _ = log::set_logger(&LOGGER);
    log::set_max_level(LevelFilter::Info);
}
