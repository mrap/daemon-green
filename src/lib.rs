//! # daemon-green
//!
//! Cross-platform per-user background **service** management. One trait,
//! two native backends:
//!
//! - **macOS** → a per-user **gui-domain LaunchAgent** (`launchctl bootstrap
//!   gui/<uid>`), so the service runs inside the user's login session and can
//!   reach the login keychain. No `SessionCreate` (it detaches from the login
//!   session and blocks keychain access).
//! - **Linux** → a **`systemd --user`** unit.
//!
//! Both are **sudo-free** and work **over SSH** (as long as a login session is
//! active, which a desktop Mac always has). The macOS backend is hardened
//! against the real footguns: it waits out the async `bootout` before
//! re-`bootstrap`ing, retries, and falls back to `launchctl asuser`.
//!
//! ```no_run
//! use daemon_green::{native, ServiceSpec};
//! let spec = ServiceSpec::new("com.example.myd", "/usr/local/bin/myd")
//!     .arg("serve")
//!     .env("MY_VAR", "1")
//!     .keep_alive(true)
//!     .run_at_load(true);
//! let mgr = native();
//! mgr.install(&spec)?;          // render unit + register (idempotent)
//! mgr.start(spec.label())?;     // bootstrap / enable
//! # Ok::<(), daemon_green::Error>(())
//! ```

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

mod render; // pure renderers — always compiled + tested
#[cfg(target_os = "macos")]
mod launchd;
#[cfg(target_os = "linux")]
mod systemd;

/// Errors from service operations. Every variant carries an actionable message
/// (command, exit code, and stderr/stdout tail where relevant) — never a silent
/// swallow.
#[derive(Debug)]
pub enum Error {
    /// A `launchctl`/`systemctl` invocation failed. Carries a human message.
    Command(String),
    /// The environment isn't supported (e.g. no systemd, or no active GUI login).
    Unsupported(String),
    /// An I/O error rendering/writing the unit file.
    Io(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Command(m) => write!(f, "{m}"),
            Error::Unsupported(m) => write!(f, "{m}"),
            Error::Io(e) => write!(f, "io error: {e}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// A platform-neutral description of a per-user background service. Backends
/// render this into a launchd plist or a systemd unit.
#[derive(Debug, Clone)]
pub struct ServiceSpec {
    /// Reverse-DNS label, e.g. `com.hex.harness`. Used as the launchd Label and
    /// the systemd unit name (`<label>.service`).
    pub label: String,
    /// Absolute path to the program. On macOS this is `ProgramArguments[0]`
    /// directly (NOT wrapped in `bash -c`, to keep the keychain-ACL identity
    /// clean).
    pub program: PathBuf,
    /// Arguments after the program.
    pub args: Vec<String>,
    /// Environment variables for the service process. Ordered (BTreeMap) so the
    /// rendered unit is deterministic.
    pub env: BTreeMap<String, String>,
    /// Working directory for the service.
    pub working_dir: Option<PathBuf>,
    /// Restart on crash (launchd KeepAlive-on-failure / systemd Restart=always).
    pub keep_alive: bool,
    /// Start at load/login/boot (launchd RunAtLoad / systemd WantedBy default).
    pub run_at_load: bool,
    /// Where stdout+stderr go. If unset, a sensible per-user default is chosen
    /// (`~/Library/Logs/<label>.log` on macOS; the journal on Linux).
    pub log_path: Option<PathBuf>,
    /// launchd `ProcessType` scheduling class (macOS only; no-op on the
    /// systemd backend, which has no equivalent knob). Defaults to
    /// `Background`, which keeps existing callers unchanged but runs the
    /// process at reduced CPU/IO scheduling priority — a bad default for a
    /// service whose work is user-visible or latency-sensitive.
    pub process_type: ProcessType,
}

/// launchd `ProcessType` values. See `launchd.plist(5)`. Only meaningful on
/// macOS; the systemd renderer ignores it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProcessType {
    /// Scheduled at reduced priority for CPU and I/O. launchd's default when
    /// the key is omitted, and this crate's default for backward
    /// compatibility with specs built before this field existed.
    #[default]
    Background,
    /// Normal scheduling priority — not throttled, not boosted.
    Standard,
    /// launchd adapts priority based on app state (foreground/background).
    Adaptive,
    /// Highest priority; for processes the user is actively interacting with.
    Interactive,
}

impl ProcessType {
    /// The exact string launchd expects in the plist `<string>` value.
    fn as_str(self) -> &'static str {
        match self {
            ProcessType::Background => "Background",
            ProcessType::Standard => "Standard",
            ProcessType::Adaptive => "Adaptive",
            ProcessType::Interactive => "Interactive",
        }
    }
}

impl ServiceSpec {
    /// Create a spec from a label and absolute program path.
    pub fn new(label: impl Into<String>, program: impl Into<PathBuf>) -> Self {
        ServiceSpec {
            label: label.into(),
            program: program.into(),
            args: Vec::new(),
            env: BTreeMap::new(),
            working_dir: None,
            keep_alive: true,
            run_at_load: true,
            log_path: None,
            process_type: ProcessType::default(),
        }
    }
    /// The service label.
    pub fn label(&self) -> &str {
        &self.label
    }
    /// Append one argument.
    pub fn arg(mut self, a: impl Into<String>) -> Self {
        self.args.push(a.into());
        self
    }
    /// Append several arguments.
    pub fn args<I, S>(mut self, it: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(it.into_iter().map(Into::into));
        self
    }
    /// Set an environment variable.
    pub fn env(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.env.insert(k.into(), v.into());
        self
    }
    /// Set the working directory.
    pub fn working_dir(mut self, p: impl Into<PathBuf>) -> Self {
        self.working_dir = Some(p.into());
        self
    }
    /// Restart on crash (default true).
    pub fn keep_alive(mut self, v: bool) -> Self {
        self.keep_alive = v;
        self
    }
    /// Start at load/login/boot (default true).
    pub fn run_at_load(mut self, v: bool) -> Self {
        self.run_at_load = v;
        self
    }
    /// Override the combined stdout/stderr log path.
    pub fn log_path(mut self, p: impl Into<PathBuf>) -> Self {
        self.log_path = Some(p.into());
        self
    }
    /// Set the launchd scheduling class (default `Background`). No effect on
    /// the systemd backend.
    pub fn process_type(mut self, v: ProcessType) -> Self {
        self.process_type = v;
        self
    }
}

/// Current state of a managed service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceStatus {
    /// Loaded and running, with the PID if known.
    Running { pid: Option<u32> },
    /// Installed/loaded but not currently running.
    Stopped,
    /// Not installed (no unit/plist registered).
    NotInstalled,
    /// In a failed state (e.g. systemd `failed`, hit the start limit).
    Failed { reason: String },
}

/// The operations a service manager backend provides. `install`/`start` are
/// idempotent.
pub trait ServiceManager {
    /// Render the unit/plist and register it. Safe to call repeatedly.
    fn install(&self, spec: &ServiceSpec) -> Result<()>;
    /// Load + start the service (idempotent).
    fn start(&self, label: &str) -> Result<()>;
    /// Stop + unload the service.
    fn stop(&self, label: &str) -> Result<()>;
    /// Restart the service (e.g. to pick up a new binary).
    fn restart(&self, label: &str) -> Result<()>;
    /// Query the current status.
    fn status(&self, label: &str) -> Result<ServiceStatus>;
    /// Return the last `lines` lines of the service's combined log.
    fn logs(&self, label: &str, lines: usize) -> Result<String>;
}

/// The native service manager for the current platform.
///
/// Compile-time dispatch: we target exactly two OSes, so `#[cfg]` is cleaner and
/// more honest than runtime probing.
#[cfg(target_os = "macos")]
pub fn native() -> Box<dyn ServiceManager> {
    Box::new(launchd::LaunchdAgent::new())
}

/// The native service manager for the current platform.
#[cfg(target_os = "linux")]
pub fn native() -> Box<dyn ServiceManager> {
    Box::new(systemd::SystemdUser::new())
}

/// Fallback for unsupported platforms — every operation returns `Unsupported`.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn native() -> Box<dyn ServiceManager> {
    Box::new(Unsupported)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
struct Unsupported;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
impl ServiceManager for Unsupported {
    fn install(&self, _: &ServiceSpec) -> Result<()> {
        Err(Error::Unsupported("daemon-green: unsupported platform".into()))
    }
    fn start(&self, _: &str) -> Result<()> {
        Err(Error::Unsupported("daemon-green: unsupported platform".into()))
    }
    fn stop(&self, _: &str) -> Result<()> {
        Err(Error::Unsupported("daemon-green: unsupported platform".into()))
    }
    fn restart(&self, _: &str) -> Result<()> {
        Err(Error::Unsupported("daemon-green: unsupported platform".into()))
    }
    fn status(&self, _: &str) -> Result<ServiceStatus> {
        Err(Error::Unsupported("daemon-green: unsupported platform".into()))
    }
    fn logs(&self, _: &str, _: usize) -> Result<String> {
        Err(Error::Unsupported("daemon-green: unsupported platform".into()))
    }
}
