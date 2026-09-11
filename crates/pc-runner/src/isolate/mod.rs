//! Isolation backend selection.
//!
//! Exactly one backend is compiled per platform: the Linux sandbox, or the
//! fail-closed `unsupported` backend everywhere else.

use crate::Runner;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod sys;
#[cfg(not(target_os = "linux"))]
mod unsupported;

/// Whether a real isolation backend exists on this platform.
#[cfg(target_os = "linux")]
pub const AVAILABLE: bool = true;
/// Whether a real isolation backend exists on this platform.
#[cfg(not(target_os = "linux"))]
pub const AVAILABLE: bool = false;

/// Construct the platform's isolation backend.
#[must_use]
pub fn default_runner() -> Box<dyn Runner> {
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxRunner::new())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Box::new(unsupported::UnsupportedRunner)
    }
}
