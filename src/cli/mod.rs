//! CLI command implementations.

pub mod config;
pub mod internal_boot;
pub mod machine;
pub mod openapi;
pub mod pack;
pub mod pack_run;
pub mod parsers;
pub mod serve;
pub mod smolfile;
pub mod vm_common;

use std::io::Write;

// ============================================================================
// Display Helpers
// ============================================================================

/// Truncate a string to max length, adding "..." if needed.
///
/// If the string fits within `max` characters, returns it unchanged.
/// Otherwise, truncates to `max - 3` characters and appends "...".
pub fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else if max <= 3 {
        "...".to_string()
    } else {
        format!("{}...", &s[..max - 3])
    }
}

/// Format an optional PID as a suffix string.
///
/// Returns " (PID: N)" if pid is Some, or empty string if None.
pub fn format_pid_suffix(pid: Option<i32>) -> String {
    pid.map(|p| format!(" (PID: {})", p)).unwrap_or_default()
}

/// Flush stdout and stderr, ignoring errors.
///
/// Used to ensure output is visible before blocking operations.
pub fn flush_output() {
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
}

/// Format bytes as human-readable string (e.g., "1.5 GB", "42.0 MB").
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Throttled byte-transfer progress bar for streaming operations.
///
/// Used by `machine cp` (upload + download). The producer calls
/// [`ProgressBar::update`] on every chunk; output is emitted at most
/// every `THROTTLE_MS` to avoid drowning the terminal on fast
/// transfers. [`ProgressBar::finish`] prints the final summary line
/// (with rate) and a newline.
///
/// Output goes to **stderr** so a `cp ... > somefile` redirect
/// doesn't capture progress noise.
pub struct ProgressBar {
    label: String,
    /// Known total in bytes. `None` for streams of unknown length
    /// (we still report bytes-so-far + rate).
    total: Option<u64>,
    started_at: std::time::Instant,
    last_print: std::time::Instant,
    /// Set to true when at least one progress line has been printed,
    /// so `finish` knows to emit a leading `\r` to overwrite it.
    printed: bool,
}

impl ProgressBar {
    const THROTTLE_MS: u128 = 250;

    /// `label` is shown at the start of every line ("Uploading",
    /// "Downloading", etc.). `total` is `Some(bytes)` for known-size
    /// transfers (uploads where we read the file first), `None` for
    /// streaming-source cases.
    pub fn new(label: impl Into<String>, total: Option<u64>) -> Self {
        let now = std::time::Instant::now();
        Self {
            label: label.into(),
            total,
            started_at: now,
            // Initialize so the first update() prints immediately —
            // gives the user feedback that something started.
            last_print: now - std::time::Duration::from_millis(THROTTLE_INITIAL_MS),
            printed: false,
        }
    }

    /// Report the running total of bytes transferred. Throttled —
    /// callers can invoke this on every chunk without flooding
    /// stderr.
    pub fn update(&mut self, bytes_so_far: u64) {
        let now = std::time::Instant::now();
        if now.duration_since(self.last_print).as_millis() < Self::THROTTLE_MS {
            return;
        }
        self.last_print = now;
        self.printed = true;
        let line = self.format_line(bytes_so_far);
        eprint!("\r{}", line);
        let _ = std::io::stderr().flush();
    }

    /// Print the final summary and a newline. Consumes self.
    pub fn finish(self, bytes_total: u64) {
        let line = self.format_line(bytes_total);
        if self.printed {
            // Overwrite the last throttled line.
            eprintln!("\r{}", line);
        } else {
            eprintln!("{}", line);
        }
    }

    fn format_line(&self, bytes_so_far: u64) -> String {
        let elapsed = self.started_at.elapsed().as_secs_f64().max(0.001);
        let rate = bytes_so_far as f64 / elapsed;
        let rate_str = format!("{}/s", format_bytes(rate as u64));
        match self.total {
            Some(total) if total > 0 => {
                let pct = (bytes_so_far as f64 * 100.0 / total as f64).min(100.0);
                format!(
                    "{}: {} / {} ({:.1}%, {})",
                    self.label,
                    format_bytes(bytes_so_far),
                    format_bytes(total),
                    pct,
                    rate_str
                )
            }
            _ => format!(
                "{}: {} ({})",
                self.label,
                format_bytes(bytes_so_far),
                rate_str
            ),
        }
    }
}

/// Initial throttle offset — ensures the first `update()` call
/// always prints, so the user sees activity immediately.
const THROTTLE_INITIAL_MS: u64 = 1000;

/// Pull an image with a CLI progress bar.
pub fn pull_with_progress(
    client: &mut smolvm::agent::AgentClient,
    image: &str,
    oci_platform: Option<&str>,
) -> smolvm::Result<smolvm_protocol::ImageInfo> {
    print!("Pulling image {}...", image);
    let _ = std::io::stdout().flush();

    let mut last_percent = 0u8;
    let mut syncing = false;
    let result = client.pull_with_registry_config_and_progress(
        image,
        oci_platform,
        |percent, _total, layer| {
            if layer == "syncing" {
                if !syncing {
                    print!(
                        "\rPulling image {}... [====================] 100% — syncing...",
                        image
                    );
                    let _ = std::io::stdout().flush();
                    syncing = true;
                }
                return;
            }
            let percent = percent as u8;
            if percent != last_percent && percent <= 100 {
                print!("\rPulling image {}... [", image);
                let filled = (percent as usize) / 5;
                for i in 0..20 {
                    if i < filled {
                        print!("=");
                    } else if i == filled {
                        print!(">");
                    } else {
                        print!(" ");
                    }
                }
                print!("] {}%", percent);
                let _ = std::io::stdout().flush();
                last_percent = percent;
            }
        },
    );
    println!(
        "\rPulling image {}... done.                              ",
        image
    );
    result
}
