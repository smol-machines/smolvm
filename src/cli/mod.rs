//! CLI command implementations.

pub mod config;
pub mod container;
pub mod microvm;
pub mod openapi;
pub mod pack;
pub mod parsers;
pub mod runpack;
pub mod sandbox;
pub mod serve;
pub mod smolfile;
pub mod vm_common;

use std::io::Write;

// ============================================================================
// Display Constants
// ============================================================================

/// Display width for container IDs (first 12 characters).
pub const CONTAINER_ID_WIDTH: usize = 12;

/// Display width for image names.
pub const IMAGE_NAME_WIDTH: usize = 18;

/// Display width for command strings.
pub const COMMAND_WIDTH: usize = 28;

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

/// Truncate a container ID for display (first 12 characters).
pub fn truncate_id(id: &str) -> &str {
    if id.len() > CONTAINER_ID_WIDTH {
        &id[..CONTAINER_ID_WIDTH]
    } else {
        id
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

/// Pull an image with a CLI progress bar.
pub fn pull_with_progress(
    client: &mut smolvm::agent::AgentClient,
    image: &str,
    platform: Option<&str>,
) -> smolvm::Result<smolvm_protocol::ImageInfo> {
    print!("Pulling image {}...", image);
    let _ = std::io::stdout().flush();

    let mut last_percent = 0u8;
    let result = client.pull_with_registry_config_and_progress(
        image,
        platform,
        |percent, _total, _layer| {
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
