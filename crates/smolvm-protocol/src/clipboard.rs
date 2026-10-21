//! Wire format of the host clipboard bridge.
//!
//! A guest clipboard command opens one connection to [`crate::ports::CLIPBOARD`]
//! and sends one request line:
//!
//! - `copy <mime>\n` then the content until it closes its write half; the host
//!   sets its clipboard and answers `ok\n` or `error: <reason>\n`.
//! - `paste <mime>\n`; the host answers `ok\n` then the content, or
//!   `error: <reason>\n` when the clipboard holds no such content.
//! - `types\n`; the host answers `ok\n` then one MIME type per line.

/// Plain text, the type every host clipboard holds.
pub const TEXT: &str = "text/plain";
/// A PNG image, the type agents paste screenshots as.
pub const PNG: &str = "image/png";

/// The largest content either side moves in one request.
pub const MAX_BYTES: u64 = 64 << 20;

/// One clipboard request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Set the host clipboard to the content that follows.
    Copy(String),
    /// Read the host clipboard as this type.
    Paste(String),
    /// List the types the host clipboard holds.
    Types,
}

impl Request {
    /// The request line, newline included.
    pub fn line(&self) -> String {
        match self {
            Self::Copy(mime) => format!("copy {mime}\n"),
            Self::Paste(mime) => format!("paste {mime}\n"),
            Self::Types => "types\n".to_string(),
        }
    }

    /// Parse a request line (without its newline).
    pub fn parse(line: &str) -> Option<Self> {
        let valid = |mime: &str| {
            !mime.is_empty()
                && mime.len() <= 128
                && mime
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/+.-_;=".contains(&b))
        };
        match line.split_once(' ') {
            Some(("copy", mime)) if valid(mime) => Some(Self::Copy(mime.to_string())),
            Some(("paste", mime)) if valid(mime) => Some(Self::Paste(mime.to_string())),
            None if line == "types" => Some(Self::Types),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_round_trip_and_refuse_odd_types() {
        for request in [
            Request::Copy(TEXT.into()),
            Request::Paste(PNG.into()),
            Request::Types,
        ] {
            let line = request.line();
            assert_eq!(Request::parse(line.trim_end()), Some(request));
        }
        for bad in [
            "copy",
            "copy ",
            "paste text plain",
            "paste a`b",
            "types x",
            "steal x",
        ] {
            assert_eq!(Request::parse(bad), None, "{bad}");
        }
    }
}
