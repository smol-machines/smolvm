//! Host-side encrypted secret store.
//!
//! Stores user secrets encrypted at rest on the host and injects decrypted
//! values into guest workload env at exec time. The secret transits the
//! private host-guest vsock channel as part of the existing `env` field in
//! `AgentRequest::Run`/`VmExec` — no protocol change.
//!
//! # Scope and non-goals
//!
//! This is defense-in-depth, not zero-knowledge. The target guest process
//! sees plaintext in its own environment. Isolation comes from:
//! (a) encryption at rest, (b) not logging values, (c) not persisting
//! plaintext to overlay disks, (d) scrubbing the immediate decrypt
//! buffers inside resolution helpers.
//!
//! # What Zeroize actually covers here
//!
//! Inside this module, decrypted plaintext lives in `Zeroizing<String>`
//! from the moment AES-GCM produces it until the resolution helper
//! copies it into the caller-visible env vector. Those intermediate
//! buffers are scrubbed on drop.
//!
//! After that copy, plaintext lives in a regular `String` inside a
//! `Vec<(String, String)>` until the outer request is serialized and
//! written to vsock. **We do not attempt to zero that storage.** Doing
//! so would require a custom serde Serializer (serde buffers bytes
//! internally before writing) and would not change the fundamental
//! property that the guest process's env contains plaintext.
//!
//! If you need true "use without access," use a broker pattern like
//! SSH agent forwarding — scrubbing host-side buffers is not a
//! substitute for it.
//!
//! # Storage layout
//!
//! - `~/.config/smolvm/secrets.toml` — TOML metadata + ciphertext
//! - `~/.local/share/smolvm/secrets.key` — 32 random bytes (file mode 0600)
//!
//! # Cipher
//!
//! AES-256-GCM with a fresh 96-bit nonce per secret. Key material is the
//! entire contents of `secrets.key`; it never leaves the host process memory
//! once loaded.

use crate::error::{Error, Result};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// File name for the encrypted secret store.
pub const DEFAULT_STORE_FILENAME: &str = "secrets.toml";

/// File name for the master encryption key.
pub const DEFAULT_KEY_FILENAME: &str = "secrets.key";

/// Length of the AES-256-GCM key in bytes.
const KEY_LEN: usize = 32;

/// Length of the GCM nonce in bytes.
const NONCE_LEN: usize = 12;

/// Maximum accepted size of `secrets.toml` on disk. A legitimate store
/// holds small strings; anything larger is almost certainly corruption
/// or an attempt to exhaust memory. 10 MiB leaves headroom for hundreds
/// of stored credentials or a handful of large ones (certs, SSH keys).
pub const MAX_STORE_FILE_BYTES: u64 = 10 * 1024 * 1024;

/// Maximum accepted length of a single stored-value secret's plaintext.
/// Real credentials are much smaller; the cap is loose enough for TLS
/// key material and tight enough to keep a runaway `set_value` from
/// writing gigabytes into `secrets.toml`.
pub const MAX_SECRET_VALUE_BYTES: usize = 1024 * 1024;

/// Maximum number of bytes read when resolving a `from_file` source.
/// Same rationale as `MAX_SECRET_VALUE_BYTES`. A file larger than this
/// is almost never a credential; we refuse rather than silently
/// injecting a huge env var into the workload.
pub const MAX_FROM_FILE_BYTES: u64 = 1024 * 1024;

// ============================================================================
// On-disk representation
// ============================================================================

/// How a secret is sourced. Persisted in `secrets.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "lowercase")]
enum StoredSecret {
    /// Encrypted value stored inline in `secrets.toml`.
    Value {
        /// Base64-encoded 12-byte GCM nonce.
        nonce: String,
        /// Base64-encoded AES-GCM ciphertext (plaintext + auth tag).
        ciphertext: String,
    },
    /// Value read from a host environment variable at resolution time.
    Env {
        /// Name of the host env var to read.
        env_var: String,
    },
    /// Value read from a host file at resolution time.
    File {
        /// Path to the file on the host.
        path: PathBuf,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct SecretsFile {
    #[serde(default)]
    secrets: BTreeMap<String, StoredSecret>,
}

// ============================================================================
// Public API
// ============================================================================

/// Classification of a stored secret (for listing without revealing values).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretKind {
    /// Encrypted literal value.
    Value,
    /// Indirection to a host environment variable.
    Env,
    /// Indirection to a host file path.
    File,
}

impl SecretKind {
    /// Human-readable name for CLI output.
    pub fn as_str(self) -> &'static str {
        match self {
            SecretKind::Value => "value",
            SecretKind::Env => "env",
            SecretKind::File => "file",
        }
    }
}

/// Encrypted host-side store of secrets, keyed by secret name.
///
/// Load once, query/mutate, then `save()` to persist. The master key is
/// loaded lazily from `~/.local/share/smolvm/secrets.key` when encryption
/// or decryption is actually needed.
pub struct SecretStore {
    file: SecretsFile,
}

impl SecretStore {
    /// Load the store from `~/.config/smolvm/secrets.toml`.
    ///
    /// If the file does not exist, returns an empty store (creating a new
    /// store is implicit when a user first runs `smolvm secret set`).
    pub fn load() -> Result<Self> {
        let path = Self::store_path()?;
        if !path.exists() {
            return Ok(Self {
                file: SecretsFile::default(),
            });
        }

        // Bounded read against a live-growing file. We do not trust
        // `metadata().len()` alone because the file could grow between
        // stat and read — `read_file_bounded_size` enforces the cap on
        // actual bytes read, not on the size reported by stat.
        let contents = read_file_bounded_size(&path, MAX_STORE_FILE_BYTES).map_err(|e| {
            Error::config(
                format!("read secret store at {}", path.display()),
                e.to_string(),
            )
        })?;

        let file: SecretsFile = toml::from_str(&contents).map_err(|e| {
            Error::config(
                format!("parse secret store at {}", path.display()),
                e.to_string(),
            )
        })?;

        Ok(Self { file })
    }

    /// Load, mutate, and save the store under an exclusive OS file lock.
    ///
    /// Every mutation of `secrets.toml` must go through this helper so
    /// concurrent `smolvm secret set`/`delete` invocations serialize
    /// cleanly. The lock file is `secrets.toml.lock` in the same
    /// directory; if another process holds the lock, we retry briefly
    /// before giving up with a clear error.
    ///
    /// The lock is released when the closure returns (whether or not
    /// the save succeeded). Early returns inside the closure propagate
    /// the error without saving, so a failed mutation doesn't write a
    /// half-built store.
    pub fn with_lock<F, T>(f: F) -> Result<T>
    where
        F: FnOnce(&mut SecretStore) -> Result<T>,
    {
        use fs2::FileExt;
        use std::time::{Duration, Instant};

        let store_path = Self::store_path()?;
        let parent = store_path.parent().ok_or_else(|| {
            Error::config("resolve secret store parent dir", "no parent directory")
        })?;
        std::fs::create_dir_all(parent).map_err(|e| {
            Error::config(
                format!("create secret store dir {}", parent.display()),
                e.to_string(),
            )
        })?;
        let lock_path = parent.join("secrets.toml.lock");

        // Open (or create) the lockfile and acquire an exclusive lock.
        // We retry for a short window so two back-to-back `secret set`
        // invocations don't race visibly.
        let lock_file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|e| {
                Error::config(
                    format!("open secret store lock {}", lock_path.display()),
                    e.to_string(),
                )
            })?;
        set_file_mode_0600(&lock_file)?;

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match lock_file.try_lock_exclusive() {
                Ok(()) => break,
                Err(_) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => {
                    return Err(Error::config(
                        "acquire secret store lock",
                        format!(
                            "another process is editing the secret store (lock: {}): {}",
                            lock_path.display(),
                            e
                        ),
                    ));
                }
            }
        }

        // Load under the lock so we see the latest state.
        let mut store = Self::load()?;
        let result = f(&mut store);
        if result.is_ok() {
            store.save()?;
        }
        // Dropping `lock_file` releases the lock.
        let _ = FileExt::unlock(&lock_file);
        result
    }

    /// Persist the store to `~/.config/smolvm/secrets.toml`.
    ///
    /// Creates the parent directory if needed. Writes atomically via a
    /// rename from a temp file, so a partial write can't corrupt the store.
    ///
    /// Most callers should use [`with_lock`](Self::with_lock) instead,
    /// which acquires an OS-level exclusive lock and reloads + saves
    /// atomically. Direct `save()` is safe when the caller owns serial
    /// access already (tests that run under a mutex, one-shot scripts).
    pub fn save(&self) -> Result<()> {
        let path = Self::store_path()?;
        let parent = path.parent().ok_or_else(|| {
            Error::config("resolve secret store parent dir", "no parent directory")
        })?;
        std::fs::create_dir_all(parent).map_err(|e| {
            Error::config(
                format!("create secret store dir {}", parent.display()),
                e.to_string(),
            )
        })?;

        let toml_str = toml::to_string_pretty(&self.file)
            .map_err(|e| Error::config("serialize secret store", e.to_string()))?;

        // Atomic write: temp file in same dir, then rename.
        let tmp = path.with_extension("toml.tmp");
        {
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp)
                .map_err(|e| {
                    Error::config(
                        format!("create temp secret store {}", tmp.display()),
                        e.to_string(),
                    )
                })?;
            set_file_mode_0600(&f)?;
            f.write_all(toml_str.as_bytes()).map_err(|e| {
                Error::config(
                    format!("write secret store {}", tmp.display()),
                    e.to_string(),
                )
            })?;
            f.sync_all().ok();
        }
        std::fs::rename(&tmp, &path).map_err(|e| {
            Error::config(
                format!("rename {} -> {}", tmp.display(), path.display()),
                e.to_string(),
            )
        })?;
        Ok(())
    }

    /// Path to the secret store TOML file.
    pub fn store_path() -> Result<PathBuf> {
        let home = dirs::home_dir()
            .ok_or_else(|| Error::config("resolve path", "no home directory found"))?;
        Ok(home
            .join(".config")
            .join("smolvm")
            .join(DEFAULT_STORE_FILENAME))
    }

    /// Path to the master encryption key file.
    pub fn key_path() -> Result<PathBuf> {
        let home = dirs::home_dir()
            .ok_or_else(|| Error::config("resolve path", "no home directory found"))?;
        Ok(home
            .join(".local")
            .join("share")
            .join("smolvm")
            .join(DEFAULT_KEY_FILENAME))
    }

    /// Store a literal value, encrypting it with AES-256-GCM.
    pub fn set_value(&mut self, name: &str, value: &str) -> Result<()> {
        check_secret_key(name)?;
        if value.len() > MAX_SECRET_VALUE_BYTES {
            return Err(Error::config(
                "set secret value",
                format!(
                    "value length {} exceeds maximum {} bytes",
                    value.len(),
                    MAX_SECRET_VALUE_BYTES
                ),
            ));
        }
        let key = load_or_create_master_key()?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*key));

        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ct = cipher.encrypt(nonce, value.as_bytes()).map_err(|e| {
            Error::config("encrypt secret", format!("AES-GCM encrypt failed: {}", e))
        })?;

        self.file.secrets.insert(
            name.to_string(),
            StoredSecret::Value {
                nonce: B64.encode(nonce_bytes),
                ciphertext: B64.encode(ct),
            },
        );
        Ok(())
    }

    /// Store an indirection to a host environment variable.
    pub fn set_env(&mut self, name: &str, env_var: &str) -> Result<()> {
        check_secret_key(name)?;
        self.file.secrets.insert(
            name.to_string(),
            StoredSecret::Env {
                env_var: env_var.to_string(),
            },
        );
        Ok(())
    }

    /// Store an indirection to a host file path.
    ///
    /// The path must be absolute. Callers that start from user input
    /// (CLI flags, Smolfile fields) are responsible for canonicalizing
    /// or resolving relative paths *before* calling this setter; this
    /// is the final gate that keeps relative paths out of the store.
    pub fn set_file(&mut self, name: &str, path: &Path) -> Result<()> {
        check_secret_key(name)?;
        if !path.is_absolute() {
            return Err(Error::config(
                "set file secret",
                format!(
                    "path '{}' must be absolute; resolve relative paths before calling set_file",
                    path.display()
                ),
            ));
        }
        self.file.secrets.insert(
            name.to_string(),
            StoredSecret::File {
                path: path.to_path_buf(),
            },
        );
        Ok(())
    }

    /// Remove a secret. Returns true if it existed.
    pub fn delete(&mut self, name: &str) -> bool {
        self.file.secrets.remove(name).is_some()
    }

    /// Whether a secret with the given name exists.
    pub fn contains(&self, name: &str) -> bool {
        self.file.secrets.contains_key(name)
    }

    /// List names and source kinds (never values).
    pub fn list(&self) -> Vec<(String, SecretKind)> {
        self.file
            .secrets
            .iter()
            .map(|(k, v)| (k.clone(), kind_of(v)))
            .collect()
    }

    /// Decrypt/read a secret, returning its plaintext value.
    ///
    /// The returned `Zeroizing<String>` overwrites its memory on drop, so
    /// callers should let it drop as soon as the value has been passed on.
    ///
    /// Returns a structured [`RevealError`] that classifies the failure
    /// (store miss, env unset, file unreadable, crypto failure, or an
    /// internal error). Callers that want the generic `Error` form —
    /// the CLI `secret show` command, etc. — use
    /// [`Self::reveal_as_error`].
    pub fn reveal(&self, name: &str) -> std::result::Result<Zeroizing<String>, RevealError> {
        let entry = self.file.secrets.get(name).ok_or(RevealError::NotFound)?;

        match entry {
            StoredSecret::Value { nonce, ciphertext } => {
                let key = load_or_create_master_key().map_err(RevealError::Internal)?;
                let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*key));
                let nonce_bytes = B64.decode(nonce).map_err(|e| {
                    RevealError::Internal(Error::config("decode nonce", e.to_string()))
                })?;
                if nonce_bytes.len() != NONCE_LEN {
                    return Err(RevealError::Internal(Error::config(
                        "decode nonce",
                        format!("expected {} bytes, got {}", NONCE_LEN, nonce_bytes.len()),
                    )));
                }
                let ct = B64.decode(ciphertext).map_err(|e| {
                    RevealError::Internal(Error::config("decode ciphertext", e.to_string()))
                })?;
                let nonce = Nonce::from_slice(&nonce_bytes);
                let pt = cipher
                    .decrypt(nonce, ct.as_ref())
                    .map_err(|_| RevealError::CryptoFailed)?;
                let s = String::from_utf8(pt).map_err(|e| {
                    RevealError::Internal(Error::config("decode secret utf8", e.to_string()))
                })?;
                Ok(Zeroizing::new(s))
            }
            StoredSecret::Env { env_var } => {
                let v = std::env::var(env_var).map_err(|_| RevealError::EnvUnset)?;
                Ok(Zeroizing::new(v))
            }
            StoredSecret::File { path } => {
                let v = read_from_file_source(path).map_err(|e| match e {
                    FileSourceError::TooLarge => RevealError::FileTooLarge,
                    // Symlink and other I/O failures both present as
                    // "we can't read this file" from the caller's
                    // perspective. Distinct from TooLarge because
                    // that's a bounded-resource class with its own
                    // 4xx message.
                    FileSourceError::Symlink | FileSourceError::Io(_) => {
                        RevealError::FileReadFailed
                    }
                })?;
                // Trim trailing newline — common for file-based credentials.
                let trimmed = v.trim_end_matches(['\n', '\r']).to_string();
                Ok(Zeroizing::new(trimmed))
            }
        }
    }

    /// `reveal` that returns the project-wide [`Error`] type for
    /// ergonomic use from the CLI and other trusted callers that
    /// don't care about the failure taxonomy.
    pub fn reveal_as_error(&self, name: &str) -> Result<Zeroizing<String>> {
        self.reveal(name).map_err(|e| e.into_error(name))
    }
}

/// Classified failure from [`SecretStore::reveal`].
///
/// The variants align 1:1 with [`ResolutionFailure`] so API callers
/// can convert cleanly. CLI callers use
/// [`SecretStore::reveal_as_error`] which collapses this into the
/// project's generic [`Error`].
#[derive(Debug)]
pub enum RevealError {
    /// No entry with this key in the store.
    NotFound,
    /// Entry is a `from_env` indirection and the host env var is unset.
    EnvUnset,
    /// Entry is a `from_file` indirection and the file couldn't be read
    /// (missing, permission denied, symlink, non-UTF-8, etc.).
    FileReadFailed,
    /// Entry is a `from_file` indirection and the file is over the
    /// per-source byte cap.
    FileTooLarge,
    /// Entry is an encrypted value and AES-GCM decryption failed —
    /// wrong master key, tampered ciphertext, or the key file has
    /// changed since this entry was written.
    CryptoFailed,
    /// Internal error: store file unreadable after open, key file I/O
    /// failure, UTF-8 decode of a (successfully decrypted) value
    /// failed, etc. The underlying [`Error`] is preserved for logging.
    Internal(Error),
}

impl RevealError {
    /// Lift into the project-wide [`Error`] type for callers that
    /// don't want the classification. `name` is the secret key; it's
    /// included in the produced message.
    pub fn into_error(self, name: &str) -> Error {
        match self {
            Self::NotFound => {
                Error::config("reveal secret", format!("secret '{}' not found", name))
            }
            Self::EnvUnset => Error::config(
                "read secret from env",
                format!("secret '{}' references env var which is not set", name),
            ),
            Self::FileReadFailed => Error::config(
                "read secret from file",
                format!("secret '{}' file is unreadable", name),
            ),
            Self::FileTooLarge => Error::config(
                "read secret from file",
                format!("secret '{}' file exceeds the size cap", name),
            ),
            Self::CryptoFailed => Error::config(
                "decrypt secret",
                format!(
                    "AES-GCM decrypt failed for '{}' (wrong key or tampered?)",
                    name
                ),
            ),
            Self::Internal(e) => e,
        }
    }
}

impl From<RevealError> for ResolutionFailure {
    fn from(e: RevealError) -> Self {
        match e {
            RevealError::NotFound => Self::StoreMiss,
            RevealError::EnvUnset => Self::EnvUnset,
            RevealError::FileReadFailed => Self::FileReadFailed,
            RevealError::FileTooLarge => Self::FileTooLarge,
            RevealError::CryptoFailed => Self::CryptoFailed,
            RevealError::Internal(_) => Self::Internal,
        }
    }
}

/// Structured error from bounded-read / file-source helpers so
/// callers can classify without string-matching the inner `io::Error`.
#[derive(Debug)]
enum FileSourceError {
    /// The stored path points at a symlink; we refuse to follow.
    Symlink,
    /// File size exceeded the per-call cap.
    TooLarge,
    /// Any other I/O failure (missing, permission denied, non-UTF-8
    /// content, etc.). The inner error is available for callers that
    /// want to log it; classifiers treat this as `FileReadFailed`.
    Io(std::io::Error),
}

impl std::fmt::Display for FileSourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Symlink => write!(
                f,
                "from_file path is a symlink; refusing to follow \
                 (store the canonicalized target instead)"
            ),
            Self::TooLarge => write!(f, "file size exceeds maximum"),
            Self::Io(e) => write!(f, "{}", e),
        }
    }
}

impl From<std::io::Error> for FileSourceError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Read a file to string while refusing to allocate more than `cap`
/// bytes. The cap is enforced against *bytes actually read*, not against
/// the length reported by `metadata()` — this closes a TOCTOU where the
/// file grows between stat and read.
fn read_file_bounded_size(
    path: &std::path::Path,
    cap: u64,
) -> std::result::Result<String, FileSourceError> {
    use std::io::Read;
    let f = std::fs::File::open(path)?;
    let mut buf = String::new();
    // `take` caps the actual read. We request `cap + 1` so an over-cap
    // file fills the reader by one byte, letting us detect the breach.
    f.take(cap + 1).read_to_string(&mut buf)?;
    if buf.len() as u64 > cap {
        return Err(FileSourceError::TooLarge);
    }
    Ok(buf)
}

/// Read a `from_file` source with both the size cap and a symlink
/// refusal. Symlinks are rejected at resolve time so a stored path whose
/// target gets replaced by a symlink post-persistence can't redirect the
/// read elsewhere (e.g., `/etc/shadow`). If a user needs a symlink for
/// legitimate reasons, they can store the canonicalized target.
fn read_from_file_source(path: &std::path::Path) -> std::result::Result<String, FileSourceError> {
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Err(FileSourceError::Symlink);
    }
    read_file_bounded_size(path, MAX_FROM_FILE_BYTES)
}

fn kind_of(s: &StoredSecret) -> SecretKind {
    match s {
        StoredSecret::Value { .. } => SecretKind::Value,
        StoredSecret::Env { .. } => SecretKind::Env,
        StoredSecret::File { .. } => SecretKind::File,
    }
}

/// Reject empty names or names containing `=` (would break env var formatting)
/// and non-printable control characters.
fn check_secret_key(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::config("validate secret name", "name is empty"));
    }
    if name.contains('=') || name.contains('\0') {
        return Err(Error::config(
            "validate secret name",
            "name must not contain '=' or NUL",
        ));
    }
    if name.chars().any(|c| c.is_control()) {
        return Err(Error::config(
            "validate secret name",
            "name must not contain control characters",
        ));
    }
    Ok(())
}

// ============================================================================
// Master key management
// ============================================================================

/// Load the master key from disk, or generate and persist a new one on first
/// use. Returns the raw 32 bytes wrapped in `Zeroizing` so it's scrubbed.
fn load_or_create_master_key() -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let path = SecretStore::key_path()?;
    if path.exists() {
        let bytes = std::fs::read(&path).map_err(|e| {
            Error::config(
                format!("read master key at {}", path.display()),
                e.to_string(),
            )
        })?;
        if bytes.len() != KEY_LEN {
            return Err(Error::config(
                format!("read master key at {}", path.display()),
                format!("expected {} bytes, got {}", KEY_LEN, bytes.len()),
            ));
        }
        let mut arr = [0u8; KEY_LEN];
        arr.copy_from_slice(&bytes);
        return Ok(Zeroizing::new(arr));
    }

    // Create parent dir (mode 0700 on unix) + fresh random key (0600).
    let parent = path
        .parent()
        .ok_or_else(|| Error::config("resolve key parent dir", "no parent directory"))?;
    std::fs::create_dir_all(parent).map_err(|e| {
        Error::config(
            format!("create key dir {}", parent.display()),
            e.to_string(),
        )
    })?;
    set_dir_mode_0700(parent)?;

    let mut key = [0u8; KEY_LEN];
    rand::thread_rng().fill_bytes(&mut key);

    {
        let mut f = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .map_err(|e| {
                Error::config(
                    format!("create master key at {}", path.display()),
                    e.to_string(),
                )
            })?;
        set_file_mode_0600(&f)?;
        f.write_all(&key).map_err(|e| {
            Error::config(
                format!("write master key at {}", path.display()),
                e.to_string(),
            )
        })?;
        f.sync_all().ok();
    }

    Ok(Zeroizing::new(key))
}

#[cfg(unix)]
fn set_file_mode_0600(f: &std::fs::File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    f.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|e| Error::config("set file mode 0600", e.to_string()))
}

#[cfg(not(unix))]
fn set_file_mode_0600(_f: &std::fs::File) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_dir_mode_0700(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| Error::config("set dir mode 0700", e.to_string()))
}

#[cfg(not(unix))]
fn set_dir_mode_0700(_path: &Path) -> Result<()> {
    Ok(())
}

// ============================================================================
// Smolfile / VmRecord / pack manifest integration
// ============================================================================

// The *shape* of a ref lives in `smolvm-protocol` (it's what flows
// across wire / on-disk boundaries). The *policy* — which source kinds
// are allowed at which trust boundary — lives here, alongside the code
// that enforces it at validation and resolution time.
pub use smolvm_protocol::{SecretRef, SecretSourceKind};

/// Trust level of the actor that supplied a [`SecretRef`].
///
/// The smolvm process loads secrets from its own host. Different input
/// surfaces present refs with different trust; the scope chosen at the
/// validation site determines which source kinds can be honored.
///
/// | Scope | `from_store` | `from_env` | `from_file` |
/// |---|:-:|:-:|:-:|
/// | `TrustedLocal` | yes | yes | yes (absolute paths only) |
/// | `RecordReplay` | yes | yes | yes |
/// | `Untrusted` | yes | no | no |
///
/// Callers must call [`validate_ref`] before acting on a ref received
/// from any source. Handlers that pull fields out of a `SecretRef`
/// directly — without going through `validate_ref` — are treating all
/// inputs as fully trusted and are a latent bug.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionScope {
    /// Caller is trusted equivalently to the smolvm process itself
    /// (typically: the CLI running as the host user). All source kinds
    /// are accepted; `from_file` still requires an absolute path for
    /// defense-in-depth against CWD-dependent surprises.
    TrustedLocal,

    /// Ref was persisted by a `TrustedLocal` actor in a prior session
    /// (e.g., read back from a VM record or a `.smolmachine`
    /// manifest). Trust is preserved across time.
    RecordReplay,

    /// Ref came in from an unauthenticated or semi-trusted source: an
    /// HTTP request body, or a pack manifest at build time. Only
    /// `from_store` is honored — `from_env` would leak the smolvm
    /// process's environment and `from_file` would turn the ref field
    /// into an arbitrary host-file read primitive.
    Untrusted,
}

impl ResolutionScope {
    fn allows_env(self) -> bool {
        !matches!(self, Self::Untrusted)
    }
    fn allows_file(self) -> bool {
        !matches!(self, Self::Untrusted)
    }
}

/// Structural or scope-policy violations rejected by [`validate_ref`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretRefError {
    /// None of `from_store`, `from_env`, `from_file` was set.
    NoSource,
    /// More than one source field was set.
    MultipleSources,
    /// `from_file` was given a relative path. Persisted refs must be
    /// absolute to avoid CWD-dependent resolution surprises.
    RelativeFilePath(std::path::PathBuf),
    /// The source kind is valid in general but not in the given scope —
    /// e.g., `from_file` submitted via an untrusted HTTP request body.
    SourceNotAllowedInScope {
        /// Which source kind was attempted.
        kind: SecretSourceKind,
        /// Which scope rejected it.
        scope: ResolutionScope,
    },
}

impl std::fmt::Display for SecretRefError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSource => write!(
                f,
                "no source set: exactly one of from_store, from_env, from_file must be specified"
            ),
            Self::MultipleSources => write!(
                f,
                "multiple sources set: exactly one of from_store, from_env, from_file must be specified"
            ),
            Self::RelativeFilePath(p) => write!(
                f,
                "from_file path '{}' is relative; absolute paths are required",
                p.display()
            ),
            Self::SourceNotAllowedInScope { kind, scope } => write!(
                f,
                "source kind '{}' is not allowed in scope {:?}; use from_store instead",
                kind.as_str(),
                scope
            ),
        }
    }
}

impl std::error::Error for SecretRefError {}

/// Classified reasons a resolution can fail.
///
/// Distinct from [`SecretRefError`]: `SecretRefError` is a validation
/// failure (the ref itself is malformed or rejected by policy), while
/// [`ResolutionFailure`] happens *after* validation, when we actually
/// try to turn an accepted ref into a value.
///
/// The classification drives two things: audit log records (so
/// operators can distinguish "someone is probing for missing secrets"
/// from "the store is corrupted") and HTTP status-code mapping for
/// the API (client-side 400 vs. server-side 500).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionFailure {
    /// `from_store` names a secret that isn't in the store.
    StoreMiss,
    /// `from_env` references an env var that isn't set on the host.
    EnvUnset,
    /// `from_file` path is missing, not readable, or not a regular
    /// file. Also covers the "target is a symlink" refusal.
    FileReadFailed,
    /// `from_file` target exceeds the size cap.
    FileTooLarge,
    /// Decrypt failed (wrong master key, tampered ciphertext, or the
    /// key file has changed since this entry was written).
    CryptoFailed,
    /// Any other failure: store file unreadable, key file unreadable,
    /// UTF-8 decoding of a secret failed, etc. Server-side condition.
    Internal,
}

impl ResolutionFailure {
    /// Whether the failure reflects something the caller can fix.
    /// Determines whether the HTTP layer should return 4xx or 5xx.
    pub fn is_client_error(self) -> bool {
        matches!(
            self,
            Self::StoreMiss | Self::EnvUnset | Self::FileReadFailed | Self::FileTooLarge
        )
    }

    /// Stable short identifier suitable for logs and public-facing
    /// error payloads. Never includes path, env-var name, or value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StoreMiss => "store_miss",
            Self::EnvUnset => "env_unset",
            Self::FileReadFailed => "file_read_failed",
            Self::FileTooLarge => "file_too_large",
            Self::CryptoFailed => "crypto_failed",
            Self::Internal => "internal",
        }
    }
}

impl std::fmt::Display for ResolutionFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A resolution failure attached to the secret key it happened on.
///
/// API handlers want this form so they can produce a response body
/// that names the bad secret without exposing the underlying error
/// text (which may include paths, env-var names, or filesystem
/// errors).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionError {
    /// Secret key (the map key in `[secrets]` or `req.secrets`).
    pub key: String,
    /// Classified failure kind.
    pub kind: ResolutionFailure,
}

impl std::fmt::Display for ResolutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "secret '{}': {}", self.key, self.kind)
    }
}

impl std::error::Error for ResolutionError {}

/// Validate structure and scope policy for a [`SecretRef`].
///
/// Call before persisting or acting on any ref received from an outside
/// source. There are no "partial" refs in this codebase — if it wasn't
/// validated, it shouldn't be stored or resolved.
pub fn validate_ref(
    r: &SecretRef,
    scope: ResolutionScope,
) -> std::result::Result<(), SecretRefError> {
    let count = [
        r.from_store.is_some(),
        r.from_env.is_some(),
        r.from_file.is_some(),
    ]
    .into_iter()
    .filter(|b| *b)
    .count();

    match count {
        0 => return Err(SecretRefError::NoSource),
        1 => {}
        _ => return Err(SecretRefError::MultipleSources),
    }

    if r.from_env.is_some() && !scope.allows_env() {
        return Err(SecretRefError::SourceNotAllowedInScope {
            kind: SecretSourceKind::Env,
            scope,
        });
    }
    if let Some(path) = &r.from_file {
        if !scope.allows_file() {
            return Err(SecretRefError::SourceNotAllowedInScope {
                kind: SecretSourceKind::File,
                scope,
            });
        }
        if !path.is_absolute() {
            return Err(SecretRefError::RelativeFilePath(path.clone()));
        }
    }

    Ok(())
}

/// Tracing target for secret-resolution audit records.
///
/// Operators tail this stream with
/// `RUST_LOG=smolvm::secrets::audit=info` to see every resolution event.
/// Records include the secret key, source kind, scope, and outcome —
/// never the resolved value, never the `from_file` path, never the
/// `from_env` variable name (those can themselves be revealing).
pub const AUDIT_TARGET: &str = "smolvm::secrets::audit";

/// Resolve a single ref against the host secret store and emit an
/// audit record.
///
/// **Caller responsibility:** validate the ref at its trust boundary
/// (`validate_ref(scope)`) before calling this. Resolution assumes the
/// ref has already been accepted by policy; the `scope` argument here
/// is recorded for forensics, not re-checked.
///
/// Every call emits exactly one tracing event at `AUDIT_TARGET`: fields
/// are `secret_key`, `source_kind`, `scope`, and `result` (`ok` |
/// `error`). The full error message is deliberately omitted from the
/// log because it may contain `from_file` paths or `from_env` names.
pub fn resolve_secret_ref(
    name: &str,
    r: &SecretRef,
    store: &SecretStore,
    scope: ResolutionScope,
) -> Result<Zeroizing<String>> {
    resolve_secret_ref_classified(name, r, store, scope)
        .map_err(|f| Error::config(format!("resolve secret '{}'", name), f.as_str().to_string()))
}

/// Like [`resolve_secret_ref`] but surfaces the failure classification
/// directly. API handlers that need to map specific failures to HTTP
/// status codes (400 vs 500) consume this; other callers use
/// [`resolve_secret_ref`] and get the generic `Error` form.
///
/// Emits the same audit record as `resolve_secret_ref`, with the
/// classified failure's `as_str()` as the `error_kind` field on
/// failure (e.g., `store_miss` rather than the generic
/// `resolution_failed`).
pub fn resolve_secret_ref_classified(
    name: &str,
    r: &SecretRef,
    store: &SecretStore,
    scope: ResolutionScope,
) -> std::result::Result<Zeroizing<String>, ResolutionFailure> {
    let kind_str = r.source_kind().map(|k| k.as_str()).unwrap_or("unknown");
    let scope_str = scope_label(scope);

    let result: std::result::Result<Zeroizing<String>, ResolutionFailure> =
        if let Some(key) = &r.from_store {
            // Direct enum conversion — no string matching on error text.
            store.reveal(key).map_err(ResolutionFailure::from)
        } else if let Some(env_var) = &r.from_env {
            std::env::var(env_var)
                .map(Zeroizing::new)
                .map_err(|_| ResolutionFailure::EnvUnset)
        } else if let Some(path) = &r.from_file {
            read_from_file_source(path)
                .map(|v| Zeroizing::new(v.trim_end_matches(['\n', '\r']).to_string()))
                .map_err(classify_file_source_error)
        } else {
            // Never reachable if validate_ref was called at the boundary.
            Err(ResolutionFailure::Internal)
        };

    match &result {
        Ok(_) => tracing::info!(
            target: AUDIT_TARGET,
            secret_key = %name,
            source_kind = %kind_str,
            scope = %scope_str,
            result = "ok",
        ),
        Err(f) => tracing::info!(
            target: AUDIT_TARGET,
            secret_key = %name,
            source_kind = %kind_str,
            scope = %scope_str,
            result = "error",
            error_kind = %f.as_str(),
        ),
    }

    result
}

/// Map a [`FileSourceError`] from a request-side `from_file` ref into
/// the resolution-failure taxonomy. No string matching; the classes
/// are structural, so this is a pure enum translation.
fn classify_file_source_error(e: FileSourceError) -> ResolutionFailure {
    match e {
        FileSourceError::TooLarge => ResolutionFailure::FileTooLarge,
        FileSourceError::Symlink | FileSourceError::Io(_) => ResolutionFailure::FileReadFailed,
    }
}

fn scope_label(scope: ResolutionScope) -> &'static str {
    match scope {
        ResolutionScope::TrustedLocal => "trusted-local",
        ResolutionScope::RecordReplay => "record-replay",
        ResolutionScope::Untrusted => "untrusted",
    }
}

/// Resolve a map of secret refs and flatten into `(name, value)` tuples
/// ready to append to an agent-bound env vector.
///
/// Returns an empty vec for empty input. The plaintext values are copied
/// out of their `Zeroizing` buffers into regular `String`s for the
/// return value — the intra-function buffers scrub on drop, but the
/// returned `Vec<(String, String)>` is plain memory. See the module
/// docs for the precise scope of what this does and does not scrub.
///
/// **No caching.** Every call reloads `SecretStore` and redoes all
/// resolutions. This is deliberate: rotating a secret via
/// `smolvm secret set X new-value` takes effect at the next resolution
/// with no restart. Do not add a cache here without replacing the
/// rotation semantics with an explicit invalidation path.
///
/// Callers choose the scope based on where the refs came from:
/// `TrustedLocal` for refs a CLI user just supplied, `RecordReplay` for
/// refs read out of a VM record or pack manifest, `Untrusted` for refs
/// that arrived from an HTTP request body (which must first have been
/// validated via `SecretRef::validate(Untrusted)` to enforce the
/// allowed-sources policy).
pub fn resolve_refs_to_env(
    refs: &BTreeMap<String, SecretRef>,
    scope: ResolutionScope,
) -> Result<Vec<(String, String)>> {
    if refs.is_empty() {
        return Ok(Vec::new());
    }
    let store = SecretStore::load()?;
    let resolved = resolve_secrets(refs, &store, scope)?;
    Ok(resolved
        .into_iter()
        .map(|(k, v)| (k, (*v).clone()))
        .collect())
}

/// Resolve a map of refs, returning a classified [`ResolutionError`]
/// on the first failure rather than a generic `Error`.
///
/// API handlers use this form so they can map failure kinds to
/// HTTP status codes (4xx vs 5xx, see [`ResolutionFailure::is_client_error`])
/// and include the specific secret key in the response body.
pub fn resolve_refs_to_env_classified(
    refs: &BTreeMap<String, SecretRef>,
    scope: ResolutionScope,
) -> std::result::Result<Vec<(String, String)>, ResolutionError> {
    if refs.is_empty() {
        return Ok(Vec::new());
    }
    let store = SecretStore::load().map_err(|_| ResolutionError {
        key: "<store>".to_string(),
        kind: ResolutionFailure::Internal,
    })?;
    let mut out = Vec::with_capacity(refs.len());
    for (name, r) in refs {
        let value = resolve_secret_ref_classified(name, r, &store, scope).map_err(|kind| {
            ResolutionError {
                key: name.clone(),
                kind,
            }
        })?;
        out.push((name.clone(), (*value).clone()));
    }
    Ok(out)
}

/// Resolve a map of secret refs into plaintext `(name, value)` pairs.
///
/// Returned values are `Zeroizing<String>` so memory is scrubbed on drop.
/// The caller should feed these into the agent request env vector and let
/// them drop immediately after.
///
/// Each ref is expected to have been validated at its trust boundary
/// before being persisted or passed in here. The `scope` argument is
/// recorded in audit logs for every resolution attempt.
pub fn resolve_secrets(
    refs: &BTreeMap<String, SecretRef>,
    store: &SecretStore,
    scope: ResolutionScope,
) -> Result<Vec<(String, Zeroizing<String>)>> {
    let mut out = Vec::with_capacity(refs.len());
    for (name, r) in refs {
        out.push((name.clone(), resolve_secret_ref(name, r, store, scope)?));
    }
    Ok(out)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Redirect HOME to a temp dir for the duration of a test so the real
    /// `~/.config` and `~/.local/share` are not touched.
    struct HomeGuard {
        _dir: TempDir,
        prev: Option<std::ffi::OsString>,
    }

    impl HomeGuard {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let prev = std::env::var_os("HOME");
            std::env::set_var("HOME", dir.path());
            Self { _dir: dir, prev }
        }
    }

    impl Drop for HomeGuard {
        fn drop(&mut self) {
            if let Some(p) = self.prev.take() {
                std::env::set_var("HOME", p);
            } else {
                std::env::remove_var("HOME");
            }
        }
    }

    /// Hold a global lock across every test that mutates HOME. Without this,
    /// tests running in parallel clobber each other's sandboxed HOME.
    fn test_lock() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::{Mutex, OnceLock};
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn roundtrip_value_secret() {
        let _lock = test_lock();
        let _home = HomeGuard::new();

        let mut store = SecretStore::load().unwrap();
        store.set_value("API_KEY", "sk-hunter2").unwrap();
        store.save().unwrap();

        let reloaded = SecretStore::load().unwrap();
        let revealed = reloaded.reveal("API_KEY").unwrap();
        assert_eq!(&*revealed, "sk-hunter2");
    }

    #[test]
    fn nonce_is_unique_per_set() {
        let _lock = test_lock();
        let _home = HomeGuard::new();

        let mut store = SecretStore::load().unwrap();
        store.set_value("A", "same").unwrap();
        // Capture first ciphertext.
        let first = match &store.file.secrets["A"] {
            StoredSecret::Value { nonce, ciphertext } => (nonce.clone(), ciphertext.clone()),
            _ => panic!("expected Value variant"),
        };

        store.set_value("A", "same").unwrap();
        let second = match &store.file.secrets["A"] {
            StoredSecret::Value { nonce, ciphertext } => (nonce.clone(), ciphertext.clone()),
            _ => panic!("expected Value variant"),
        };

        assert_ne!(first.0, second.0, "nonce must differ between sets");
        assert_ne!(
            first.1, second.1,
            "ciphertext must differ (semantic security)"
        );
    }

    #[test]
    fn env_indirection_resolves() {
        let _lock = test_lock();
        let _home = HomeGuard::new();

        std::env::set_var("SMOLVM_TEST_SECRET_ENV", "from-env-value");
        let mut store = SecretStore::load().unwrap();
        store.set_env("VAR", "SMOLVM_TEST_SECRET_ENV").unwrap();
        assert_eq!(&*store.reveal("VAR").unwrap(), "from-env-value");

        std::env::remove_var("SMOLVM_TEST_SECRET_ENV");
        assert!(store.reveal("VAR").is_err());
    }

    #[test]
    fn file_indirection_resolves_and_trims_newline() {
        let _lock = test_lock();
        let _home = HomeGuard::new();

        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("cred");
        std::fs::write(&p, "hunter2\n").unwrap();

        let mut store = SecretStore::load().unwrap();
        store.set_file("FILE_SECRET", &p).unwrap();
        assert_eq!(&*store.reveal("FILE_SECRET").unwrap(), "hunter2");
    }

    #[test]
    fn delete_removes_entry() {
        let _lock = test_lock();
        let _home = HomeGuard::new();

        let mut store = SecretStore::load().unwrap();
        store.set_value("X", "val").unwrap();
        assert!(store.contains("X"));
        assert!(store.delete("X"));
        assert!(!store.contains("X"));
        assert!(!store.delete("X"));
    }

    #[test]
    fn list_reports_kinds_not_values() {
        let _lock = test_lock();
        let _home = HomeGuard::new();

        let mut store = SecretStore::load().unwrap();
        store.set_value("V", "secret").unwrap();
        store.set_env("E", "HOME").unwrap();
        store.set_file("F", Path::new("/etc/hostname")).unwrap();

        let listed: BTreeMap<String, SecretKind> = store.list().into_iter().collect();
        assert_eq!(listed.get("V"), Some(&SecretKind::Value));
        assert_eq!(listed.get("E"), Some(&SecretKind::Env));
        assert_eq!(listed.get("F"), Some(&SecretKind::File));
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let _lock = test_lock();
        let _home = HomeGuard::new();

        let mut store = SecretStore::load().unwrap();
        store.set_value("X", "plaintext").unwrap();
        store.save().unwrap();

        // Clobber the master key with fresh random bytes.
        let key_path = SecretStore::key_path().unwrap();
        let mut rng = rand::thread_rng();
        let mut buf = [0u8; KEY_LEN];
        rng.fill_bytes(&mut buf);
        std::fs::write(&key_path, buf).unwrap();

        let reloaded = SecretStore::load().unwrap();
        assert!(reloaded.reveal("X").is_err());
    }

    #[test]
    fn check_secret_key_rejects_bad_inputs() {
        let _lock = test_lock();
        let _home = HomeGuard::new();

        let mut store = SecretStore::load().unwrap();
        assert!(store.set_value("", "v").is_err());
        assert!(store.set_value("a=b", "v").is_err());
        assert!(store.set_value("a\0b", "v").is_err());
        assert!(store.set_value("a\tb", "v").is_err());
        assert!(store.set_value("OK_NAME", "v").is_ok());
    }

    #[test]
    fn secret_ref_resolve_from_store() {
        let _lock = test_lock();
        let _home = HomeGuard::new();

        let mut store = SecretStore::load().unwrap();
        store.set_value("MY_KEY", "value-from-store").unwrap();

        let r = SecretRef {
            from_store: Some("MY_KEY".to_string()),
            from_env: None,
            from_file: None,
        };
        assert_eq!(
            &*resolve_secret_ref("DST", &r, &store, ResolutionScope::RecordReplay).unwrap(),
            "value-from-store"
        );
    }

    #[test]
    fn smolfile_secrets_section_parses() {
        // Regression test: ensure the Smolfile [secrets] section deserializes
        // into BTreeMap<String, SecretRef> for all three source kinds.
        let toml_src = r#"
image = "alpine:latest"

[secrets]
FROM_STORE = { from_store = "NAMED_KEY" }
FROM_ENV   = { from_env = "HOST_VAR" }
FROM_FILE  = { from_file = "/etc/secret" }
"#;
        let sf: crate::smolfile::Smolfile = toml::from_str(toml_src).unwrap();
        assert_eq!(sf.secrets.len(), 3);
        assert_eq!(
            sf.secrets["FROM_STORE"].from_store.as_deref(),
            Some("NAMED_KEY")
        );
        assert_eq!(sf.secrets["FROM_ENV"].from_env.as_deref(), Some("HOST_VAR"));
        assert_eq!(
            sf.secrets["FROM_FILE"]
                .from_file
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned()),
            Some("/etc/secret".to_string())
        );
    }

    #[test]
    fn smolfile_rejects_unknown_secret_fields() {
        // `deny_unknown_fields` on SecretRef ensures typos don't silently pass.
        let toml_src = r#"
[secrets]
X = { from_stor = "typo" }
"#;
        let res: std::result::Result<crate::smolfile::Smolfile, toml::de::Error> =
            toml::from_str(toml_src);
        assert!(res.is_err(), "expected parse error for unknown field");
    }

    // Scope-policy validation tests. The ref struct itself lives in
    // smolvm-protocol; policy is enforced here, so its tests live here.

    fn store_ref(name: &str) -> SecretRef {
        SecretRef {
            from_store: Some(name.to_string()),
            from_env: None,
            from_file: None,
        }
    }
    fn env_ref(var: &str) -> SecretRef {
        SecretRef {
            from_store: None,
            from_env: Some(var.to_string()),
            from_file: None,
        }
    }
    fn file_ref(path: &str) -> SecretRef {
        SecretRef {
            from_store: None,
            from_env: None,
            from_file: Some(path.into()),
        }
    }

    #[test]
    fn validate_rejects_no_source() {
        let r = SecretRef {
            from_store: None,
            from_env: None,
            from_file: None,
        };
        assert_eq!(
            validate_ref(&r, ResolutionScope::TrustedLocal),
            Err(SecretRefError::NoSource)
        );
    }

    #[test]
    fn validate_rejects_multiple_sources() {
        let r = SecretRef {
            from_store: Some("x".into()),
            from_env: Some("y".into()),
            from_file: None,
        };
        assert_eq!(
            validate_ref(&r, ResolutionScope::TrustedLocal),
            Err(SecretRefError::MultipleSources)
        );
    }

    #[test]
    fn validate_allows_store_in_every_scope() {
        let r = store_ref("k");
        assert!(validate_ref(&r, ResolutionScope::TrustedLocal).is_ok());
        assert!(validate_ref(&r, ResolutionScope::RecordReplay).is_ok());
        assert!(validate_ref(&r, ResolutionScope::Untrusted).is_ok());
    }

    #[test]
    fn validate_refuses_env_in_untrusted() {
        let r = env_ref("HOST_VAR");
        assert!(validate_ref(&r, ResolutionScope::TrustedLocal).is_ok());
        assert!(validate_ref(&r, ResolutionScope::RecordReplay).is_ok());
        assert_eq!(
            validate_ref(&r, ResolutionScope::Untrusted),
            Err(SecretRefError::SourceNotAllowedInScope {
                kind: SecretSourceKind::Env,
                scope: ResolutionScope::Untrusted,
            })
        );
    }

    #[test]
    fn validate_refuses_file_in_untrusted() {
        let r = file_ref("/absolute/ok");
        assert!(validate_ref(&r, ResolutionScope::TrustedLocal).is_ok());
        assert!(validate_ref(&r, ResolutionScope::RecordReplay).is_ok());
        assert!(matches!(
            validate_ref(&r, ResolutionScope::Untrusted),
            Err(SecretRefError::SourceNotAllowedInScope {
                kind: SecretSourceKind::File,
                scope: ResolutionScope::Untrusted,
            })
        ));
    }

    #[test]
    fn validate_refuses_relative_from_file_in_every_scope() {
        let r = file_ref("relative/path");
        assert!(matches!(
            validate_ref(&r, ResolutionScope::TrustedLocal),
            Err(SecretRefError::RelativeFilePath(_))
        ));
        assert!(matches!(
            validate_ref(&r, ResolutionScope::RecordReplay),
            Err(SecretRefError::RelativeFilePath(_))
        ));
    }

    #[test]
    fn reveal_error_variants_classify_structurally() {
        // Proves the string-matching classifier is gone. We construct
        // each RevealError variant directly (not via reveal() driving
        // a real failure) and verify the From<RevealError> conversion.
        // If someone later reintroduces string matching and rewords a
        // `reveal` error message, this test still passes only if the
        // enum mapping is authoritative — which it is now.
        let cases = [
            (RevealError::NotFound, ResolutionFailure::StoreMiss),
            (RevealError::EnvUnset, ResolutionFailure::EnvUnset),
            (
                RevealError::FileReadFailed,
                ResolutionFailure::FileReadFailed,
            ),
            (RevealError::FileTooLarge, ResolutionFailure::FileTooLarge),
            (RevealError::CryptoFailed, ResolutionFailure::CryptoFailed),
            (
                RevealError::Internal(Error::config("x", "y")),
                ResolutionFailure::Internal,
            ),
        ];
        for (reveal_err, expected) in cases {
            assert_eq!(ResolutionFailure::from(reveal_err), expected);
        }
    }

    #[test]
    fn resolve_classified_store_miss() {
        let _lock = test_lock();
        let _home = HomeGuard::new();

        let store = SecretStore::load().unwrap();
        let r = store_ref("DOES_NOT_EXIST");
        let err =
            resolve_secret_ref_classified("DOES_NOT_EXIST", &r, &store, ResolutionScope::Untrusted)
                .unwrap_err();
        assert_eq!(err, ResolutionFailure::StoreMiss);
        assert!(err.is_client_error());
    }

    #[test]
    fn resolve_classified_env_unset() {
        let _lock = test_lock();
        let _home = HomeGuard::new();

        let store = SecretStore::load().unwrap();
        let r = env_ref("SMOLVM_TEST_UNSET_ENV_VAR_XYZ");
        std::env::remove_var("SMOLVM_TEST_UNSET_ENV_VAR_XYZ");
        let err = resolve_secret_ref_classified("X", &r, &store, ResolutionScope::TrustedLocal)
            .unwrap_err();
        assert_eq!(err, ResolutionFailure::EnvUnset);
        assert!(err.is_client_error());
    }

    #[test]
    fn resolve_classified_file_missing() {
        let _lock = test_lock();
        let _home = HomeGuard::new();

        let store = SecretStore::load().unwrap();
        let r = file_ref("/nonexistent/path/to/creds");
        let err = resolve_secret_ref_classified("X", &r, &store, ResolutionScope::TrustedLocal)
            .unwrap_err();
        assert_eq!(err, ResolutionFailure::FileReadFailed);
        assert!(err.is_client_error());
    }

    #[test]
    fn resolve_classified_file_too_large() {
        let _lock = test_lock();
        let _home = HomeGuard::new();

        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("huge");
        let blob = vec![b'x'; (MAX_FROM_FILE_BYTES + 1) as usize];
        std::fs::write(&p, blob).unwrap();

        let store = SecretStore::load().unwrap();
        let r = SecretRef {
            from_store: None,
            from_env: None,
            from_file: Some(p),
        };
        let err = resolve_secret_ref_classified("X", &r, &store, ResolutionScope::TrustedLocal)
            .unwrap_err();
        assert_eq!(err, ResolutionFailure::FileTooLarge);
        assert!(err.is_client_error());
    }

    #[test]
    fn resolution_failure_5xx_vs_4xx() {
        // Client-fixable conditions must be 4xx-class.
        assert!(ResolutionFailure::StoreMiss.is_client_error());
        assert!(ResolutionFailure::EnvUnset.is_client_error());
        assert!(ResolutionFailure::FileReadFailed.is_client_error());
        assert!(ResolutionFailure::FileTooLarge.is_client_error());
        // Server-state conditions must be 5xx-class.
        assert!(!ResolutionFailure::CryptoFailed.is_client_error());
        assert!(!ResolutionFailure::Internal.is_client_error());
    }

    #[test]
    fn resolve_refs_to_env_classified_reports_first_failure_with_key() {
        let _lock = test_lock();
        let _home = HomeGuard::new();

        let mut refs = BTreeMap::new();
        // Put a present and a missing secret in the map. The classified
        // resolver must return the missing one named — not a generic
        // "first error" that loses the key.
        let mut store = SecretStore::load().unwrap();
        store.set_value("PRESENT", "value").unwrap();
        store.save().unwrap();

        refs.insert("PRESENT".to_string(), store_ref("PRESENT"));
        refs.insert("MISSING".to_string(), store_ref("MISSING"));

        let err = resolve_refs_to_env_classified(&refs, ResolutionScope::Untrusted).unwrap_err();
        assert_eq!(err.key, "MISSING");
        assert_eq!(err.kind, ResolutionFailure::StoreMiss);
    }

    #[test]
    fn with_lock_serializes_concurrent_mutations() {
        let _lock = test_lock();
        let _home = HomeGuard::new();

        // Seed the store so with_lock has something to reload each time.
        SecretStore::with_lock(|s| s.set_value("SEED", "0")).unwrap();

        // Fire 8 threads all doing set_value with different names.
        // Without the lock, they'd race on load→mutate→save and lose
        // entries. With the lock, every entry ends up in the store.
        let handles: Vec<_> = (0..8)
            .map(|i| {
                std::thread::spawn(move || {
                    SecretStore::with_lock(|s| s.set_value(&format!("K{}", i), &format!("v{}", i)))
                        .unwrap();
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        let store = SecretStore::load().unwrap();
        for i in 0..8 {
            assert!(
                store.contains(&format!("K{}", i)),
                "K{} missing — lock didn't serialize writes",
                i
            );
        }
        assert!(store.contains("SEED"));
    }

    #[test]
    #[cfg(unix)]
    fn from_file_refuses_symlink() {
        let _lock = test_lock();
        let _home = HomeGuard::new();

        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real");
        std::fs::write(&real, "real-content").unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let mut store = SecretStore::load().unwrap();
        store.set_file("VIA_SYMLINK", &link).unwrap();
        // Resolution must refuse — attacker could replace `link` to
        // point at any file smolvm can read.
        assert!(store.reveal("VIA_SYMLINK").is_err());

        // Direct (non-symlink) ref still works.
        store.set_file("DIRECT", &real).unwrap();
        assert_eq!(&*store.reveal("DIRECT").unwrap(), "real-content");
    }

    #[test]
    fn set_file_refuses_relative_path() {
        let _lock = test_lock();
        let _home = HomeGuard::new();

        let mut store = SecretStore::load().unwrap();
        // Relative — must be refused at the store boundary, not silently
        // persisted to be rejected later by `validate()`.
        let res = store.set_file("X", Path::new("relative/creds"));
        assert!(res.is_err());
        assert!(!store.contains("X"));

        // Absolute still works.
        let res = store.set_file("Y", Path::new("/tmp/creds"));
        assert!(res.is_ok());
    }

    #[test]
    fn audit_log_records_do_not_contain_sensitive_material() {
        use std::sync::{Arc, Mutex};
        use tracing::subscriber;
        use tracing_subscriber::fmt::MakeWriter;

        #[derive(Clone, Default)]
        struct SharedBuf(Arc<Mutex<Vec<u8>>>);

        impl std::io::Write for SharedBuf {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl<'a> MakeWriter<'a> for SharedBuf {
            type Writer = SharedBuf;
            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }

        let _lock = test_lock();
        let _home = HomeGuard::new();

        let buf = SharedBuf::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_env_filter(format!("{}=info", AUDIT_TARGET))
            .finish();

        // Set up a file-source ref whose path and contents are both
        // recognizable sentinels — we'll verify neither appears in the
        // emitted audit record.
        let tmp = tempfile::tempdir().unwrap();
        let sentinel_path = tmp.path().join("Secret-Path-Sentinel-12345");
        std::fs::write(&sentinel_path, "secret-value-sentinel-XYZ\n").unwrap();

        let store = SecretStore::load().unwrap();
        let r = SecretRef {
            from_store: None,
            from_env: None,
            from_file: Some(sentinel_path.clone()),
        };

        subscriber::with_default(subscriber, || {
            let _v = resolve_secret_ref("AUDIT_TEST", &r, &store, ResolutionScope::RecordReplay)
                .unwrap();
        });

        let logged = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert!(
            logged.contains("AUDIT_TEST"),
            "audit record should include the secret key"
        );
        assert!(
            logged.contains("record-replay"),
            "audit record should include the scope"
        );
        assert!(
            !logged.contains("secret-value-sentinel"),
            "audit record must NOT include the resolved value, got: {}",
            logged
        );
        assert!(
            !logged.contains("Secret-Path-Sentinel"),
            "audit record must NOT include the from_file path, got: {}",
            logged
        );
    }

    #[test]
    fn oversized_value_rejected() {
        let _lock = test_lock();
        let _home = HomeGuard::new();

        let mut store = SecretStore::load().unwrap();
        let big = "x".repeat(MAX_SECRET_VALUE_BYTES + 1);
        assert!(store.set_value("BIG", &big).is_err());
        // A value right at the limit still fits.
        let ok = "x".repeat(MAX_SECRET_VALUE_BYTES);
        assert!(store.set_value("OK", &ok).is_ok());
    }

    #[test]
    fn oversized_store_file_rejected() {
        let _lock = test_lock();
        let _home = HomeGuard::new();

        // Write an over-cap placeholder straight into the store path to
        // simulate corruption or a malicious writer; `load` must refuse.
        let path = SecretStore::store_path().unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let blob = vec![b'#'; (MAX_STORE_FILE_BYTES + 1) as usize];
        std::fs::write(&path, blob).unwrap();
        assert!(SecretStore::load().is_err());
    }

    #[test]
    fn oversized_from_file_rejected() {
        let _lock = test_lock();
        let _home = HomeGuard::new();

        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("huge");
        let blob = vec![b'x'; (MAX_FROM_FILE_BYTES + 1) as usize];
        std::fs::write(&p, blob).unwrap();

        let mut store = SecretStore::load().unwrap();
        store.set_file("HUGE", &p).unwrap();
        // Resolution must refuse — no silent gigantic env var injection.
        assert!(store.reveal("HUGE").is_err());
    }

    #[test]
    fn key_file_is_mode_0600() {
        let _lock = test_lock();
        let _home = HomeGuard::new();

        let _ = load_or_create_master_key().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = SecretStore::key_path().unwrap();
            let meta = std::fs::metadata(&path).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }
    }
}
