//! This crate contains methods to deal with SSH keys, as defined in
//! crate Russh. This includes in particular various functions for
//! opening key files, deciphering encrypted keys, and dealing with
//! agents.
//!
//! The following example shows how to do all these in a single example:
//! start and SSH agent server, connect to it with a client, decipher
//! an encrypted ED25519 private key (the password is `b"blabla"`), send it to
//! the agent, and ask the agent to sign a piece of data
//! (`b"Please sign this"`, below).
//!
//!```
//! use russh::keys::*;
//! use futures::Future;
//!
//! #[derive(Clone)]
//! struct X{}
//! impl agent::server::Agent for X {
//!     fn confirm(self, _: std::sync::Arc<PrivateKey>) -> Box<dyn Future<Output = (Self, bool)> + Send + Unpin> {
//!         Box::new(futures::future::ready((self, true)))
//!     }
//! }
//!
//! const PKCS8_ENCRYPTED: &'static str = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIGjMF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBAWQiUHKoocuxfoZ/hF\nYTjkAgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQ83d1d5/S2wz475uC\nCUrE7QRAvdVpD5e3zKH/MZjilWrMOm6cyI1LKBCssLztPyvOALtroLAPlp7WYWfu\n9Sncmm7u14n2lia7r1r5I3VBsVuH0g==\n-----END ENCRYPTED PRIVATE KEY-----\n";
//!
//! #[cfg(unix)]
//! fn main() {
//!    env_logger::try_init().unwrap_or(());
//!    let dir = tempfile::tempdir().unwrap();
//!    let agent_path = dir.path().join("agent");
//!
//!    let mut core = tokio::runtime::Runtime::new().unwrap();
//!    let agent_path_ = agent_path.clone();
//!    // Starting a server
//!    core.spawn(async move {
//!        let mut listener = tokio::net::UnixListener::bind(&agent_path_)
//!            .unwrap();
//!        russh::keys::agent::server::serve(tokio_stream::wrappers::UnixListenerStream::new(listener), X {}).await
//!    });
//!    let key = decode_secret_key(PKCS8_ENCRYPTED, Some("blabla")).unwrap();
//!    let public = key.public_key().clone();
//!    core.block_on(async move {
//!        let stream = tokio::net::UnixStream::connect(&agent_path).await?;
//!        let mut client = agent::client::AgentClient::connect(stream);
//!        client.add_identity(&key, &[agent::Constraint::KeyLifetime { seconds: 60 }]).await?;
//!        client.request_identities().await?;
//!        let buf = b"signed message".to_vec();
//!        let sig = client.sign_request(&public.into(), None, buf).await.unwrap();
//!        // Here, `sig` is encoded in a format usable internally by the SSH protocol.
//!        Ok::<(), Error>(())
//!    }).unwrap()
//! }
//!
//! #[cfg(not(unix))]
//! fn main() {}
//!
//! ```

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::string::FromUtf8Error;

use aes::cipher::inout::PadError;
use data_encoding::BASE64_MIME;
use thiserror::Error;

use crate::helpers::EncodedExt;

pub mod key;
pub use key::PrivateKeyWithHashAlg;

mod format;
pub use format::*;
// Reexports
pub use signature;
pub use ssh_encoding;
pub use ssh_key::{self, Algorithm, Certificate, EcdsaCurve, HashAlg, PrivateKey, PublicKey};

/// OpenSSH agent protocol implementation
pub mod agent;

#[cfg(not(target_arch = "wasm32"))]
pub mod known_hosts;

#[cfg(not(target_arch = "wasm32"))]
pub use known_hosts::{check_known_hosts, check_known_hosts_path};

pub use crate::cert::PublicKeyOrCertificate;

#[derive(Debug, Error)]
pub enum Error {
    /// The key could not be read, for an unknown reason
    #[error("Could not read key")]
    CouldNotReadKey,
    /// The type of the key is unsupported
    #[error("Unsupported key type {}", key_type_string)]
    UnsupportedKeyType {
        key_type_string: String,
        key_type_raw: Vec<u8>,
    },
    /// The type of the key is unsupported
    #[error("Invalid Ed25519 key data")]
    Ed25519KeyError(#[from] ed25519_dalek::SignatureError),
    /// The type of the key is unsupported
    #[error("Invalid ECDSA key data")]
    EcdsaKeyError(#[from] p256::elliptic_curve::Error),
    /// The key is encrypted (should supply a password?)
    #[error("The key is encrypted")]
    KeyIsEncrypted,
    /// The key contents are inconsistent
    #[error("The key is corrupt")]
    KeyIsCorrupt,
    /// Home directory could not be found
    #[error("No home directory found")]
    NoHomeDir,
    /// The server key has changed
    #[error("The server key changed at line {}", line)]
    KeyChanged { line: usize },
    /// The key uses an unsupported algorithm
    #[error("Unknown key algorithm: {0}")]
    UnknownAlgorithm(::pkcs8::ObjectIdentifier),
    /// Index out of bounds
    #[error("Index out of bounds")]
    IndexOutOfBounds,
    /// Unknown signature type
    #[error("Unknown signature type: {}", sig_type)]
    UnknownSignatureType { sig_type: String },
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid parameters")]
    InvalidParameters,
    /// Agent protocol error
    #[error("Agent protocol error")]
    AgentProtocolError,
    #[error("Agent failure")]
    AgentFailure,
    #[error(transparent)]
    IO(#[from] std::io::Error),

    #[cfg(feature = "rsa")]
    #[error("Rsa: {0}")]
    Rsa(#[from] rsa::Error),

    #[error(transparent)]
    Pad(#[from] PadError),

    #[error(transparent)]
    Unpad(#[from] aes::cipher::block_padding::Error),

    #[error("Base64 decoding error: {0}")]
    Decode(#[from] data_encoding::DecodeError),
    #[error("Der: {0}")]
    Der(#[from] der::Error),
    #[error("Spki: {0}")]
    Spki(#[from] spki::Error),
    #[cfg(feature = "rsa")]
    #[error("Pkcs1: {0}")]
    Pkcs1(#[from] pkcs1::Error),
    #[error("Pkcs8: {0}")]
    Pkcs8(#[from] ::pkcs8::Error),
    #[error("Sec1: {0}")]
    Sec1(#[from] sec1::Error),

    #[error("SshKey: {0}")]
    SshKey(#[from] ssh_key::Error),
    #[error("SshEncoding: {0}")]
    SshEncoding(#[from] ssh_encoding::Error),

    #[error("Environment variable `{0}` not found")]
    EnvVar(&'static str),
    #[error(
        "Unable to connect to ssh-agent. The environment variable `SSH_AUTH_SOCK` was set, but it \
         points to a nonexistent file or directory."
    )]
    BadAuthSock,

    #[error(transparent)]
    Utf8(#[from] FromUtf8Error),

    #[cfg(windows)]
    #[error("Pageant: {0}")]
    Pageant(#[from] pageant::Error),
}

/// Load a public key from a file. Ed25519, EC-DSA and RSA keys are supported.
///
/// ```
/// russh::keys::load_public_key("../files/id_ed25519.pub").unwrap();
/// ```
pub fn load_public_key<P: AsRef<Path>>(path: P) -> Result<ssh_key::PublicKey, Error> {
    let mut pubkey = String::new();
    let mut file = File::open(path.as_ref())?;
    file.read_to_string(&mut pubkey)?;

    // First non-blank, non-`#` line: `<algorithm> <base64> [comment]` or a
    // bare base64 blob. The comment may contain spaces.
    let line = pubkey
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .ok_or(Error::CouldNotReadKey)?;
    let Some((_, rest)) = line.split_once(char::is_whitespace) else {
        return parse_public_key_base64(line);
    };
    let rest = rest.trim_start();
    let (key, comment) = rest
        .split_once(char::is_whitespace)
        .unwrap_or((rest, ""));
    let mut key = parse_public_key_base64(key)?;
    key.set_comment(comment.trim_start());
    Ok(key)
}

/// Reads a public key from the standard encoding. In some cases, the
/// encoding is prefixed with a key type identifier and a space (such
/// as `ssh-ed25519 AAAAC3N...`).
///
/// ```
/// russh::keys::parse_public_key_base64("AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ").is_ok();
/// ```
pub fn parse_public_key_base64(key: &str) -> Result<ssh_key::PublicKey, Error> {
    let base = BASE64_MIME.decode(key.as_bytes())?;
    key::parse_public_key(&base)
}

pub trait PublicKeyBase64 {
    /// Create the base64 part of the public key blob.
    fn public_key_bytes(&self) -> Vec<u8>;
    fn public_key_base64(&self) -> String {
        let mut s = BASE64_MIME.encode(&self.public_key_bytes());
        assert_eq!(s.pop(), Some('\n'));
        assert_eq!(s.pop(), Some('\r'));
        s.replace("\r\n", "")
    }
}

impl PublicKeyBase64 for ssh_key::PublicKey {
    fn public_key_bytes(&self) -> Vec<u8> {
        self.key_data().encoded().unwrap_or_default()
    }
}

impl PublicKeyBase64 for PrivateKey {
    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key().public_key_bytes()
    }
}

/// Load a secret key, deciphering it with the supplied password if necessary.
pub fn load_secret_key<P: AsRef<Path>>(
    secret_: P,
    password: Option<&str>,
) -> Result<PrivateKey, Error> {
    let mut secret_file = std::fs::File::open(secret_)?;
    let mut secret = String::new();
    secret_file.read_to_string(&mut secret)?;
    decode_secret_key(&secret, password)
}

/// Load a openssh certificate
pub fn load_openssh_certificate<P: AsRef<Path>>(cert_: P) -> Result<Certificate, ssh_key::Error> {
    let mut cert_file = std::fs::File::open(cert_)?;
    let mut cert = String::new();
    cert_file.read_to_string(&mut cert)?;

    Certificate::from_openssh(&cert)
}

fn is_base64_char(c: char) -> bool {
    c.is_ascii_lowercase()
        || c.is_ascii_uppercase()
        || c.is_ascii_digit()
        || c == '/'
        || c == '+'
        || c == '='
}

#[cfg(test)]
mod test {

    #[cfg(unix)]
    use futures::Future;

    use super::*;
    #[cfg(unix)]
    use crate::keys::agent::AgentIdentity;
    use crate::keys::key::PublicKeyExt;

    const ED25519_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jYmMAAAAGYmNyeXB0AAAAGAAAABDLGyfA39
J2FcJygtYqi5ISAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIN+Wjn4+4Fcvl2Jl
KpggT+wCRxpSvtqqpVrQrKN1/A22AAAAkOHDLnYZvYS6H9Q3S3Nk4ri3R2jAZlQlBbUos5
FkHpYgNw65KCWCTXtP7ye2czMC3zjn2r98pJLobsLYQgRiHIv/CUdAdsqbvMPECB+wl/UQ
e+JpiSq66Z6GIt0801skPh20jxOO3F52SoX1IeO5D5PXfZrfSZlw6S8c7bwyp2FHxDewRx
7/wNsnDM0T7nLv/Q==
-----END OPENSSH PRIVATE KEY-----";

    // password is 'test'
    const ED25519_AESCTR_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABD1phlku5
A2G7Q9iP+DcOc9AAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIHeLC1lWiCYrXsf/
85O/pkbUFZ6OGIt49PX3nw8iRoXEAAAAkKRF0st5ZI7xxo9g6A4m4l6NarkQre3mycqNXQ
dP3jryYgvsCIBAA5jMWSjrmnOTXhidqcOy4xYCrAttzSnZ/cUadfBenL+DQq6neffw7j8r
0tbCxVGp6yCQlKrgSZf6c0Hy7dNEIU2bJFGxLe6/kWChcUAt/5Ll5rI7DVQPJdLgehLzvv
sJWR7W+cGvJ/vLsw==
-----END OPENSSH PRIVATE KEY-----";

    #[cfg(feature = "rsa")]
    const RSA_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAuSvQ9m76zhRB4m0BUKPf17lwccj7KQ1Qtse63AOqP/VYItqEH8un
rxPogXNBgrcCEm/ccLZZsyE3qgp3DRQkkqvJhZ6O8VBPsXxjZesRCqoFNCczy+Mf0R/Qmv
Rnpu5+4DDLz0p7vrsRZW9ji/c98KzxeUonWgkplQaCBYLN875WdeUYMGtb1MLfNCEj177j
gZl3CzttLRK3su6dckowXcXYv1gPTPZAwJb49J43o1QhV7+1zdwXvuFM6zuYHdu9ZHSKir
6k1dXOET3/U+LWG5ofAo8oxUWv/7vs6h7MeajwkUeIBOWYtD+wGYRvVpxvj7nyOoWtg+jm
0X6ndnsD+QAAA8irV+ZAq1fmQAAAAAdzc2gtcnNhAAABAQC5K9D2bvrOFEHibQFQo9/XuX
BxyPspDVC2x7rcA6o/9Vgi2oQfy6evE+iBc0GCtwISb9xwtlmzITeqCncNFCSSq8mFno7x
UE+xfGNl6xEKqgU0JzPL4x/RH9Ca9Gem7n7gMMvPSnu+uxFlb2OL9z3wrPF5SidaCSmVBo
IFgs3zvlZ15Rgwa1vUwt80ISPXvuOBmXcLO20tErey7p1ySjBdxdi/WA9M9kDAlvj0njej
VCFXv7XN3Be+4UzrO5gd271kdIqKvqTV1c4RPf9T4tYbmh8CjyjFRa//u+zqHsx5qPCRR4
gE5Zi0P7AZhG9WnG+PufI6ha2D6ObRfqd2ewP5AAAAAwEAAQAAAQAdELqhI/RsSpO45eFR
9hcZtnrm8WQzImrr9dfn1w9vMKSf++rHTuFIQvi48Q10ZiOGH1bbvlPAIVOqdjAPtnyzJR
HhzmyjhjasJlk30zj+kod0kz63HzSMT9EfsYNfmYoCyMYFCKz52EU3xc87Vhi74XmZz0D0
CgIj6TyZftmzC4YJCiwwU8K+29nxBhcbFRxpgwAksFL6PCSQsPl4y7yvXGcX+7lpZD8547
v58q3jIkH1g2tBOusIuaiphDDStVJhVdKA55Z0Kju2kvCqsRIlf1efrq43blRgJFFFCxNZ
8Cpolt4lOHhg+o3ucjILlCOgjDV8dB21YLxmgN5q+xFNAAAAgQC1P+eLUkHDFXnleCEVrW
xL/DFxEyneLQz3IawGdw7cyAb7vxsYrGUvbVUFkxeiv397pDHLZ5U+t5cOYDBZ7G43Mt2g
YfWBuRNvYhHA9Sdf38m5qPA6XCvm51f+FxInwd/kwRKH01RHJuRGsl/4Apu4DqVob8y00V
WTYyV6JBNDkQAAAIEA322lj7ZJXfK/oLhMM/RS+DvaMea1g/q43mdRJFQQso4XRCL6IIVn
oZXFeOxrMIRByVZBw+FSeB6OayWcZMySpJQBo70GdJOc3pJb3js0T+P2XA9+/jwXS58K9a
+IkgLkv9XkfxNGNKyPEEzXC8QQzvjs1LbmO59VLko8ypwHq/cAAACBANQqaULI0qdwa0vm
d3Ae1+k3YLZ0kapSQGVIMT2lkrhKV35tj7HIFpUPa4vitHzcUwtjYhqFezVF+JyPbJ/Fsp
XmEc0g1fFnQp5/SkUwoN2zm8Up52GBelkq2Jk57mOMzWO0QzzNuNV/feJk02b2aE8rrAqP
QR+u0AypRPmzHnOPAAAAEXJvb3RAMTQwOTExNTQ5NDBkAQ==
-----END OPENSSH PRIVATE KEY-----";

    #[test]
    fn test_load_public_key_comment() {
        const KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIK2pr+Bfus1hvPof4Wb/plZCzSbqadHH0u+/f4ODtKnE";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key.pub");
        let load = |contents: &str| {
            std::fs::write(&path, contents).unwrap();
            load_public_key(&path).unwrap()
        };

        let key = load(&format!("ssh-ed25519 {KEY} my comment\n"));
        assert_eq!(key.comment().to_string(), "my comment");
        assert_eq!(
            key.to_openssh().unwrap(),
            format!("ssh-ed25519 {KEY} my comment")
        );

        let key = load(&format!("ssh-ed25519 {KEY}\n"));
        assert!(key.comment().is_empty());

        let key = load(&format!("{KEY}\n"));
        assert!(key.comment().is_empty());

        let key = load(&format!("# a comment line\r\n\r\nssh-ed25519\t{KEY}  tabs and crlf \r\n"));
        assert_eq!(key.comment().to_string(), "tabs and crlf");

        for bad in ["", "\n# only a comment\n", "ssh-ed25519 not-base64\n"] {
            std::fs::write(&path, bad).unwrap();
            assert!(load_public_key(&path).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn test_decode_ed25519_secret_key() {
        env_logger::try_init().unwrap_or(());
        decode_secret_key(ED25519_KEY, Some("blabla")).unwrap();
    }

    #[test]
    fn test_decode_ed25519_aesctr_secret_key() {
        env_logger::try_init().unwrap_or(());
        decode_secret_key(ED25519_AESCTR_KEY, Some("test")).unwrap();
    }

    // Key from RFC 8410 Section 10.3. This is a key using PrivateKeyInfo structure.
    const RFC8410_ED25519_PRIVATE_ONLY_KEY: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
-----END PRIVATE KEY-----";

    #[test]
    fn test_decode_rfc8410_ed25519_private_only_key() {
        env_logger::try_init().unwrap_or(());
        assert!(
            decode_secret_key(RFC8410_ED25519_PRIVATE_ONLY_KEY, None)
                .unwrap()
                .algorithm()
                == ssh_key::Algorithm::Ed25519,
        );
        // We always encode public key, skip test_decode_encode_symmetry.
    }

    // Key from RFC 8410 Section 10.3. This is a key using OneAsymmetricKey structure.
    const RFC8410_ED25519_PRIVATE_PUBLIC_KEY: &str = "-----BEGIN PRIVATE KEY-----
MHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
oB8wHQYKKoZIhvcNAQkJFDEPDA1DdXJkbGUgQ2hhaXJzgSEAGb9ECWmEzf6FQbrB
Z9w7lshQhqowtrbLDFw4rXAxZuE=
-----END PRIVATE KEY-----";

    #[test]
    fn test_decode_rfc8410_ed25519_private_public_key() {
        env_logger::try_init().unwrap_or(());
        assert!(
            decode_secret_key(RFC8410_ED25519_PRIVATE_PUBLIC_KEY, None)
                .unwrap()
                .algorithm()
                == ssh_key::Algorithm::Ed25519,
        );
        // We can't encode attributes, skip test_decode_encode_symmetry.
    }

    #[cfg(feature = "rsa")]
    #[test]
    fn test_decode_rsa_secret_key() {
        env_logger::try_init().unwrap_or(());
        decode_secret_key(RSA_KEY, None).unwrap();
    }

    #[test]
    fn test_decode_openssh_p256_secret_key() {
        // Generated using: ssh-keygen -t ecdsa -b 256 -m rfc4716 -f $file
        let key = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQQ/i+HCsmZZPy0JhtT64vW7EmeA1DeA
M/VnPq3vAhu+xooJ7IMMK3lUHlBDosyvA2enNbCWyvNQc25dVt4oh9RhAAAAqHG7WMFxu1
jBAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBD+L4cKyZlk/LQmG
1Pri9bsSZ4DUN4Az9Wc+re8CG77GignsgwwreVQeUEOizK8DZ6c1sJbK81Bzbl1W3iiH1G
EAAAAgLAmXR6IlN0SdiD6o8qr+vUr0mXLbajs/m0UlegElOmoAAAANcm9iZXJ0QGJic2Rl
dgECAw==
-----END OPENSSH PRIVATE KEY-----
";
        assert!(
            decode_secret_key(key, None).unwrap().algorithm()
                == ssh_key::Algorithm::Ecdsa {
                    curve: ssh_key::EcdsaCurve::NistP256
                },
        );
    }

    #[test]
    fn test_decode_openssh_p384_secret_key() {
        // Generated using: ssh-keygen -t ecdsa -b 384 -m rfc4716 -f $file
        let key = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAiAAAABNlY2RzYS
1zaGEyLW5pc3RwMzg0AAAACG5pc3RwMzg0AAAAYQTkLnKPk/1NZD9mQ8XoebD7ASv9/svh
5jO75HF7RYAqKK3fl5wsHe4VTJAOT3qH841yTcK79l0dwhHhHeg60byL7F9xOEzr2kqGeY
Uwrl7fVaL7hfHzt6z+sG8smSQ3tF8AAADYHjjBch44wXIAAAATZWNkc2Etc2hhMi1uaXN0
cDM4NAAAAAhuaXN0cDM4NAAAAGEE5C5yj5P9TWQ/ZkPF6Hmw+wEr/f7L4eYzu+Rxe0WAKi
it35ecLB3uFUyQDk96h/ONck3Cu/ZdHcIR4R3oOtG8i+xfcThM69pKhnmFMK5e31Wi+4Xx
87es/rBvLJkkN7RfAAAAMFzt6053dxaQT0Ta/CGfZna0nibHzxa55zgBmje/Ho3QDNlBCH
Ylv0h4Wyzto8NfLQAAAA1yb2JlcnRAYmJzZGV2AQID
-----END OPENSSH PRIVATE KEY-----
";
        assert!(
            decode_secret_key(key, None).unwrap().algorithm()
                == ssh_key::Algorithm::Ecdsa {
                    curve: ssh_key::EcdsaCurve::NistP384
                },
        );
    }

    #[test]
    fn test_decode_openssh_p521_secret_key() {
        // Generated using: ssh-keygen -t ecdsa -b 521 -m rfc4716 -f $file
        let key = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAArAAAABNlY2RzYS
1zaGEyLW5pc3RwNTIxAAAACG5pc3RwNTIxAAAAhQQA7a9awmFeDjzYiuUOwMfXkKTevfQI
iGlduu8BkjBOWXpffJpKsdTyJI/xI05l34OvqfCCkPUcfFWHK+LVRGahMBgBcGB9ZZOEEq
iKNIT6C9WcJTGDqcBSzQ2yTSOxPXfUmVTr4D76vbYu5bjd9aBKx8HdfMvPeo0WD0ds/LjX
LdJoDXcAAAEQ9fxlIfX8ZSEAAAATZWNkc2Etc2hhMi1uaXN0cDUyMQAAAAhuaXN0cDUyMQ
AAAIUEAO2vWsJhXg482IrlDsDH15Ck3r30CIhpXbrvAZIwTll6X3yaSrHU8iSP8SNOZd+D
r6nwgpD1HHxVhyvi1URmoTAYAXBgfWWThBKoijSE+gvVnCUxg6nAUs0Nsk0jsT131JlU6+
A++r22LuW43fWgSsfB3XzLz3qNFg9HbPy41y3SaA13AAAAQgH4DaftY0e/KsN695VJ06wy
Ve0k2ddxoEsSE15H4lgNHM2iuYKzIqZJOReHRCTff6QGgMYPDqDfFfL1Hc1Ntql0pwAAAA
1yb2JlcnRAYmJzZGV2AQIDBAU=
-----END OPENSSH PRIVATE KEY-----
";
        assert!(
            decode_secret_key(key, None).unwrap().algorithm()
                == ssh_key::Algorithm::Ecdsa {
                    curve: ssh_key::EcdsaCurve::NistP521
                },
        );
    }

    #[test]
    fn test_fingerprint() {
        let key = parse_public_key_base64(
            "AAAAC3NzaC1lZDI1NTE5AAAAILagOJFgwaMNhBWQINinKOXmqS4Gh5NgxgriXwdOoINJ",
        )
        .unwrap();
        assert_eq!(
            format!("{}", key.fingerprint(ssh_key::HashAlg::Sha256)),
            "SHA256:ldyiXa1JQakitNU5tErauu8DvWQ1dZ7aXu+rm7KQuog"
        );
    }

    #[test]
    fn test_parse_p256_public_key() {
        env_logger::try_init().unwrap_or(());
        let key = "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMxBTpMIGvo7CnordO7wP0QQRqpBwUjOLl4eMhfucfE1sjTYyK5wmTl1UqoSDS1PtRVTBdl+0+9pquFb46U7fwg=";

        assert!(
            parse_public_key_base64(key).unwrap().algorithm()
                == ssh_key::Algorithm::Ecdsa {
                    curve: ssh_key::EcdsaCurve::NistP256
                },
        );
    }

    #[test]
    fn test_parse_p384_public_key() {
        env_logger::try_init().unwrap_or(());
        let key = "AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBBVFgxJxpCaAALZG/S5BHT8/IUQ5mfuKaj7Av9g7Jw59fBEGHfPBz1wFtHGYw5bdLmfVZTIDfogDid5zqJeAKr1AcD06DKTXDzd2EpUjqeLfQ5b3erHuX758fgu/pSDGRA==";

        assert!(
            parse_public_key_base64(key).unwrap().algorithm()
                == ssh_key::Algorithm::Ecdsa {
                    curve: ssh_key::EcdsaCurve::NistP384
                }
        );
    }

    #[test]
    fn test_parse_p521_public_key() {
        env_logger::try_init().unwrap_or(());
        let key = "AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAAQepXEpOrzlX22r4E5zEHjhHWeZUe//zaevTanOWRBnnaCGWJFGCdjeAbNOuAmLtXc+HZdJTCZGREeSLSrpJa71QDCgZl0N7DkDUanCpHZJe/DCK6qwtHYbEMn28iLMlGCOrCIa060EyJHbp1xcJx4I1SKj/f/fm3DhhID/do6zyf8Cg==";

        assert!(
            parse_public_key_base64(key).unwrap().algorithm()
                == ssh_key::Algorithm::Ecdsa {
                    curve: ssh_key::EcdsaCurve::NistP521
                }
        );
    }

    #[test]
    fn test_srhb() {
        env_logger::try_init().unwrap_or(());
        let key = "AAAAB3NzaC1yc2EAAAADAQABAAACAQC0Xtz3tSNgbUQAXem4d+d6hMx7S8Nwm/DOO2AWyWCru+n/+jQ7wz2b5+3oG2+7GbWZNGj8HCc6wJSA3jUsgv1N6PImIWclD14qvoqY3Dea1J0CJgXnnM1xKzBz9C6pDHGvdtySg+yzEO41Xt4u7HFn4Zx5SGuI2NBsF5mtMLZXSi33jCIWVIkrJVd7sZaY8jiqeVZBB/UvkLPWewGVuSXZHT84pNw4+S0Rh6P6zdNutK+JbeuO+5Bav4h9iw4t2sdRkEiWg/AdMoSKmo97Gigq2mKdW12ivnXxz3VfxrCgYJj9WwaUUWSfnAju5SiNly0cTEAN4dJ7yB0mfLKope1kRhPsNaOuUmMUqlu/hBDM/luOCzNjyVJ+0LLB7SV5vOiV7xkVd4KbEGKou8eeCR3yjFazUe/D1pjYPssPL8cJhTSuMc+/UC9zD8yeEZhB9V+vW4NMUR+lh5+XeOzenl65lWYd/nBZXLBbpUMf1AOfbz65xluwCxr2D2lj46iApSIpvE63i3LzFkbGl9GdUiuZJLMFJzOWdhGGc97cB5OVyf8umZLqMHjaImxHEHrnPh1MOVpv87HYJtSBEsN4/omINCMZrk++CRYAIRKRpPKFWV7NQHcvw3m7XLR3KaTYe+0/MINIZwGdou9fLUU3zSd521vDjA/weasH0CyDHq7sZw==";

        parse_public_key_base64(key).unwrap();
    }

    #[cfg(feature = "rsa")]
    #[test]
    fn test_nikao() {
        env_logger::try_init().unwrap_or(());
        let key = "-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAw/FG8YLVoXhsUVZcWaY7iZekMxQ2TAfSVh0LTnRuzsumeLhb
0fh4scIt4C4MLwpGe/u3vj290C28jLkOtysqnIpB4iBUrFNRmEz2YuvjOzkFE8Ju
0l1VrTZ9APhpLZvzT2N7YmTXcLz1yWopCe4KqTHczEP4lfkothxEoACXMaxezt5o
wIYfagDaaH6jXJgJk1SQ5VYrROVpDjjX8/Zg01H1faFQUikYx0M8EwL1fY5B80Hd
6DYSok8kUZGfkZT8HQ54DBgocjSs449CVqkVoQC1aDB+LZpMWovY15q7hFgfQmYD
qulbZRWDxxogS6ui/zUR2IpX7wpQMKKkBS1qdQIDAQABAoIBAQCodpcCKfS2gSzP
uapowY1KvP/FkskkEU18EDiaWWyzi1AzVn5LRo+udT6wEacUAoebLU5K2BaMF+aW
Lr1CKnDWaeA/JIDoMDJk+TaU0i5pyppc5LwXTXvOEpzi6rCzL/O++88nR4AbQ7sm
Uom6KdksotwtGvttJe0ktaUi058qaoFZbels5Fwk5bM5GHDdV6De8uQjSfYV813P
tM/6A5rRVBjC5uY0ocBHxPXkqAdHfJuVk0uApjLrbm6k0M2dg1X5oyhDOf7ZIzAg
QGPgvtsVZkQlyrD1OoCMPwzgULPXTe8SktaP9EGvKdMf5kQOqUstqfyx+E4OZa0A
T82weLjBAoGBAOUChhaLQShL3Vsml/Nuhhw5LsxU7Li34QWM6P5AH0HMtsSncH8X
ULYcUKGbCmmMkVb7GtsrHa4ozy0fjq0Iq9cgufolytlvC0t1vKRsOY6poC2MQgaZ
bqRa05IKwhZdHTr9SUwB/ngtVNWRzzbFKLkn2W5oCpQGStAKqz3LbKstAoGBANsJ
EyrXPbWbG+QWzerCIi6shQl+vzOd3cxqWyWJVaZglCXtlyySV2eKWRW7TcVvaXQr
Nzm/99GNnux3pUCY6szy+9eevjFLLHbd+knzCZWKTZiWZWr503h/ztfFwrMzhoAh
z4nukD/OETugPvtG01c2sxZb/F8LH9KORznhlSlpAoGBAJnqg1J9j3JU4tZTbwcG
fo5ThHeCkINp2owPc70GPbvMqf4sBzjz46QyDaM//9SGzFwocplhNhaKiQvrzMnR
LSVucnCEm/xdXLr/y6S6tEiFCwnx3aJv1uQRw2bBYkcDmBTAjVXPdUcyOHU+BYXr
Jv6ioMlKlel8/SUsNoFWypeVAoGAXhr3Bjf1xlm+0O9PRyZjQ0RR4DN5eHbB/XpQ
cL8hclsaK3V5tuek79JL1f9kOYhVeVi74G7uzTSYbCY3dJp+ftGCjDAirNEMaIGU
cEMgAgSqs/0h06VESwg2WRQZQ57GkbR1E2DQzuj9FG4TwSe700OoC9o3gqon4PHJ
/j9CM8kCgYEAtPJf3xaeqtbiVVzpPAGcuPyajTzU0QHPrXEl8zr/+iSK4Thc1K+c
b9sblB+ssEUQD5IQkhTWcsXdslINQeL77WhIMZ2vBAH8Hcin4jgcLmwUZfpfnnFs
QaChXiDsryJZwsRnruvMRX9nedtqHrgnIsJLTXjppIhGhq5Kg4RQfOU=
-----END RSA PRIVATE KEY-----
";
        decode_secret_key(key, None).unwrap();
    }

    #[cfg(feature = "rsa")]
    #[test]
    fn test_decode_pkcs8_rsa_secret_key() {
        // Generated using: ssh-keygen -t rsa -b 1024 -m pkcs8 -f $file
        let key = "-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDTwWfiCKHw/1F6
pvm6hZpFSjCVSu4Pp0/M4xT9Cec1+2uj/6uEE9Vh/UhlerkxVbrW/YaqjnlAiemZ
0RGN+sq7b8LxsgvOAo7gdBv13TLkKxNFiRbSy8S257uA9/K7G4Uw+NW22zoLSKCp
pdJOFzaYMIT/UX9EOq9hIIn4bS4nXJ4V5+aHBtMddHHDQPEDHBHuifpP2L4Wopzu
WoQoVtN9cwHSLh0Bd7uT+X9useIJrFzcsxVXwD2WGfR59Ue3rxRu6JqC46Klf55R
5NQ8OQ+7NHXjW5HO076W1GXcnhGKT5CGjglTdk5XxQkNZsz72cHu7RDaADdWAWnE
hSyH7flrAgMBAAECggEAbFdpCjn2eTJ4grOJ1AflTYxO3SOQN8wXxTFuHKUDehgg
E7GNFK99HnyTnPA0bmx5guQGEZ+BpCarsXpJbAYj0dC1wimhZo7igS6G272H+zua
yZoBZmrBQ/++bJbvxxGmjM7TsZHq2bkYEpR3zGKOGUHB2kvdPJB2CNC4JrXdxl7q
djjsr5f/SreDmHqcNBe1LcyWLSsuKTfwTKhsE1qEe6QA2uOpUuFrsdPoeYrfgapu
sK6qnpxvOTJHCN/9jjetrP2fGl78FMBYfXzjAyKSKzLvzOwMAmcHxy50RgUvezx7
A1RwMpB7VoV0MOpcAjlQ1T7YDH9avdPMzp0EZ24y+QKBgQD/MxDJjHu33w13MnIg
R4BrgXvrgL89Zde5tML2/U9C2LRvFjbBvgnYdqLsuqxDxGY/8XerrAkubi7Fx7QI
m2uvTOZF915UT/64T35zk8nAAFhzicCosVCnBEySvdwaaBKoj/ywemGrwoyprgFe
r8LGSo42uJi0zNf5IxmVzrDlRwKBgQDUa3P/+GxgpUYnmlt63/7sII6HDssdTHa9
x5uPy8/2ackNR7FruEAJR1jz6akvKnvtbCBeRxLeOFwsseFta8rb2vks7a/3I8ph
gJlbw5Bttpc+QsNgC61TdSKVsfWWae+YT77cfGPM4RaLlxRnccW1/HZjP2AMiDYG
WCiluO+svQKBgQC3a/yk4FQL1EXZZmigysOCgY6Ptfm+J3TmBQYcf/R4F0mYjl7M
4coxyxNPEty92Gulieh5ey0eMhNsFB1SEmNTm/HmV+V0tApgbsJ0T8SyO41Xfar7
lHZjlLN0xQFt+V9vyA3Wyh9pVGvFiUtywuE7pFqS+hrH2HNindfF1MlQAQKBgQDF
YxBIxKzY5duaA2qMdMcq3lnzEIEXua0BTxGz/n1CCizkZUFtyqnetWjoRrGK/Zxp
FDfDw6G50397nNPQXQEFaaZv5HLGYYC3N8vKJKD6AljqZxmsD03BprA7kEGYwtn8
m+XMdt46TNMpZXt1YJiLMo1ETmjPXGdvX85tqLs2tQKBgQDCbwd+OBzSiic3IQlD
E/OHAXH6HNHmUL3VD5IiRh4At2VAIl8JsmafUvvbtr5dfT3PA8HB6sDG4iXQsBbR
oTSAo/DtIWt1SllGx6MvcPqL1hp1UWfoIGTnE3unHtgPId+DnjMbTcuZOuGl7evf
abw8VeY2goORjpBXsfydBETbgQ==
-----END PRIVATE KEY-----
";
        assert!(decode_secret_key(key, None).unwrap().algorithm().is_rsa());
        test_decode_encode_symmetry(key);
    }

    #[test]
    fn test_decode_pkcs8_p256_secret_key() {
        // Generated using: ssh-keygen -t ecdsa -b 256 -m pkcs8 -f $file
        let key = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgE0C7/pyJDcZTAgWo
ydj6EE8QkZ91jtGoGmdYAVd7LaqhRANCAATWkGOof7R/PAUuOr2+ZPUgB8rGVvgr
qa92U3p4fkJToKXku5eq/32OBj23YMtz76jO3yfMbtG3l1JWLowPA8tV
-----END PRIVATE KEY-----
";
        assert!(
            decode_secret_key(key, None).unwrap().algorithm()
                == ssh_key::Algorithm::Ecdsa {
                    curve: ssh_key::EcdsaCurve::NistP256
                },
        );
        test_decode_encode_symmetry(key);
    }

    #[test]
    fn test_decode_pkcs8_p384_secret_key() {
        // Generated using: ssh-keygen -t ecdsa -b 384 -m pkcs8 -f $file
        let key = "-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCaqAL30kg+T5BUOYG9
MrzeDXiUwy9LM8qJGNXiMYou0pVjFZPZT3jAsrUQo47PLQ6hZANiAARuEHbXJBYK
9uyJj4PjT56OHjT2GqMa6i+FTG9vdLtu4OLUkXku+kOuFNjKvEI1JYBrJTpw9kSZ
CI3WfCsQvVjoC7m8qRyxuvR3Rv8gGXR1coQciIoCurLnn9zOFvXCS2Y=
-----END PRIVATE KEY-----
";
        assert!(
            decode_secret_key(key, None).unwrap().algorithm()
                == ssh_key::Algorithm::Ecdsa {
                    curve: ssh_key::EcdsaCurve::NistP384
                },
        );
        test_decode_encode_symmetry(key);
    }

    #[test]
    fn test_decode_pkcs8_p521_secret_key() {
        // Generated using: ssh-keygen -t ecdsa -b 521 -m pkcs8 -f $file
        let key = "-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIB1As9UBUsCiMK7Rzs
EoMgqDM/TK7y7+HgCWzw5UujXvSXCzYCeBgfJszn7dVoJE9G/1ejmpnVTnypdKEu
iIvd4LyhgYkDgYYABAADBCrg7hkomJbCsPMuMcq68ulmo/6Tv8BDS13F8T14v5RN
/0iT/+nwp6CnbBFewMI2TOh/UZNyPpQ8wOFNn9zBmAFCMzkQibnSWK0hrRstY5LT
iaOYDwInbFDsHu8j3TGs29KxyVXMexeV6ROQyXzjVC/quT1R5cOQ7EadE4HvaWhT
Ow==
-----END PRIVATE KEY-----
";
        assert!(
            decode_secret_key(key, None).unwrap().algorithm()
                == ssh_key::Algorithm::Ecdsa {
                    curve: ssh_key::EcdsaCurve::NistP521
                },
        );
        test_decode_encode_symmetry(key);
    }

    fn test_decode_encode_symmetry(key: &str) {
        let original_key_bytes = data_encoding::BASE64_MIME
            .decode(
                key.lines()
                    .filter(|line| !line.starts_with("-----"))
                    .collect::<Vec<&str>>()
                    .join("")
                    .as_bytes(),
            )
            .unwrap();
        let decoded_key = decode_secret_key(key, None).unwrap();
        let encoded_key_bytes = pkcs8::encode_pkcs8(&decoded_key).unwrap();
        assert_eq!(original_key_bytes, encoded_key_bytes);
    }

    #[cfg(feature = "rsa")]
    #[test]
    fn test_o01eg() {
        env_logger::try_init().unwrap_or(());

        let key = "-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,EA77308AAF46981303D8C44D548D097E

QR18hXmAgGehm1QMMYGF34PAtBpTj+8/ZPFx2zZxir7pzDpfYoNAIf/fzLsW1ruG
0xo/ZK/T3/TpMgjmLsCR6q+KU4jmCcCqWQIGWYJt9ljFI5y/CXr5uqP3DKcqtdxQ
fbBAfXJ8ITF+Tj0Cljm2S1KYHor+mkil5Lf/ZNiHxcLfoI3xRnpd+2cemN9Ly9eY
HNTbeWbLosfjwdfPJNWFNV5flm/j49klx/UhXhr5HNFNgp/MlTrvkH4rBt4wYPpE
cZBykt4Fo1KGl95pT22inGxQEXVHF1Cfzrf5doYWxjiRTmfhpPSz/Tt0ev3+jIb8
Htx6N8tNBoVxwCiQb7jj3XNim2OGohIp5vgW9sh6RDfIvr1jphVOgCTFKSo37xk0
156EoCVo3VcLf+p0/QitbUHR+RGW/PvUJV/wFR5ShYqjI+N2iPhkD24kftJ/MjPt
AAwCm/GYoYjGDhIzQMB+FETZKU5kz23MQtZFbYjzkcI/RE87c4fkToekNCdQrsoZ
wG0Ne2CxrwwEnipHCqT4qY+lZB9EbqQgbWOXJgxA7lfznBFjdSX7uDc/mnIt9Y6B
MZRXH3PTfotHlHMe+Ypt5lfPBi/nruOl5wLo3L4kY5pUyqR0cXKNycIJZb/pJAnE
ryIb59pZP7njvoHzRqnC9dycnTFW3geK5LU+4+JMUS32F636aorunRCl6IBmVQHL
uZ+ue714fn/Sn6H4dw6IH1HMDG1hr8ozP4sNUCiAQ05LsjDMGTdrUsr2iBBpkQhu
VhUDZy9g/5XF1EgiMbZahmqi5WaJ5K75ToINHb7RjOE7MEiuZ+RPpmYLE0HXyn9X
HTx0ZGr022dDI6nkvUm6OvEwLUUmmGKRHKe0y1EdICGNV+HWqnlhGDbLWeMyUcIY
M6Zh9Dw3WXD3kROf5MrJ6n9MDIXx9jy7nmBh7m6zKjBVIw94TE0dsRcWb0O1IoqS
zLQ6ihno+KsQHDyMVLEUz1TuE52rIpBmqexDm3PdDfCgsNdBKP6QSTcoqcfHKeex
K93FWgSlvFFQQAkJumJJ+B7ZWnK+2pdjdtWwTpflAKNqc8t//WmjWZzCtbhTHCXV
1dnMk7azWltBAuXnjW+OqmuAzyh3ayKgqfW66mzSuyQNa1KqFhqpJxOG7IHvxVfQ
kYeSpqODnL87Zd/dU8s0lOxz3/ymtjPMHlOZ/nHNqW90IIeUwWJKJ46Kv6zXqM1t
MeD1lvysBbU9rmcUdop0D3MOgGpKkinR5gy4pUsARBiz4WhIm8muZFIObWes/GDS
zmmkQRO1IcfXKAHbq/OdwbLBm4vM9nk8vPfszoEQCnfOSd7aWrLRjDR+q2RnzNzh
K+fodaJ864JFIfB/A+aVviVWvBSt0eEbEawhTmNPerMrAQ8tRRhmNxqlDP4gOczi
iKUmK5recsXk5us5Ik7peIR/f9GAghpoJkF0HrHio47SfABuK30pzcj62uNWGljS
3d9UQLCepT6RiPFhks/lgimbtSoiJHql1H9Q/3q4MuO2PuG7FXzlTnui3zGw/Vvy
br8gXU8KyiY9sZVbmplRPF+ar462zcI2kt0a18mr0vbrdqp2eMjb37QDbVBJ+rPE
-----END RSA PRIVATE KEY-----
";
        decode_secret_key(key, Some("12345")).unwrap();
    }

    #[cfg(feature = "rsa")]
    pub const PKCS8_RSA: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAwBGetHjW+3bDQpVktdemnk7JXgu1NBWUM+ysifYLDBvJ9ttX
GNZSyQKA4v/dNr0FhAJ8I9BuOTjYCy1YfKylhl5D/DiSSXFPsQzERMmGgAlYvU2U
+FTxpBC11EZg69CPVMKKevfoUD+PZA5zB7Hc1dXFfwqFc5249SdbAwD39VTbrOUI
WECvWZs6/ucQxHHXP2O9qxWqhzb/ddOnqsDHUNoeceiNiCf2anNymovrIMjAqq1R
t2UP3f06/Zt7Jx5AxKqS4seFkaDlMAK8JkEDuMDOdKI36raHkKanfx8CnGMSNjFQ
QtvnpD8VSGkDTJN3Qs14vj2wvS477BQXkBKN1QIDAQABAoIBABb6xLMw9f+2ENyJ
hTggagXsxTjkS7TElCu2OFp1PpMfTAWl7oDBO7xi+UqvdCcVbHCD35hlWpqsC2Ui
8sBP46n040ts9UumK/Ox5FWaiuYMuDpF6vnfJ94KRcb0+KmeFVf9wpW9zWS0hhJh
jC+yfwpyfiOZ/ad8imGCaOguGHyYiiwbRf381T/1FlaOGSae88h+O8SKTG1Oahq4
0HZ/KBQf9pij0mfVQhYBzsNu2JsHNx9+DwJkrXT7K9SHBpiBAKisTTCnQmS89GtE
6J2+bq96WgugiM7X6OPnmBmE/q1TgV18OhT+rlvvNi5/n8Z1ag5Xlg1Rtq/bxByP
CeIVHsECgYEA9dX+LQdv/Mg/VGIos2LbpJUhJDj0XWnTRq9Kk2tVzr+9aL5VikEb
09UPIEa2ToL6LjlkDOnyqIMd/WY1W0+9Zf1ttg43S/6Rvv1W8YQde0Nc7QTcuZ1K
9jSSP9hzsa3KZtx0fCtvVHm+ac9fP6u80tqumbiD2F0cnCZcSxOb4+UCgYEAyAKJ
70nNKegH4rTCStAqR7WGAsdPE3hBsC814jguplCpb4TwID+U78Xxu0DQF8WtVJ10
SJuR0R2q4L9uYWpo0MxdawSK5s9Am27MtJL0mkFQX0QiM7hSZ3oqimsdUdXwxCGg
oktxCUUHDIPJNVd4Xjg0JTh4UZT6WK9hl1zLQzECgYEAiZRCFGc2KCzVLF9m0cXA
kGIZUxFAyMqBv+w3+zq1oegyk1z5uE7pyOpS9cg9HME2TAo4UPXYpLAEZ5z8vWZp
45sp/BoGnlQQsudK8gzzBtnTNp5i/MnnetQ/CNYVIVnWjSxRUHBqdMdRZhv0/Uga
e5KA5myZ9MtfSJA7VJTbyHUCgYBCcS13M1IXaMAt3JRqm+pftfqVs7YeJqXTrGs/
AiDlGQigRk4quFR2rpAV/3rhWsawxDmb4So4iJ16Wb2GWP4G1sz1vyWRdSnmOJGC
LwtYrvfPHegqvEGLpHa7UsgDpol77hvZriwXwzmLO8A8mxkeW5dfAfpeR5o+mcxW
pvnTEQKBgQCKx6Ln0ku6jDyuDzA9xV2/PET5D75X61R2yhdxi8zurY/5Qon3OWzk
jn/nHT3AZghGngOnzyv9wPMKt9BTHyTB6DlB6bRVLDkmNqZh5Wi8U1/IjyNYI0t2
xV/JrzLAwPoKk3bkqys3bUmgo6DxVC/6RmMwPQ0rmpw78kOgEej90g==
-----END RSA PRIVATE KEY-----
";

    #[cfg(feature = "rsa")]
    #[test]
    fn test_pkcs8() {
        env_logger::try_init().unwrap_or(());
        println!("test");
        decode_secret_key(PKCS8_RSA, Some("blabla")).unwrap();
    }

    #[cfg(feature = "rsa")]
    const PKCS8_ENCRYPTED: &str = "-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQITo1O0b8YrS0CAggA
MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBBtLH4T1KOfo1GGr7salhR8BIIE
0KN9ednYwcTGSX3hg7fROhTw7JAJ1D4IdT1fsoGeNu2BFuIgF3cthGHe6S5zceI2
MpkfwvHbsOlDFWMUIAb/VY8/iYxhNmd5J6NStMYRC9NC0fVzOmrJqE1wITqxtORx
IkzqkgFUbaaiFFQPepsh5CvQfAgGEWV329SsTOKIgyTj97RxfZIKA+TR5J5g2dJY
j346SvHhSxJ4Jc0asccgMb0HGh9UUDzDSql0OIdbnZW5KzYJPOx+aDqnpbz7UzY/
P8N0w/pEiGmkdkNyvGsdttcjFpOWlLnLDhtLx8dDwi/sbEYHtpMzsYC9jPn3hnds
TcotqjoSZ31O6rJD4z18FOQb4iZs3MohwEdDd9XKblTfYKM62aQJWH6cVQcg+1C7
jX9l2wmyK26Tkkl5Qg/qSfzrCveke5muZgZkFwL0GCcgPJ8RixSB4GOdSMa/hAMU
kvFAtoV2GluIgmSe1pG5cNMhurxM1dPPf4WnD+9hkFFSsMkTAuxDZIdDk3FA8zof
Yhv0ZTfvT6V+vgH3Hv7Tqcxomy5Qr3tj5vvAqqDU6k7fC4FvkxDh2mG5ovWvc4Nb
Xv8sed0LGpYitIOMldu6650LoZAqJVv5N4cAA2Edqldf7S2Iz1QnA/usXkQd4tLa
Z80+sDNv9eCVkfaJ6kOVLk/ghLdXWJYRLenfQZtVUXrPkaPpNXgD0dlaTN8KuvML
Uw/UGa+4ybnPsdVflI0YkJKbxouhp4iB4S5ACAwqHVmsH5GRnujf10qLoS7RjDAl
o/wSHxdT9BECp7TT8ID65u2mlJvH13iJbktPczGXt07nBiBse6OxsClfBtHkRLzE
QF6UMEXsJnIIMRfrZQnduC8FUOkfPOSXc8r9SeZ3GhfbV/DmWZvFPCpjzKYPsM5+
N8Bw/iZ7NIH4xzNOgwdp5BzjH9hRtCt4sUKVVlWfEDtTnkHNOusQGKu7HkBF87YZ
RN/Nd3gvHob668JOcGchcOzcsqsgzhGMD8+G9T9oZkFCYtwUXQU2XjMN0R4VtQgZ
rAxWyQau9xXMGyDC67gQ5xSn+oqMK0HmoW8jh2LG/cUowHFAkUxdzGadnjGhMOI2
zwNJPIjF93eDF/+zW5E1l0iGdiYyHkJbWSvcCuvTwma9FIDB45vOh5mSR+YjjSM5
nq3THSWNi7Cxqz12Q1+i9pz92T2myYKBBtu1WDh+2KOn5DUkfEadY5SsIu/Rb7ub
5FBihk2RN3y/iZk+36I69HgGg1OElYjps3D+A9AjVby10zxxLAz8U28YqJZm4wA/
T0HLxBiVw+rsHmLP79KvsT2+b4Diqih+VTXouPWC/W+lELYKSlqnJCat77IxgM9e
YIhzD47OgWl33GJ/R10+RDoDvY4koYE+V5NLglEhbwjloo9Ryv5ywBJNS7mfXMsK
/uf+l2AscZTZ1mhtL38efTQCIRjyFHc3V31DI0UdETADi+/Omz+bXu0D5VvX+7c6
b1iVZKpJw8KUjzeUV8yOZhvGu3LrQbhkTPVYL555iP1KN0Eya88ra+FUKMwLgjYr
JkUx4iad4dTsGPodwEP/Y9oX/Qk3ZQr+REZ8lg6IBoKKqqrQeBJ9gkm1jfKE6Xkc
Cog3JMeTrb3LiPHgN6gU2P30MRp6L1j1J/MtlOAr5rux
-----END ENCRYPTED PRIVATE KEY-----";

    #[test]
    fn test_gpg() {
        env_logger::try_init().unwrap_or(());
        let key = [
            0, 0, 0, 7, 115, 115, 104, 45, 114, 115, 97, 0, 0, 0, 3, 1, 0, 1, 0, 0, 1, 129, 0, 163,
            72, 59, 242, 4, 248, 139, 217, 57, 126, 18, 195, 170, 3, 94, 154, 9, 150, 89, 171, 236,
            192, 178, 185, 149, 73, 210, 121, 95, 126, 225, 209, 199, 208, 89, 130, 175, 229, 163,
            102, 176, 155, 69, 199, 155, 71, 214, 170, 61, 202, 2, 207, 66, 198, 147, 65, 10, 176,
            20, 105, 197, 133, 101, 126, 193, 252, 245, 254, 182, 14, 250, 118, 113, 18, 220, 38,
            220, 75, 247, 50, 163, 39, 2, 61, 62, 28, 79, 199, 238, 189, 33, 194, 190, 22, 87, 91,
            1, 215, 115, 99, 138, 124, 197, 127, 237, 228, 170, 42, 25, 117, 1, 106, 36, 54, 163,
            163, 207, 129, 133, 133, 28, 185, 170, 217, 12, 37, 113, 181, 182, 180, 178, 23, 198,
            233, 31, 214, 226, 114, 146, 74, 205, 177, 82, 232, 238, 165, 44, 5, 250, 150, 236, 45,
            30, 189, 254, 118, 55, 154, 21, 20, 184, 235, 223, 5, 20, 132, 249, 147, 179, 88, 146,
            6, 100, 229, 200, 221, 157, 135, 203, 57, 204, 43, 27, 58, 85, 54, 219, 138, 18, 37,
            80, 106, 182, 95, 124, 140, 90, 29, 48, 193, 112, 19, 53, 84, 201, 153, 52, 249, 15,
            41, 5, 11, 147, 18, 8, 27, 31, 114, 45, 224, 118, 111, 176, 86, 88, 23, 150, 184, 252,
            128, 52, 228, 90, 30, 34, 135, 234, 123, 28, 239, 90, 202, 239, 188, 175, 8, 141, 80,
            59, 194, 80, 43, 205, 34, 137, 45, 140, 244, 181, 182, 229, 247, 94, 216, 115, 173,
            107, 184, 170, 102, 78, 249, 4, 186, 234, 169, 148, 98, 128, 33, 115, 232, 126, 84, 76,
            222, 145, 90, 58, 1, 4, 163, 243, 93, 215, 154, 205, 152, 178, 109, 241, 197, 82, 148,
            222, 78, 44, 193, 248, 212, 157, 118, 217, 75, 211, 23, 229, 121, 28, 180, 208, 173,
            204, 14, 111, 226, 25, 163, 220, 95, 78, 175, 189, 168, 67, 159, 179, 176, 200, 150,
            202, 248, 174, 109, 25, 89, 176, 220, 226, 208, 187, 84, 169, 157, 14, 88, 217, 221,
            117, 254, 51, 45, 93, 184, 80, 225, 158, 29, 76, 38, 69, 72, 71, 76, 50, 191, 210, 95,
            152, 175, 26, 207, 91, 7,
        ];
        ssh_key::PublicKey::decode(&key).unwrap();
    }

    #[cfg(feature = "rsa")]
    #[test]
    fn test_pkcs8_encrypted() {
        env_logger::try_init().unwrap_or(());
        println!("test");
        decode_secret_key(PKCS8_ENCRYPTED, Some("blabla")).unwrap();
    }

    #[cfg(unix)]
    async fn test_client_agent(key: PrivateKey) -> Result<(), Box<dyn std::error::Error>> {
        env_logger::try_init().unwrap_or(());
        use std::process::Stdio;

        let dir = tempfile::tempdir()?;
        let agent_path = dir.path().join("agent");
        let mut agent = tokio::process::Command::new("ssh-agent")
            .arg("-a")
            .arg(&agent_path)
            .arg("-D")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        // Wait for the socket to be created
        while agent_path.canonicalize().is_err() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let public = key.public_key();
        let stream = tokio::net::UnixStream::connect(&agent_path).await?;
        let mut client = agent::client::AgentClient::connect(stream);
        client.add_identity(&key, &[]).await?;
        client.request_identities().await?;
        let buf = b"blabla".to_vec();
        let len = buf.len();
        let buf = client
            .sign_request(
                &AgentIdentity::from(public.clone()),
                Some(HashAlg::Sha256),
                buf,
            )
            .await
            .unwrap();
        let (a, b) = buf.split_at(len);

        match key.public_key().key_data() {
            ssh_key::public::KeyData::Ed25519 { .. } => {
                let sig = &b[b.len() - 64..];
                let sig = ssh_key::Signature::new(key.algorithm(), sig)?;
                use signature::Verifier;
                assert!(Verifier::verify(public, a, &sig).is_ok());
            }
            ssh_key::public::KeyData::Ecdsa { .. } => {}
            _ => {}
        }

        agent.kill().await?;
        agent.wait().await?;

        Ok(())
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_client_agent_ed25519() {
        let key = decode_secret_key(ED25519_KEY, Some("blabla")).unwrap();
        test_client_agent(key).await.expect("ssh-agent test failed")
    }

    #[tokio::test]
    #[cfg(all(unix, feature = "rsa"))]
    async fn test_client_agent_rsa() {
        let key = decode_secret_key(PKCS8_ENCRYPTED, Some("blabla")).unwrap();
        test_client_agent(key).await.expect("ssh-agent test failed")
    }

    #[tokio::test]
    #[cfg(all(unix, feature = "rsa"))]
    async fn test_client_agent_openssh_rsa() {
        let key = decode_secret_key(RSA_KEY, None).unwrap();
        test_client_agent(key).await.expect("ssh-agent test failed")
    }

    #[test]
    #[cfg(all(unix, feature = "rsa"))]
    fn test_agent() {
        env_logger::try_init().unwrap_or(());
        let dir = tempfile::tempdir().unwrap();
        let agent_path = dir.path().join("agent");

        let core = tokio::runtime::Runtime::new().unwrap();
        use agent;
        use signature::Verifier;

        #[derive(Clone)]
        struct X {}
        impl agent::server::Agent for X {
            fn confirm(
                self,
                _: std::sync::Arc<PrivateKey>,
            ) -> Box<dyn Future<Output = (Self, bool)> + Send + Unpin> {
                Box::new(futures::future::ready((self, true)))
            }
        }
        let agent_path_ = agent_path.clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        core.spawn(async move {
            let mut listener = tokio::net::UnixListener::bind(&agent_path_).unwrap();
            let _ = tx.send(());
            agent::server::serve(
                Incoming {
                    listener: &mut listener,
                },
                X {},
            )
            .await
        });

        let key = decode_secret_key(PKCS8_ENCRYPTED, Some("blabla")).unwrap();
        core.block_on(async move {
            let public = key.public_key();
            // make sure the listener created the file handle
            rx.await.unwrap();
            let stream = tokio::net::UnixStream::connect(&agent_path).await.unwrap();
            let mut client = agent::client::AgentClient::connect(stream);
            client
                .add_identity(&key, &[agent::Constraint::KeyLifetime { seconds: 60 }])
                .await
                .unwrap();
            client.request_identities().await.unwrap();
            let buf = b"blabla".to_vec();
            let len = buf.len();
            let buf = client
                .sign_request(&AgentIdentity::from(public.clone()), None, buf)
                .await
                .unwrap();
            let (a, b) = buf.split_at(len);
            if let ssh_key::public::KeyData::Ed25519 { .. } = public.key_data() {
                let sig = &b[b.len() - 64..];
                let sig = ssh_key::Signature::new(key.algorithm(), sig).unwrap();
                assert!(Verifier::verify(public, a, &sig).is_ok());
            }
        })
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_agent_rejects_duplicate_lifetime() {
        #[derive(Clone)]
        struct X {}
        impl agent::server::Agent for X {}

        let dir = tempfile::tempdir().unwrap();
        let agent_path = dir.path().join("agent");
        let mut listener = tokio::net::UnixListener::bind(&agent_path).unwrap();
        tokio::spawn(async move {
            agent::server::serve(
                Incoming {
                    listener: &mut listener,
                },
                X {},
            )
            .await
        });

        let key = decode_secret_key(ED25519_KEY, Some("blabla")).unwrap();
        let stream = tokio::net::UnixStream::connect(&agent_path).await.unwrap();
        let mut client = agent::client::AgentClient::connect(stream);
        let lifetime = || agent::Constraint::KeyLifetime { seconds: 60 };
        assert!(client
            .add_identity(&key, &[lifetime(), lifetime()])
            .await
            .is_err());
        assert!(client.request_identities().await.unwrap().is_empty());
        client.add_identity(&key, &[lifetime()]).await.unwrap();
        assert_eq!(client.request_identities().await.unwrap().len(), 1);
    }

    #[tokio::test]
    #[cfg(all(unix, feature = "rsa"))]
    async fn test_agent_sign_honors_rsa_hash_flags() {
        use signature::Verifier;

        #[derive(Clone)]
        struct X {}
        impl agent::server::Agent for X {}

        let dir = tempfile::tempdir().unwrap();
        let agent_path = dir.path().join("agent");
        let mut listener = tokio::net::UnixListener::bind(&agent_path).unwrap();
        tokio::spawn(async move {
            agent::server::serve(
                Incoming {
                    listener: &mut listener,
                },
                X {},
            )
            .await
        });

        let stream = tokio::net::UnixStream::connect(&agent_path).await.unwrap();
        let mut client = agent::client::AgentClient::connect(stream);

        let rsa = decode_secret_key(RSA_KEY, None).unwrap();
        let ed25519 = decode_secret_key(ED25519_KEY, Some("blabla")).unwrap();
        client.add_identity(&rsa, &[]).await.unwrap();
        client.add_identity(&ed25519, &[]).await.unwrap();

        let data = b"blabla";
        for (hash_alg, expected) in [
            (Some(HashAlg::Sha256), "rsa-sha2-256"),
            (Some(HashAlg::Sha512), "rsa-sha2-512"),
            (None, "ssh-rsa"),
        ] {
            let sig = client
                .sign_request_signature(rsa.public_key(), hash_alg, data)
                .await
                .unwrap();
            assert_eq!(sig.algorithm().as_str(), expected);
            assert!(Verifier::verify(rsa.public_key(), data, &sig).is_ok());
        }

        for hash_alg in [Some(HashAlg::Sha256), Some(HashAlg::Sha512), None] {
            let sig = client
                .sign_request_signature(ed25519.public_key(), hash_alg, data)
                .await
                .unwrap();
            assert_eq!(sig.algorithm(), Algorithm::Ed25519);
            assert!(Verifier::verify(ed25519.public_key(), data, &sig).is_ok());
        }
    }

    #[cfg(unix)]
    struct Incoming<'a> {
        listener: &'a mut tokio::net::UnixListener,
    }

    #[cfg(unix)]
    impl futures::stream::Stream for Incoming<'_> {
        type Item = Result<tokio::net::UnixStream, std::io::Error>;

        fn poll_next(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            let (sock, _addr) = futures::ready!(self.get_mut().listener.poll_accept(cx))?;
            std::task::Poll::Ready(Some(Ok(sock)))
        }
    }

    /// Helper to spawn an ssh-agent and return the agent process and socket path
    #[cfg(unix)]
    async fn spawn_agent() -> Result<
        (tokio::process::Child, std::path::PathBuf, tempfile::TempDir),
        Box<dyn std::error::Error>,
    > {
        use std::process::Stdio;

        let dir = tempfile::tempdir()?;
        let agent_path = dir.path().join("agent");
        let agent = tokio::process::Command::new("ssh-agent")
            .arg("-a")
            .arg(&agent_path)
            .arg("-D")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        // Wait for the socket to be created
        while agent_path.canonicalize().is_err() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        Ok((agent, agent_path, dir))
    }

    /// Helper to create a test certificate
    #[cfg(unix)]
    fn create_test_cert(ca_key: &PrivateKey, user_key: &PrivateKey) -> ssh_key::Certificate {
        use ssh_key::certificate;
                use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let valid_after = now - 3600; // 1 hour ago
        let valid_before = now + 86400 * 365; // 1 year from now

        let mut builder = certificate::Builder::new_with_random_nonce(
            &mut rand::rng(),
            user_key.public_key(),
            valid_after,
            valid_before,
        )
        .unwrap();

        builder.serial(1).unwrap();
        builder.key_id("test-cert").unwrap();
        builder.cert_type(certificate::CertType::User).unwrap();
        builder.valid_principal("testuser").unwrap();
        builder.sign(ca_key).unwrap()
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_request_identities_full_with_keys_and_certs() {
        use crate::keys::agent::{AgentIdentity, client::AgentClient};
                use std::io::Write;
        use std::process::Stdio;

        env_logger::try_init().unwrap_or(());

        let (mut agent, agent_path, dir) = spawn_agent().await.unwrap();

        // Create a CA key and user key
        let ca_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let user_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let plain_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();

        // Create a certificate
        let cert = create_test_cert(&ca_key, &user_key);

        // Write the keys and certificate to temp files
        let user_key_path = dir.path().join("user_key");
        let cert_path = dir.path().join("user_key-cert.pub");
        let plain_key_path = dir.path().join("plain_key");

        // Write user key (the one to be certified)
        let mut f = std::fs::File::create(&user_key_path).unwrap();
        f.write_all(
            user_key
                .to_openssh(ssh_key::LineEnding::LF)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        std::fs::set_permissions(
            &user_key_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();

        // Write certificate
        let mut f = std::fs::File::create(&cert_path).unwrap();
        f.write_all(cert.to_openssh().unwrap().as_bytes()).unwrap();

        // Write plain key
        let mut f = std::fs::File::create(&plain_key_path).unwrap();
        f.write_all(
            plain_key
                .to_openssh(ssh_key::LineEnding::LF)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        std::fs::set_permissions(
            &plain_key_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();

        // Use ssh-add to add the certificate (it will pick up user_key-cert.pub automatically)
        let status = tokio::process::Command::new("ssh-add")
            .arg(&user_key_path)
            .env("SSH_AUTH_SOCK", &agent_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .unwrap();
        assert!(status.success(), "ssh-add for certificate failed");

        // Add plain key
        let status = tokio::process::Command::new("ssh-add")
            .arg(&plain_key_path)
            .env("SSH_AUTH_SOCK", &agent_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .unwrap();
        assert!(status.success(), "ssh-add for plain key failed");

        // Connect to agent and test request_identities_full
        let stream = tokio::net::UnixStream::connect(&agent_path).await.unwrap();
        let mut client = AgentClient::connect(stream);

        let identities = client.request_identities().await.unwrap();

        // ssh-add with a certificate adds the cert identity, and the plain key adds another
        // The exact count depends on ssh-agent behavior - just verify we have both types
        assert!(!identities.is_empty(), "Expected at least one identity");

        // Count the types
        let mut key_count = 0;
        let mut cert_count = 0;

        for identity in &identities {
            match identity {
                AgentIdentity::PublicKey { .. } => key_count += 1,
                AgentIdentity::Certificate { certificate: c, .. } => {
                    cert_count += 1;
                    // Verify the certificate matches what we created
                    assert_eq!(c.key_id(), "test-cert");
                    // Verify public_key() works
                    let pk = identity.public_key();
                    assert_eq!(pk.key_data(), c.public_key());
                }
            }
            // Verify comment() works
            let _ = identity.comment();
        }

        // We should have at least one of each (ssh-add may add both key and cert for the same identity)
        assert!(
            key_count >= 1,
            "Expected at least 1 public key, got {}",
            key_count
        );
        assert!(
            cert_count >= 1,
            "Expected at least 1 certificate, got {}",
            cert_count
        );

        agent.kill().await.unwrap();
        agent.wait().await.unwrap();
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_sign_request_cert() {
        use crate::keys::agent::client::AgentClient;
                use std::io::Write;
        use std::process::Stdio;

        env_logger::try_init().unwrap_or(());

        let (mut agent, agent_path, dir) = spawn_agent().await.unwrap();

        // Create a CA key and user key
        let ca_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let user_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();

        // Create a certificate
        let cert = create_test_cert(&ca_key, &user_key);

        // Write the key and certificate to temp files
        let user_key_path = dir.path().join("user_key");
        let cert_path = dir.path().join("user_key-cert.pub");

        let mut f = std::fs::File::create(&user_key_path).unwrap();
        f.write_all(
            user_key
                .to_openssh(ssh_key::LineEnding::LF)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        std::fs::set_permissions(
            &user_key_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();

        let mut f = std::fs::File::create(&cert_path).unwrap();
        f.write_all(cert.to_openssh().unwrap().as_bytes()).unwrap();

        // Use ssh-add to add the certificate
        let status = tokio::process::Command::new("ssh-add")
            .arg(&user_key_path)
            .env("SSH_AUTH_SOCK", &agent_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .unwrap();
        assert!(status.success(), "ssh-add failed");

        // Connect to agent and test sign_request_cert
        let stream = tokio::net::UnixStream::connect(&agent_path).await.unwrap();
        let mut client = AgentClient::connect(stream);

        // Create data to sign
        let data_to_sign = b"test data to sign";
        let buf = data_to_sign.to_vec();
        let len = buf.len();

        // Sign using the certificate (None for hash_alg since Ed25519 doesn't need it)
        let signed_buf = client.sign_request(&cert.into(), None, buf).await.unwrap();

        // Verify the signature is appended to the original data
        assert!(signed_buf.len() > len, "Signed buffer should be larger");

        // Extract and verify signature
        let (original, sig_data) = signed_buf.split_at(len);
        assert_eq!(original, data_to_sign);

        // The signature should be valid
        // For ed25519, signature is 64 bytes, but encoded with type prefix
        assert!(sig_data.len() > 64, "Signature data should include type");

        agent.kill().await.unwrap();
        agent.wait().await.unwrap();
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_sign_request_cert_missing_key_returns_agent_failure() {
        use crate::keys::agent::client::AgentClient;

        env_logger::try_init().unwrap_or(());

        let (mut agent, agent_path, _dir) = spawn_agent().await.unwrap();

        // Create a CA key and user key, but DON'T add them to the agent
        let ca_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let user_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();

        // Create a certificate
        let cert = create_test_cert(&ca_key, &user_key);

        // Connect to agent WITHOUT adding any keys
        let stream = tokio::net::UnixStream::connect(&agent_path).await.unwrap();
        let mut client = AgentClient::connect(stream);

        // Verify the agent has no keys
        let identities = client.request_identities().await.unwrap();
        assert!(identities.is_empty(), "Agent should have no keys");

        // Create data to sign
        let data_to_sign = b"test data to sign";
        let buf = data_to_sign.to_vec();

        // Try to sign using the certificate - should fail because the key isn't in the agent
        let result = client.sign_request(&cert.into(), None, buf).await;

        // Verify we get an AgentFailure error
        assert!(
            result.is_err(),
            "Signing should fail when key is not in agent"
        );
        match result {
            Err(Error::AgentFailure) => {
                // This is the expected error
            }
            Err(e) => {
                panic!("Expected AgentFailure error, got: {:?}", e);
            }
            Ok(_) => {
                panic!("Expected error, but signing succeeded");
            }
        }

        agent.kill().await.unwrap();
        agent.wait().await.unwrap();
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_sign_request_missing_key_returns_agent_failure() {
        use crate::keys::agent::client::AgentClient;

        env_logger::try_init().unwrap_or(());

        let (mut agent, agent_path, _dir) = spawn_agent().await.unwrap();

        // Create a key but DON'T add it to the agent
        let key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();

        // Connect to agent WITHOUT adding any keys
        let stream = tokio::net::UnixStream::connect(&agent_path).await.unwrap();
        let mut client = AgentClient::connect(stream);

        // Verify the agent has no keys
        let identities = client.request_identities().await.unwrap();
        assert!(identities.is_empty(), "Agent should have no keys");

        // Create data to sign
        let data_to_sign = b"test data to sign";
        let buf = data_to_sign.to_vec();

        // Try to sign using the public key - should fail because the key isn't in the agent
        let result = client
            .sign_request(&key.public_key().clone().into(), None, buf)
            .await;

        // Verify we get an AgentFailure error
        assert!(
            result.is_err(),
            "Signing should fail when key is not in agent"
        );
        match result {
            Err(Error::AgentFailure) => {
                // This is the expected error
            }
            Err(e) => {
                panic!("Expected AgentFailure error, got: {:?}", e);
            }
            Ok(_) => {
                panic!("Expected error, but signing succeeded");
            }
        }

        agent.kill().await.unwrap();
        agent.wait().await.unwrap();
    }

    /// Helper to create a test RSA certificate
    #[cfg(all(unix, feature = "rsa"))]
    fn create_test_rsa_cert(ca_key: &PrivateKey, user_key: &PrivateKey) -> ssh_key::Certificate {
        use ssh_key::certificate;
                use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let valid_after = now - 3600; // 1 hour ago
        let valid_before = now + 86400 * 365; // 1 year from now

        let mut builder = certificate::Builder::new_with_random_nonce(
            &mut rand::rng(),
            user_key.public_key(),
            valid_after,
            valid_before,
        )
        .unwrap();

        builder.serial(1).unwrap();
        builder.key_id("test-rsa-cert").unwrap();
        builder.cert_type(certificate::CertType::User).unwrap();
        builder.valid_principal("testuser").unwrap();
        builder.sign(ca_key).unwrap()
    }

    #[tokio::test]
    #[cfg(all(unix, feature = "rsa"))]
    async fn test_sign_request_cert_rsa() {
        use crate::keys::agent::client::AgentClient;
                use std::io::Write;
        use std::process::Stdio;

        env_logger::try_init().unwrap_or(());

        let (mut agent, agent_path, dir) = spawn_agent().await.unwrap();

        // Create RSA CA key and user key
        let ca_key = PrivateKey::random(
            &mut rand::rng(),
            ssh_key::Algorithm::Rsa {
                hash: Some(HashAlg::Sha256),
            },
        )
        .unwrap();
        let user_key = PrivateKey::random(
            &mut rand::rng(),
            ssh_key::Algorithm::Rsa {
                hash: Some(HashAlg::Sha256),
            },
        )
        .unwrap();

        // Create a certificate
        let cert = create_test_rsa_cert(&ca_key, &user_key);

        // Write the key and certificate to temp files
        let user_key_path = dir.path().join("user_rsa_key");
        let cert_path = dir.path().join("user_rsa_key-cert.pub");

        let mut f = std::fs::File::create(&user_key_path).unwrap();
        f.write_all(
            user_key
                .to_openssh(ssh_key::LineEnding::LF)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        std::fs::set_permissions(
            &user_key_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();

        let mut f = std::fs::File::create(&cert_path).unwrap();
        f.write_all(cert.to_openssh().unwrap().as_bytes()).unwrap();

        // Use ssh-add to add the certificate
        let status = tokio::process::Command::new("ssh-add")
            .arg(&user_key_path)
            .env("SSH_AUTH_SOCK", &agent_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .unwrap();
        assert!(status.success(), "ssh-add failed");

        // Connect to agent and test sign_request_cert
        let stream = tokio::net::UnixStream::connect(&agent_path).await.unwrap();
        let mut client = AgentClient::connect(stream);

        // Create data to sign
        let data_to_sign = b"test data to sign with RSA cert";
        let buf = data_to_sign.to_vec();
        let len = buf.len();

        // Sign using the certificate with SHA-256 hash algorithm
        let signed_buf = client
            .sign_request(&cert.into(), Some(HashAlg::Sha256), buf)
            .await
            .unwrap();

        // Verify the signature is appended to the original data
        assert!(signed_buf.len() > len, "Signed buffer should be larger");

        // Extract and verify signature
        let (original, sig_data) = signed_buf.split_at(len);
        assert_eq!(original, data_to_sign);

        // The RSA signature should be substantial
        assert!(
            sig_data.len() > 100,
            "RSA signature data should be substantial"
        );

        agent.kill().await.unwrap();
        agent.wait().await.unwrap();
    }

    #[tokio::test]
    #[cfg(all(unix, feature = "rsa"))]
    async fn test_sign_request_cert_rsa_sha512() {
        use crate::keys::agent::client::AgentClient;
                use std::io::Write;
        use std::process::Stdio;

        env_logger::try_init().unwrap_or(());

        let (mut agent, agent_path, dir) = spawn_agent().await.unwrap();

        // Create RSA CA key and user key
        let ca_key = PrivateKey::random(
            &mut rand::rng(),
            ssh_key::Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            },
        )
        .unwrap();
        let user_key = PrivateKey::random(
            &mut rand::rng(),
            ssh_key::Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            },
        )
        .unwrap();

        // Create a certificate
        let cert = create_test_rsa_cert(&ca_key, &user_key);

        // Write the key and certificate to temp files
        let user_key_path = dir.path().join("user_rsa_key");
        let cert_path = dir.path().join("user_rsa_key-cert.pub");

        let mut f = std::fs::File::create(&user_key_path).unwrap();
        f.write_all(
            user_key
                .to_openssh(ssh_key::LineEnding::LF)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        std::fs::set_permissions(
            &user_key_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();

        let mut f = std::fs::File::create(&cert_path).unwrap();
        f.write_all(cert.to_openssh().unwrap().as_bytes()).unwrap();

        // Use ssh-add to add the certificate
        let status = tokio::process::Command::new("ssh-add")
            .arg(&user_key_path)
            .env("SSH_AUTH_SOCK", &agent_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .unwrap();
        assert!(status.success(), "ssh-add failed");

        // Connect to agent and test sign_request_cert with SHA-512
        let stream = tokio::net::UnixStream::connect(&agent_path).await.unwrap();
        let mut client = AgentClient::connect(stream);

        // Create data to sign
        let data_to_sign = b"test data to sign with RSA cert SHA-512";
        let buf = data_to_sign.to_vec();
        let len = buf.len();

        // Sign using the certificate with SHA-512 hash algorithm
        let signed_buf = client
            .sign_request(&cert.into(), Some(HashAlg::Sha512), buf)
            .await
            .unwrap();

        // Verify the signature is appended to the original data
        assert!(signed_buf.len() > len, "Signed buffer should be larger");

        // Extract and verify signature
        let (original, sig_data) = signed_buf.split_at(len);
        assert_eq!(original, data_to_sign);

        // The RSA signature should be substantial
        assert!(
            sig_data.len() > 100,
            "RSA signature data should be substantial"
        );

        agent.kill().await.unwrap();
        agent.wait().await.unwrap();
    }
}
