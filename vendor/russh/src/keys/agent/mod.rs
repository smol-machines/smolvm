use std::borrow::Cow;

use russh_cryptovec::CryptoVec;
use ssh_key::{Certificate, PublicKey};

/// Cryptographic context that binds an SSH agent to one server connection.
///
/// OpenSSH agents use this context to enforce destination constraints. It is
/// produced by the client key exchange and can be sent to an agent with
/// [`client::AgentClient::bind_session`].
#[derive(Debug, Clone)]
pub struct AgentSessionBinding {
    pub(crate) host_key: Vec<u8>,
    pub(crate) session_id: CryptoVec,
    pub(crate) signature: Vec<u8>,
}

impl AgentSessionBinding {
    pub(crate) fn new(host_key: Vec<u8>, session_id: CryptoVec, signature: Vec<u8>) -> Self {
        Self {
            host_key,
            session_id,
            signature,
        }
    }

    pub fn host_key(&self) -> &[u8] {
        &self.host_key[..]
    }

    pub fn session_id(&self) -> &CryptoVec {
        &self.session_id
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature[..]
    }
}

/// Write clients for SSH agents.
pub mod client;
mod msg;
/// Write servers for SSH agents.
pub mod server;

/// Constraints on how keys can be used
#[derive(Debug, PartialEq, Eq)]
pub enum Constraint {
    /// The key shall disappear from the agent's memory after that many seconds.
    KeyLifetime { seconds: u32 },
    /// Signatures need to be confirmed by the agent (for instance using a dialog).
    Confirm,
    /// Custom constraints
    Extensions { name: Vec<u8>, details: Vec<u8> },
}

/// An identity held by an SSH agent, which may be either a plain public key
/// or an OpenSSH certificate.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum AgentIdentity {
    /// A plain public key
    PublicKey {
        /// The public key
        key: PublicKey,
        /// Comment associated with this identity
        comment: String,
    },
    /// An OpenSSH certificate
    Certificate {
        /// The certificate (contains public key plus CA signature, principals, validity, etc.)
        certificate: Certificate,
        /// Comment associated with this identity
        comment: String,
    },
}

impl From<PublicKey> for AgentIdentity {
    fn from(key: PublicKey) -> Self {
        Self::PublicKey {
            key,
            comment: String::new(),
        }
    }
}

impl From<Certificate> for AgentIdentity {
    fn from(certificate: Certificate) -> Self {
        Self::Certificate {
            certificate,
            comment: String::new(),
        }
    }
}

impl AgentIdentity {
    /// Returns the underlying public key.
    /// For certificates, extracts the public key from the certificate.
    /// Returns a borrowed reference for plain keys, or an owned value for certificates.
    pub fn public_key(&self) -> Cow<'_, PublicKey> {
        match self {
            Self::PublicKey { key, .. } => Cow::Borrowed(key),
            Self::Certificate { certificate, .. } => {
                Cow::Owned(PublicKey::new(certificate.public_key().clone(), ""))
            }
        }
    }

    /// Returns the comment associated with this identity.
    pub fn comment(&self) -> &str {
        match self {
            Self::PublicKey { comment, .. } => comment,
            Self::Certificate { comment, .. } => comment,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::{PrivateKey, certificate};

    fn create_test_certificate() -> Certificate {
        use std::time::{SystemTime, UNIX_EPOCH};

        // Create a CA key
        let ca_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();

        // Create a user key to be certified
        let user_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();

        // Build and sign the certificate with reasonable validity window
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
        builder.sign(&ca_key).unwrap()
    }

    #[test]
    fn test_agent_identity_public_key_variant() {
        let key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone();
        let comment = "test-key-comment".to_string();

        let identity = AgentIdentity::PublicKey {
            key: key.clone(),
            comment: comment.clone(),
        };

        // Test public_key() returns borrowed reference
        let retrieved_key = identity.public_key();
        assert!(matches!(retrieved_key, Cow::Borrowed(_)));
        assert_eq!(retrieved_key.key_data(), key.key_data());

        // Test comment()
        assert_eq!(identity.comment(), "test-key-comment");
    }

    #[test]
    fn test_agent_identity_certificate_variant() {
        let cert = create_test_certificate();
        let comment = "test-cert-comment".to_string();

        let identity = AgentIdentity::Certificate {
            certificate: cert.clone(),
            comment: comment.clone(),
        };

        // Test public_key() returns owned value extracted from cert
        let retrieved_key = identity.public_key();
        assert!(matches!(retrieved_key, Cow::Owned(_)));
        assert_eq!(retrieved_key.key_data(), cert.public_key());

        // Test comment()
        assert_eq!(identity.comment(), "test-cert-comment");
    }

    #[test]
    fn test_agent_identity_clone() {
        let key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone();

        let identity = AgentIdentity::PublicKey {
            key,
            comment: "cloneable".to_string(),
        };

        let cloned = identity.clone();
        assert_eq!(cloned.comment(), identity.comment());
    }

    #[test]
    fn test_agent_identity_debug() {
        let key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone();

        let identity = AgentIdentity::PublicKey {
            key,
            comment: "debug-test".to_string(),
        };

        // Just verify Debug is implemented and doesn't panic
        let debug_str = format!("{:?}", identity);
        assert!(debug_str.contains("PublicKey"));
    }
}
