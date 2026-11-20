use rand::rng;
// Copyright 2016 Pierre-Étienne Meunier
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
use ssh_encoding::Decode;
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, EcdsaCurve, PublicKey};

use crate::keys::Error;

pub trait PublicKeyExt {
    fn decode(bytes: &[u8]) -> Result<PublicKey, Error>;
}

impl PublicKeyExt for PublicKey {
    fn decode(mut bytes: &[u8]) -> Result<PublicKey, Error> {
        check_cert_nesting(bytes)?;
        let key = KeyData::decode(&mut bytes)?;
        Ok(PublicKey::new(key, ""))
    }
}

#[doc(hidden)]
pub trait Verify {
    fn verify_client_auth(&self, buffer: &[u8], sig: &[u8]) -> bool;
    fn verify_server_auth(&self, buffer: &[u8], sig: &[u8]) -> bool;
}

/// Upper bound on certificate nesting in a key blob.
const MAX_CERT_NESTING: usize = 8;

/// Reject key/certificate blobs nested deeply enough to overflow the stack.
///
/// `ssh-key` decodes a certificate's `signature_key` with `KeyData::decode`,
/// which recurses into another certificate with no depth limit, so a crafted
/// pre-auth blob aborts the process. Every nesting level must carry its own
/// `*-cert-v01@*` algorithm name, so counting that marker bounds the depth.
/// A legitimate certificate has one (its CA key is a plain key).
// ponytail: substring count can over-count markers inside opaque fields; the
// limit leaves headroom. Drop once ssh-key caps the depth itself.
pub(crate) fn check_cert_nesting(blob: &[u8]) -> Result<(), ssh_key::Error> {
    const MARKER: &[u8] = b"-cert-v01@";
    if blob.windows(MARKER.len()).filter(|w| *w == MARKER).count() > MAX_CERT_NESTING {
        return Err(ssh_key::Error::CertificateFieldInvalid(
            ssh_key::certificate::Field::SignatureKey,
        ));
    }
    Ok(())
}

/// Parse a public key from a byte slice.
pub fn parse_public_key(mut p: &[u8]) -> Result<PublicKey, Error> {
    check_cert_nesting(p)?;
    Ok(ssh_key::public::KeyData::decode(&mut p)?.into())
}

/// Obtain a cryptographic-safe random number generator.
pub fn safe_rng() -> impl rand::CryptoRng {
    rng()
}

mod private_key_with_hash_alg {
    use std::ops::Deref;
    use std::sync::Arc;

    use ssh_key::Algorithm;

    use crate::helpers::AlgorithmExt;

    /// Helper structure to correlate a key and (in case of RSA) a hash algorithm.
    /// Only used for authentication, not key storage as RSA keys do not inherently
    /// have a hash algorithm associated with them.
    #[derive(Clone, Debug)]
    pub struct PrivateKeyWithHashAlg {
        key: Arc<crate::keys::PrivateKey>,
        hash_alg: Option<crate::keys::HashAlg>,
    }

    impl PrivateKeyWithHashAlg {
        /// Direct constructor.
        ///
        /// For RSA, passing `None` is mapped to the legacy `sha-rsa` (SHA-1).
        /// For other keys, `hash_alg` is ignored.
        pub fn new(
            key: Arc<crate::keys::PrivateKey>,
            mut hash_alg: Option<crate::keys::HashAlg>,
        ) -> Self {
            if !key.algorithm().is_rsa() {
                hash_alg = None;
            }
            Self { key, hash_alg }
        }

        pub fn algorithm(&self) -> Algorithm {
            self.key.algorithm().with_hash_alg(self.hash_alg)
        }

        pub fn hash_alg(&self) -> Option<crate::keys::HashAlg> {
            self.hash_alg
        }
    }

    impl Deref for PrivateKeyWithHashAlg {
        type Target = crate::keys::PrivateKey;

        fn deref(&self) -> &Self::Target {
            &self.key
        }
    }
}

pub use private_key_with_hash_alg::PrivateKeyWithHashAlg;

pub const ALL_KEY_TYPES: &[Algorithm] = &[
    Algorithm::Dsa,
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP256,
    },
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP384,
    },
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP521,
    },
    Algorithm::Ed25519,
    #[cfg(feature = "rsa")]
    Algorithm::Rsa { hash: None },
    #[cfg(feature = "rsa")]
    Algorithm::Rsa {
        hash: Some(ssh_key::HashAlg::Sha256),
    },
    #[cfg(feature = "rsa")]
    Algorithm::Rsa {
        hash: Some(ssh_key::HashAlg::Sha512),
    },
    Algorithm::SkEcdsaSha2NistP256,
    Algorithm::SkEd25519,
];

#[cfg(test)]
mod test {
    fn s(v: &mut Vec<u8>, b: &[u8]) {
        v.extend((b.len() as u32).to_be_bytes());
        v.extend(b);
    }

    /// Smallest certificate chain where each level's CA key is the next certificate.
    fn nested_cert(depth: usize) -> Vec<u8> {
        let mut inner = Vec::new();
        s(&mut inner, b"a@b");
        s(&mut inner, b"");
        for _ in 0..depth {
            let mut v = Vec::new();
            s(&mut v, b"a-cert-v01@x");
            s(&mut v, b""); // nonce
            s(&mut v, b""); // opaque public key
            v.extend(0u64.to_be_bytes()); // serial
            v.extend(1u32.to_be_bytes()); // user cert
            s(&mut v, b""); // key id
            s(&mut v, b""); // principals
            v.extend(0u64.to_be_bytes());
            v.extend(u64::MAX.to_be_bytes());
            s(&mut v, b""); // critical options
            s(&mut v, b""); // extensions
            s(&mut v, b""); // reserved
            s(&mut v, &inner); // signature key
            let mut sig = Vec::new();
            s(&mut sig, b"a@b");
            s(&mut sig, b"x");
            s(&mut v, &sig);
            inner = v;
        }
        inner
    }

    #[test]
    fn deeply_nested_certificate_is_rejected() {
        // A single certificate is well-formed and still decodes.
        assert!(super::parse_public_key(&nested_cert(1)).is_ok());
        // A certificate key used as a CA key is rejected (draft-ietf-sshm-cert §2.1.1).
        assert!(super::parse_public_key(&nested_cert(2)).is_err());
        // One packet's worth of nesting; without the guard this aborts on stack overflow.
        let deep = nested_cert(2848);
        assert!(super::parse_public_key(&deep).is_err());
        assert!(crate::cert::PublicKeyOrCertificate::decode("ssh-ed25519", &deep).is_err());
        assert!(
            crate::cert::PublicKeyOrCertificate::decode("ssh-ed25519-cert-v01@openssh.com", &deep)
                .is_err()
        );
    }
}
