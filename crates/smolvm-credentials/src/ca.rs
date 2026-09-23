//! Per-machine certificate authority.
//!
//! The interceptor presents a leaf certificate for whichever credential host
//! the guest dials. Those leaves are signed by a CA generated for the machine
//! at create time: the public certificate is the only thing that enters the
//! guest, and no two machines share a signing key, so one machine's trust
//! store can never be used to impersonate a host toward another.

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::path::Path;
use zeroize::Zeroizing;

pub use smolvm_protocol::credentials::GUEST_CA_FILE;
const CA_KEY_FILE: &str = "ca.key";
/// Subdirectory holding only what the guest may see. Mount this, never the
/// directory that also holds the signing key.
pub const GUEST_SUBDIR: &str = "guest";

/// A CA able to mint leaves for intercepted hosts.
pub struct MachineCa {
    /// The certificate the guest trusts, exactly as written to `ca.pem`.
    cert_pem: String,
    cert_der: CertificateDer<'static>,
    /// Issuer view of the CA: same key and subject as `cert_der`. When loaded
    /// from disk this is re-derived from the machine name and key rather than
    /// parsed, which is all signing a leaf needs.
    issuer: Certificate,
    key: KeyPair,
}

fn ca_params(machine: &str) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let mut dn = DistinguishedName::new();
    dn.push(DnType::OrganizationName, "smolvm machine credentials");
    dn.push(
        DnType::CommonName,
        format!("smolvm {machine} credential CA"),
    );
    params.distinguished_name = dn;
    params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    params.not_after = rcgen::date_time_ymd(2099, 1, 1);
    params
}

impl MachineCa {
    /// Generate a fresh CA named after the machine.
    pub fn generate(machine: &str) -> Result<Self> {
        let key = KeyPair::generate().context("generate CA key")?;
        let cert = ca_params(machine)
            .self_signed(&key)
            .context("self-sign CA")?;
        Ok(Self {
            cert_pem: cert.pem(),
            cert_der: cert.der().clone(),
            issuer: cert,
            key,
        })
    }

    /// Persist the CA into `dir` (created if needed): `ca.key` owner-private
    /// beside a `guest/ca.pem` copy of the public certificate, which is the
    /// only path ever mounted into the machine.
    pub fn save(&self, dir: &Path) -> Result<()> {
        let guest = Self::guest_dir(dir);
        std::fs::create_dir_all(&guest).with_context(|| format!("create {}", guest.display()))?;
        std::fs::write(dir.join(GUEST_CA_FILE), &self.cert_pem)?;
        std::fs::write(guest.join(GUEST_CA_FILE), &self.cert_pem)?;
        let key_path = dir.join(CA_KEY_FILE);
        std::fs::write(&key_path, Zeroizing::new(self.key.serialize_pem()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    /// Load a CA previously written by [`MachineCa::save`] for `machine`.
    pub fn load(dir: &Path, machine: &str) -> Result<Self> {
        let cert_pem = std::fs::read_to_string(dir.join(GUEST_CA_FILE))
            .with_context(|| format!("read {}", dir.join(GUEST_CA_FILE).display()))?;
        let key_pem = Zeroizing::new(
            std::fs::read_to_string(dir.join(CA_KEY_FILE))
                .with_context(|| format!("read {}", dir.join(CA_KEY_FILE).display()))?,
        );
        let key = KeyPair::from_pem(&key_pem).context("parse CA key")?;
        let cert_der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .next()
            .context("CA certificate missing")??;
        let issuer = ca_params(machine)
            .self_signed(&key)
            .context("rebuild CA issuer")?;
        Ok(Self {
            cert_pem,
            cert_der,
            issuer,
            key,
        })
    }

    /// Whether `dir` already holds a saved CA.
    pub fn exists(dir: &Path) -> bool {
        dir.join(GUEST_CA_FILE).is_file()
            && dir.join(CA_KEY_FILE).is_file()
            && Self::guest_dir(dir).join(GUEST_CA_FILE).is_file()
    }

    /// The guest-visible subdirectory of a CA directory.
    pub fn guest_dir(dir: &Path) -> std::path::PathBuf {
        dir.join(GUEST_SUBDIR)
    }

    /// PEM of the public certificate — what the guest trusts.
    pub fn certificate_pem(&self) -> &str {
        &self.cert_pem
    }

    /// Mint a server leaf for `host`, returning the chain (leaf, CA) and key
    /// in the form rustls wants.
    pub fn issue_leaf(
        &self,
        host: &str,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        let leaf_key = KeyPair::generate().context("generate leaf key")?;
        let mut params = CertificateParams::new(Vec::<String>::new()).context("leaf params")?;
        params.subject_alt_names = vec![SanType::DnsName(
            host.try_into().context("host is not a valid DNS name")?,
        )];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        params.distinguished_name = dn;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        params.not_after = rcgen::date_time_ymd(2099, 1, 1);
        let leaf = params
            .signed_by(&leaf_key, &self.issuer, &self.key)
            .context("sign leaf")?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        Ok((vec![leaf.der().clone(), self.cert_der.clone()], key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_load_and_issue_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let ca = MachineCa::generate("demo").unwrap();
        ca.save(dir.path()).unwrap();
        assert!(MachineCa::exists(dir.path()));
        assert!(!MachineCa::guest_dir(dir.path()).join(CA_KEY_FILE).exists());
        let loaded = MachineCa::load(dir.path(), "demo").unwrap();
        assert_eq!(loaded.certificate_pem(), ca.certificate_pem());
        let (chain, _key) = loaded.issue_leaf("api.example.com").unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[1], ca.cert_der);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join(CA_KEY_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
