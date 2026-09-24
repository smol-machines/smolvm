//! Per-machine certificate authority.
//!
//! The interceptor presents a leaf certificate for whichever credential host
//! the guest dials. Those leaves are signed by a CA generated for the machine
//! at create time: the public certificate is the only thing that enters the
//! guest, and no two machines share a signing key, so one machine's trust
//! store can never be used to impersonate a host toward another. The CA is
//! name-constrained to the machine's credential hosts, so even its own key
//! cannot mint a certificate the guest would accept for any other domain.

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, KeyPair, KeyUsagePurpose, NameConstraints,
    SanType,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::path::Path;
use zeroize::Zeroizing;

pub use smolvm_protocol::credentials::GUEST_CA_FILE;
const CA_KEY_FILE: &str = "ca.key";
/// Machine name the CA was generated for. Part of its subject, so a CA that
/// moves to another machine (a restored checkpoint) still signs as itself.
const CA_NAME_FILE: &str = "ca.name";
/// Subdirectory holding only what the guest may see. Mount this, never the
/// directory that also holds the signing key.
pub const GUEST_SUBDIR: &str = "guest";

/// A CA able to mint leaves for intercepted hosts.
pub struct MachineCa {
    /// Machine the CA was generated for; its subject is derived from this.
    name: String,
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
    /// Generate a fresh CA named after the machine, valid only for
    /// `permitted_hosts` (and their subdomains): a critical name constraint
    /// makes clients reject any leaf it signs for another domain.
    pub fn generate(machine: &str, permitted_hosts: &[String]) -> Result<Self> {
        anyhow::ensure!(
            !permitted_hosts.is_empty(),
            "a machine CA needs at least one permitted host"
        );
        let key = KeyPair::generate().context("generate CA key")?;
        let mut params = ca_params(machine);
        params.name_constraints = Some(NameConstraints {
            permitted_subtrees: permitted_hosts
                .iter()
                .map(|host| GeneralSubtree::DnsName(host.clone()))
                .collect(),
            excluded_subtrees: Vec::new(),
        });
        let cert = params.self_signed(&key).context("self-sign CA")?;
        Ok(Self {
            name: machine.to_string(),
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
        std::fs::write(dir.join(CA_NAME_FILE), &self.name)?;
        let key_path = dir.join(CA_KEY_FILE);
        std::fs::write(&key_path, Zeroizing::new(self.key.serialize_pem()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    /// Load a CA previously written by [`MachineCa::save`]. `machine` names
    /// it only when the directory predates the recorded name.
    pub fn load(dir: &Path, machine: &str) -> Result<Self> {
        let name = std::fs::read_to_string(dir.join(CA_NAME_FILE))
            .map(|name| name.trim().to_string())
            .unwrap_or_else(|_| machine.to_string());
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
        let issuer = ca_params(&name)
            .self_signed(&key)
            .context("rebuild CA issuer")?;
        Ok(Self {
            name,
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

    /// The CA as one portable document (name, certificate and signing key),
    /// for a live checkpoint whose captured guest already trusts it. Holds
    /// the private key: write it only where the checkpoint itself is kept.
    pub fn export(&self) -> Zeroizing<String> {
        Zeroizing::new(
            serde_json::json!({
                "name": self.name,
                "certificate": self.cert_pem,
                "key": *Zeroizing::new(self.key.serialize_pem()),
            })
            .to_string(),
        )
    }

    /// Rebuild a CA from [`MachineCa::export`].
    pub fn import(document: &str) -> Result<Self> {
        let mut value: serde_json::Value =
            serde_json::from_str(document).context("parse exported CA")?;
        let mut take = |key: &str| match value.get_mut(key).map(serde_json::Value::take) {
            Some(serde_json::Value::String(text)) => Ok(Zeroizing::new(text)),
            _ => anyhow::bail!("exported CA has no {key}"),
        };
        let name = take("name")?.to_string();
        let cert_pem = take("certificate")?.to_string();
        let key = KeyPair::from_pem(&take("key")?).context("parse exported CA key")?;
        let cert_der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .next()
            .context("exported CA has no certificate")??;
        let issuer = ca_params(&name)
            .self_signed(&key)
            .context("rebuild CA issuer")?;
        Ok(Self {
            name,
            cert_pem,
            cert_der,
            issuer,
            key,
        })
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
        let ca = MachineCa::generate("demo", &["api.example.com".to_string()]).unwrap();
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

    #[test]
    fn a_ca_moved_to_another_machine_still_signs_as_itself() {
        use rustls::client::danger::ServerCertVerifier;
        use rustls::client::WebPkiServerVerifier;
        use rustls_pki_types::{ServerName, UnixTime};

        let original = MachineCa::generate("cred", &["api.example.com".to_string()]).unwrap();
        let exported = original.export();
        // A restore installs the CA under the new machine's name.
        let dir = tempfile::tempdir().unwrap();
        MachineCa::import(&exported)
            .unwrap()
            .save(dir.path())
            .unwrap();
        let moved = MachineCa::load(dir.path(), "cred-restored").unwrap();
        assert_eq!(moved.certificate_pem(), original.certificate_pem());

        // The guest trusts the original certificate; leaves from the moved CA
        // must chain to it.
        let mut roots = rustls::RootCertStore::empty();
        roots.add(original.cert_der.clone()).unwrap();
        let verifier = WebPkiServerVerifier::builder_with_provider(
            std::sync::Arc::new(roots),
            std::sync::Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .unwrap();
        let (chain, _key) = moved.issue_leaf("api.example.com").unwrap();
        verifier
            .verify_server_cert(
                &chain[0],
                &chain[1..],
                &ServerName::try_from("api.example.com").unwrap(),
                &[],
                UnixTime::now(),
            )
            .expect("a leaf from the moved CA verifies against the original");

        assert!(MachineCa::import("{}").is_err());
        assert!(MachineCa::import("not json").is_err());
    }

    #[test]
    fn leaves_verify_only_for_the_permitted_hosts() {
        use rustls::client::danger::ServerCertVerifier;
        use rustls::client::WebPkiServerVerifier;
        use rustls_pki_types::{ServerName, UnixTime};

        let ca = MachineCa::generate("demo", &["api.example.com".to_string()]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.cert_der.clone()).unwrap();
        let verifier = WebPkiServerVerifier::builder_with_provider(
            std::sync::Arc::new(roots),
            std::sync::Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .unwrap();
        let verify = |host: &'static str| {
            let (chain, _key) = ca.issue_leaf(host).unwrap();
            verifier.verify_server_cert(
                &chain[0],
                &chain[1..],
                &ServerName::try_from(host).unwrap(),
                &[],
                UnixTime::now(),
            )
        };
        verify("api.example.com").expect("the credential host verifies");
        verify("v2.api.example.com").expect("its subdomains stay inside the constraint");
        assert!(
            verify("bank.example.org").is_err(),
            "the CA key must not be able to vouch for any other domain"
        );
        assert!(MachineCa::generate("demo", &[]).is_err());
    }
}
