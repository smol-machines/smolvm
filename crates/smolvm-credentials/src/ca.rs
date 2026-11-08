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
        let key = KeyPair::generate().context("generate CA key")?;
        Self::certify(machine, key, permitted_hosts)
    }

    /// Self-sign a CA certificate for `key`, named after `machine` and
    /// constrained to `permitted_hosts`.
    fn certify(machine: &str, key: KeyPair, permitted_hosts: &[String]) -> Result<Self> {
        anyhow::ensure!(
            !permitted_hosts.is_empty(),
            "a machine CA needs at least one permitted host"
        );
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

    /// The DNS subtrees the certificate permits leaves for.
    pub fn permitted_hosts(&self) -> Result<Vec<String>> {
        use x509_parser::extensions::GeneralName;
        use x509_parser::prelude::{FromDer, X509Certificate};
        let (_, cert) =
            X509Certificate::from_der(&self.cert_der).context("parse CA certificate")?;
        let constraints = cert
            .name_constraints()
            .context("read CA name constraints")?
            .context("CA certificate has no name constraints")?;
        Ok(constraints
            .value
            .permitted_subtrees
            .iter()
            .flatten()
            .filter_map(|subtree| match subtree.base {
                GeneralName::DNSName(name) => Some(name.to_string()),
                _ => None,
            })
            .collect())
    }

    /// This CA re-certified so it also permits every host in `hosts`, with
    /// the same key and name, or `None` when it already permits them all.
    ///
    /// Only ever widens: a subtree the certificate permits stays permitted,
    /// because processes in the guest (and in branches sharing the CA) may
    /// already trust the current certificate for it. Leaves the new
    /// certificate signs chain to the old one as well, since both carry the
    /// same subject and key, so a process that loaded the old certificate
    /// keeps trusting the hosts it already permitted; only hosts it never
    /// permitted need the new one.
    pub fn widened(&self, hosts: &[String]) -> Result<Option<Self>> {
        let mut permitted = self.permitted_hosts()?;
        let mut changed = false;
        for host in hosts {
            let covered = permitted
                .iter()
                .any(|p| host == p || host.ends_with(&format!(".{p}")));
            if !covered {
                permitted.push(host.clone());
                changed = true;
            }
        }
        if !changed {
            return Ok(None);
        }
        let key =
            KeyPair::from_pem(&Zeroizing::new(self.key.serialize_pem())).context("copy CA key")?;
        Self::certify(&self.name, key, &permitted).map(Some)
    }

    /// Persist the CA into `dir` (created if needed): `ca.key` owner-private
    /// beside a `guest/ca.pem` copy of the public certificate, which is the
    /// only path ever mounted into the machine.
    pub fn save(&self, dir: &Path) -> Result<()> {
        let guest = Self::guest_dir(dir);
        std::fs::create_dir_all(&guest).with_context(|| format!("create {}", guest.display()))?;
        // The key first: a reader that finds a certificate must find its key.
        let key_path = dir.join(CA_KEY_FILE);
        write_replacing(
            &key_path,
            Zeroizing::new(self.key.serialize_pem()).as_bytes(),
            0o600,
        )?;
        write_replacing(&dir.join(CA_NAME_FILE), self.name.as_bytes(), 0o644)?;
        write_replacing(&dir.join(GUEST_CA_FILE), self.cert_pem.as_bytes(), 0o644)?;
        // A running guest may be reading this one through its mount: replace
        // it whole, never truncate it in place.
        write_replacing(&guest.join(GUEST_CA_FILE), self.cert_pem.as_bytes(), 0o644)?;
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
        // Name the issuer's key and this leaf's own key. OpenSSL's strict
        // verification (Python's default context) rejects a non-self-signed
        // certificate without an Authority Key Identifier, and RFC 5280
        // requires one; marking the leaf explicitly as not a CA is what makes
        // rcgen write its Subject Key Identifier.
        params.is_ca = IsCa::ExplicitNoCa;
        params.use_authority_key_identifier_extension = true;
        params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        params.not_after = rcgen::date_time_ymd(2099, 1, 1);
        let leaf = params
            .signed_by(&leaf_key, &self.issuer, &self.key)
            .context("sign leaf")?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        // The leaf alone: the guest holds the CA as a trust anchor, and after
        // the CA was widened it may hold an earlier certificate for the same
        // key, which a presented copy of the current one would only compete
        // with during path building.
        Ok((vec![leaf.der().clone()], key))
    }
}

/// Write `bytes` to `path` through a sibling temporary file renamed over it,
/// so a concurrent reader sees the old content or the new, never a mix.
fn write_replacing(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let dir = path.parent().context("path has no parent")?;
    let name = path
        .file_name()
        .context("path has no file name")?
        .to_string_lossy();
    let tmp = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    // Created with its final mode, so a private key is never readable by
    // others, not even briefly.
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, mode);
    #[cfg(not(unix))]
    let _ = mode;
    let written = options
        .open(&tmp)
        .and_then(|mut file| std::io::Write::write_all(&mut file, bytes));
    if let Err(error) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(error).with_context(|| format!("write {}", tmp.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("replace {}", path.display()))?;
    Ok(())
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
        assert_eq!(
            chain.len(),
            1,
            "the guest holds the CA; only the leaf is sent"
        );
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

    /// Widening re-certifies the same key for more hosts: a guest holding the
    /// earlier certificate keeps verifying the hosts it permitted, a guest
    /// holding the new one also verifies the new hosts, and neither verifies
    /// a host the CA never permitted.
    #[test]
    fn a_widened_ca_keeps_earlier_certificates_valid_for_their_hosts() {
        use rustls::client::danger::ServerCertVerifier;
        use rustls::client::WebPkiServerVerifier;
        use rustls_pki_types::{ServerName, UnixTime};

        let dir = tempfile::tempdir().unwrap();
        let original = MachineCa::generate("demo", &["api.example.com".to_string()]).unwrap();
        original.save(dir.path()).unwrap();
        assert!(original
            .widened(&["v2.api.example.com".to_string()])
            .unwrap()
            .is_none());
        let widened = MachineCa::load(dir.path(), "demo")
            .unwrap()
            .widened(&["other.example.org".to_string()])
            .unwrap()
            .expect("a new subtree widens");
        widened.save(dir.path()).unwrap();
        let reloaded = MachineCa::load(dir.path(), "demo").unwrap();
        let mut hosts = reloaded.permitted_hosts().unwrap();
        hosts.sort();
        assert_eq!(hosts, ["api.example.com", "other.example.org"]);

        let verifier = |trusted: &CertificateDer<'static>| {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(trusted.clone()).unwrap();
            WebPkiServerVerifier::builder_with_provider(
                std::sync::Arc::new(roots),
                std::sync::Arc::new(rustls::crypto::ring::default_provider()),
            )
            .build()
            .unwrap()
        };
        let verifies = |trusted: &CertificateDer<'static>, host: &'static str| {
            let (chain, _key) = reloaded.issue_leaf(host).unwrap();
            verifier(trusted)
                .verify_server_cert(
                    &chain[0],
                    &chain[1..],
                    &ServerName::try_from(host).unwrap(),
                    &[],
                    UnixTime::now(),
                )
                .is_ok()
        };
        assert!(verifies(&original.cert_der, "api.example.com"));
        assert!(!verifies(&original.cert_der, "other.example.org"));
        assert!(verifies(&reloaded.cert_der, "api.example.com"));
        assert!(verifies(&reloaded.cert_der, "other.example.org"));
        assert!(!verifies(&reloaded.cert_der, "bank.example.net"));
    }

    /// A leaf names its own key and its issuer's: the Authority Key
    /// Identifier equals the CA certificate's Subject Key Identifier, also for
    /// a CA reloaded from disk, whose issuer is re-derived rather than parsed.
    #[test]
    fn leaves_carry_key_identifiers_that_chain_to_the_ca() {
        use x509_parser::extensions::ParsedExtension;
        use x509_parser::prelude::{FromDer, X509Certificate};

        fn identifiers(der: &[u8]) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
            let (_, cert) = X509Certificate::from_der(der).unwrap();
            let (mut subject, mut authority) = (None, None);
            for ext in cert.extensions() {
                match ext.parsed_extension() {
                    ParsedExtension::SubjectKeyIdentifier(id) => subject = Some(id.0.to_vec()),
                    ParsedExtension::AuthorityKeyIdentifier(aki) => {
                        authority = aki.key_identifier.as_ref().map(|id| id.0.to_vec())
                    }
                    _ => {}
                }
            }
            (subject, authority)
        }

        let dir = tempfile::tempdir().unwrap();
        let ca = MachineCa::generate("demo", &["api.example.com".to_string()]).unwrap();
        ca.save(dir.path()).unwrap();
        let (ca_subject, _) = identifiers(&ca.cert_der);
        let ca_subject = ca_subject.expect("the CA names its own key");
        for issuer in [&ca, &MachineCa::load(dir.path(), "demo").unwrap()] {
            let (chain, _key) = issuer.issue_leaf("api.example.com").unwrap();
            let (leaf_subject, leaf_authority) = identifiers(&chain[0]);
            assert!(leaf_subject.is_some(), "the leaf names its own key");
            assert_ne!(leaf_subject.as_deref(), Some(ca_subject.as_slice()));
            assert_eq!(
                leaf_authority.as_deref(),
                Some(ca_subject.as_slice()),
                "the leaf's authority key identifier is the CA's subject key identifier"
            );
        }
    }
}
