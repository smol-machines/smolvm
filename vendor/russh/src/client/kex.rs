use core::fmt;
use std::cell::RefCell;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;

use bytes::Bytes;
use log::{debug, error, warn};
use ssh_encoding::{Decode, Encode};
use ssh_key::{Certificate, Mpint, PublicKey, Signature};

use super::IncomingSshPacket;
use crate::client::{Config, NewKeys};
use crate::kex::dh::groups::DhGroup;
use crate::kex::{KEXES, KexAlgorithm, KexAlgorithmImplementor, KexCause, KexProgress};
use crate::keys::agent::AgentSessionBinding;
use crate::keys::key::parse_public_key;
use crate::negotiation::{Names, Select};
use crate::parsing::ensure_end;
use crate::session::Exchange;
use crate::sshbuffer::PacketWriter;
use crate::{CryptoVec, Error, SshId, msg, negotiation, strict_kex_violation};

thread_local! {
    static HASH_BUFFER: RefCell<CryptoVec> = RefCell::new(CryptoVec::new());
}

// Some servers (Huawei VRP among them) pad ECDSA signature scalars with leading
// zeros. ssh-key rejects that as a non-canonical mpint; OpenSSH accepts it.
// Re-encodes r and s canonically so the strict decoder can take it from there.
fn canonicalize_ecdsa_signature(blob: &[u8]) -> Option<Vec<u8>> {
    let mut reader = blob;
    let algorithm = String::decode(&mut reader).ok()?;
    if !algorithm.starts_with("ecdsa-sha2-") {
        return None;
    }
    let inner = Vec::<u8>::decode(&mut reader).ok()?;
    let mut scalars = inner.as_slice();
    let mut canonical_scalars = Vec::new();
    for _ in 0..2 {
        let scalar = Vec::<u8>::decode(&mut scalars).ok()?;
        Mpint::from_positive_bytes(&scalar)
            .encode(&mut canonical_scalars)
            .ok()?;
    }
    if !reader.is_empty() || !scalars.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    algorithm.encode(&mut out).ok()?;
    canonical_scalars.encode(&mut out).ok()?;
    Some(out)
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum ClientKexState {
    Created,
    WaitingForGexReply {
        names: Names,
        kex: KexAlgorithm,
    },
    WaitingForDhReply {
        // both KexInit and DH init sent
        names: Names,
        kex: KexAlgorithm,
    },
    WaitingForNewKeys {
        server_host_key: PublicKey,
        server_host_certificate: Option<Certificate>,
        agent_session_binding: Option<AgentSessionBinding>,
        newkeys: NewKeys,
    },
}

pub(crate) struct ClientKex {
    exchange: Exchange,
    cause: KexCause,
    state: ClientKexState,
    config: Arc<Config>,
}

impl Debug for ClientKex {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("ClientKex");
        s.field("cause", &self.cause);
        match self.state {
            ClientKexState::Created => {
                s.field("state", &"created");
            }
            ClientKexState::WaitingForGexReply { .. } => {
                s.field("state", &"waiting for GEX response");
            }
            ClientKexState::WaitingForDhReply { .. } => {
                s.field("state", &"waiting for DH response");
            }
            ClientKexState::WaitingForNewKeys { .. } => {
                s.field("state", &"waiting for NEWKEYS");
            }
        }
        s.finish()
    }
}

impl ClientKex {
    pub fn new(
        config: Arc<Config>,
        client_sshid: &SshId,
        server_sshid: &[u8],
        cause: KexCause,
    ) -> Self {
        let exchange = Exchange::new(client_sshid.as_kex_hash_bytes(), server_sshid);
        Self {
            config,
            exchange,
            cause,
            state: ClientKexState::Created,
        }
    }

    /// `Created` is "our KEXINIT is out, the peer's has not arrived".
    pub fn peer_kexinit_received(&self) -> bool {
        !matches!(self.state, ClientKexState::Created)
    }

    /// Whether strict kex was negotiated, as soon as the peer's KEXINIT has
    /// been read (i.e. before the exchange completes).
    pub fn strict_kex(&self) -> bool {
        match self.state {
            ClientKexState::Created => false,
            ClientKexState::WaitingForGexReply { ref names, .. }
            | ClientKexState::WaitingForDhReply { ref names, .. } => names.strict_kex(),
            ClientKexState::WaitingForNewKeys { ref newkeys, .. } => newkeys.names.strict_kex(),
        }
    }

    pub fn kexinit(&mut self, output: &mut PacketWriter) -> Result<(), Error> {
        self.exchange.client_kex_init =
            negotiation::write_kex(&self.config.preferred, output, None)?;

        Ok(())
    }

    pub fn step(
        mut self,
        input: Option<&mut IncomingSshPacket>,
        output: &mut PacketWriter,
    ) -> Result<KexProgress<Self>, Error> {
        match self.state {
            ClientKexState::Created => {
                // At this point we expect to read the KEXINIT from the other side

                let Some(input) = input else {
                    return Err(Error::KexInit);
                };
                if input.buffer.first() != Some(&msg::KEXINIT) {
                    error!(
                        "Unexpected kex message at this stage: {:?}",
                        input.buffer.first()
                    );
                    return Err(Error::KexInit);
                }

                let names = {
                    // read algorithms from packet.
                    self.exchange.server_kex_init = input.buffer.clone().into();
                    negotiation::Client::read_kex(
                        &input.buffer,
                        &self.config.preferred,
                        None,
                        None,
                        &self.cause,
                    )?
                };
                debug!("negotiated algorithms: {names:?}");

                // seqno has already been incremented after read()
                if names.strict_kex() && !self.cause.is_rekey() && input.seqn.0 != 1 {
                    return Err(strict_kex_violation(
                        msg::KEXINIT,
                        input.seqn.0 as usize - 1,
                    ));
                }

                let mut kex = KEXES.get(&names.kex).ok_or(Error::UnknownAlgo)?.make();

                if kex.skip_exchange() {
                    // Non-standard no-kex exchange
                    let newkeys = compute_keys(
                        Vec::new(),
                        kex,
                        names.clone(),
                        self.exchange.clone(),
                        self.cause.session_id(),
                    )?;

                    output.write_packet(|w| {
                        msg::NEWKEYS.encode(w)?;
                        Ok(())
                    })?;

                    return Ok(KexProgress::Done {
                        server_host_certificate: None,
                        agent_session_binding: None,
                        newkeys,
                        server_host_key: None,
                    });
                }

                if kex.is_dh_gex() {
                    output.write_packet(|w| {
                        kex.client_dh_gex_init(&self.config.gex, w)?;
                        Ok(())
                    })?;

                    self.state = ClientKexState::WaitingForGexReply { names, kex };
                } else {
                    output.write_packet(|w| {
                        kex.client_dh(&mut self.exchange.client_ephemeral, w)?;
                        Ok(())
                    })?;

                    self.state = ClientKexState::WaitingForDhReply { names, kex };
                }

                Ok(KexProgress::NeedsReply {
                    kex: self,
                    reset_seqn: false,
                })
            }
            ClientKexState::WaitingForGexReply { names, mut kex } => {
                let Some(input) = input else {
                    return Err(Error::KexInit);
                };

                if input.buffer.first() != Some(&msg::KEX_DH_GEX_GROUP) {
                    error!(
                        "Unexpected kex message at this stage: {:?}",
                        input.buffer.first()
                    );
                    return Err(Error::KexInit);
                }

                #[allow(clippy::indexing_slicing)] // length checked
                let mut r = &input.buffer[1..];

                let prime = Mpint::decode(&mut r)?;
                let generator = Mpint::decode(&mut r)?;
                ensure_end(&r)?;
                debug!("received gex group: prime={prime}, generator={generator}");

                let group = DhGroup {
                    prime: prime.as_bytes().to_vec().into(),
                    generator: generator.as_bytes().to_vec().into(),
                };

                if group.bit_size() < self.config.gex.min_group_size
                    || group.bit_size() > self.config.gex.max_group_size
                {
                    warn!(
                        "DH prime size ({} bits) not within requested range",
                        group.bit_size()
                    );
                    return Err(Error::KexInit);
                }

                let exchange = &mut self.exchange;
                exchange.gex = Some((self.config.gex.clone(), group.clone()));
                kex.dh_gex_set_group(group)?;
                output.write_packet(|w| {
                    kex.client_dh(&mut exchange.client_ephemeral, w)?;
                    Ok(())
                })?;
                self.state = ClientKexState::WaitingForDhReply { names, kex };

                Ok(KexProgress::NeedsReply {
                    kex: self,
                    reset_seqn: false,
                })
            }
            ClientKexState::WaitingForDhReply { mut names, mut kex } => {
                // At this point, we've sent ECDH_INTI and
                // are waiting for the ECDH_REPLY from the server.

                let Some(input) = input else {
                    return Err(Error::KexInit);
                };

                if names.ignore_guessed {
                    // Ignore the next packet if (1) it follows and (2) it's not the correct guess.
                    debug!("ignoring guessed kex");
                    names.ignore_guessed = false;
                    self.state = ClientKexState::WaitingForDhReply { names, kex };
                    return Ok(KexProgress::NeedsReply {
                        kex: self,
                        reset_seqn: false,
                    });
                }

                if input.buffer.first()
                    != Some(match kex.is_dh_gex() {
                        true => &msg::KEX_DH_GEX_REPLY,
                        false => &msg::KEX_ECDH_REPLY,
                    })
                {
                    error!(
                        "Unexpected kex message at this stage: {:?}",
                        input.buffer.first()
                    );
                    return Err(Error::KexInit);
                }

                #[allow(clippy::indexing_slicing)] // length checked
                let r = &mut &input.buffer[1..];

                // The raw blob is kept as well as the parsed key. It is what
                // goes into the exchange hash below: for a certificate the
                // parsed form is only the key *inside* it, and re-encoding that
                // would hash something the server never sent — a failure that
                // looks like a bad signature and is computed entirely locally,
                // so there is nothing on the wire to compare against.
                let server_host_key_blob = Bytes::decode(r)?;
                let server_host_certificate = if names.host_key_is_certificate {
                    crate::keys::key::check_cert_nesting(&server_host_key_blob)?;
                    Some(Certificate::from_bytes(&server_host_key_blob)?)
                } else {
                    None
                };
                let server_host_key = match &server_host_certificate {
                    // The certificate's own signature is checked by the client
                    // against its trusted authorities, not here; what the key
                    // exchange is signed with is the key the certificate
                    // contains. The two are separate proofs and collapsing them
                    // would accept a certificate nobody vouched for.
                    Some(certificate) => PublicKey::new(certificate.public_key().clone(), ""),
                    None => parse_public_key(&server_host_key_blob)?,
                };
                debug!(
                    "received server host key: {:?} (certificate: {})",
                    server_host_key.to_openssh(),
                    server_host_certificate.is_some()
                );

                let server_ephemeral = Bytes::decode(r)?;
                self.exchange
                    .server_ephemeral
                    .extend_from_slice(&server_ephemeral);
                kex.compute_shared_secret(&self.exchange.server_ephemeral)?;

                let mut pubkey_vec = Vec::new();
                server_host_key_blob.encode(&mut pubkey_vec)?;

                let exchange = &self.exchange;
                let hash = HASH_BUFFER.with({
                    |buffer| {
                        let mut buffer = buffer.borrow_mut();
                        buffer.clear();
                        kex.compute_exchange_hash(&pubkey_vec, exchange, &mut buffer)
                    }
                })?;

                let signature_blob = Bytes::decode(r)?;
                let mut signature_reader = &signature_blob[..];
                let signature = match Signature::decode(&mut signature_reader) {
                    Err(err @ ssh_key::Error::Encoding(ssh_encoding::Error::MpintEncoding)) => {
                        let canonical =
                            canonicalize_ecdsa_signature(&signature_blob).ok_or(err)?;
                        Signature::decode(&mut canonical.as_slice())?
                    }
                    result => {
                        let signature = result?;
                        ensure_end(&signature_reader)?;
                        signature
                    }
                };
                ensure_end(r)?;

                if let Err(e) =
                    signature::Verifier::verify(&server_host_key, hash.as_ref(), &signature)
                {
                    debug!("wrong server sig: {e:?}");
                    return Err(Error::WrongServerSig);
                }

                let agent_session_binding = (!self.cause.is_rekey()).then(|| {
                    AgentSessionBinding::new(
                        server_host_key_blob.to_vec(),
                        CryptoVec::from(&hash[..]),
                        signature_blob.to_vec(),
                    )
                });
                let newkeys = compute_keys(
                    hash,
                    kex,
                    names.clone(),
                    self.exchange.clone(),
                    self.cause.session_id(),
                )?;

                output.write_packet(|w| {
                    msg::NEWKEYS.encode(w)?;
                    Ok(())
                })?;

                let reset_seqn = newkeys.names.strict_kex() || self.cause.is_strict_rekey();

                self.state = ClientKexState::WaitingForNewKeys {
                    server_host_key,
                    server_host_certificate,
                    agent_session_binding,
                    newkeys,
                };

                Ok(KexProgress::NeedsReply {
                    kex: self,
                    reset_seqn,
                })
            }
            ClientKexState::WaitingForNewKeys {
                server_host_key,
                server_host_certificate,
                agent_session_binding,
                newkeys,
            } => {
                // At this point the exchange is complete
                // and we're waiting for a KEWKEYS packet
                let Some(input) = input else {
                    return Err(Error::KexInit);
                };

                if input.buffer.first() != Some(&msg::NEWKEYS) {
                    error!(
                        "Unexpected kex message at this stage: {:?}",
                        input.buffer.first()
                    );
                    return Err(Error::Kex);
                }

                #[allow(clippy::indexing_slicing, reason = "length checked")]
                let r = &input.buffer[1..];
                ensure_end(&r)?;

                Ok(KexProgress::Done {
                    server_host_certificate,
                    agent_session_binding,
                    newkeys,
                    server_host_key: Some(server_host_key),
                })
            }
        }
    }
}

fn compute_keys(
    hash: Vec<u8>,
    kex: KexAlgorithm,
    names: Names,
    exchange: Exchange,
    session_id: Option<&CryptoVec>,
) -> Result<NewKeys, Error> {
    let session_id_ref: &[u8] = match session_id {
        Some(sid) => sid,
        None => &hash,
    };
    // Now computing keys.
    let c = kex.compute_keys(
        session_id_ref,
        &hash,
        names.cipher,
        names.server_mac,
        names.client_mac,
        false,
    )?;
    // The session_id stored in NewKeys is sensitive key material
    // (used in key derivation), so keep it as CryptoVec.
    // On initial exchange the exchange hash becomes the session_id;
    // on rekey we already have it as CryptoVec.
    let session_id_cv = match session_id {
        Some(s) => s.clone(),
        None => {
            let mut cv = CryptoVec::new();
            cv.extend(&hash);
            cv
        }
    };
    Ok(NewKeys {
        exchange,
        names,
        kex,
        key: 0,
        cipher: c,
        session_id: session_id_cv,
    })
}

#[cfg(test)]
mod ecdsa_signature_canonicalization_tests {
    use ssh_encoding::{Decode, Encode};
    use ssh_key::Signature;

    use super::canonicalize_ecdsa_signature;

    fn blob(algorithm: &str, r: &[u8], s: &[u8]) -> Vec<u8> {
        let mut scalars = Vec::new();
        r.encode(&mut scalars).unwrap();
        s.encode(&mut scalars).unwrap();
        let mut out = Vec::new();
        algorithm.encode(&mut out).unwrap();
        scalars.encode(&mut out).unwrap();
        out
    }

    #[test]
    fn strips_leading_zeros() {
        let r = [vec![0, 0, 0], vec![0x42; 65]].concat();
        let s = [vec![0, 0], vec![0x80; 66]].concat();
        let padded = blob("ecdsa-sha2-nistp521", &r, &s);
        assert!(matches!(
            Signature::decode(&mut padded.as_slice()),
            Err(ssh_key::Error::Encoding(ssh_encoding::Error::MpintEncoding))
        ));

        let canonical = canonicalize_ecdsa_signature(&padded).unwrap();
        assert_eq!(canonical, blob("ecdsa-sha2-nistp521", &r[3..], &s[1..]));
        assert!(Signature::decode(&mut canonical.as_slice()).is_ok());

        let p256 = blob("ecdsa-sha2-nistp256", &[0, 1], &[2]);
        assert_eq!(
            canonicalize_ecdsa_signature(&p256).unwrap(),
            blob("ecdsa-sha2-nistp256", &[1], &[2])
        );
    }

    #[test]
    fn rejects_other_algorithms_and_malformed_blobs() {
        assert!(canonicalize_ecdsa_signature(&blob("ssh-rsa", &[0, 1], &[2])).is_none());

        let good = blob("ecdsa-sha2-nistp521", &[0, 1], &[2]);
        assert!(canonicalize_ecdsa_signature(&good[..good.len() - 1]).is_none());
        assert!(canonicalize_ecdsa_signature(&[good.clone(), vec![0xff]].concat()).is_none());

        let mut scalars = Vec::new();
        for s in [&[0, 1][..], &[2], &[3]] {
            s.encode(&mut scalars).unwrap();
        }
        let mut three_scalars = Vec::new();
        "ecdsa-sha2-nistp521".encode(&mut three_scalars).unwrap();
        scalars.encode(&mut three_scalars).unwrap();
        assert!(canonicalize_ecdsa_signature(&three_scalars).is_none());
    }
}
