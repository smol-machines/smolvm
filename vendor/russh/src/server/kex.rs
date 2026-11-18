use core::fmt;
use std::cell::RefCell;

use client::GexParams;
use log::debug;
use num_bigint::BigUint;
use ssh_encoding::Encode;
use ssh_key::Algorithm;

use super::*;
use crate::helpers::sign_with_hash_alg;
use crate::kex::dh::biguint_to_mpint;
use crate::kex::{KEXES, KexAlgorithm, KexAlgorithmImplementor, KexCause};
use crate::keys::key::PrivateKeyWithHashAlg;
use crate::negotiation::{Names, Select, is_key_compatible_with_algo};
use crate::parsing::ensure_end;
use crate::{msg, negotiation};

thread_local! {
    static HASH_BUF: RefCell<CryptoVec> = RefCell::new(CryptoVec::new());
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum ServerKexState {
    Created,
    WaitingForGexRequest {
        names: Names,
        kex: KexAlgorithm,
    },
    WaitingForDhInit {
        // both KexInit and DH init sent
        names: Names,
        kex: KexAlgorithm,
    },
    WaitingForNewKeys {
        newkeys: NewKeys,
    },
}

pub(crate) struct ServerKex {
    exchange: Exchange,
    cause: KexCause,
    state: ServerKexState,
    config: Arc<Config>,
}

impl Debug for ServerKex {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("ClientKex");
        s.field("cause", &self.cause);
        match self.state {
            ServerKexState::Created => {
                s.field("state", &"created");
            }
            ServerKexState::WaitingForGexRequest { .. } => {
                s.field("state", &"waiting for GEX request");
            }
            ServerKexState::WaitingForDhInit { .. } => {
                s.field("state", &"waiting for DH reply");
            }
            ServerKexState::WaitingForNewKeys { .. } => {
                s.field("state", &"waiting for NEWKEYS");
            }
        }
        s.finish()
    }
}

impl ServerKex {
    pub fn new(
        config: Arc<Config>,
        client_sshid: &[u8],
        server_sshid: &SshId,
        cause: KexCause,
    ) -> Self {
        let exchange = Exchange::new(client_sshid, server_sshid.as_kex_hash_bytes());
        Self {
            config,
            exchange,
            cause,
            state: ServerKexState::Created,
        }
    }

    /// `Created` is "our KEXINIT is out, the peer's has not arrived".
    pub fn peer_kexinit_received(&self) -> bool {
        !matches!(self.state, ServerKexState::Created)
    }

    pub fn strict_kex(&self) -> bool {
        match self.state {
            ServerKexState::Created => false,
            ServerKexState::WaitingForGexRequest { ref names, .. }
            | ServerKexState::WaitingForDhInit { ref names, .. } => names.strict_kex(),
            ServerKexState::WaitingForNewKeys { ref newkeys } => newkeys.names.strict_kex(),
        }
    }

    /// A wrong `first_kex_packet_follows` guess was ignored in this exchange, so the peer's packets
    /// after KEXINIT sit one sequence number later than the strict-kex order expects (RFC 4253 §7.1
    /// requires the guess to be ignored and the correct packet to follow).
    pub fn guess_ignored(&self) -> bool {
        match self.state {
            ServerKexState::Created => false,
            ServerKexState::WaitingForGexRequest { ref names, .. }
            | ServerKexState::WaitingForDhInit { ref names, .. } => names.guessed_ignored,
            ServerKexState::WaitingForNewKeys { ref newkeys } => newkeys.names.guessed_ignored,
        }
    }

    pub fn kexinit(&mut self, output: &mut PacketWriter) -> Result<(), Error> {
        self.exchange.server_kex_init =
            negotiation::write_kex(&self.config.preferred, output, Some(self.config.as_ref()))?;

        Ok(())
    }

    pub async fn step<H: Handler + Send>(
        mut self,
        input: Option<&mut IncomingSshPacket>,
        output: &mut PacketWriter,
        handler: &mut H,
    ) -> Result<KexProgress<Self>, H::Error> {
        match self.state {
            ServerKexState::Created => {
                let Some(input) = input else {
                    return Err(Error::KexInit)?;
                };
                if input.buffer.first() != Some(&msg::KEXINIT) {
                    error!(
                        "Unexpected kex message at this stage: {:?}",
                        input.buffer.first()
                    );
                    return Err(Error::KexInit)?;
                }

                let names = {
                    self.exchange.client_kex_init = input.buffer.clone().into();
                    negotiation::Server::read_kex(
                        &input.buffer,
                        &self.config.preferred,
                        Some(&self.config.keys),
                        Some(&self.config.certificates),
                        &self.cause,
                    )?
                };
                debug!("negotiated: {names:?}");

                // seqno has already been incremented after read()
                if names.strict_kex() && !self.cause.is_rekey() && input.seqn.0 != 1 {
                    return Err(strict_kex_violation(
                        msg::KEXINIT,
                        input.seqn.0 as usize - 1,
                    ))?;
                }

                let kex = KEXES.get(&names.kex).ok_or(Error::UnknownAlgo)?.make();

                if kex.skip_exchange() {
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
                    self.state = ServerKexState::WaitingForGexRequest { names, kex };
                } else {
                    self.state = ServerKexState::WaitingForDhInit { names, kex };
                }

                Ok(KexProgress::NeedsReply {
                    kex: self,
                    reset_seqn: false,
                })
            }
            ServerKexState::WaitingForGexRequest { names, mut kex } => {
                let Some(input) = input else {
                    return Err(Error::KexInit)?;
                };
                if input.buffer.first() != Some(&msg::KEX_DH_GEX_REQUEST) {
                    error!(
                        "Unexpected kex message at this stage: {:?}",
                        input.buffer.first()
                    );
                    return Err(Error::KexInit)?;
                }

                #[allow(clippy::indexing_slicing)] // length checked
                let mut r = &input.buffer[1..];
                let gex_params = GexParams::decode(&mut r)?;
                ensure_end(&r)?;
                debug!("client requests a gex group: {gex_params:?}");

                let Some(dh_group) = handler.lookup_dh_gex_group(&gex_params).await? else {
                    debug!(
                        "server::Handler impl did not find a matching DH group (is lookup_dh_gex_group implemented?)"
                    );
                    return Err(Error::Kex)?;
                };

                let prime = biguint_to_mpint(&BigUint::from_bytes_be(&dh_group.prime));
                let generator = biguint_to_mpint(&BigUint::from_bytes_be(&dh_group.generator));

                self.exchange.gex = Some((gex_params, dh_group.clone()));
                kex.dh_gex_set_group(dh_group)?;

                output.write_packet(|w| {
                    msg::KEX_DH_GEX_GROUP.encode(w)?;
                    prime.encode(w)?;
                    generator.encode(w)?;
                    Ok(())
                })?;

                self.state = ServerKexState::WaitingForDhInit { names, kex };

                Ok(KexProgress::NeedsReply {
                    kex: self,
                    reset_seqn: false,
                })
            }
            ServerKexState::WaitingForDhInit { mut names, mut kex } => {
                let Some(input) = input else {
                    return Err(Error::KexInit)?;
                };

                if names.ignore_guessed {
                    // Ignore the next packet if (1) it follows and (2) it's not the correct guess.
                    // Dropbear always guesses (its list starts with kexguess2@matt.ucc.asn.au), so with
                    // strict kex its real KEX_ECDH_INIT then arrives at sequence number 2; see `guess_ignored`.
                    debug!("ignoring guessed kex");
                    names.ignore_guessed = false;
                    names.guessed_ignored = true;
                    self.state = ServerKexState::WaitingForDhInit { names, kex };
                    return Ok(KexProgress::NeedsReply {
                        kex: self,
                        reset_seqn: false,
                    });
                }

                if input.buffer.first()
                    != Some(match kex.is_dh_gex() {
                        true => &msg::KEX_DH_GEX_INIT,
                        false => &msg::KEX_ECDH_INIT,
                    })
                {
                    error!(
                        "Unexpected kex message at this stage: {:?}",
                        input.buffer.first()
                    );
                    return Err(Error::KexInit)?;
                }

                #[allow(clippy::indexing_slicing)] // length checked
                let mut r = &input.buffer[1..];

                self.exchange
                    .client_ephemeral
                    .extend_from_slice(&Bytes::decode(&mut r).map_err(Into::into)?);
                ensure_end(&r)?;

                let exchange = &mut self.exchange;
                kex.server_dh(exchange, &input.buffer)?;

                // Present a certificate only when one was negotiated;
                // `names.key` is then the plain algorithm the certificate
                // contains, which is what signs the exchange below.
                let (key, certificate) = if names.host_key_is_certificate {
                    self.config
                        .certificates
                        .iter()
                        .filter(|c| {
                            // RSA certificates are usable with any RSA cert algorithm
                            // variant (ssh-rsa-cert, rsa-sha2-256-cert, rsa-sha2-512-cert)
                            // since the hash variant controls the KEx signing algorithm,
                            // not the certificate itself.
                            match (&c.algorithm(), &names.key) {
                                (Algorithm::Rsa { .. }, Algorithm::Rsa { .. }) => true,
                                _ => {
                                    c.algorithm().to_certificate_type()
                                        == names.key.to_certificate_type()
                                }
                            }
                        })
                        // Only certificates with a matching private key were
                        // advertised, so skip any without one here as well.
                        .find_map(|c| {
                            self.config
                                .keys
                                .iter()
                                .find(|k| k.public_key().key_data() == c.public_key())
                                .map(|k| (k, Some(c)))
                        })
                        .ok_or(Error::UnknownKey)?
                } else {
                    let key = self
                        .config
                        .keys
                        .iter()
                        .find(|key| is_key_compatible_with_algo(key, &names.key))
                        .ok_or(Error::UnknownKey)?;
                    (key, None)
                };

                let certificate_blob = certificate
                    .map(|cert| {
                        let mut blob = Vec::new();
                        cert.encode(&mut blob)?;
                        Ok::<_, Error>(blob)
                    })
                    .transpose()?;

                // Look up the key we'll be using to sign the exchange hash
                let signature_hash_alg = match &names.key {
                    Algorithm::Rsa { hash } => *hash,
                    _ => None,
                };

                let hash = HASH_BUF.with(|buffer| {
                    let mut buffer = buffer.borrow_mut();
                    buffer.clear();

                    let mut pubkey_vec = Vec::new();
                    if let Some(blob) = &certificate_blob {
                        blob.encode(&mut pubkey_vec)?;
                    } else {
                        key.public_key().to_bytes()?.encode(&mut pubkey_vec)?;
                    }

                    let hash = kex.compute_exchange_hash(&pubkey_vec, exchange, &mut buffer)?;

                    Ok::<_, Error>(hash)
                })?;

                // Hash signature
                debug!("signing with key {key:?}");
                let signature = sign_with_hash_alg(
                    &PrivateKeyWithHashAlg::new(Arc::new(key.clone()), signature_hash_alg),
                    &hash,
                )
                .map_err(Into::into)?;

                output.write_packet(|w| {
                    match kex.is_dh_gex() {
                        true => &msg::KEX_DH_GEX_REPLY,
                        false => &msg::KEX_ECDH_REPLY,
                    }
                    .encode(w)?;
                    if let Some(blob) = &certificate_blob {
                        blob.encode(w)?;
                    } else {
                        key.public_key().to_bytes()?.encode(w)?;
                    }
                    exchange.server_ephemeral.encode(w)?;
                    signature.encode(w)?;
                    Ok(())
                })?;

                output.write_packet(|w| {
                    msg::NEWKEYS.encode(w)?;
                    Ok(())
                })?;

                let newkeys = compute_keys(
                    hash,
                    kex,
                    names.clone(),
                    self.exchange.clone(),
                    self.cause.session_id(),
                )?;

                let reset_seqn = newkeys.names.strict_kex() || self.cause.is_strict_rekey();

                self.state = ServerKexState::WaitingForNewKeys { newkeys };

                Ok(KexProgress::NeedsReply {
                    kex: self,
                    reset_seqn,
                })
            }
            ServerKexState::WaitingForNewKeys { newkeys } => {
                let Some(input) = input else {
                    return Err(Error::KexInit.into());
                };

                if input.buffer.first() != Some(&msg::NEWKEYS) {
                    error!(
                        "Unexpected kex message at this stage: {:?}",
                        input.buffer.first()
                    );
                    return Err(Error::Kex.into());
                }
                #[allow(clippy::indexing_slicing, reason = "checked")]
                let r = &input.buffer[1..];
                ensure_end(&r)?;

                debug!("new keys received");
                Ok(KexProgress::Done {
                    server_host_certificate: None,
                    agent_session_binding: None,
                    newkeys,
                    server_host_key: None,
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
        names.client_mac,
        names.server_mac,
        true,
    )?;
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
mod tests {
    use crate::tests::raw_no_crypto::{assert_rejected, kexinit_payload, raw_kex_signal, timeout};

    #[tokio::test]
    async fn kexinit_with_trailing_bytes_rejected_by_server() {
        let result = timeout(raw_kex_signal(|payload| {
            payload.extend_from_slice(&kexinit_payload("none"));
            payload.push(0);
        }))
        .await;

        assert_rejected(result, "server accepted a kexinit with trailing bytes");
    }
}
