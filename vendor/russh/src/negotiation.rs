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
use std::borrow::Cow;

use bytes::Bytes;
use log::debug;
use rand_core::Rng;
use ssh_encoding::{Decode, Encode};
use ssh_key::{Algorithm, Certificate, EcdsaCurve, HashAlg, PrivateKey};

use crate::cipher::CIPHERS;
use crate::helpers::{AlgorithmExt, NameList};
use crate::kex::{
    KexCause, EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT, EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
};
use crate::keys::key::safe_rng;
use crate::parsing::ensure_end;
#[cfg(not(target_arch = "wasm32"))]
use crate::server::Config;
use crate::sshbuffer::PacketWriter;
use crate::{cipher, compression, kex, mac, msg, AlgorithmKind, Error};

#[cfg(target_arch = "wasm32")]
/// WASM-only stub
pub struct Config {
    keys: Vec<PrivateKey>,
    certificates: Vec<Certificate>,
}

#[derive(Debug, Clone)]
pub struct Names {
    pub kex: kex::Name,
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub key: Algorithm,
    pub cipher: cipher::Name,
    pub client_mac: mac::Name,
    pub server_mac: mac::Name,
    pub server_compression: compression::Compression,
    pub client_compression: compression::Compression,
    pub ignore_guessed: bool,
    /// A wrong `first_kex_packet_follows` guess was received and ignored: the peer's real KEX packet
    /// and everything after it arrive one sequence number later than the strict-kex order expects.
    pub guessed_ignored: bool,
    /// Whether `key` was negotiated as a certificate algorithm or not
    pub(crate) host_key_is_certificate: bool,
    // Prevent accidentally contructing [Names] without a [KeyCause]
    // as strict kext algo is not sent during a rekey and hence the state
    // of [strict_kex] cannot be known without a [KexCause].
    strict_kex: bool,
}

impl Names {
    pub fn strict_kex(&self) -> bool {
        self.strict_kex
    }
}

/// Lists of preferred algorithms. This is normally hard-coded into implementations.
#[derive(Debug, Clone)]
pub struct Preferred {
    /// Preferred key exchange algorithms.
    pub kex: Cow<'static, [kex::Name]>,
    /// Preferred host & public key algorithms.
    pub key: Cow<'static, [Algorithm]>,
    /// Host-key algorithms for which to also advertise the OpenSSH
    /// certificate variant (`*-cert-v01@openssh.com`), most preferred first.
    ///
    /// A list separate from `key` because [`Algorithm`] displays only the
    /// plain name; the certificate name is derived with
    /// [`Algorithm::to_certificate_type`]. These are advertised ahead of
    /// `key`, so a server that has a certificate presents it in preference
    /// to a bare key.
    ///
    /// Empty by default, and only used by the client (a server advertises
    /// certificates from [`Config::certificates`](crate::server::Config)
    /// instead). Advertising a certificate algorithm makes a server prove
    /// its identity with a certificate instead of a bare key, which a client
    /// can only act on once it knows which authorities it trusts (see
    /// [`check_server_key`](crate::client::Handler::check_server_key))
    /// — so turning it on is the caller's decision, never a default.
    pub host_key_certificates: Cow<'static, [Algorithm]>,
    /// Preferred symmetric ciphers.
    pub cipher: Cow<'static, [cipher::Name]>,
    /// Preferred MAC algorithms.
    pub mac: Cow<'static, [mac::Name]>,
    /// Preferred compression algorithms.
    pub compression: Cow<'static, [compression::Name]>,
}

pub(crate) fn is_key_compatible_with_algo(key: &PrivateKey, algo: &Algorithm) -> bool {
    match algo {
        // All RSA keys are compatible with all RSA based algos.
        Algorithm::Rsa { .. } => key.algorithm().is_rsa(),
        // Other keys have to match exactly
        a => key.algorithm() == *a,
    }
}

/// Certificate algorithm names a server can honor: those of its certificates
/// that come with a matching private key to sign the exchange with, gated by
/// `pref.key` so the preference list stays the policy knob for certificates
/// too. An RSA certificate is offered under every RSA variant pref.key allows
/// since the hash picks the exchange-signature algorithm, not the certificate.
pub(crate) fn server_certificate_names(
    pref: &Preferred,
    certificates: &[Certificate],
    keys: &[PrivateKey],
) -> Vec<String> {
    let mut names = Vec::new();
    for cert in certificates {
        if !keys
            .iter()
            .any(|k| k.public_key().key_data() == cert.public_key())
        {
            debug!("no host key matching certificate {:?}", cert.key_id());
            continue;
        }
        let variants: Vec<Algorithm> = pref
            .key
            .iter()
            .filter(|a| match (&cert.algorithm(), a) {
                (Algorithm::Rsa { .. }, Algorithm::Rsa { .. }) => true,
                (c, a) => c == *a,
            })
            .cloned()
            .collect();
        for name in variants.iter().map(Algorithm::to_certificate_type) {
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }
    names
}

impl Preferred {
    pub(crate) fn possible_host_key_algos_for_keys(
        &self,
        available_host_keys: &[PrivateKey],
    ) -> Vec<Algorithm> {
        self.key
            .iter()
            .filter(|n| {
                available_host_keys
                    .iter()
                    .any(|k| is_key_compatible_with_algo(k, n))
            })
            .cloned()
            .collect::<Vec<_>>()
    }
}

const SAFE_KEX_ORDER: &[kex::Name] = &[
    kex::MLKEM768X25519_SHA256,
    kex::CURVE25519,
    kex::CURVE25519_PRE_RFC_8731,
    kex::DH_GEX_SHA256,
    kex::DH_G18_SHA512,
    kex::DH_G17_SHA512,
    kex::DH_G16_SHA512,
    kex::DH_G15_SHA512,
    kex::DH_G14_SHA256,
    kex::EXTENSION_SUPPORT_AS_CLIENT,
    kex::EXTENSION_SUPPORT_AS_SERVER,
    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
];

const KEX_EXTENSION_NAMES: &[kex::Name] = &[
    kex::EXTENSION_SUPPORT_AS_CLIENT,
    kex::EXTENSION_SUPPORT_AS_SERVER,
    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
];

const CIPHER_ORDER: &[cipher::Name] = &[
    cipher::CHACHA20_POLY1305,
    cipher::AES_256_GCM,
    cipher::AES_256_CTR,
    cipher::AES_192_CTR,
    cipher::AES_128_CTR,
];

// SHA-1 MAC variants are excluded from defaults.
const SAFE_HMAC_ORDER: &[mac::Name] = &[
    mac::HMAC_SHA512_ETM,
    mac::HMAC_SHA256_ETM,
    mac::HMAC_SHA512,
    mac::HMAC_SHA256,
];

const COMPRESSION_ORDER: &[compression::Name] = &[
    compression::NONE,
    #[cfg(feature = "flate2")]
    compression::ZLIB,
    #[cfg(feature = "flate2")]
    compression::ZLIB_LEGACY,
];

impl Preferred {
    pub const DEFAULT: Preferred = Preferred {
        kex: Cow::Borrowed(SAFE_KEX_ORDER),
        host_key_certificates: Cow::Borrowed(&[]),
        key: Cow::Borrowed(&[
            Algorithm::Ed25519,
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP384,
            },
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP521,
            },
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            },
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha256),
            },
            Algorithm::Rsa { hash: None },
        ]),
        cipher: Cow::Borrowed(CIPHER_ORDER),
        mac: Cow::Borrowed(SAFE_HMAC_ORDER),
        compression: Cow::Borrowed(COMPRESSION_ORDER),
    };

    pub const COMPRESSED: Preferred = Preferred {
        kex: Cow::Borrowed(SAFE_KEX_ORDER),
        host_key_certificates: Cow::Borrowed(&[]),
        key: Preferred::DEFAULT.key,
        cipher: Cow::Borrowed(CIPHER_ORDER),
        mac: Cow::Borrowed(SAFE_HMAC_ORDER),
        compression: Cow::Borrowed(COMPRESSION_ORDER),
    };
}

impl Default for Preferred {
    fn default() -> Preferred {
        Preferred::DEFAULT
    }
}

pub(crate) trait Select {
    fn is_server() -> bool;

    fn select<A: AsRef<str> + Clone, B: AsRef<str> + Clone>(
        a: &[A],
        b: &[B],
        kind: AlgorithmKind,
    ) -> Result<(bool, A), Error>;

    /// `available_host_keys`, if present, is used to limit the host key algorithms to the ones we have keys for.
    /// `available_certificates` (server only) are the host certificates the server can present.
    fn read_kex(
        buffer: &[u8],
        pref: &Preferred,
        available_host_keys: Option<&[PrivateKey]>,
        available_certificates: Option<&[Certificate]>,
        cause: &KexCause,
    ) -> Result<Names, Error> {
        let &Some(mut r) = &buffer.get(17..) else {
            return Err(Error::Inconsistent);
        };

        // Key exchange

        let kex_list = NameList::decode(&mut r)?;
        // Filter out extension kex names from both lists before selecting
        let _local_kexes_no_ext = pref
            .kex
            .iter()
            .filter(|k| !KEX_EXTENSION_NAMES.contains(k))
            .cloned()
            .collect::<Vec<_>>();
        let _remote_kexes_no_ext = kex_list
            .iter()
            .filter(|k| {
                // Keep unknown algorithm names: they can't be selected, but they must
                // still count towards the client's *first* choice so that an optimistic
                // `first_kex_packet_follows` guess for an algorithm we don't implement is
                // correctly judged as wrong (kex_both_first == false). See issue #733.
                kex::Name::try_from(k.as_str())
                    .ok()
                    .map(|k| !KEX_EXTENSION_NAMES.contains(&k))
                    .unwrap_or(true)
            })
            .collect::<Vec<_>>();
        let (kex_both_first, kex_algorithm) = Self::select(
            &_local_kexes_no_ext,
            &_remote_kexes_no_ext,
            AlgorithmKind::Kex,
        )?;

        // Strict kex detection

        let strict_kex_requested = pref.kex.contains(if Self::is_server() {
            &EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER
        } else {
            &EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT
        });
        let strict_kex_provided = Self::select(
            &[if Self::is_server() {
                EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT
            } else {
                EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER
            }],
            &kex_list,
            AlgorithmKind::Kex,
        )
        .is_ok();

        if strict_kex_requested && strict_kex_provided {
            debug!("strict kex enabled")
        }

        // Host key

        let key_list = NameList::decode(&mut r)?;
        let possible_host_key_algos = match available_host_keys {
            Some(available_host_keys) => pref.possible_host_key_algos_for_keys(available_host_keys),
            None => pref.key.iter().map(ToOwned::to_owned).collect::<Vec<_>>(),
        };

        // Certificate algorithms come from `pref.host_key_certificates` on the
        // client and from the certificates the server holds (with a matching
        // host key) on the server. Selection runs over the same combined
        // name-list the peer saw — certificates ahead of plain keys — so
        // `key_both_first` keeps its meaning for `first_kex_packet_follows`.
        // The algorithm kept for a certificate is the plain one it contains:
        // that is what signs the exchange, and it is what every later step
        // needs; that a certificate was negotiated is recorded separately in
        // [`Names`].
        let certificate_names = if Self::is_server() {
            match (available_certificates, available_host_keys) {
                (Some(certificates), Some(keys)) => {
                    server_certificate_names(pref, certificates, keys)
                }
                _ => Vec::new(),
            }
        } else {
            pref.host_key_certificates
                .iter()
                .map(Algorithm::to_certificate_type)
                .collect::<Vec<_>>()
        };
        let (key_both_first, key_algorithm, host_key_is_certificate) = if certificate_names
            .is_empty()
        {
            let (both_first, algorithm) =
                Self::select(&possible_host_key_algos[..], &key_list, AlgorithmKind::Key)?;
            (both_first, algorithm, false)
        } else {
            let advertised = certificate_names
                .iter()
                .cloned()
                .chain(possible_host_key_algos.iter().map(ToString::to_string))
                .collect::<Vec<_>>();
            let (both_first, name) = Self::select(&advertised[..], &key_list, AlgorithmKind::Key)?;
            let is_certificate = certificate_names.contains(&name);
            let algorithm = if is_certificate {
                Algorithm::new_certificate_ext(&name).map_err(|_| Error::KexInit)?
            } else {
                possible_host_key_algos
                    .iter()
                    .find(|a| a.to_string() == name)
                    .cloned()
                    .ok_or(Error::KexInit)?
            };
            (both_first, algorithm, is_certificate)
        };

        // Cipher

        let cipher_list = NameList::decode(&mut r)?;
        let (_cipher_both_first, cipher) =
            Self::select(&pref.cipher, &cipher_list, AlgorithmKind::Cipher)?;
        String::decode(&mut r)?; // cipher server-to-client.

        // MAC

        let need_mac = CIPHERS.get(&cipher).map(|x| x.needs_mac()).unwrap_or(false);

        // Select a MAC, refusing `none` whenever the negotiated cipher needs an
        // integrity MAC — regardless of whether `none` was a common choice or
        // only the no-common-MAC fallback. Pairing e.g. aes*-ctr/cbc with
        // mac=none yields a tag_len() of 0 and a panic on the read path.
        let select_mac = |list: &[String]| match Self::select(&pref.mac, list, AlgorithmKind::Mac) {
            Ok((_, m)) if need_mac && m == mac::NONE => Err(Error::NoCommonAlgo {
                kind: AlgorithmKind::Mac,
                ours: pref.mac.iter().map(|x| x.as_ref().to_owned()).collect(),
                theirs: list.to_vec(),
            }),
            Ok((_, m)) => Ok(m),
            Err(_) if !need_mac => Ok(mac::NONE),
            Err(e) => Err(e),
        };

        let client_mac = select_mac(&NameList::decode(&mut r)?)?;
        let server_mac = select_mac(&NameList::decode(&mut r)?)?;

        // Compression

        // client-to-server compression.
        let client_compression = compression::Compression::new(
            &Self::select(
                &pref.compression,
                &NameList::decode(&mut r)?,
                AlgorithmKind::Compression,
            )?
            .1,
        );

        // server-to-client compression.
        let server_compression = compression::Compression::new(
            &Self::select(
                &pref.compression,
                &NameList::decode(&mut r)?,
                AlgorithmKind::Compression,
            )?
            .1,
        );
        String::decode(&mut r)?; // languages client-to-server
        String::decode(&mut r)?; // languages server-to-client

        let follows = u8::decode(&mut r)? != 0;
        u32::decode(&mut r)?;
        ensure_end(&r)?;
        Ok(Names {
            kex: kex_algorithm,
            key: key_algorithm,
            cipher,
            client_mac,
            server_mac,
            client_compression,
            server_compression,
            host_key_is_certificate,
            // Ignore the next packet if (1) it follows and (2) it's not the correct guess.
            ignore_guessed: follows && !(kex_both_first && key_both_first),
            guessed_ignored: false,
            strict_kex: (strict_kex_requested && strict_kex_provided) || cause.is_strict_rekey(),
        })
    }
}

pub struct Server;
pub struct Client;

impl Select for Server {
    fn is_server() -> bool {
        true
    }

    fn select<A: AsRef<str> + Clone, B: AsRef<str> + Clone>(
        server_list: &[A],
        client_list: &[B],
        kind: AlgorithmKind,
    ) -> Result<(bool, A), Error> {
        let mut both_first_choice = true;
        for c in client_list {
            for s in server_list {
                if c.as_ref() == s.as_ref() {
                    return Ok((both_first_choice, s.clone()));
                }
                both_first_choice = false
            }
        }
        Err(Error::NoCommonAlgo {
            kind,
            ours: server_list.iter().map(|x| x.as_ref().to_owned()).collect(),
            theirs: client_list.iter().map(|x| x.as_ref().to_owned()).collect(),
        })
    }
}

impl Select for Client {
    fn is_server() -> bool {
        false
    }

    fn select<A: AsRef<str> + Clone, B: AsRef<str> + Clone>(
        client_list: &[A],
        server_list: &[B],
        kind: AlgorithmKind,
    ) -> Result<(bool, A), Error> {
        let mut both_first_choice = true;
        for c in client_list {
            for s in server_list {
                if s.as_ref() == c.as_ref() {
                    return Ok((both_first_choice, c.clone()));
                }
                both_first_choice = false
            }
        }
        Err(Error::NoCommonAlgo {
            kind,
            ours: client_list.iter().map(|x| x.as_ref().to_owned()).collect(),
            theirs: server_list.iter().map(|x| x.as_ref().to_owned()).collect(),
        })
    }
}

pub(crate) fn write_kex(
    prefs: &Preferred,
    writer: &mut PacketWriter,
    server_config: Option<&Config>,
) -> Result<Bytes, Error> {
    writer.packet_bytes(|w| {
        msg::KEXINIT.encode(w)?;

        let mut cookie = [0; 16];
        safe_rng().fill_bytes(&mut cookie);
        for b in cookie {
            b.encode(w)?;
        }

        NameList(
            prefs
                .kex
                .iter()
                .filter(|k| {
                    !(if server_config.is_some() {
                        [
                            crate::kex::EXTENSION_SUPPORT_AS_CLIENT,
                            crate::kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
                        ]
                    } else {
                        [
                            crate::kex::EXTENSION_SUPPORT_AS_SERVER,
                            crate::kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
                        ]
                    })
                    .contains(*k)
                })
                .map(|x| x.as_ref().to_owned())
                .collect(),
        )
        .encode(w)?; // kex algo

        if let Some(server_config) = server_config {
            // Only advertise host key algorithms that we have keys for, with
            // certificate algorithms ahead of plain keys so a client that
            // accepts both is served the certificate.
            NameList(
                server_certificate_names(prefs, &server_config.certificates, &server_config.keys)
                    .into_iter()
                    .chain(
                        prefs
                            .key
                            .iter()
                            .filter(|algo| {
                                server_config
                                    .keys
                                    .iter()
                                    .any(|k| is_key_compatible_with_algo(k, algo))
                            })
                            .map(|x| x.to_string()),
                    )
                    .collect(),
            )
            .encode(w)?;
        } else {
            NameList(
                prefs
                    .host_key_certificates
                    .iter()
                    .map(Algorithm::to_certificate_type)
                    .chain(prefs.key.iter().map(ToString::to_string))
                    .collect(),
            )
            .encode(w)?;
        }

        // cipher client to server
        NameList(
            prefs
                .cipher
                .iter()
                .map(|x| x.as_ref().to_string())
                .collect(),
        )
        .encode(w)?;

        // cipher server to client
        NameList(
            prefs
                .cipher
                .iter()
                .map(|x| x.as_ref().to_string())
                .collect(),
        )
        .encode(w)?;

        // mac client to server
        NameList(prefs.mac.iter().map(|x| x.as_ref().to_string()).collect()).encode(w)?;

        // mac server to client
        NameList(prefs.mac.iter().map(|x| x.as_ref().to_string()).collect()).encode(w)?;

        // compress client to server
        NameList(
            prefs
                .compression
                .iter()
                .map(|x| x.as_ref().to_string())
                .collect(),
        )
        .encode(w)?;

        // compress server to client
        NameList(
            prefs
                .compression
                .iter()
                .map(|x| x.as_ref().to_string())
                .collect(),
        )
        .encode(w)?;

        Vec::<String>::new().encode(w)?; // languages client to server
        Vec::<String>::new().encode(w)?; // languages server to client

        0u8.encode(w)?; // doesn't follow
        0u32.encode(w)?; // reserved
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use ssh_encoding::Encode;

    use super::*;
    use crate::helpers::NameList;

    /// Build a minimal KEXINIT payload with custom kex and host-key
    /// name-lists and a `first_kex_packet_follows` flag. All other lists come
    /// from the default preferences so negotiation succeeds.
    fn build_kexinit_keys(kex_names: &[&str], key_names: &[&str], follows: bool) -> Vec<u8> {
        let pref = Preferred::DEFAULT;
        let mut buf = vec![msg::KEXINIT];
        buf.extend_from_slice(&[0u8; 16]); // cookie
        let names = |v: Vec<String>| NameList(v);
        names(kex_names.iter().map(|s| s.to_string()).collect())
            .encode(&mut buf)
            .unwrap();
        names(key_names.iter().map(|s| s.to_string()).collect())
            .encode(&mut buf)
            .unwrap();
        for _ in 0..2 {
            names(pref.cipher.iter().map(|x| x.as_ref().to_string()).collect())
                .encode(&mut buf)
                .unwrap();
        }
        for _ in 0..2 {
            names(pref.mac.iter().map(|x| x.as_ref().to_string()).collect())
                .encode(&mut buf)
                .unwrap();
        }
        for _ in 0..2 {
            names(
                pref.compression
                    .iter()
                    .map(|x| x.as_ref().to_string())
                    .collect(),
            )
            .encode(&mut buf)
            .unwrap();
        }
        Vec::<String>::new().encode(&mut buf).unwrap(); // lang c2s
        Vec::<String>::new().encode(&mut buf).unwrap(); // lang s2c
        (follows as u8).encode(&mut buf).unwrap();
        0u32.encode(&mut buf).unwrap();
        buf
    }

    fn build_kexinit(kex_names: &[&str], follows: bool) -> Vec<u8> {
        let keys = Preferred::DEFAULT
            .key
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        build_kexinit_keys(
            kex_names,
            &keys.iter().map(String::as_str).collect::<Vec<_>>(),
            follows,
        )
    }

    /// Regression test for #733: a client that optimistically guesses a kex
    /// algorithm russh does not implement (`sntrup761x25519-sha512`) — while
    /// listing russh's own first choice (`mlkem768x25519-sha256`) second —
    /// must have its guessed packet ignored, not consumed as the negotiated key.
    #[test]
    fn wrong_guess_for_unknown_kex_is_ignored() {
        let buf = build_kexinit(
            &[
                "sntrup761x25519-sha512",
                "mlkem768x25519-sha256",
                "curve25519-sha256",
            ],
            true,
        );
        let names = Server::read_kex(&buf, &Preferred::DEFAULT, None,
            None, &KexCause::Initial).unwrap();
        assert_eq!(names.kex, kex::MLKEM768X25519_SHA256);
        assert!(names.ignore_guessed, "wrong guess must be ignored");
    }

    /// A correct guess (client's first == server's first) must NOT be ignored.
    #[test]
    fn correct_guess_is_not_ignored() {
        let buf = build_kexinit(&["mlkem768x25519-sha256", "curve25519-sha256"], true);
        let names = Server::read_kex(&buf, &Preferred::DEFAULT, None,
            None, &KexCause::Initial).unwrap();
        assert!(!names.ignore_guessed, "correct guess must be honored");
    }

    const KEX_FIRST: &[&str] = &["mlkem768x25519-sha256"];
    const ED25519_CERT: &str = "ssh-ed25519-cert-v01@openssh.com";

    fn cert_prefs(certs: &'static [Algorithm]) -> Preferred {
        Preferred {
            host_key_certificates: Cow::Borrowed(certs),
            ..Preferred::DEFAULT
        }
    }

    #[test]
    fn certificate_negotiated_when_advertised() {
        let buf = build_kexinit_keys(KEX_FIRST, &[ED25519_CERT, "ssh-ed25519"], false);
        let names = Client::read_kex(
            &buf,
            &cert_prefs(&[Algorithm::Ed25519]),
            None,
            None,
            &KexCause::Initial,
        )
        .unwrap();
        assert!(names.host_key_is_certificate);
        assert_eq!(names.key, Algorithm::Ed25519);
    }

    /// The negotiated algorithm for an RSA certificate must keep the hash
    /// variant: it is what verifies the exchange signature.
    #[test]
    fn rsa_certificate_keeps_hash_variant() {
        let buf = build_kexinit_keys(KEX_FIRST, &["rsa-sha2-512-cert-v01@openssh.com"], false);
        let names = Client::read_kex(
            &buf,
            &cert_prefs(&[Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            }]),
            None,
            None,
            &KexCause::Initial,
        )
        .unwrap();
        assert!(names.host_key_is_certificate);
        assert_eq!(
            names.key,
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha512)
            }
        );
    }

    /// A client that did not opt into certificates must never negotiate one,
    /// no matter what the server offers.
    #[test]
    fn certificate_ignored_when_not_advertised() {
        let buf = build_kexinit_keys(KEX_FIRST, &[ED25519_CERT, "ssh-ed25519"], false);
        let names = Client::read_kex(&buf, &Preferred::DEFAULT, None,
            None, &KexCause::Initial).unwrap();
        assert!(!names.host_key_is_certificate);
        assert_eq!(names.key, Algorithm::Ed25519);
    }

    /// `host_key_certificates` is client-only: a server has no certificate to
    /// present, so its negotiation must ignore the field entirely.
    #[test]
    fn server_ignores_certificate_preferences() {
        let buf = build_kexinit_keys(KEX_FIRST, &[ED25519_CERT, "ssh-ed25519"], false);
        let names = Server::read_kex(
            &buf,
            &cert_prefs(&[Algorithm::Ed25519]),
            None,
            None,
            &KexCause::Initial,
        )
        .unwrap();
        assert!(!names.host_key_is_certificate);
        assert_eq!(names.key, Algorithm::Ed25519);
    }

    /// Certificates are advertised ahead of plain keys, so a peer guess that
    /// matches the certificate is a correct guess…
    #[test]
    fn certificate_correct_guess_not_ignored() {
        let buf = build_kexinit_keys(KEX_FIRST, &[ED25519_CERT, "ssh-ed25519"], true);
        let names = Client::read_kex(
            &buf,
            &cert_prefs(&[Algorithm::Ed25519]),
            None,
            None,
            &KexCause::Initial,
        )
        .unwrap();
        assert!(names.host_key_is_certificate);
        assert!(!names.ignore_guessed);
    }

    /// …while a peer whose first choice is the plain key — or who offers no
    /// certificate at all — guessed wrong, and the guessed packet must be
    /// ignored: with certificates enabled the client's own first choice is
    /// always the certificate.
    #[test]
    fn plain_first_choice_with_certificates_enabled_is_wrong_guess() {
        let buf = build_kexinit_keys(KEX_FIRST, &["ssh-ed25519", ED25519_CERT], true);
        let names = Client::read_kex(
            &buf,
            &cert_prefs(&[Algorithm::Ed25519]),
            None,
            None,
            &KexCause::Initial,
        )
        .unwrap();
        assert!(
            names.host_key_is_certificate,
            "client preference still wins"
        );
        assert!(names.ignore_guessed);

        let buf = build_kexinit_keys(KEX_FIRST, &["ssh-ed25519"], true);
        let names = Client::read_kex(
            &buf,
            &cert_prefs(&[Algorithm::Ed25519]),
            None,
            None,
            &KexCause::Initial,
        )
        .unwrap();
        assert!(!names.host_key_is_certificate);
        assert!(names.ignore_guessed);
    }

    /// A cipher that requires a separate integrity MAC (aes*-ctr/cbc, 3des)
    /// must never negotiate `mac=none`, even when both peers list `none` as a
    /// common choice: the resulting tag_len()==0 pairing panics the read path.
    #[test]
    fn needs_mac_cipher_rejects_negotiated_none_mac() {
        let pref = Preferred::DEFAULT;
        let mut buf = vec![msg::KEXINIT];
        buf.extend_from_slice(&[0u8; 16]); // cookie
        let names = |v: Vec<String>| NameList(v);
        names(pref.kex.iter().map(|x| x.as_ref().to_string()).collect())
            .encode(&mut buf)
            .unwrap();
        names(pref.key.iter().map(ToString::to_string).collect())
            .encode(&mut buf)
            .unwrap();
        // aes256-ctr, which needs_mac().
        for _ in 0..2 {
            names(vec!["aes256-ctr".to_string()])
                .encode(&mut buf)
                .unwrap();
        }
        // Only `none` offered for MAC.
        for _ in 0..2 {
            names(vec!["none".to_string()]).encode(&mut buf).unwrap();
        }
        for _ in 0..2 {
            names(
                pref.compression
                    .iter()
                    .map(|x| x.as_ref().to_string())
                    .collect(),
            )
            .encode(&mut buf)
            .unwrap();
        }
        Vec::<String>::new().encode(&mut buf).unwrap(); // lang c2s
        Vec::<String>::new().encode(&mut buf).unwrap(); // lang s2c
        0u8.encode(&mut buf).unwrap(); // follows
        0u32.encode(&mut buf).unwrap();

        // A `none`-only MAC list must ship `none` in local prefs to be common.
        let with_none_mac = Preferred {
            cipher: Cow::Borrowed(&[cipher::AES_256_CTR]),
            mac: Cow::Borrowed(&[mac::NONE]),
            ..Preferred::DEFAULT
        };
        assert!(
            Server::read_kex(&buf, &with_none_mac, None, None, &KexCause::Initial).is_err(),
            "aes-ctr + mac=none must be refused"
        );
    }

    fn host_cert(subject: &PrivateKey, ca: &PrivateKey) -> Certificate {
        let mut builder = ssh_key::certificate::Builder::new_with_random_nonce(
            &mut rand::rng(),
            subject.public_key(),
            0,
            u64::MAX,
        )
        .unwrap();
        builder.key_id("test").unwrap();
        builder
            .cert_type(ssh_key::certificate::CertType::Host)
            .unwrap();
        builder.valid_principal("localhost").unwrap();
        builder.sign(ca).unwrap()
    }

    /// A certificate without a matching private key can never be honored and
    /// must not be advertised.
    #[test]
    fn certificate_without_matching_key_is_not_advertised() {
        let ca = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let stale_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let good_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let stale_cert = host_cert(&stale_key, &ca);
        let good_cert = host_cert(&good_key, &ca);

        let keys = vec![good_key];
        assert_eq!(
            server_certificate_names(&Preferred::DEFAULT, &[stale_cert], &keys),
            Vec::<String>::new()
        );
        assert_eq!(
            server_certificate_names(&Preferred::DEFAULT, &[good_cert], &keys),
            vec![ED25519_CERT.to_string()]
        );
    }

    /// A certificate whose algorithm is excluded from `pref.key` must not be
    /// advertised: the preference list gates certificates like plain keys.
    #[test]
    fn certificate_for_banned_algorithm_is_not_advertised() {
        let ca = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let cert = host_cert(&key, &ca);
        let keys = vec![key];

        let no_ed25519 = Preferred {
            key: Cow::Owned(vec![Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            }]),
            ..Preferred::DEFAULT
        };
        assert_eq!(
            server_certificate_names(&no_ed25519, std::slice::from_ref(&cert), &keys),
            Vec::<String>::new()
        );
        assert_eq!(
            server_certificate_names(&Preferred::DEFAULT, &[cert], &keys),
            vec![ED25519_CERT.to_string()]
        );
    }

    /// The RSA cert variants a server advertises follow `pref.key`, so the
    /// preference list stays the policy knob for e.g. banning SHA-1.
    #[cfg(feature = "rsa")]
    #[test]
    fn rsa_certificate_variants_follow_preferences() {
        let ca = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let rsa_key =
            PrivateKey::random(&mut rand::rng(), Algorithm::Rsa { hash: None }).unwrap();
        let cert = host_cert(&rsa_key, &ca);
        let keys = vec![rsa_key];

        // Default preferences allow all three variants, in preference order.
        assert_eq!(
            server_certificate_names(&Preferred::DEFAULT, std::slice::from_ref(&cert), &keys),
            vec![
                "rsa-sha2-512-cert-v01@openssh.com".to_string(),
                "rsa-sha2-256-cert-v01@openssh.com".to_string(),
                "ssh-rsa-cert-v01@openssh.com".to_string(),
            ]
        );

        // Preferences without `ssh-rsa` must not advertise its cert variant.
        let no_sha1 = Preferred {
            key: Cow::Owned(vec![Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            }]),
            ..Preferred::DEFAULT
        };
        assert_eq!(
            server_certificate_names(&no_sha1, &[cert], &keys),
            vec!["rsa-sha2-512-cert-v01@openssh.com".to_string()]
        );
    }
}
