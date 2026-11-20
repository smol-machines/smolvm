use std::convert::{TryFrom, TryInto};

use p256::NistP256;
use p384::NistP384;
use p521::NistP521;
use pkcs8::{AssociatedOid, EncodePrivateKey, PrivateKeyInfoRef, SecretDocument};
use spki::ObjectIdentifier;
use ssh_key::PrivateKey;
use ssh_key::private::{EcdsaKeypair, Ed25519Keypair, Ed25519PrivateKey, KeypairData};

use crate::keys::Error;
use crate::keys::key::safe_rng;

/// Decode a PKCS#8-encoded private key (ASN.1 or X9.62)
pub fn decode_pkcs8(
    ciphertext: &[u8],
    password: Option<&[u8]>,
) -> Result<ssh_key::PrivateKey, Error> {
    let doc = SecretDocument::try_from(ciphertext)?;
    let doc = if let Some(password) = password {
        doc.decode_msg::<pkcs8::EncryptedPrivateKeyInfoRef<'_>>()?
            .decrypt(password)?
    } else {
        doc
    };

    if let Ok(key) = doc.decode_msg::<sec1::EcPrivateKey>() {
        // X9.62 EC private key
        let Some(curve) = key.parameters.and_then(|x| x.named_curve()) else {
            return Err(Error::CouldNotReadKey);
        };
        let kp = ec_key_data_into_keypair(curve, key)?;
        return Ok(PrivateKey::new(KeypairData::Ecdsa(kp), "")?);
    }

    // SEC1 key with full domain parameters (not a named curve OID)
    if let Ok(kp) = explicit_curve_params::decode_sec1_with_full_domain_params(ciphertext) {
        return Ok(PrivateKey::new(KeypairData::Ecdsa(kp), "")?);
    }

    // ASN.1 key (PKCS#8)
    Ok(pkcs8_pki_into_keypair_data(doc.decode_msg::<PrivateKeyInfoRef<'_>>()?)?.try_into()?)
}

fn pkcs8_pki_into_keypair_data(pki: PrivateKeyInfoRef<'_>) -> Result<KeypairData, Error> {
    // Temporary if {} due to multiple const_oid crate versions
    #[cfg(feature = "rsa")]
    if pki.algorithm.oid.as_bytes() == pkcs1::ALGORITHM_OID.as_bytes() {
        let sk = &pkcs1::RsaPrivateKeyRef::try_from(pki.private_key)?;
        let pk = rsa::PrivateKey::from_components(
            rsa::BoxedUint::from_be_slice_vartime(sk.modulus.as_bytes()),
            rsa::BoxedUint::from_be_slice_vartime(sk.public_exponent.as_bytes()),
            rsa::BoxedUint::from_be_slice_vartime(sk.private_exponent.as_bytes()),
            vec![
                rsa::BoxedUint::from_be_slice_vartime(sk.prime1.as_bytes()),
                rsa::BoxedUint::from_be_slice_vartime(sk.prime2.as_bytes()),
            ],
        )?;
        return Ok(KeypairData::Rsa(pk.try_into()?));
    }
    match pki.algorithm.oid {
        ed25519_dalek::pkcs8::ALGORITHM_OID => {
            let kpb = ed25519_dalek::pkcs8::KeypairBytes::try_from(pki)?;
            let pk = Ed25519PrivateKey::from_bytes(&kpb.secret_key);
            Ok(KeypairData::Ed25519(Ed25519Keypair {
                public: pk.clone().into(),
                private: pk,
            }))
        }
        sec1::ALGORITHM_OID => Ok(KeypairData::Ecdsa(ec_key_data_into_keypair(
            pki.algorithm.parameters_oid()?,
            pki,
        )?)),
        oid => Err(Error::UnknownAlgorithm(oid)),
    }
}

fn ec_key_data_into_keypair<K, E>(
    curve_oid: ObjectIdentifier,
    private_key: K,
) -> Result<EcdsaKeypair, Error>
where
    p256::SecretKey: TryFrom<K, Error = E>,
    p384::SecretKey: TryFrom<K, Error = E>,
    p521::SecretKey: TryFrom<K, Error = E>,
    crate::keys::Error: From<E>,
{
    Ok(match curve_oid {
        NistP256::OID => {
            let sk = p256::SecretKey::try_from(private_key)?;
            EcdsaKeypair::NistP256 {
                public: sk.public_key().into(),
                private: sk.into(),
            }
        }
        NistP384::OID => {
            let sk = p384::SecretKey::try_from(private_key)?;
            EcdsaKeypair::NistP384 {
                public: sk.public_key().into(),
                private: sk.into(),
            }
        }
        NistP521::OID => {
            let sk = p521::SecretKey::try_from(private_key)?;
            EcdsaKeypair::NistP521 {
                public: sk.public_key().into(),
                private: sk.into(),
            }
        }
        oid => return Err(Error::UnknownAlgorithm(oid)),
    })
}

mod explicit_curve_params {
    use super::*;

    use der::{
        Reader, SliceReader, Tag, TagNumber, Tagged,
        asn1::{AnyRef, ContextSpecific, UintRef},
    };

    /// Try to parse an SEC1 EC key with full domain parameters.
    ///
    /// Some key generators (e.g. OpenSSL with certain options) produce SEC1 keys
    /// where the `[0]` parameters field contains full EC domain parameters instead
    /// of a named curve OID. The `sec1` crate does not support this format.
    pub fn decode_sec1_with_full_domain_params(der_bytes: &[u8]) -> Result<EcdsaKeypair, Error> {
        let mut reader = SliceReader::new(der_bytes)?;
        reader.sequence(|seq| {
            let version: u8 = seq.decode()?;
            if version < 1 {
                return Err(Error::CouldNotReadKey);
            }

            let priv_key: AnyRef = seq.decode()?;
            priv_key.tag().assert_eq(Tag::OctetString)?;

            let params = ContextSpecific::<AnyRef>::decode_explicit(seq, TagNumber(0))?
                .ok_or(Error::CouldNotReadKey)?;

            let curve_oid = extract_curve_from_domain_params(params.value)?;

            let keypair = build_ec_keypair_from_bytes(curve_oid, priv_key.value())?;

            // Drain any remaining optional fields (e.g. [1] publicKey) so finish() succeeds
            seq.drain(seq.remaining_len())?;
            Ok(keypair)
        })
    }

    /// Extract the named curve OID from full EC domain parameters.
    /// Handles two formats:
    /// 1. Standard ECParameters: SEQUENCE { FieldID, Curve, base, order, cofactor }
    /// 2. Wrapped ECParameters: SEQUENCE { INTEGER version, SEQUENCE { FieldID, ... } }
    fn extract_curve_from_domain_params(params: AnyRef<'_>) -> Result<ObjectIdentifier, Error> {
        params.tag().assert_eq(Tag::Sequence)?;

        // Use a standalone SliceReader so we aren't required to consume all of ECParams
        // (Curve, base, order, cofactor follow FieldID but are irrelevant here).
        let mut seq = SliceReader::new(params.value())?;

        // Skip optional ECParameters version INTEGER
        if Tag::peek(&seq)? == Tag::Integer {
            seq.decode::<u8>()?;
        }

        // FieldID ::= SEQUENCE { fieldType OID, parameters ANY }
        seq.sequence(|field_id| {
            let _field_oid: ObjectIdentifier = field_id.decode()?;
            // prime INTEGER — as_bytes() strips DER sign-extension leading zero
            let prime: UintRef = field_id.decode()?;
            Ok(match prime.as_bytes().len() {
                32 => NistP256::OID,
                48 => NistP384::OID,
                66 => NistP521::OID,
                _ => return Err(Error::CouldNotReadKey),
            })
        })
    }

    /// Build an EcdsaKeypair from raw private key bytes and a curve OID.
    fn build_ec_keypair_from_bytes(
        curve_oid: ObjectIdentifier,
        private_key_bytes: &[u8],
    ) -> Result<EcdsaKeypair, Error> {
        if curve_oid == NistP256::OID {
            let sk = p256::SecretKey::from_slice(private_key_bytes)
                .map_err(|_| Error::CouldNotReadKey)?;
            Ok(EcdsaKeypair::NistP256 {
                public: sk.public_key().into(),
                private: sk.into(),
            })
        } else if curve_oid == NistP384::OID {
            let sk = p384::SecretKey::from_slice(private_key_bytes)
                .map_err(|_| Error::CouldNotReadKey)?;
            Ok(EcdsaKeypair::NistP384 {
                public: sk.public_key().into(),
                private: sk.into(),
            })
        } else if curve_oid == NistP521::OID {
            let sk = p521::SecretKey::from_slice(private_key_bytes)
                .map_err(|_| Error::CouldNotReadKey)?;
            Ok(EcdsaKeypair::NistP521 {
                public: sk.public_key().into(),
                private: sk.into(),
            })
        } else {
            Err(Error::UnknownAlgorithm(curve_oid))
        }
    }
}

/// Encode into a password-protected PKCS#8-encoded private key.
pub fn encode_pkcs8_encrypted(
    pass: &[u8],
    rounds: u32,
    key: &PrivateKey,
) -> Result<Vec<u8>, Error> {
    let pvi_bytes = encode_pkcs8(key)?;
    let pvi = PrivateKeyInfoRef::try_from(pvi_bytes.as_slice())?;

    use rand_core::Rng;
    let mut rng = safe_rng();
    let mut salt = [0; 32];
    rng.fill_bytes(&mut salt);
    let mut iv = [0; 16];
    rng.fill_bytes(&mut iv);

    let doc = pvi.encrypt_with_params(
        pkcs5::pbes2::Parameters::generate_pbkdf2_sha256_aes256cbc(rounds, &salt, iv)
            .map_err(|_| Error::InvalidParameters)?,
        pass,
    )?;
    Ok(doc.as_bytes().to_vec())
}

/// Encode into a PKCS#8-encoded private key.
pub fn encode_pkcs8(key: &ssh_key::PrivateKey) -> Result<Vec<u8>, Error> {
    let v = match key.key_data() {
        ssh_key::private::KeypairData::Ed25519(pair) => {
            let sk: ed25519_dalek::SigningKey = pair.try_into()?;
            sk.to_pkcs8_der()?.as_bytes().to_vec()
        }
        #[cfg(feature = "rsa")]
        ssh_key::private::KeypairData::Rsa(pair) => {
            use rsa::pkcs8::EncodePrivateKey;
            let sk: rsa::PrivateKey = pair.try_into()?;
            sk.to_pkcs8_der()?.as_bytes().to_vec()
        }
        ssh_key::private::KeypairData::Ecdsa(pair) => match pair {
            EcdsaKeypair::NistP256 { private, .. } => {
                let sk = p256::SecretKey::from_slice(private.as_slice())?;
                sk.to_pkcs8_der()?.as_bytes().to_vec()
            }
            EcdsaKeypair::NistP384 { private, .. } => {
                let sk = p384::SecretKey::from_slice(private.as_slice())?;
                sk.to_pkcs8_der()?.as_bytes().to_vec()
            }
            EcdsaKeypair::NistP521 { private, .. } => {
                let sk = p521::SecretKey::from_slice(private.as_slice())?;
                sk.to_pkcs8_der()?.as_bytes().to_vec()
            }
        },
        _ => {
            let algo = key.algorithm();
            let kt = algo.as_str();
            return Err(Error::UnsupportedKeyType {
                key_type_string: kt.into(),
                key_type_raw: kt.as_bytes().into(),
            });
        }
    };
    Ok(v)
}
