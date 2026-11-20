use std::marker::PhantomData;
use std::ops::Deref;

use byteorder::{BigEndian, ByteOrder};
use elliptic_curve::Generate;
use elliptic_curve::ecdh::{EphemeralSecret, SharedSecret};
use elliptic_curve::point::PointCompression;
use elliptic_curve::sec1::{FromSec1Point, ModulusSize, ToSec1Point};
use elliptic_curve::{AffinePoint, Curve, CurveArithmetic, FieldBytesSize};
use log::debug;
use p256::NistP256;
use p384::NistP384;
use p521::NistP521;
use sha2::{Digest, Sha256, Sha384, Sha512};
use ssh_encoding::{Encode, Writer};

use super::{KexAlgorithm, SharedSecret as KexSharedSecret, encode_mpint};
use crate::kex::{KexAlgorithmImplementor, KexType, compute_keys};
use crate::mac::{self};
use crate::session::Exchange;
use crate::{CryptoVec, cipher, msg};

pub struct EcdhNistP256KexType {}

impl KexType for EcdhNistP256KexType {
    fn make(&self) -> KexAlgorithm {
        EcdhNistPKex::<NistP256, Sha256> {
            local_secret: None,
            shared_secret: None,
            _digest: PhantomData,
        }
        .into()
    }
}

pub struct EcdhNistP384KexType {}

impl KexType for EcdhNistP384KexType {
    fn make(&self) -> KexAlgorithm {
        EcdhNistPKex::<NistP384, Sha384> {
            local_secret: None,
            shared_secret: None,
            _digest: PhantomData,
        }
        .into()
    }
}

pub struct EcdhNistP521KexType {}

impl KexType for EcdhNistP521KexType {
    fn make(&self) -> KexAlgorithm {
        EcdhNistPKex::<NistP521, Sha512> {
            local_secret: None,
            shared_secret: None,
            _digest: PhantomData,
        }
        .into()
    }
}

#[doc(hidden)]
pub struct EcdhNistPKex<C: Curve + CurveArithmetic, D: Digest> {
    local_secret: Option<EphemeralSecret<C>>,
    shared_secret: Option<SharedSecret<C>>,
    _digest: PhantomData<D>,
}

impl<C: Curve + CurveArithmetic, D: Digest> std::fmt::Debug for EcdhNistPKex<C, D> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Algorithm {{ local_secret: [hidden], shared_secret: [hidden] }}",
        )
    }
}

impl<C: Curve + CurveArithmetic, D: Digest> KexAlgorithmImplementor for EcdhNistPKex<C, D>
where
    C: PointCompression,
    FieldBytesSize<C>: ModulusSize,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
{
    fn skip_exchange(&self) -> bool {
        false
    }

    #[doc(hidden)]
    fn server_dh(&mut self, exchange: &mut Exchange, payload: &[u8]) -> Result<(), crate::Error> {
        debug!("server_dh");

        let client_pubkey = {
            if payload.first() != Some(&msg::KEX_ECDH_INIT) {
                return Err(crate::Error::Inconsistent);
            }

            #[allow(clippy::indexing_slicing)] // length checked
            let pubkey_len = BigEndian::read_u32(&payload[1..]) as usize;

            if payload.len() < 5 + pubkey_len {
                return Err(crate::Error::Inconsistent);
            }

            #[allow(clippy::indexing_slicing)] // length checked
            elliptic_curve::PublicKey::<C>::from_sec1_bytes(&payload[5..(5 + pubkey_len)])
                .map_err(|_| crate::Error::Inconsistent)?
        };

        let server_secret = elliptic_curve::ecdh::EphemeralSecret::<C>::generate_from_rng(&mut rand::rng());
        let server_pubkey = server_secret.public_key();

        // fill exchange.
        exchange.server_ephemeral.clear();
        exchange
            .server_ephemeral
            .extend_from_slice(&server_pubkey.to_sec1_bytes());
        let shared = server_secret.diffie_hellman(&client_pubkey);
        self.shared_secret = Some(shared);
        Ok(())
    }

    #[doc(hidden)]
    fn client_dh(
        &mut self,
        client_ephemeral: &mut Vec<u8>,
        writer: &mut impl Writer,
    ) -> Result<(), crate::Error> {
        let client_secret = elliptic_curve::ecdh::EphemeralSecret::<C>::generate_from_rng(&mut rand::rng());
        let client_pubkey = client_secret.public_key();

        // fill exchange.
        client_ephemeral.clear();
        client_ephemeral.extend_from_slice(&client_pubkey.to_sec1_bytes());

        msg::KEX_ECDH_INIT.encode(writer)?;
        client_pubkey.to_sec1_bytes().encode(writer)?;

        self.local_secret = Some(client_secret);
        Ok(())
    }

    fn compute_shared_secret(&mut self, remote_pubkey_: &[u8]) -> Result<(), crate::Error> {
        let local_secret = self.local_secret.take().ok_or(crate::Error::KexInit)?;
        let pubkey = elliptic_curve::PublicKey::<C>::from_sec1_bytes(remote_pubkey_)
            .map_err(|_| crate::Error::KexInit)?;
        self.shared_secret = Some(local_secret.diffie_hellman(&pubkey));
        Ok(())
    }

    fn shared_secret_bytes(&self) -> Option<&[u8]> {
        self.shared_secret
            .as_ref()
            .map(|s| s.raw_secret_bytes().deref())
    }

    fn compute_exchange_hash(
        &self,
        key: &[u8],
        exchange: &Exchange,
        buffer: &mut CryptoVec,
    ) -> Result<Vec<u8>, crate::Error> {
        // Computing the exchange hash, see page 7 of RFC 5656.
        buffer.clear();
        exchange.client_id.deref().encode(buffer)?;
        exchange.server_id.deref().encode(buffer)?;
        exchange.client_kex_init.deref().encode(buffer)?;
        exchange.server_kex_init.deref().encode(buffer)?;

        buffer.extend(key);
        exchange.client_ephemeral.deref().encode(buffer)?;
        exchange.server_ephemeral.deref().encode(buffer)?;

        if let Some(ref shared) = self.shared_secret {
            encode_mpint(shared.raw_secret_bytes(), buffer)?;
        }

        let mut hasher = D::new();
        hasher.update(&buffer);

        Ok(hasher.finalize().to_vec())
    }

    fn compute_keys(
        &self,
        session_id: &[u8],
        exchange_hash: &[u8],
        cipher: cipher::Name,
        remote_to_local_mac: mac::Name,
        local_to_remote_mac: mac::Name,
        is_server: bool,
    ) -> Result<crate::kex::cipher::CipherPair, crate::Error> {
        let shared_secret = self
            .shared_secret
            .as_ref()
            .map(|x| KexSharedSecret::from_mpint(x.raw_secret_bytes()))
            .transpose()?;

        compute_keys::<D>(
            shared_secret.as_ref(),
            session_id,
            exchange_hash,
            cipher,
            remote_to_local_mac,
            local_to_remote_mac,
            is_server,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shared_secret() {
        let mut party1 = EcdhNistPKex::<NistP256, Sha256> {
            local_secret: Some(EphemeralSecret::<NistP256>::generate_from_rng(&mut rand::rng())),
            shared_secret: None,
            _digest: PhantomData,
        };
        let p1_pubkey = party1.local_secret.as_ref().unwrap().public_key();

        let mut party2 = EcdhNistPKex::<NistP256, Sha256> {
            local_secret: Some(EphemeralSecret::<NistP256>::generate_from_rng(&mut rand::rng())),
            shared_secret: None,
            _digest: PhantomData,
        };
        let p2_pubkey = party2.local_secret.as_ref().unwrap().public_key();

        party1
            .compute_shared_secret(&p2_pubkey.to_sec1_bytes())
            .unwrap();

        party2
            .compute_shared_secret(&p1_pubkey.to_sec1_bytes())
            .unwrap();

        let p1_shared_secret = party1.shared_secret.unwrap();
        let p2_shared_secret = party2.shared_secret.unwrap();

        assert_eq!(
            p1_shared_secret.raw_secret_bytes(),
            p2_shared_secret.raw_secret_bytes()
        )
    }
}
