use byteorder::{BigEndian, ByteOrder};
use curve25519_dalek::montgomery::MontgomeryPoint;
use log::debug;
use sha2::Digest;
use ssh_encoding::{Encode, Writer};

use super::{
    KexAlgorithm, KexAlgorithmImplementor, KexType, SharedSecret, compute_keys, encode_mpint,
};
use crate::mac::{self};
use crate::session::Exchange;
use crate::{CryptoVec, cipher, msg};

pub struct Curve25519KexType {}

impl KexType for Curve25519KexType {
    fn make(&self) -> KexAlgorithm {
        Curve25519Kex {
            local_secret: None,
            shared_secret: None,
        }
        .into()
    }
}

#[doc(hidden)]
pub struct Curve25519Kex {
    local_secret: Option<[u8; 32]>,
    shared_secret: Option<MontgomeryPoint>,
}

impl std::fmt::Debug for Curve25519Kex {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Algorithm {{ local_secret: [hidden], shared_secret: [hidden] }}",
        )
    }
}

// We used to support curve "NIST P-256" here, but the security of
// that curve is controversial, see
// http://safecurves.cr.yp.to/rigid.html
impl KexAlgorithmImplementor for Curve25519Kex {
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

            if pubkey_len != 32 {
                return Err(crate::Error::Kex);
            }

            if payload.len() < 5 + pubkey_len {
                return Err(crate::Error::Inconsistent);
            }

            let mut pubkey = MontgomeryPoint([0; 32]);
            #[allow(clippy::indexing_slicing)] // length checked
            pubkey.0.clone_from_slice(&payload[5..5 + 32]);
            pubkey
        };

        let server_secret = rand::random::<[u8; 32]>();
        let server_pubkey = MontgomeryPoint::mul_base_clamped(server_secret);

        // fill exchange.
        exchange.server_ephemeral.clear();
        exchange
            .server_ephemeral
            .extend_from_slice(&server_pubkey.0);
        let shared = client_pubkey.mul_clamped(server_secret);
        if shared.0 == [0u8; 32] {
            // Non-contributory: the client sent a low-order point.
            debug!("client sent a low-order curve25519 pubkey");
            return Err(crate::Error::Kex);
        }
        self.shared_secret = Some(shared);
        Ok(())
    }

    #[doc(hidden)]
    fn client_dh(
        &mut self,
        client_ephemeral: &mut Vec<u8>,
        writer: &mut impl Writer,
    ) -> Result<(), crate::Error> {
        let client_secret = rand::random::<[u8; 32]>();
        let client_pubkey = MontgomeryPoint::mul_base_clamped(client_secret);

        // fill exchange.
        client_ephemeral.clear();
        client_ephemeral.extend_from_slice(&client_pubkey.0);

        msg::KEX_ECDH_INIT.encode(writer)?;
        (client_pubkey.0[..]).encode(writer)?;

        self.local_secret = Some(client_secret);
        Ok(())
    }

    fn compute_shared_secret(&mut self, remote_pubkey_: &[u8]) -> Result<(), crate::Error> {
        let local_secret = self.local_secret.take().ok_or(crate::Error::KexInit)?;
        if remote_pubkey_.len() != 32 {
            return Err(crate::Error::Kex);
        }
        let mut remote_pubkey = MontgomeryPoint([0; 32]);
        remote_pubkey.0.clone_from_slice(remote_pubkey_);
        let shared = remote_pubkey.mul_clamped(local_secret);
        if shared.0 == [0u8; 32] {
            // Non-contributory: the server sent a low-order point.
            debug!("server sent a low-order curve25519 pubkey");
            return Err(crate::Error::Kex);
        }
        self.shared_secret = Some(shared);
        Ok(())
    }

    fn shared_secret_bytes(&self) -> Option<&[u8]> {
        self.shared_secret.as_ref().map(|s| s.0.as_slice())
    }

    fn compute_exchange_hash(
        &self,
        key: &[u8],
        exchange: &Exchange,
        buffer: &mut CryptoVec,
    ) -> Result<Vec<u8>, crate::Error> {
        // Computing the exchange hash, see page 7 of RFC 5656.
        buffer.clear();
        exchange.client_id.encode(buffer)?;
        exchange.server_id.encode(buffer)?;
        exchange.client_kex_init.encode(buffer)?;
        exchange.server_kex_init.encode(buffer)?;

        buffer.extend(key);
        exchange.client_ephemeral.encode(buffer)?;
        exchange.server_ephemeral.encode(buffer)?;

        if let Some(ref shared) = self.shared_secret {
            encode_mpint(&shared.0, buffer)?;
        }

        let mut hasher = sha2::Sha256::new();
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
    ) -> Result<super::cipher::CipherPair, crate::Error> {
        let shared_secret = self
            .shared_secret
            .as_ref()
            .map(|x| SharedSecret::from_mpint(&x.0))
            .transpose()?;

        compute_keys::<sha2::Sha256>(
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
    use crate::session::Exchange;

    fn kex_ecdh_init(pubkey: [u8; 32]) -> Vec<u8> {
        let mut payload = vec![msg::KEX_ECDH_INIT];
        payload.extend_from_slice(&32u32.to_be_bytes());
        payload.extend_from_slice(&pubkey);
        payload
    }

    /// Low-order points make the shared secret non-contributory (all zeros).
    #[test]
    fn server_dh_rejects_low_order_points() {
        // order 2, order 4, and two points of order 8
        let low_order: [[u8; 32]; 4] = [
            [0; 32],
            hex_literal::hex!("0100000000000000000000000000000000000000000000000000000000000000"),
            hex_literal::hex!("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
            hex_literal::hex!("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
        ];

        for pubkey in low_order {
            let mut kex = Curve25519Kex {
                local_secret: None,
                shared_secret: None,
            };
            let mut exchange = Exchange::new(b"client", b"server");
            assert!(
                kex.server_dh(&mut exchange, &kex_ecdh_init(pubkey)).is_err(),
                "accepted low-order point {pubkey:02x?}"
            );
        }
    }

    #[test]
    fn server_dh_accepts_a_normal_point() {
        let mut kex = Curve25519Kex {
            local_secret: None,
            shared_secret: None,
        };
        let mut exchange = Exchange::new(b"client", b"server");
        let peer = MontgomeryPoint::mul_base_clamped(rand::random::<[u8; 32]>());
        kex.server_dh(&mut exchange, &kex_ecdh_init(peer.0)).unwrap();
    }
}
