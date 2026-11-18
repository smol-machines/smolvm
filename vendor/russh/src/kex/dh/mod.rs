pub mod groups;
use std::marker::PhantomData;

use byteorder::{BigEndian, ByteOrder};
use digest::Digest;
use groups::DH;
use log::{error, trace};
use num_bigint::BigUint;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use ssh_encoding::{Decode, Encode, Reader, Writer};

use self::groups::{
    DhGroup, DH_GROUP1, DH_GROUP14, DH_GROUP15, DH_GROUP16, DH_GROUP17, DH_GROUP18,
};
use super::{compute_keys, KexAlgorithm, KexAlgorithmImplementor, KexType, SharedSecret};
use crate::client::GexParams;
use crate::session::Exchange;
use crate::{cipher, mac, msg, CryptoVec, Error};

pub(crate) struct DhGroup15Sha512KexType {}

impl KexType for DhGroup15Sha512KexType {
    fn make(&self) -> KexAlgorithm {
        DhGroupKex::<Sha512>::new(Some(&DH_GROUP15)).into()
    }
}

pub(crate) struct DhGroup17Sha512KexType {}

impl KexType for DhGroup17Sha512KexType {
    fn make(&self) -> KexAlgorithm {
        DhGroupKex::<Sha512>::new(Some(&DH_GROUP17)).into()
    }
}

pub(crate) struct DhGroup18Sha512KexType {}

impl KexType for DhGroup18Sha512KexType {
    fn make(&self) -> KexAlgorithm {
        DhGroupKex::<Sha512>::new(Some(&DH_GROUP18)).into()
    }
}

pub(crate) struct DhGexSha1KexType {}

impl KexType for DhGexSha1KexType {
    fn make(&self) -> KexAlgorithm {
        DhGroupKex::<Sha1>::new(None).into()
    }
}

pub(crate) struct DhGexSha256KexType {}

impl KexType for DhGexSha256KexType {
    fn make(&self) -> KexAlgorithm {
        DhGroupKex::<Sha256>::new(None).into()
    }
}

pub(crate) struct DhGroup1Sha1KexType {}

impl KexType for DhGroup1Sha1KexType {
    fn make(&self) -> KexAlgorithm {
        DhGroupKex::<Sha1>::new(Some(&DH_GROUP1)).into()
    }
}

pub(crate) struct DhGroup14Sha1KexType {}

impl KexType for DhGroup14Sha1KexType {
    fn make(&self) -> KexAlgorithm {
        DhGroupKex::<Sha1>::new(Some(&DH_GROUP14)).into()
    }
}

pub(crate) struct DhGroup14Sha256KexType {}

impl KexType for DhGroup14Sha256KexType {
    fn make(&self) -> KexAlgorithm {
        DhGroupKex::<Sha256>::new(Some(&DH_GROUP14)).into()
    }
}

pub(crate) struct DhGroup16Sha512KexType {}

impl KexType for DhGroup16Sha512KexType {
    fn make(&self) -> KexAlgorithm {
        DhGroupKex::<Sha512>::new(Some(&DH_GROUP16)).into()
    }
}

#[doc(hidden)]
pub(crate) struct DhGroupKex<D: Digest> {
    dh: Option<DH>,
    shared_secret: Option<Vec<u8>>,
    is_dh_gex: bool,
    _digest: PhantomData<D>,
}

impl<D: Digest> DhGroupKex<D> {
    pub(crate) fn new(group: Option<&DhGroup>) -> DhGroupKex<D> {
        DhGroupKex {
            dh: group.map(DH::new),
            shared_secret: None,
            is_dh_gex: group.is_none(),
            _digest: PhantomData,
        }
    }
}

impl<D: Digest> std::fmt::Debug for DhGroupKex<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Algorithm {{ local_secret: [hidden], shared_secret: [hidden] }}",
        )
    }
}

pub(crate) fn biguint_to_mpint(biguint: &BigUint) -> Vec<u8> {
    let mut mpint = Vec::new();
    let bytes = biguint.to_bytes_be();
    if let Some(b) = bytes.first()
        && b > &0x7f
    {
        mpint.push(0);
    }
    mpint.extend(&bytes);
    mpint
}

impl<D: Digest> KexAlgorithmImplementor for DhGroupKex<D> {
    fn skip_exchange(&self) -> bool {
        false
    }

    fn is_dh_gex(&self) -> bool {
        self.is_dh_gex
    }

    fn client_dh_gex_init(
        &mut self,
        gex: &GexParams,
        writer: &mut impl Writer,
    ) -> Result<(), Error> {
        msg::KEX_DH_GEX_REQUEST.encode(writer)?;
        (gex.min_group_size() as u32).encode(writer)?;
        (gex.preferred_group_size() as u32).encode(writer)?;
        (gex.max_group_size() as u32).encode(writer)?;
        Ok(())
    }

    #[allow(dead_code)]
    fn dh_gex_set_group(&mut self, group: DhGroup) -> Result<(), crate::Error> {
        self.dh = Some(DH::new(&group));
        Ok(())
    }

    #[doc(hidden)]
    fn server_dh(&mut self, exchange: &mut Exchange, payload: &[u8]) -> Result<(), Error> {
        let Some(dh) = self.dh.as_mut() else {
            error!("DH kex sequence error, dh is None in server_dh");
            return Err(Error::Inconsistent);
        };

        let client_pubkey = {
            if payload.first() != Some(&msg::KEX_ECDH_INIT)
                && payload.first() != Some(&msg::KEX_DH_GEX_INIT)
            {
                return Err(Error::Inconsistent);
            }

            #[allow(clippy::indexing_slicing)] // length checked
            let pubkey_len = BigEndian::read_u32(&payload[1..]) as usize;

            if payload.len() < 5 + pubkey_len {
                return Err(Error::Inconsistent);
            }

            &payload
                .get(5..(5 + pubkey_len))
                .ok_or(Error::Inconsistent)?
        };

        trace!("client_pubkey: {client_pubkey:?}");

        dh.generate_private_key(true);
        let server_pubkey = &dh.generate_public_key();
        if !dh.validate_public_key(server_pubkey) {
            return Err(Error::Inconsistent);
        }

        let encoded_server_pubkey = biguint_to_mpint(server_pubkey);

        // fill exchange.
        exchange.server_ephemeral.clear();
        exchange.server_ephemeral.extend_from_slice(&encoded_server_pubkey);

        let decoded_client_pubkey = DH::decode_public_key(client_pubkey);
        if !dh.validate_public_key(&decoded_client_pubkey) {
            return Err(Error::Inconsistent);
        }

        let shared = dh.compute_shared_secret(decoded_client_pubkey);
        if !dh.validate_shared_secret(&shared) {
            return Err(Error::Inconsistent);
        }
        self.shared_secret = Some(biguint_to_mpint(&shared));
        Ok(())
    }

    #[doc(hidden)]
    fn client_dh(
        &mut self,
        client_ephemeral: &mut Vec<u8>,
        writer: &mut impl Writer,
    ) -> Result<(), Error> {
        let Some(dh) = self.dh.as_mut() else {
            error!("DH kex sequence error, dh is None in client_dh");
            return Err(Error::Inconsistent);
        };

        dh.generate_private_key(false);
        let client_pubkey = &dh.generate_public_key();

        if !dh.validate_public_key(client_pubkey) {
            return Err(Error::Inconsistent);
        }

        // fill exchange.
        let encoded_pubkey = biguint_to_mpint(client_pubkey);
        client_ephemeral.clear();
        client_ephemeral.extend_from_slice(&encoded_pubkey);

        if self.is_dh_gex {
            msg::KEX_DH_GEX_INIT.encode(writer)?;
        } else {
            msg::KEX_ECDH_INIT.encode(writer)?;
        }

        encoded_pubkey.encode(writer)?;

        Ok(())
    }

    fn compute_shared_secret(&mut self, remote_pubkey_: &[u8]) -> Result<(), Error> {
        let Some(dh) = self.dh.as_mut() else {
            error!("DH kex sequence error, dh is None in compute_shared_secret");
            return Err(Error::Inconsistent);
        };

        let remote_pubkey = DH::decode_public_key(remote_pubkey_);

        if !dh.validate_public_key(&remote_pubkey) {
            return Err(Error::Inconsistent);
        }

        let shared = dh.compute_shared_secret(remote_pubkey);
        if !dh.validate_shared_secret(&shared) {
            return Err(Error::Inconsistent);
        }
        self.shared_secret = Some(biguint_to_mpint(&shared));
        Ok(())
    }

    fn shared_secret_bytes(&self) -> Option<&[u8]> {
        self.shared_secret.as_deref()
    }

    fn compute_exchange_hash(
        &self,
        key: &[u8],
        exchange: &Exchange,
        buffer: &mut CryptoVec,
    ) -> Result<Vec<u8>, Error> {
        // Computing the exchange hash, see page 7 of RFC 5656.
        buffer.clear();
        exchange.client_id.encode(buffer)?;
        exchange.server_id.encode(buffer)?;
        exchange.client_kex_init.encode(buffer)?;
        exchange.server_kex_init.encode(buffer)?;

        buffer.extend(key);

        if let Some((gex_params, dh_group)) = &exchange.gex {
            gex_params.encode(buffer)?;
            biguint_to_mpint(&BigUint::from_bytes_be(&dh_group.prime)).encode(buffer)?;
            biguint_to_mpint(&BigUint::from_bytes_be(&dh_group.generator)).encode(buffer)?;
        }

        exchange.client_ephemeral.encode(buffer)?;
        exchange.server_ephemeral.encode(buffer)?;

        if let Some(ref shared) = self.shared_secret {
            shared.encode(buffer)?;
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
    ) -> Result<super::cipher::CipherPair, Error> {
        let shared_secret = self
            .shared_secret
            .as_deref()
            .map(SharedSecret::from_mpint)
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

impl Encode for GexParams {
    fn encoded_len(&self) -> Result<usize, ssh_encoding::Error> {
        Ok(0u32.encoded_len()? * 3)
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<(), ssh_encoding::Error> {
        (self.min_group_size() as u32).encode(writer)?;
        (self.preferred_group_size() as u32).encode(writer)?;
        (self.max_group_size() as u32).encode(writer)?;
        Ok(())
    }
}

impl Decode for GexParams {
    fn decode(reader: &mut impl Reader) -> Result<Self, Error> {
        let min_group_size = u32::decode(reader)? as usize;
        let preferred_group_size = u32::decode(reader)? as usize;
        let max_group_size = u32::decode(reader)? as usize;
        GexParams::from_peer_request(min_group_size, preferred_group_size, max_group_size)
    }

    type Error = Error;
}
