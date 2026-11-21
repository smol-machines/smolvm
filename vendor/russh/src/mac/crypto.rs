use std::marker::PhantomData;

use byteorder::{BigEndian, ByteOrder};
use digest::typenum::Unsigned;
use digest::{KeyInit, OutputSizeUser};
use generic_array::{ArrayLength, GenericArray};
use subtle::ConstantTimeEq;

use super::{Mac, MacAlgorithm};

pub struct CryptoMacAlgorithm<
    M: digest::Mac + KeyInit + Send + 'static,
    KL: ArrayLength + 'static,
>(pub PhantomData<M>, pub PhantomData<KL>);

pub struct CryptoMac<M: digest::Mac + KeyInit + Send + 'static, KL: ArrayLength + 'static> {
    pub(crate) key: GenericArray<u8, KL>,
    pub(crate) p: PhantomData<M>,
}

impl<M: digest::Mac + KeyInit + Send + 'static, KL: ArrayLength + 'static> MacAlgorithm
    for CryptoMacAlgorithm<M, KL>
where
    <M as OutputSizeUser>::OutputSize: ArrayLength,
{
    fn key_len(&self) -> usize {
        KL::to_usize()
    }

    fn make_mac(&self, mac_key: &[u8]) -> Box<dyn Mac + Send> {
        let mut key = GenericArray::<u8, KL>::default();
        key.copy_from_slice(mac_key);
        Box::new(CryptoMac::<M, KL> {
            key,
            p: PhantomData,
        }) as Box<dyn Mac + Send>
    }
}

impl<M: digest::Mac + KeyInit + Send + 'static, KL: ArrayLength + 'static> Mac for CryptoMac<M, KL>
where
    <M as OutputSizeUser>::OutputSize: ArrayLength,
{
    fn mac_len(&self) -> usize {
        M::OutputSize::to_usize()
    }

    fn compute(&self, sequence_number: u32, payload: &[u8], output: &mut [u8]) {
        #[allow(clippy::unwrap_used)]
        let mut hmac = <M as KeyInit>::new_from_slice(&self.key).unwrap();
        let mut seqno_buf = [0; 4];
        BigEndian::write_u32(&mut seqno_buf, sequence_number);
        hmac.update(&seqno_buf);
        hmac.update(payload);
        output.copy_from_slice(&hmac.finalize().into_bytes());
    }

    fn verify(&self, sequence_number: u32, payload: &[u8], mac: &[u8]) -> bool {
        let mut buf = GenericArray::<u8, M::OutputSize>::default();
        self.compute(sequence_number, payload, &mut buf);
        buf.ct_eq(mac).into()
    }
}
