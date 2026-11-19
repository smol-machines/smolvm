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

use std::convert::TryInto;
use std::marker::PhantomData;

use aes::cipher::{
    InOutBuf, Iv, IvSizeUser, Key, KeyIvInit, KeySizeUser, StreamCipher, StreamCipherError,
    StreamCipherSeek,
};
#[allow(deprecated)]
use rand_core::Rng;

use super::super::Error;
use super::PACKET_LENGTH_LEN;
use crate::keys::key::safe_rng;
use crate::mac::{Mac, MacAlgorithm};

fn new_cipher_from_slices<C: KeyIvInit>(k: &[u8], n: &[u8]) -> C {
    #[allow(clippy::expect_used)]
    C::new(
        <&Key<C>>::try_from(k).expect("key length matches"),
        <&Iv<C>>::try_from(n).expect("iv length matches"),
    )
}

/// Cloneable wrapper for `Ctr128BE<>`
pub struct CtrWrapper<C>
where
    C: KeyIvInit,
{
    key: Key<C>,
    initial_iv: Iv<C>,
    pos: u64,
}

impl<C: KeyIvInit> Clone for CtrWrapper<C> {
    fn clone(&self) -> Self {
        Self {
            key: self.key.clone(),
            initial_iv: self.initial_iv.clone(),
            pos: self.pos,
        }
    }
}

impl<C: KeyIvInit> KeySizeUser for CtrWrapper<C> {
    type KeySize = <C as KeySizeUser>::KeySize;
}

impl<C: KeyIvInit> IvSizeUser for CtrWrapper<C> {
    type IvSize = <C as IvSizeUser>::IvSize;
}

impl<C: KeyIvInit> KeyIvInit for CtrWrapper<C> {
    fn new(key: &Key<Self>, iv: &Iv<Self>) -> Self {
        Self {
            key: key.clone(),
            initial_iv: iv.clone(),
            pos: 0,
        }
    }
}

impl<C: KeyIvInit + StreamCipher + StreamCipherSeek> StreamCipher for CtrWrapper<C> {
    fn check_remaining(&self, _data_len: usize) -> Result<(), StreamCipherError> {
        Ok(())
    }

    fn unchecked_apply_keystream_inout(&mut self, buf: InOutBuf<'_, '_, u8>) {
        let mut cipher = C::new(&self.key, &self.initial_iv);
        cipher.seek(self.pos);
        cipher.unchecked_apply_keystream_inout(buf);
        self.pos = cipher.current_pos();
    }

    fn unchecked_write_keystream(&mut self, buf: &mut [u8]) {
        let mut cipher = C::new(&self.key, &self.initial_iv);
        cipher.seek(self.pos);
        cipher.unchecked_write_keystream(buf);
        self.pos = cipher.current_pos();
    }
}

pub struct SshBlockCipher<C: BlockStreamCipher + PacketLengthProbe + KeySizeUser + IvSizeUser>(
    pub PhantomData<C>,
);

impl<
    C: BlockStreamCipher + PacketLengthProbe + KeySizeUser + IvSizeUser + KeyIvInit + Send + 'static,
> super::Cipher for SshBlockCipher<C>
{
    fn key_len(&self) -> usize {
        C::key_size()
    }

    fn nonce_len(&self) -> usize {
        C::iv_size()
    }

    fn needs_mac(&self) -> bool {
        true
    }

    fn make_opening_key(
        &self,
        k: &[u8],
        n: &[u8],
        m: &[u8],
        mac: &dyn MacAlgorithm,
    ) -> Box<dyn super::OpeningKey + Send> {
        Box::new(OpeningKey {
            cipher: new_cipher_from_slices::<C>(k, n),
            mac: mac.make_mac(m),
        })
    }

    fn make_sealing_key(
        &self,
        k: &[u8],
        n: &[u8],
        m: &[u8],
        mac: &dyn MacAlgorithm,
    ) -> Box<dyn super::SealingKey + Send> {
        Box::new(SealingKey {
            cipher: new_cipher_from_slices::<C>(k, n),
            mac: mac.make_mac(m),
        })
    }
}

pub struct OpeningKey<C: BlockStreamCipher + PacketLengthProbe> {
    pub(crate) cipher: C,
    pub(crate) mac: Box<dyn Mac + Send>,
}

pub struct SealingKey<C: BlockStreamCipher> {
    pub(crate) cipher: C,
    pub(crate) mac: Box<dyn Mac + Send>,
}

impl<C: BlockStreamCipher + PacketLengthProbe + KeySizeUser + IvSizeUser> super::OpeningKey
    for OpeningKey<C>
{
    fn packet_length_to_read_for_block_length(&self) -> usize {
        16
    }

    fn decrypt_packet_length(
        &self,
        _sequence_number: u32,
        encrypted_packet_length: &[u8],
    ) -> [u8; 4] {
        let mut first_block = [0u8; 16];
        // Fine because of self.packet_length_to_read_for_block_length()
        #[allow(clippy::indexing_slicing)]
        first_block.copy_from_slice(&encrypted_packet_length[..16]);

        if self.mac.is_etm() {
            // Fine because of self.packet_length_to_read_for_block_length()
            #[allow(clippy::unwrap_used, clippy::indexing_slicing)]
            encrypted_packet_length[..4].try_into().unwrap()
        } else {
            self.cipher.decrypt_packet_length_block(&mut first_block);

            // Fine because of self.packet_length_to_read_for_block_length()
            #[allow(clippy::unwrap_used, clippy::indexing_slicing)]
            first_block[..4].try_into().unwrap()
        }
    }

    fn tag_len(&self) -> usize {
        self.mac.mac_len()
    }

    fn open<'a>(
        &mut self,
        sequence_number: u32,
        ciphertext_and_tag: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let ciphertext_len = ciphertext_and_tag.len() - self.tag_len();
        let (ciphertext_in_plaintext_out, tag) = ciphertext_and_tag.split_at_mut(ciphertext_len);
        if self.mac.is_etm() {
            if !self
                .mac
                .verify(sequence_number, ciphertext_in_plaintext_out, tag)
            {
                return Err(Error::PacketAuth);
            }
            #[allow(clippy::indexing_slicing)]
            self.cipher
                .decrypt_data(&mut ciphertext_in_plaintext_out[PACKET_LENGTH_LEN..]);
        } else {
            self.cipher.decrypt_data(ciphertext_in_plaintext_out);

            if !self
                .mac
                .verify(sequence_number, ciphertext_in_plaintext_out, tag)
            {
                return Err(Error::PacketAuth);
            }
        }

        #[allow(clippy::indexing_slicing)]
        Ok(&ciphertext_in_plaintext_out[PACKET_LENGTH_LEN..])
    }
}

impl<C: BlockStreamCipher + KeySizeUser + IvSizeUser> super::SealingKey for SealingKey<C> {
    fn padding_length(&self, payload: &[u8]) -> usize {
        let block_size = 16;

        let pll = if self.mac.is_etm() {
            0
        } else {
            PACKET_LENGTH_LEN
        };

        let extra_len = PACKET_LENGTH_LEN + super::PADDING_LENGTH_LEN + self.mac.mac_len();

        let padding_len = if payload.len() + extra_len <= super::MINIMUM_PACKET_LEN {
            super::MINIMUM_PACKET_LEN - payload.len() - super::PADDING_LENGTH_LEN - pll
        } else {
            block_size - ((pll + super::PADDING_LENGTH_LEN + payload.len()) % block_size)
        };
        if padding_len < PACKET_LENGTH_LEN {
            padding_len + block_size
        } else {
            padding_len
        }
    }

    fn fill_padding(&self, padding_out: &mut [u8]) {
        safe_rng().fill_bytes(padding_out);
    }

    fn tag_len(&self) -> usize {
        self.mac.mac_len()
    }

    fn seal(
        &mut self,
        sequence_number: u32,
        plaintext_in_ciphertext_out: &mut [u8],
        tag_out: &mut [u8],
    ) {
        if self.mac.is_etm() {
            #[allow(clippy::indexing_slicing)]
            self.cipher
                .encrypt_data(&mut plaintext_in_ciphertext_out[PACKET_LENGTH_LEN..]);
            self.mac
                .compute(sequence_number, plaintext_in_ciphertext_out, tag_out);
        } else {
            self.mac
                .compute(sequence_number, plaintext_in_ciphertext_out, tag_out);
            self.cipher.encrypt_data(plaintext_in_ciphertext_out);
        }
    }
}

pub trait BlockStreamCipher {
    fn encrypt_data(&mut self, data: &mut [u8]);
    fn decrypt_data(&mut self, data: &mut [u8]);
}

pub(crate) trait PacketLengthProbe {
    fn decrypt_packet_length_block(&self, first_block: &mut [u8; 16]);
}

impl<T: StreamCipher> BlockStreamCipher for T {
    fn encrypt_data(&mut self, data: &mut [u8]) {
        self.apply_keystream(data);
    }

    fn decrypt_data(&mut self, data: &mut [u8]) {
        self.apply_keystream(data);
    }
}

impl<T: StreamCipher + Clone> PacketLengthProbe for T {
    fn decrypt_packet_length_block(&self, first_block: &mut [u8; 16]) {
        let mut cipher = self.clone();
        cipher.apply_keystream(first_block);
    }
}

#[cfg(test)]
mod tests {
    use aes::Aes128;
    use aes::cipher::KeyIvInit;
    use aes::cipher::StreamCipher;
    use aes::cipher::{IvSizeUser, KeySizeUser};
    use ctr::Ctr128BE;
    use digest::typenum::U16;
    use tokio::io::AsyncWriteExt;

    use super::{BlockStreamCipher, CtrWrapper, OpeningKey, PacketLengthProbe};
    use crate::mac::MacAlgorithm;
    use crate::sshbuffer::SSHBuffer;

    #[test]
    fn stream_cipher_probe_does_not_advance_cipher_state() {
        let plaintext = *b"0123456789ABCDEF";
        let key = fixture_bytes::<16>(7);
        let iv = fixture_bytes::<16>(3);

        let mut encryptor = CtrWrapper::<Ctr128BE<Aes128>>::new(&key.into(), &iv.into());
        let mut ciphertext = plaintext;
        encryptor.apply_keystream(&mut ciphertext);

        let cipher = CtrWrapper::<Ctr128BE<Aes128>>::new(&key.into(), &iv.into());
        let mut probed_block = ciphertext;
        cipher.decrypt_packet_length_block(&mut probed_block);
        assert_eq!(probed_block, plaintext);

        let mut decrypted = ciphertext;
        let mut cipher_after_probe = cipher;
        cipher_after_probe.decrypt_data(&mut decrypted);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_packet_length_uses_independent_cipher_state() -> std::io::Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let opening = OpeningKey {
            cipher: OwnedStateCipher::new(),
            mac: crate::mac::_NONE.make_mac(&[]),
        };
        let mut opening = opening;
        let mut buffer = SSHBuffer::new();
        let bytes_read = runtime
            .block_on(async {
                let (mut writer, mut reader) = tokio::io::duplex(64);
                writer.write_all(&[0; 17]).await?;
                drop(writer);
                crate::cipher::read(&mut reader, &mut buffer, &mut opening).await
            })
            .map_err(std::io::Error::other)?;

        assert_eq!(bytes_read, 16);
        Ok(())
    }

    struct OwnedStateCipher {
        packet_length: Box<[u8; 4]>,
    }

    impl OwnedStateCipher {
        fn new() -> Self {
            Self {
                packet_length: Box::new([0, 0, 0, 13]),
            }
        }
    }

    impl Clone for OwnedStateCipher {
        fn clone(&self) -> Self {
            Self {
                packet_length: Box::new([0, 0, 0, 12]),
            }
        }
    }

    impl KeySizeUser for OwnedStateCipher {
        type KeySize = U16;
    }

    impl IvSizeUser for OwnedStateCipher {
        type IvSize = U16;
    }

    impl BlockStreamCipher for OwnedStateCipher {
        fn encrypt_data(&mut self, _data: &mut [u8]) {}

        fn decrypt_data(&mut self, data: &mut [u8]) {
            if let Some(prefix) = data.get_mut(..4) {
                prefix.copy_from_slice(&self.packet_length[..]);
            }
        }
    }

    impl PacketLengthProbe for OwnedStateCipher {
        fn decrypt_packet_length_block(&self, first_block: &mut [u8; 16]) {
            if let Some(prefix) = first_block.get_mut(..4) {
                prefix.copy_from_slice(&[0, 0, 0, 12]);
            }
        }
    }

    fn fixture_bytes<const N: usize>(seed: u8) -> [u8; N] {
        let mut bytes = [0; N];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = seed.wrapping_add(i as u8);
        }
        bytes
    }
}
