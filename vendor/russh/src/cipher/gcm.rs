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

// http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.chacha20poly1305?annotate=HEAD

use std::convert::TryInto;

#[cfg(feature = "aws-lc-rs")]
use aws_lc_rs::{
    aead::{
        Aad, Algorithm, BoundKey, NONCE_LEN, Nonce as AeadNonce, NonceSequence,
        OpeningKey as AeadOpeningKey, SealingKey as AeadSealingKey, UnboundKey,
    },
    error::Unspecified,
};
use rand_core::Rng;
#[cfg(all(not(feature = "aws-lc-rs"), feature = "ring"))]
use ring::{
    aead::{
        Aad, Algorithm, BoundKey, NONCE_LEN, Nonce as AeadNonce, NonceSequence,
        OpeningKey as AeadOpeningKey, SealingKey as AeadSealingKey, UnboundKey,
    },
    error::Unspecified,
};

use super::super::Error;
use crate::keys::key::safe_rng;
use crate::mac::MacAlgorithm;

pub struct GcmCipher(pub(crate) &'static Algorithm);

impl super::Cipher for GcmCipher {
    fn key_len(&self) -> usize {
        self.0.key_len()
    }

    fn nonce_len(&self) -> usize {
        self.0.nonce_len()
    }

    fn make_opening_key(
        &self,
        k: &[u8],
        n: &[u8],
        _: &[u8],
        _: &dyn MacAlgorithm,
    ) -> Box<dyn super::OpeningKey + Send> {
        #[allow(clippy::unwrap_used)]
        Box::new(OpeningKey(AeadOpeningKey::new(
            UnboundKey::new(self.0, k).unwrap(),
            Nonce(n.try_into().unwrap()),
        )))
    }

    fn make_sealing_key(
        &self,
        k: &[u8],
        n: &[u8],
        _: &[u8],
        _: &dyn MacAlgorithm,
    ) -> Box<dyn super::SealingKey + Send> {
        #[allow(clippy::unwrap_used)]
        Box::new(SealingKey(AeadSealingKey::new(
            UnboundKey::new(self.0, k).unwrap(),
            Nonce(n.try_into().unwrap()),
        )))
    }
}

pub struct OpeningKey<N: NonceSequence>(AeadOpeningKey<N>);

pub struct SealingKey<N: NonceSequence>(AeadSealingKey<N>);

struct Nonce([u8; NONCE_LEN]);

impl NonceSequence for Nonce {
    fn advance(&mut self) -> Result<AeadNonce, Unspecified> {
        let mut previous_nonce = [0u8; NONCE_LEN];
        #[allow(clippy::indexing_slicing)] // length checked
        previous_nonce.clone_from_slice(&self.0[..]);
        let mut carry = 1;
        #[allow(clippy::indexing_slicing)] // length checked
        for i in (0..NONCE_LEN).rev() {
            let n = self.0[i] as u16 + carry;
            self.0[i] = n as u8;
            carry = n >> 8;
        }
        Ok(AeadNonce::assume_unique_for_key(previous_nonce))
    }
}

impl<N: NonceSequence> super::OpeningKey for OpeningKey<N> {
    fn decrypt_packet_length(
        &self,
        _sequence_number: u32,
        encrypted_packet_length: &[u8],
    ) -> [u8; 4] {
        // Fine because of self.packet_length_to_read_for_block_length()
        #[allow(clippy::unwrap_used, clippy::indexing_slicing)]
        encrypted_packet_length.try_into().unwrap()
    }

    fn tag_len(&self) -> usize {
        self.0.algorithm().tag_len()
    }

    fn open<'a>(
        &mut self,
        _sequence_number: u32,
        ciphertext_and_tag: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        // Packet length is sent unencrypted
        let mut packet_length = [0; super::PACKET_LENGTH_LEN];

        #[allow(clippy::indexing_slicing)] // length checked
        packet_length.clone_from_slice(&ciphertext_and_tag[..super::PACKET_LENGTH_LEN]);

        let buf = self
            .0
            .open_in_place(
                Aad::from(&packet_length),
                #[allow(clippy::indexing_slicing)] // length checked
                &mut ciphertext_and_tag[super::PACKET_LENGTH_LEN..],
            )
            .map_err(|_| Error::DecryptionError)?;

        Ok(buf)
    }
}

impl<N: NonceSequence> super::SealingKey for SealingKey<N> {
    fn padding_length(&self, payload: &[u8]) -> usize {
        let block_size = 16;
        let extra_len = super::PACKET_LENGTH_LEN + super::PADDING_LENGTH_LEN;
        let padding_len = if payload.len() + extra_len <= super::MINIMUM_PACKET_LEN {
            super::MINIMUM_PACKET_LEN - payload.len() - super::PADDING_LENGTH_LEN
        } else {
            block_size - ((super::PADDING_LENGTH_LEN + payload.len()) % block_size)
        };
        if padding_len < super::PACKET_LENGTH_LEN {
            padding_len + block_size
        } else {
            padding_len
        }
    }

    fn fill_padding(&self, padding_out: &mut [u8]) {
        safe_rng().fill_bytes(padding_out);
    }

    fn tag_len(&self) -> usize {
        self.0.algorithm().tag_len()
    }

    fn seal(
        &mut self,
        _sequence_number: u32,
        plaintext_in_ciphertext_out: &mut [u8],
        tag: &mut [u8],
    ) {
        // Packet length is received unencrypted
        let mut packet_length = [0; super::PACKET_LENGTH_LEN];
        #[allow(clippy::indexing_slicing)] // length checked
        packet_length.clone_from_slice(&plaintext_in_ciphertext_out[..super::PACKET_LENGTH_LEN]);

        #[allow(clippy::unwrap_used)]
        let tag_out = self
            .0
            .seal_in_place_separate_tag(
                Aad::from(&packet_length),
                #[allow(clippy::indexing_slicing)]
                &mut plaintext_in_ciphertext_out[super::PACKET_LENGTH_LEN..],
            )
            .unwrap();

        tag.clone_from_slice(tag_out.as_ref());
    }
}
