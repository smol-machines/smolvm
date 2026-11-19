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

#[cfg(feature = "aws-lc-rs")]
use aws_lc_rs::aead::chacha20_poly1305_openssh;
#[cfg(all(not(feature = "aws-lc-rs"), feature = "ring"))]
use ring::aead::chacha20_poly1305_openssh;

use super::super::Error;
use crate::mac::MacAlgorithm;

pub struct SshChacha20Poly1305Cipher {}

impl super::Cipher for SshChacha20Poly1305Cipher {
    fn key_len(&self) -> usize {
        chacha20_poly1305_openssh::KEY_LEN
    }

    fn make_opening_key(
        &self,
        k: &[u8],
        _: &[u8],
        _: &[u8],
        _: &dyn MacAlgorithm,
    ) -> Box<dyn super::OpeningKey + Send> {
        Box::new(OpeningKey(chacha20_poly1305_openssh::OpeningKey::new(
            #[allow(clippy::unwrap_used)]
            k.try_into().unwrap(),
        )))
    }

    fn make_sealing_key(
        &self,
        k: &[u8],
        _: &[u8],
        _: &[u8],
        _: &dyn MacAlgorithm,
    ) -> Box<dyn super::SealingKey + Send> {
        Box::new(SealingKey(chacha20_poly1305_openssh::SealingKey::new(
            #[allow(clippy::unwrap_used)]
            k.try_into().unwrap(),
        )))
    }
}

pub struct OpeningKey(chacha20_poly1305_openssh::OpeningKey);

pub struct SealingKey(chacha20_poly1305_openssh::SealingKey);

impl super::OpeningKey for OpeningKey {
    fn decrypt_packet_length(
        &self,
        sequence_number: u32,
        encrypted_packet_length: &[u8],
    ) -> [u8; 4] {
        self.0.decrypt_packet_length(
            sequence_number,
            #[allow(clippy::unwrap_used)]
            encrypted_packet_length.try_into().unwrap(),
        )
    }

    fn tag_len(&self) -> usize {
        chacha20_poly1305_openssh::TAG_LEN
    }

    fn open<'a>(
        &mut self,
        sequence_number: u32,
        ciphertext_and_tag: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let ciphertext_len = ciphertext_and_tag.len() - self.tag_len();
        let (ciphertext_in_plaintext_out, tag) = ciphertext_and_tag.split_at_mut(ciphertext_len);

        self.0
            .open_in_place(
                sequence_number,
                ciphertext_in_plaintext_out,
                #[allow(clippy::unwrap_used)]
                &tag.try_into().unwrap(),
            )
            .map_err(|_| Error::DecryptionError)
    }
}

impl super::SealingKey for SealingKey {
    fn padding_length(&self, payload: &[u8]) -> usize {
        let block_size = 8;
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

    // As explained in "SSH via CTR mode with stateful decryption" in
    // https://openvpn.net/papers/ssh-security.pdf, the padding doesn't need to
    // be random because we're doing stateful counter-mode encryption. Use
    // fixed padding to avoid PRNG overhead.
    fn fill_padding(&self, padding_out: &mut [u8]) {
        for padding_byte in padding_out {
            *padding_byte = 0;
        }
    }

    fn tag_len(&self) -> usize {
        chacha20_poly1305_openssh::TAG_LEN
    }

    fn seal(
        &mut self,
        sequence_number: u32,
        plaintext_in_ciphertext_out: &mut [u8],
        tag: &mut [u8],
    ) {
        self.0.seal_in_place(
            sequence_number,
            plaintext_in_ciphertext_out,
            #[allow(clippy::unwrap_used)]
            tag.try_into().unwrap(),
        );
    }
}
