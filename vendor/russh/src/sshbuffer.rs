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

use core::fmt;
use std::borrow::Cow;
use std::num::Wrapping;

use bytes::{Bytes, BytesMut};
use log::debug;
use ssh_encoding::Writer;
use super::cipher::SealingKey;
use compression::Compress;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::*;

/// The SSH client/server identification string.
#[derive(Debug)]
pub enum SshId {
    /// When sending the id, append RFC standard `\r\n`. Example: `SshId::Standard("SSH-2.0-acme")`
    Standard(Cow<'static, str>),
    /// When sending the id, use this buffer as it is and do not append additional line terminators.
    Raw(Cow<'static, str>),
}

impl SshId {
    pub(crate) fn as_kex_hash_bytes(&self) -> &[u8] {
        match self {
            Self::Standard(s) => s.as_bytes(),
            Self::Raw(s) => s.trim_end_matches(['\n', '\r']).as_bytes(),
        }
    }

    /// Write the SSH identification string to a buffer.
    /// Buffer is not sensitive - SSH identification strings are public protocol data.
    pub(crate) fn write(&self, buffer: &mut Vec<u8>) {
        match self {
            Self::Standard(s) => buffer.extend_from_slice(format!("{s}\r\n").as_bytes()),
            Self::Raw(s) => buffer.extend_from_slice(s.as_bytes()),
        }
    }
}

#[test]
fn test_ssh_id() {
    let mut buffer = Vec::new();
    SshId::Standard("SSH-2.0-acme".into()).write(&mut buffer);
    assert_eq!(&buffer[..], b"SSH-2.0-acme\r\n");

    let mut buffer = Vec::new();
    SshId::Raw("SSH-2.0-raw\n".into()).write(&mut buffer);
    assert_eq!(&buffer[..], b"SSH-2.0-raw\n");

    assert_eq!(
        SshId::Standard("SSH-2.0-acme".into()).as_kex_hash_bytes(),
        b"SSH-2.0-acme"
    );
    assert_eq!(
        SshId::Raw("SSH-2.0-raw\n".into()).as_kex_hash_bytes(),
        b"SSH-2.0-raw"
    );
}

#[test]
fn test_write_packet_leaves_reusable_buffer_for_cold_path_packets() {
    let mut writer = PacketWriter::clear();
    let large_len = 128 * 1024;
    let packet_buffer_capacity = writer.packet_buffer.capacity();

    writer
        .write_packet(|buf| {
            buf.resize(buf.len() + large_len, 0x5a);
            Ok(())
        })
        .unwrap();
    assert_eq!(writer.packet_buffer.capacity(), packet_buffer_capacity);
}

#[test]
fn reserve_cleartext_packet_output_reserves_output_capacity() {
    let mut writer = PacketWriter::clear();
    let payload_bytes = 4096;
    let packet_count = 4;

    writer.reserve_cleartext_packet_output(payload_bytes, packet_count);

    let expected = payload_bytes
        + packet_count * (PacketWriter::PACKET_PREFIX_LEN + writer.cipher.tag_len() + 32);
    assert!(writer.write_buffer.buffer.capacity() >= expected);
    assert!(writer.write_buffer.buffer.is_empty());
}

#[cfg(feature = "flate2")]
#[test]
fn reserve_cleartext_packet_output_ignores_compressed_writer() {
    let mut writer = PacketWriter::new(Box::new(cipher::clear::Key {}), zlib_compress());
    let capacity = writer.write_buffer.buffer.capacity();

    writer.reserve_cleartext_packet_output(4096, 4);

    assert_eq!(writer.write_buffer.buffer.capacity(), capacity);
}

#[test]
fn test_packet_returns_retained_bytes() {
    let mut writer = PacketWriter::clear();
    let retained = writer
        .packet(|buf| {
            buf.extend_from_slice(b"abc");
            Ok(())
        })
        .unwrap();

    assert_eq!(&retained[..], b"abc");
}

#[test]
fn packet_bytes_returns_retained_bytes() {
    let mut writer = PacketWriter::clear();
    let retained = writer
        .packet_bytes(|buf| {
            buf.extend_from_slice(b"abc");
            Ok(())
        })
        .unwrap();

    assert_eq!(&retained[..], b"abc");
}

#[test]
fn packet_bytes_matches_packet_output() {
    let payload = b"abcdefghijklmno".to_vec();

    let mut packet_writer = PacketWriter::clear();
    let packet_retained = packet_writer
        .packet(|buf| {
            buf.extend_from_slice(&payload);
            Ok(())
        })
        .unwrap();
    let packet_buffer = packet_writer.buffer().buffer.clone();
    let packet_bytes = packet_writer.buffer().bytes;

    let mut packet_bytes_writer = PacketWriter::clear();
    let bytes_retained = packet_bytes_writer
        .packet_bytes(|buf| {
            buf.extend_from_slice(&payload);
            Ok(())
        })
        .unwrap();

    assert_eq!(packet_retained, bytes_retained);
    assert_eq!(packet_bytes_writer.buffer().buffer, packet_buffer);
    assert_eq!(packet_bytes_writer.buffer().bytes, packet_bytes);
}

#[test]
fn test_write_packet_matches_clear_cipher_write_output() {
    let payload = b"abcdefghijklmno".to_vec();

    let mut expected = SSHBuffer::new();
    let mut clear = cipher::clear::Key {};
    clear.write(&payload, &mut expected);

    let mut writer = PacketWriter::clear();
    writer
        .write_packet(|buf| {
            buf.extend_from_slice(&payload);
            Ok(())
        })
        .unwrap();

    assert_eq!(writer.buffer().buffer, expected.buffer);
    assert_eq!(writer.buffer().bytes, payload.len());
    assert_eq!(writer.buffer().seqn, Wrapping(1));
}

#[test]
fn installing_a_cipher_starts_a_new_write_key_epoch() {
    let mut writer = PacketWriter::clear();
    writer.packet_raw(b"initial key exchange").unwrap();
    assert_ne!(writer.buffer().bytes, 0);

    writer.set_cipher(Box::new(cipher::clear::Key {}));

    assert_eq!(writer.buffer().bytes, 0);
    writer.packet_raw(b"encrypted epoch").unwrap();
    assert_eq!(writer.buffer().bytes, b"encrypted epoch".len());
}

// `tokio::test` is resolved even in non-test builds, and the WASM target's
// tokio has no `macros` feature; `#[cfg(test)]` drops the item first.
#[cfg(test)]
#[tokio::test]
async fn automatic_rekey_read_counter_tracks_payload_bytes() {
    let payload = b"inbound rekey accounting";
    let mut writer = PacketWriter::clear();
    writer.packet_raw(payload).unwrap();
    let encoded = writer.buffer().buffer.clone();
    let (mut reader, mut sender) = tokio::io::duplex(encoded.len());
    sender.write_all(&encoded).await.unwrap();
    drop(sender);

    let mut buffer = SSHBuffer::new();
    let mut opening_key = cipher::clear::Key {};
    cipher::read(&mut reader, &mut buffer, &mut opening_key)
        .await
        .unwrap();

    assert_eq!(buffer.bytes, payload.len());
}

#[test]
fn test_write_packet_restores_output_buffer_on_error() {
    let mut writer = PacketWriter::clear();
    writer
        .write_packet(|buf| {
            buf.extend_from_slice(b"ok");
            Ok(())
        })
        .unwrap();
    let before = writer.buffer().buffer.clone();

    let err = writer.write_packet(|buf| {
        buf.extend_from_slice(b"partial");
        Err(Error::Inconsistent)
    });

    assert!(matches!(err, Err(Error::Inconsistent)));
    assert_eq!(writer.buffer().buffer, before);
}

#[cfg(all(test, feature = "flate2"))]
fn zlib_compress() -> Compress {
    let mut compress = Compress::None;
    compression::Compression::Zlib.init_compress(&mut compress);
    compress
}

#[cfg(feature = "flate2")]
#[test]
fn test_write_packet_compressed_matches_clear_cipher_output() {
    let payload = b"abcdefghijklmnoabcdefghijklmno".to_vec();

    let mut expected = SSHBuffer::new();
    let mut clear = cipher::clear::Key {};
    let mut compress = zlib_compress();
    let mut compressed = Vec::new();
    let packet = compress.compress(&payload, &mut compressed).unwrap();
    clear.write(packet, &mut expected);

    let mut writer = PacketWriter::new(Box::new(cipher::clear::Key {}), zlib_compress());
    writer
        .write_packet(|buf| {
            buf.extend_from_slice(&payload);
            Ok(())
        })
        .unwrap();

    assert_eq!(writer.buffer().buffer, expected.buffer);
    assert_eq!(writer.buffer().bytes, packet.len());
    assert_eq!(writer.buffer().seqn, Wrapping(1));
}

#[cfg(feature = "flate2")]
#[test]
fn test_packet_retains_plaintext_for_compressed_packets() {
    let payload = b"abcdefghijklmnoabcdefghijklmno".to_vec();

    let mut writer = PacketWriter::new(Box::new(cipher::clear::Key {}), zlib_compress());
    let retained = writer
        .packet(|buf| {
            buf.extend_from_slice(&payload);
            Ok(())
        })
        .unwrap();

    assert_eq!(&retained[..], &payload);
}

#[cfg(feature = "flate2")]
#[test]
fn packet_bytes_compressed_matches_packet_output() {
    let payload = b"abcdefghijklmnoabcdefghijklmno".to_vec();

    let mut packet_writer = PacketWriter::new(Box::new(cipher::clear::Key {}), zlib_compress());
    let packet_retained = packet_writer
        .packet(|buf| {
            buf.extend_from_slice(&payload);
            Ok(())
        })
        .unwrap();
    let packet_buffer = packet_writer.buffer().buffer.clone();
    let packet_bytes = packet_writer.buffer().bytes;

    let mut packet_bytes_writer =
        PacketWriter::new(Box::new(cipher::clear::Key {}), zlib_compress());
    let bytes_retained = packet_bytes_writer
        .packet_bytes(|buf| {
            buf.extend_from_slice(&payload);
            Ok(())
        })
        .unwrap();

    assert_eq!(packet_retained, bytes_retained);
    assert_eq!(packet_bytes_writer.buffer().buffer, packet_buffer);
    assert_eq!(packet_bytes_writer.buffer().bytes, packet_bytes);
}

/// SSH packet read/write buffer. Uses Vec<u8> (not CryptoVec/mlocked) because
/// packet data is not secret material.
#[derive(Debug, Default)]
pub struct SSHBuffer {
    pub buffer: Vec<u8>,
    pub len: usize,   // next packet length.
    pub bytes: usize, // total payload bytes read/written since the last rekey
    // Sequence numbers are on 32 bits and wrap.
    // https://tools.ietf.org/html/rfc4253#section-6.4
    pub seqn: Wrapping<u32>,
}

impl SSHBuffer {
    pub fn new() -> Self {
        SSHBuffer {
            buffer: Vec::new(),
            len: 0,
            bytes: 0,
            seqn: Wrapping(0),
        }
    }

    pub fn send_ssh_id(&mut self, id: &SshId) {
        id.write(&mut self.buffer);
    }
}

pub(crate) struct PacketBytesWriter {
    buffer: BytesMut,
}

impl Writer for PacketBytesWriter {
    fn write(&mut self, bytes: &[u8]) -> ssh_encoding::Result<()> {
        self.buffer.extend_from_slice(bytes);
        Ok(())
    }
}

impl PacketBytesWriter {
    #[allow(dead_code)]
    pub(crate) fn push(&mut self, byte: u8) {
        self.buffer.extend_from_slice(&[byte]);
    }

    #[allow(dead_code)]
    pub(crate) fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.buffer.len()
    }

    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    fn freeze(self) -> Bytes {
        self.buffer.freeze()
    }
}

/// Incoming SSH packet after decryption and optional decompression.
/// Uses Vec<u8> (not CryptoVec/mlocked) because incoming network data is not secret.
#[derive(Debug)]
pub(crate) struct IncomingSshPacket {
    pub buffer: Vec<u8>,
    pub seqn: Wrapping<u32>,
}

/// Packet writer for constructing and encrypting outgoing SSH packets.
pub(crate) struct PacketWriter {
    cipher: Box<dyn SealingKey + Send>,
    compress: Compress,
    packet_buffer: Vec<u8>,
    write_buffer: SSHBuffer,
}

impl Debug for PacketWriter {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketWriter").finish()
    }
}

impl PacketWriter {
    // SSH packet prefix = packet_length (cipher::PACKET_LENGTH_LEN bytes)
    // + padding_length (1 byte).
    const PACKET_PREFIX_LEN: usize = cipher::PACKET_LENGTH_LEN + 1;

    pub fn clear() -> Self {
        Self::new(Box::new(cipher::clear::Key {}), Compress::None)
    }

    pub fn new(cipher: Box<dyn SealingKey + Send>, compress: Compress) -> Self {
        Self {
            cipher,
            compress,
            packet_buffer: Vec::new(),
            write_buffer: SSHBuffer::new(),
        }
    }

    fn prepare_packet<F: FnOnce(&mut Vec<u8>) -> Result<(), Error>>(
        &mut self,
        f: F,
    ) -> Result<Vec<u8>, Error> {
        let mut buf = std::mem::take(&mut self.packet_buffer);
        buf.clear();
        match f(&mut buf) {
            Ok(()) => Ok(buf),
            Err(err) => {
                self.packet_buffer = buf;
                Err(err)
            }
        }
    }

    fn write_packet_in_place<F: FnOnce(&mut Vec<u8>) -> Result<(), Error>>(
        &mut self,
        f: F,
    ) -> Result<(), Error> {
        self.write_payload_into_output(|buffer, payload_start| {
            f(buffer)?;
            Ok(buffer.len() - payload_start)
        })
    }

    fn write_payload_into_output<F>(&mut self, f: F) -> Result<(), Error>
    where
        F: FnOnce(&mut Vec<u8>, usize) -> Result<usize, Error>,
    {
        let offset = self.write_buffer.buffer.len();
        let payload_start = offset + Self::PACKET_PREFIX_LEN;

        self.write_buffer.buffer.resize(payload_start, 0);
        match f(&mut self.write_buffer.buffer, payload_start) {
            Ok(payload_len) => {
                if payload_len == 0 {
                    self.write_buffer.buffer.truncate(offset);
                    return Ok(());
                }

                if let Some(message_type) = self.write_buffer.buffer.get(payload_start) {
                    debug!("> msg type {message_type:?}, len {payload_len}");
                }

                self.cipher
                    .finish_packet(offset, payload_len, &mut self.write_buffer);
                Ok(())
            }
            Err(err) => {
                self.write_buffer.buffer.truncate(offset);
                Err(err)
            }
        }
    }

    fn write_compressed_payload_into_output(&mut self, buf: &[u8]) -> Result<(), Error> {
        let offset = self.write_buffer.buffer.len();
        let payload_start = offset + Self::PACKET_PREFIX_LEN;

        self.write_buffer.buffer.resize(payload_start, 0);
        match self
            .compress
            .compress_into(buf, &mut self.write_buffer.buffer, payload_start)
        {
            Ok(payload_len) => {
                if payload_len == 0 {
                    self.write_buffer.buffer.truncate(offset);
                    return Ok(());
                }

                self.cipher
                    .finish_packet(offset, payload_len, &mut self.write_buffer);
                Ok(())
            }
            Err(err) => {
                self.write_buffer.buffer.truncate(offset);
                Err(err)
            }
        }
    }

    pub fn packet_raw(&mut self, buf: &[u8]) -> Result<(), Error> {
        if let Some(message_type) = buf.first() {
            debug!("> msg type {message_type:?}, len {}", buf.len());
            if matches!(&self.compress, Compress::None) {
                self.cipher.write(buf, &mut self.write_buffer);
            } else {
                self.write_compressed_payload_into_output(buf)?;
            }
        }
        Ok(())
    }

    /// Sends a packet using the reusable plaintext packet buffer.
    ///
    /// The closure must append only the packet payload bytes. It must not
    /// modify or truncate any existing contents in the provided buffer.
    /// When compression is disabled, the buffer may already contain queued
    /// packets and the reserved 5-byte packet header prefix for the packet
    /// being built, so callers must only write new payload bytes starting at
    /// the current end of the buffer.
    pub fn write_packet<F: FnOnce(&mut Vec<u8>) -> Result<(), Error>>(
        &mut self,
        f: F,
    ) -> Result<(), Error> {
        if matches!(&self.compress, Compress::None) {
            return self.write_packet_in_place(f);
        }
        let buf = self.prepare_packet(f)?;
        let result = self.packet_raw(&buf);
        self.packet_buffer = buf;
        result
    }

    pub(crate) fn reserve_cleartext_packet_output(
        &mut self,
        payload_bytes: usize,
        packet_count: usize,
    ) {
        if !matches!(&self.compress, Compress::None) {
            return;
        }

        // Padding is cipher-dependent and rounded to the cipher block size.
        // Reserving a small fixed margin avoids repeated output-buffer growth
        // without coupling callers to individual cipher padding formulas.
        let per_packet_margin = Self::PACKET_PREFIX_LEN + self.cipher.tag_len() + 32;
        let additional = payload_bytes.saturating_add(packet_count.saturating_mul(per_packet_margin));
        self.write_buffer.buffer.reserve(additional);
    }

    /// Sends and returns the packet contents for callers that need to retain
    /// the plaintext packet after it has been queued for encryption.
    #[allow(dead_code)]
    pub fn packet<F: FnOnce(&mut Vec<u8>) -> Result<(), Error>>(
        &mut self,
        f: F,
    ) -> Result<Bytes, Error> {
        let buf = self.prepare_packet(f)?;
        if let Err(err) = self.packet_raw(&buf) {
            self.packet_buffer = buf;
            return Err(err);
        }
        Ok(Bytes::from(buf))
    }

    pub(crate) fn packet_bytes<F>(&mut self, f: F) -> Result<Bytes, Error>
    where
        F: FnOnce(&mut PacketBytesWriter) -> Result<(), Error>,
    {
        let mut buf = PacketBytesWriter {
            buffer: BytesMut::new(),
        };
        f(&mut buf)?;
        let packet = buf.freeze();
        self.packet_raw(packet.as_ref())?;
        Ok(packet)
    }

    pub fn buffer(&mut self) -> &mut SSHBuffer {
        &mut self.write_buffer
    }

    /// Payload bytes written since the current cipher was installed.
    pub fn bytes_written(&self) -> usize {
        self.write_buffer.bytes
    }

    pub fn compress(&mut self) -> &mut Compress {
        &mut self.compress
    }

    pub fn set_cipher(&mut self, cipher: Box<dyn SealingKey + Send>) {
        self.cipher = cipher;
        // Every cipher installation starts a new key epoch. In particular,
        // discard the cleartext KEX packets counted before the initial keys
        // were installed as well as the previous encrypted epoch on rekey.
        self.write_buffer.bytes = 0;
    }

    pub fn reset_seqn(&mut self) {
        self.write_buffer.seqn = Wrapping(0);
    }

    pub async fn flush_into<W: AsyncWrite + Unpin>(&mut self, w: &mut W) -> std::io::Result<()> {
        if !self.write_buffer.buffer.is_empty() {
            w.write_all(&self.write_buffer.buffer).await?;
            w.flush().await?;
            self.write_buffer.buffer.clear();
        }
        Ok(())
    }
}
