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

use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::mem::replace;
use std::num::Wrapping;
use std::time::Duration;

use byteorder::{BigEndian, ByteOrder};
use bytes::Bytes;
use log::{debug, trace};
use ssh_encoding::Encode;
use tokio::sync::oneshot;

use crate::cipher::OpeningKey;
use crate::client::GexParams;
use crate::kex::dh::groups::DhGroup;
use crate::kex::{KexAlgorithm, KexAlgorithmImplementor};
use crate::sshbuffer::PacketWriter;
use crate::{
    ChannelId, ChannelParams, CryptoVec, Disconnect, Limits, auth, cipher, mac, msg, negotiation,
};

#[derive(Debug)]
pub(crate) struct Encrypted {
    pub state: EncryptedState,

    // It's always Some, except when we std::mem::replace it temporarily.
    pub exchange: Option<Exchange>,
    pub kex: KexAlgorithm,
    pub key: usize,
    pub client_mac: mac::Name,
    pub server_mac: mac::Name,
    pub session_id: CryptoVec,
    pub channels: HashMap<ChannelId, ChannelParams>,
    pub last_channel_id: Wrapping<u32>,
    // Non-sensitive packet assembly buffer, analogous to
    // OpenSSH sshbuf (output side).  Not mlocked because it
    // holds only protocol framing and ciphertext.
    pub write: Vec<u8>,
    pub write_cursor: usize,
    pub last_rekey: russh_util::time::Instant,
    pub server_compression: crate::compression::Compression,
    pub client_compression: crate::compression::Compression,
    pub decompress: crate::compression::Decompress,
    pub rekey_wanted: bool,
    pub received_extensions: Vec<String>,
    pub extension_info_awaiters: HashMap<String, Vec<oneshot::Sender<()>>>,
}

pub(crate) struct CommonSession<Config> {
    pub auth_user: String,
    pub remote_sshid: Vec<u8>,
    pub config: Config,
    pub encrypted: Option<Encrypted>,
    pub auth_method: Option<auth::Method>,
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub(crate) auth_attempts: usize,
    pub packet_writer: PacketWriter,
    pub remote_to_local: Box<dyn OpeningKey + Send>,
    pub wants_reply: bool,
    pub disconnected: bool,
    // Non-sensitive incoming-packet scratch buffer.
    pub buffer: Vec<u8>,
    pub strict_kex: bool,
    pub alive_timeouts: usize,
    pub received_data: bool,
}

impl<C> Debug for CommonSession<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommonSession")
            .field("auth_user", &self.auth_user)
            .field("remote_sshid", &self.remote_sshid)
            .field("encrypted", &self.encrypted)
            .field("auth_method", &self.auth_method)
            .field("auth_attempts", &self.auth_attempts)
            .field("packet_writer", &self.packet_writer)
            .field("wants_reply", &self.wants_reply)
            .field("disconnected", &self.disconnected)
            .field("buffer", &self.buffer)
            .field("strict_kex", &self.strict_kex)
            .field("alive_timeouts", &self.alive_timeouts)
            .field("received_data", &self.received_data)
            .finish()
    }
}

#[must_use]
#[derive(Debug, Clone, Copy)]
pub(crate) enum ChannelFlushResult {
    Incomplete {
        wrote: usize,
    },
    Complete {
        wrote: usize,
        pending_eof: bool,
        pending_close: bool,
    },
}
impl ChannelFlushResult {
    pub(crate) fn wrote(&self) -> usize {
        match self {
            ChannelFlushResult::Incomplete { wrote } => *wrote,
            ChannelFlushResult::Complete { wrote, .. } => *wrote,
        }
    }
    pub(crate) fn complete(wrote: usize, channel: &mut ChannelParams) -> Self {
        let (pending_eof, pending_close) = channel.take_pending_controls();
        ChannelFlushResult::Complete {
            wrote,
            pending_eof,
            pending_close,
        }
    }
}

impl<C> CommonSession<C> {
    pub(crate) fn has_any_pending_data(&self) -> bool {
        self.encrypted
            .as_ref()
            .is_some_and(Encrypted::has_any_pending_data)
    }

    /// Channel-scoped messages (`CHANNEL_DATA`, `CHANNEL_EOF`, `CHANNEL_CLOSE`,
    /// `CHANNEL_REQUEST`, ...) operate on an already-open channel. An
    /// authenticated peer must not be able to drive channel callbacks
    /// (`data`, `exit_status`, `channel_close`, ...) for a recipient id that
    /// was never opened or whose local open is still waiting for peer
    /// confirmation. The encrypted channel table is authoritative for the SSH
    /// protocol state.
    pub(crate) fn is_established_channel(&self, channel: ChannelId) -> bool {
        self.encrypted
            .as_ref()
            .and_then(|enc| enc.channels.get(&channel))
            .is_some_and(|channel| channel.confirmed)
    }

    pub fn newkeys(&mut self, newkeys: NewKeys) {
        if let Some(ref mut enc) = self.encrypted {
            enc.exchange = Some(newkeys.exchange);
            enc.kex = newkeys.kex;
            enc.key = newkeys.key;
            enc.client_mac = newkeys.names.client_mac;
            enc.server_mac = newkeys.names.server_mac;
            self.remote_to_local = newkeys.cipher.remote_to_local;
            self.packet_writer
                .set_cipher(newkeys.cipher.local_to_remote);
            self.strict_kex = self.strict_kex || newkeys.names.strict_kex();

            // Reset compression state
            enc.client_compression
                .init_compress(self.packet_writer.compress());
            enc.server_compression.init_decompress(&mut enc.decompress);
        }
    }

    pub fn encrypted(&mut self, state: EncryptedState, newkeys: NewKeys) {
        let strict_kex = newkeys.names.strict_kex();
        self.encrypted = Some(Encrypted {
            exchange: Some(newkeys.exchange),
            kex: newkeys.kex,
            key: newkeys.key,
            client_mac: newkeys.names.client_mac,
            server_mac: newkeys.names.server_mac,
            session_id: newkeys.session_id,
            state,
            channels: HashMap::new(),
            last_channel_id: Wrapping(1),
            write: Vec::new(),
            write_cursor: 0,
            last_rekey: russh_util::time::Instant::now(),
            server_compression: newkeys.names.server_compression,
            client_compression: newkeys.names.client_compression,
            decompress: crate::compression::Decompress::None,
            rekey_wanted: false,
            received_extensions: Vec::new(),
            extension_info_awaiters: HashMap::new(),
        });
        self.remote_to_local = newkeys.cipher.remote_to_local;
        self.packet_writer
            .set_cipher(newkeys.cipher.local_to_remote);
        self.strict_kex = strict_kex;

        // For non-deferred compression (RFC 4253 "zlib"), activate immediately
        // after initial key exchange. Deferred compression ("zlib@openssh.com")
        // will be activated later, after authentication succeeds.
        if let Some(ref mut enc) = self.encrypted {
            if !enc.client_compression.is_deferred() {
                enc.client_compression
                    .init_compress(self.packet_writer.compress());
            }
            if !enc.server_compression.is_deferred() {
                enc.server_compression.init_decompress(&mut enc.decompress);
            }
        }
    }

    /// Send a disconnect message.
    pub fn disconnect(
        &mut self,
        reason: Disconnect,
        description: &str,
        language_tag: &str,
    ) -> Result<(), crate::Error> {
        let disconnect = |buf: &mut Vec<u8>| {
            push_packet!(buf, {
                msg::DISCONNECT.encode(buf)?;
                (reason as u32).encode(buf)?;
                description.encode(buf)?;
                language_tag.encode(buf)?;
            });
            Ok(())
        };
        if !self.disconnected {
            self.disconnected = true;
            return if let Some(ref mut enc) = self.encrypted {
                disconnect(&mut enc.write)
            } else {
                disconnect(&mut self.packet_writer.buffer().buffer)
            };
        }
        Ok(())
    }

    /// Send a debug message.
    pub fn debug(
        &mut self,
        always_display: bool,
        message: &str,
        language_tag: &str,
    ) -> Result<(), crate::Error> {
        let debug = |buf: &mut Vec<u8>| {
            push_packet!(buf, {
                msg::DEBUG.encode(buf)?;
                (always_display as u8).encode(buf)?;
                message.encode(buf)?;
                language_tag.encode(buf)?;
            });
            Ok(())
        };
        if let Some(ref mut enc) = self.encrypted {
            debug(&mut enc.write)
        } else {
            debug(&mut self.packet_writer.buffer().buffer)
        }
    }

    pub(crate) fn reset_seqn(&mut self) {
        self.packet_writer.reset_seqn();
    }
}

impl Encrypted {
    pub fn byte(&mut self, channel: ChannelId, msg: u8) -> Result<(), crate::Error> {
        if let Some(channel) = self.channels.get(&channel) {
            push_packet!(self.write, {
                self.write.push(msg);
                channel.recipient_channel.encode(&mut self.write)?;
            });
        }
        Ok(())
    }

    pub fn eof(&mut self, channel: ChannelId) -> Result<(), crate::Error> {
        if let Some(channel) = self.has_pending_data_mut(channel) {
            channel.pending_eof = true;
        } else {
            self.byte(channel, msg::CHANNEL_EOF)?;
        }
        Ok(())
    }

    pub fn close(&mut self, channel: ChannelId) -> Result<(), crate::Error> {
        if let Some(channel) = self.has_pending_data_mut(channel) {
            channel.pending_close = true;
        } else {
            self.byte(channel, msg::CHANNEL_CLOSE)?;
            self.channels.remove(&channel);
        }
        Ok(())
    }

    pub fn sender_window_size(&self, channel: ChannelId) -> usize {
        if let Some(channel) = self.channels.get(&channel) {
            channel.sender_window_size as usize
        } else {
            0
        }
    }

    pub fn adjust_window_size(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        target: u32,
    ) -> Result<bool, crate::Error> {
        if let Some(channel) = self.channels.get_mut(&channel) {
            trace!(
                "adjust_window_size, channel = {}, size = {},",
                channel.sender_channel, target
            );
            if target == 0 && data.len() > channel.sender_window_size as usize {
                return Err(crate::Error::Inconsistent);
            }
            // Ignore extra data.
            // https://tools.ietf.org/html/rfc4254#section-5.2
            if data.len() as u32 <= channel.sender_window_size {
                channel.sender_window_size -= data.len() as u32;
            }
            if channel.sender_window_size < target / 2 {
                debug!(
                    "sender_window_size {:?}, target {:?}",
                    channel.sender_window_size, target
                );
                push_packet!(self.write, {
                    self.write.push(msg::CHANNEL_WINDOW_ADJUST);
                    channel.recipient_channel.encode(&mut self.write)?;
                    (target - channel.sender_window_size).encode(&mut self.write)?;
                });
                channel.sender_window_size = target;
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn consume_window(&mut self, id: ChannelId, bytes: u32, limit: u32) -> Result<(), crate::Error> {
        let Some(channel) = self.channels.get_mut(&id) else { return Ok(()); };
        let available = channel.sender_window_size.checked_add(bytes).ok_or(crate::Error::Inconsistent)?;
        if available > limit { return Err(crate::Error::Inconsistent); }
        if bytes > 0 {
            push_packet!(self.write, {
                self.write.push(msg::CHANNEL_WINDOW_ADJUST);
                channel.recipient_channel.encode(&mut self.write)?;
                bytes.encode(&mut self.write)?;
            });
            channel.sender_window_size = available;
        }
        Ok(())
    }

    fn flush_channel(
        write: &mut Vec<u8>,
        channel: &mut ChannelParams,
    ) -> Result<ChannelFlushResult, crate::Error> {
        let mut pending_size = 0;
        while let Some((buf, a, from)) = channel.pending_data.pop_front() {
            let size = Self::data_noqueue(write, channel, &buf, a, from)?;
            pending_size += size;
            if from + size < buf.len() {
                channel.pending_data.push_front((buf, a, from + size));
                return Ok(ChannelFlushResult::Incomplete {
                    wrote: pending_size,
                });
            }
        }
        Ok(ChannelFlushResult::complete(pending_size, channel))
    }

    fn flush_channel_with_writer(
        write: &mut Vec<u8>,
        writer: &mut PacketWriter,
        channel: &mut ChannelParams,
        is_rekeying: bool,
    ) -> Result<ChannelFlushResult, crate::Error> {
        let mut pending_size = 0;
        while let Some((buf, a, from)) = channel.pending_data.pop_front() {
            // While a kex is in flight, stage into `write` instead of the wire:
            // RFC 4253 s7.1 allows only transport-layer messages between
            // KEXINIT and NEWKEYS, and `Encrypted::flush` holds `write` back
            // until the kex completes.
            let size = if write.is_empty() && !is_rekeying {
                Self::data_noqueue_direct(writer, channel, &buf, a, from)?
            } else {
                Self::data_noqueue(write, channel, &buf, a, from)?
            };
            pending_size += size;
            if from + size < buf.len() {
                channel.pending_data.push_front((buf, a, from + size));
                return Ok(ChannelFlushResult::Incomplete {
                    wrote: pending_size,
                });
            }
        }
        Ok(ChannelFlushResult::complete(pending_size, channel))
    }

    fn handle_flushed_channel(
        &mut self,
        channel: ChannelId,
        flush_result: ChannelFlushResult,
    ) -> Result<(), crate::Error> {
        if let ChannelFlushResult::Complete {
            wrote: _,
            pending_eof,
            pending_close,
        } = flush_result
        {
            if pending_eof {
                self.eof(channel)?;
            }
            if pending_close {
                self.close(channel)?;
            }
        }
        Ok(())
    }

    pub fn flush_pending(&mut self, channel: ChannelId) -> Result<usize, crate::Error> {
        let flush_result = match self.channels.get_mut(&channel) {
            Some(ch) => Self::flush_channel(&mut self.write, ch)?,
            None => return Ok(0),
        };
        let wrote = flush_result.wrote();
        self.handle_flushed_channel(channel, flush_result)?;
        Ok(wrote)
    }

    pub fn flush_pending_with_writer(
        &mut self,
        writer: &mut PacketWriter,
        channel: ChannelId,
        is_rekeying: bool,
    ) -> Result<usize, crate::Error> {
        let flush_result = match self.channels.get_mut(&channel) {
            Some(ch) => Self::flush_channel_with_writer(&mut self.write, writer, ch, is_rekeying)?,
            None => return Ok(0),
        };
        let wrote = flush_result.wrote();
        self.handle_flushed_channel(channel, flush_result)?;
        Ok(wrote)
    }

    #[allow(dead_code)]
    pub fn flush_all_pending(&mut self) -> Result<(), crate::Error> {
        let channel_ids: Vec<ChannelId> = self.channels.keys().copied().collect();
        for channel_id in channel_ids {
            self.flush_pending(channel_id)?;
        }
        Ok(())
    }

    pub fn flush_all_pending_with_writer(
        &mut self,
        writer: &mut PacketWriter,
        is_rekeying: bool,
    ) -> Result<(), crate::Error> {
        let channel_ids: Vec<ChannelId> = self.channels.keys().copied().collect();
        for channel_id in channel_ids {
            self.flush_pending_with_writer(writer, channel_id, is_rekeying)?;
        }
        Ok(())
    }

    fn has_pending_data_mut(&mut self, channel: ChannelId) -> Option<&mut ChannelParams> {
        self.channels
            .get_mut(&channel)
            .filter(|c| !c.pending_data.is_empty())
    }

    pub fn has_pending_data(&self, channel: ChannelId) -> bool {
        if let Some(channel) = self.channels.get(&channel) {
            !channel.pending_data.is_empty()
        } else {
            false
        }
    }

    pub(crate) fn has_any_pending_data(&self) -> bool {
        self.channels
            .values()
            .any(|channel| !channel.pending_data.is_empty())
    }

    /// Push the largest amount of `&buf0[from..]` that can fit into
    /// the window, dividing it into packets if it is too large, and
    /// return the length that was written.
    fn data_noqueue(
        write: &mut Vec<u8>,
        channel: &mut ChannelParams,
        buf0: &[u8],
        a: Option<u32>,
        from: usize,
    ) -> Result<usize, crate::Error> {
        if from >= buf0.len() {
            return Ok(0);
        }
        let window_end = from.saturating_add(channel.recipient_window_size as usize);
        let end = std::cmp::min(buf0.len(), window_end);
        #[allow(clippy::indexing_slicing)] // length checked
        let mut buf = &buf0[from..end];
        let buf_len = buf.len();
        let max_packet_size = channel.recipient_maximum_packet_size as usize;
        if max_packet_size == 0 {
            return Err(crate::Error::Inconsistent);
        }
        let packet_count = buf_len.div_ceil(max_packet_size);
        let packet_overhead = match a {
            None => 4 + 1 + 4 + 4,
            Some(_) => 4 + 1 + 4 + 4 + 4,
        };
        write.reserve(buf_len.saturating_add(packet_count.saturating_mul(packet_overhead)));

        while !buf.is_empty() {
            // Compute the length we're allowed to send.
            let off = std::cmp::min(buf.len(), max_packet_size);
            match a {
                None => push_packet!(write, {
                    write.push(msg::CHANNEL_DATA);
                    channel.recipient_channel.encode(write)?;
                    #[allow(clippy::indexing_slicing)] // length checked
                    buf[..off].encode(write)?;
                }),
                Some(ext) => push_packet!(write, {
                    write.push(msg::CHANNEL_EXTENDED_DATA);
                    channel.recipient_channel.encode(write)?;
                    ext.encode(write)?;
                    #[allow(clippy::indexing_slicing)] // length checked
                    buf[..off].encode(write)?;
                }),
            }
            trace!(
                "buffer: {:?} {:?}",
                write.len(),
                channel.recipient_window_size
            );
            channel.recipient_window_size -= off as u32;
            #[allow(clippy::indexing_slicing)] // length checked
            {
                buf = &buf[off..]
            }
        }
        trace!("buf.len() = {:?}, buf_len = {:?}", buf.len(), buf_len);
        Ok(buf_len)
    }

    fn data_noqueue_direct(
        writer: &mut PacketWriter,
        channel: &mut ChannelParams,
        buf0: &Bytes,
        a: Option<u32>,
        from: usize,
    ) -> Result<usize, crate::Error> {
        if from >= buf0.len() {
            return Ok(0);
        }
        let buf0 = buf0.as_ref();
        let window_end = from.saturating_add(channel.recipient_window_size as usize);
        let end = std::cmp::min(buf0.len(), window_end);
        #[allow(clippy::indexing_slicing)] // length checked
        let mut buf = &buf0[from..end];
        let buf_len = buf.len();
        let max_packet_size = channel.recipient_maximum_packet_size as usize;
        if max_packet_size == 0 {
            return Err(crate::Error::Inconsistent);
        }
        let packet_count = buf_len.div_ceil(max_packet_size);
        let channel_payload_overhead = match a {
            None => 1 + 4 + 4,
            Some(_) => 1 + 4 + 4 + 4,
        };
        writer.reserve_cleartext_packet_output(
            buf_len.saturating_add(packet_count.saturating_mul(channel_payload_overhead)),
            packet_count,
        );

        while !buf.is_empty() {
            let off = std::cmp::min(buf.len(), max_packet_size);
            match a {
                None => writer.write_packet(|packet| {
                    packet.push(msg::CHANNEL_DATA);
                    channel.recipient_channel.encode(packet)?;
                    #[allow(clippy::indexing_slicing)] // length checked
                    buf[..off].encode(packet)?;
                    Ok(())
                })?,
                Some(ext) => writer.write_packet(|packet| {
                    packet.push(msg::CHANNEL_EXTENDED_DATA);
                    channel.recipient_channel.encode(packet)?;
                    ext.encode(packet)?;
                    #[allow(clippy::indexing_slicing)] // length checked
                    buf[..off].encode(packet)?;
                    Ok(())
                })?,
            }
            channel.recipient_window_size -= off as u32;
            #[allow(clippy::indexing_slicing)] // length checked
            {
                buf = &buf[off..]
            }
        }
        Ok(buf_len)
    }

    #[allow(dead_code)]
    pub fn data(
        &mut self,
        channel: ChannelId,
        buf0: impl Into<Bytes>,
        is_rekeying: bool,
    ) -> Result<(), crate::Error> {
        let buf0 = buf0.into();
        if let Some(channel) = self.channels.get_mut(&channel) {
            assert!(channel.confirmed);
            if !channel.pending_data.is_empty() || is_rekeying {
                channel.pending_data.push_back((buf0, None, 0));
                return Ok(());
            }
            let buf_len = Self::data_noqueue(&mut self.write, channel, &buf0, None, 0)?;
            if buf_len < buf0.len() {
                channel.pending_data.push_back((buf0, None, buf_len))
            }
        } else {
            debug!("{channel:?} not saved for this session");
        }
        Ok(())
    }

    pub fn data_with_writer(
        &mut self,
        writer: &mut PacketWriter,
        channel: ChannelId,
        buf0: impl Into<Bytes>,
        is_rekeying: bool,
    ) -> Result<(), crate::Error> {
        let buf0 = buf0.into();
        if let Some(channel) = self.channels.get_mut(&channel) {
            assert!(channel.confirmed);
            if !channel.pending_data.is_empty() || is_rekeying {
                channel.pending_data.push_back((buf0, None, 0));
                return Ok(());
            }
            let buf_len = if self.write.is_empty() {
                Self::data_noqueue_direct(writer, channel, &buf0, None, 0)?
            } else {
                Self::data_noqueue(&mut self.write, channel, &buf0, None, 0)?
            };
            if buf_len < buf0.len() {
                channel.pending_data.push_back((buf0, None, buf_len))
            }
        } else {
            debug!("{channel:?} not saved for this session");
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub fn extended_data(
        &mut self,
        channel: ChannelId,
        ext: u32,
        buf0: impl Into<Bytes>,
        is_rekeying: bool,
    ) -> Result<(), crate::Error> {
        let buf0 = buf0.into();
        if let Some(channel) = self.channels.get_mut(&channel) {
            assert!(channel.confirmed);
            if !channel.pending_data.is_empty() || is_rekeying {
                channel.pending_data.push_back((buf0, Some(ext), 0));
                return Ok(());
            }
            let buf_len = Self::data_noqueue(&mut self.write, channel, &buf0, Some(ext), 0)?;
            if buf_len < buf0.len() {
                channel.pending_data.push_back((buf0, Some(ext), buf_len))
            }
        }
        Ok(())
    }

    pub fn extended_data_with_writer(
        &mut self,
        writer: &mut PacketWriter,
        channel: ChannelId,
        ext: u32,
        buf0: impl Into<Bytes>,
        is_rekeying: bool,
    ) -> Result<(), crate::Error> {
        let buf0 = buf0.into();
        if let Some(channel) = self.channels.get_mut(&channel) {
            assert!(channel.confirmed);
            if !channel.pending_data.is_empty() || is_rekeying {
                channel.pending_data.push_back((buf0, Some(ext), 0));
                return Ok(());
            }
            let buf_len = if self.write.is_empty() {
                Self::data_noqueue_direct(writer, channel, &buf0, Some(ext), 0)?
            } else {
                Self::data_noqueue(&mut self.write, channel, &buf0, Some(ext), 0)?
            };
            if buf_len < buf0.len() {
                channel.pending_data.push_back((buf0, Some(ext), buf_len))
            }
        }
        Ok(())
    }

    pub fn flush(
        &mut self,
        limits: &Limits,
        writer: &mut PacketWriter,
        is_rekeying: bool,
    ) -> Result<bool, crate::Error> {
        if is_rekeying {
            // Only transport-layer messages may go out between KEXINIT and
            // NEWKEYS (RFC 4253 s7.1); `write` holds connection-layer ones.
            // The post-kex flush drains them.
            return Ok(false);
        }

        // If there are pending packets (and we've not started to rekey), flush them.
        {
            while self.write_cursor < self.write.len() {
                // Read a single packet, encrypt and send it.
                #[allow(clippy::indexing_slicing)] // length checked
                let len = BigEndian::read_u32(&self.write[self.write_cursor..]) as usize;
                #[allow(clippy::indexing_slicing)]
                let to_write = &self.write[(self.write_cursor + 4)..(self.write_cursor + 4 + len)];
                trace!(
                    "session_write_encrypted, msg type {:?}, len {}",
                    to_write.first(),
                    to_write.len()
                );

                writer.packet_raw(to_write)?;
                self.write_cursor += 4 + len
            }
        }
        if self.write_cursor >= self.write.len() {
            // If all packets have been written, clear.
            self.write_cursor = 0;
            self.write.clear();
        }

        if self.kex.skip_exchange() {
            return Ok(false);
        }

        let now = russh_util::time::Instant::now();
        let dur = now.duration_since(self.last_rekey);
        Ok(replace(&mut self.rekey_wanted, false)
            || writer.buffer().bytes >= limits.rekey_write_limit
            || dur >= limits.rekey_time_limit)
    }

    /// Delay until an automatic rekey is due: zero when the write limit is
    /// already exceeded, otherwise what is left of the time limit.
    pub(crate) fn rekey_time_remaining(
        &self,
        limits: &Limits,
        writer: &PacketWriter,
    ) -> Option<Duration> {
        if self.kex.skip_exchange() {
            return None;
        }
        if writer.bytes_written() >= limits.rekey_write_limit {
            return Some(Duration::ZERO);
        }
        let elapsed = russh_util::time::Instant::now().duration_since(self.last_rekey);
        Some(limits.rekey_time_limit.saturating_sub(elapsed))
    }

    pub fn new_channel_id(&mut self) -> ChannelId {
        self.last_channel_id += Wrapping(1);
        while self
            .channels
            .contains_key(&ChannelId(self.last_channel_id.0))
        {
            self.last_channel_id += Wrapping(1)
        }
        ChannelId(self.last_channel_id.0)
    }
    pub fn new_channel(&mut self, window_size: u32, maxpacket: u32) -> ChannelId {
        loop {
            self.last_channel_id += Wrapping(1);
            if let std::collections::hash_map::Entry::Vacant(vacant_entry) =
                self.channels.entry(ChannelId(self.last_channel_id.0))
            {
                vacant_entry.insert(ChannelParams {
                    recipient_channel: 0,
                    sender_channel: ChannelId(self.last_channel_id.0),
                    sender_window_size: window_size,
                    recipient_window_size: 0,
                    sender_maximum_packet_size: maxpacket,
                    recipient_maximum_packet_size: 0,
                    confirmed: false,
                    wants_reply: false,
                    pending_data: std::collections::VecDeque::new(),
                    pending_eof: false,
                    pending_close: false,
                });
                return ChannelId(self.last_channel_id.0);
            }
        }
    }
}

#[derive(Debug)]
pub enum EncryptedState {
    WaitingAuthServiceRequest { sent: bool, accepted: bool },
    WaitingAuthRequest(auth::AuthRequest),
    InitCompression,
    Authenticated,
}

#[derive(Debug, Default, Clone)]
pub struct Exchange {
    // All Exchange fields are public protocol values (identifiers,
    // kex init payloads, ephemeral public keys) visible on the wire.
    // They carry no secret material and do not require mlock.
    pub client_id: Vec<u8>,
    pub server_id: Vec<u8>,
    pub client_kex_init: Bytes,
    pub server_kex_init: Bytes,
    pub client_ephemeral: Vec<u8>,
    pub server_ephemeral: Vec<u8>,
    pub gex: Option<(GexParams, DhGroup)>,
}

impl Exchange {
    pub fn new(client_id: &[u8], server_id: &[u8]) -> Self {
        Exchange {
            client_id: client_id.into(),
            server_id: server_id.into(),
            ..Default::default()
        }
    }
}

#[derive(Debug)]
pub(crate) struct NewKeys {
    pub exchange: Exchange,
    pub names: negotiation::Names,
    pub kex: KexAlgorithm,
    pub key: usize,
    pub cipher: cipher::CipherPair,
    pub session_id: CryptoVec,
}

#[derive(Debug)]
pub(crate) enum GlobalRequestResponse {
    /// request was for Keepalive, ignore result
    Keepalive,
    /// request was for Keepalive but with notification of the result
    Ping(oneshot::Sender<()>),
    /// request was for NoMoreSessions, disallow additional sessions
    NoMoreSessions,
    /// request was for TcpIpForward, sends Some(port) for success or None for failure
    TcpIpForward(oneshot::Sender<Option<u32>>),
    /// request was for CancelTcpIpForward, sends true for success or false for failure
    CancelTcpIpForward(oneshot::Sender<bool>),
    /// request was for StreamLocalForward, sends true for success or false for failure
    StreamLocalForward(oneshot::Sender<bool>),
    CancelStreamLocalForward(oneshot::Sender<bool>),
    /// OpenSSH host-key ownership proof
    HostKeysProve {
        return_channel: oneshot::Sender<Result<(), crate::Error>>,
        keys: Vec<crate::keys::PublicKey>,
    },
    /// request had a custom name; sends `Some` with the response-specific
    /// payload on success or `None` on failure
    Other(oneshot::Sender<Option<CryptoVec>>),
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, VecDeque};
    use std::num::Wrapping;

    use byteorder::{BigEndian, ByteOrder};
    use bytes::Bytes;

    use super::{Encrypted, EncryptedState, Exchange};
    use crate::compression::{Compression, Decompress};
    use crate::kex::{KEXES, NONE};
    use crate::sshbuffer::PacketWriter;
    use crate::{ChannelId, ChannelParams, CryptoVec, Limits, mac, msg};

    fn test_encrypted() -> Encrypted {
        Encrypted {
            state: EncryptedState::Authenticated,
            exchange: Some(Exchange::default()),
            kex: KEXES.get(&NONE).unwrap().make(),
            key: 0,
            client_mac: mac::NONE,
            server_mac: mac::NONE,
            session_id: CryptoVec::new(),
            channels: HashMap::new(),
            last_channel_id: Wrapping(0),
            write: Vec::new(),
            write_cursor: 0,
            last_rekey: russh_util::time::Instant::now(),
            server_compression: Compression::None,
            client_compression: Compression::None,
            decompress: Decompress::None,
            rekey_wanted: false,
            received_extensions: Vec::new(),
            extension_info_awaiters: HashMap::new(),
        }
    }

    fn test_channel(
        sender_channel: ChannelId,
        recipient_channel: u32,
        pending_eof: bool,
        pending_close: bool,
    ) -> ChannelParams {
        ChannelParams {
            recipient_channel,
            sender_channel,
            recipient_window_size: 1024,
            sender_window_size: 1024,
            recipient_maximum_packet_size: 1024,
            sender_maximum_packet_size: 1024,
            confirmed: true,
            wants_reply: false,
            pending_data: VecDeque::from([(Bytes::from_static(b"hello"), None, 0)]),
            pending_eof,
            pending_close,
        }
    }

    fn packet_types(buf: &[u8]) -> Vec<u8> {
        let mut packet_types = Vec::new();
        let mut cursor = 0;

        while cursor < buf.len() {
            let packet_len = BigEndian::read_u32(&buf[cursor..cursor + 4]) as usize;
            packet_types.push(buf[cursor + 4]);
            cursor += 4 + packet_len;
        }

        packet_types
    }

    fn clear_packet_types(buf: &[u8]) -> Vec<u8> {
        let mut packet_types = Vec::new();
        let mut cursor = 0;

        while cursor < buf.len() {
            let packet_len = BigEndian::read_u32(&buf[cursor..cursor + 4]) as usize;
            packet_types.push(buf[cursor + 5]);
            cursor += 4 + packet_len;
        }

        packet_types
    }

    fn test_ready_channel(sender_channel: ChannelId, recipient_channel: u32) -> ChannelParams {
        let mut channel = test_channel(sender_channel, recipient_channel, false, false);
        channel.pending_data.clear();
        channel
    }

    fn test_channel_windowed(
        sender_channel: ChannelId,
        recipient_channel: u32,
        window_size: u32,
        pending_eof: bool,
        pending_close: bool,
    ) -> ChannelParams {
        ChannelParams {
            recipient_channel,
            sender_channel,
            recipient_window_size: window_size,
            sender_window_size: 1024,
            recipient_maximum_packet_size: 1024,
            sender_maximum_packet_size: 1024,
            confirmed: true,
            wants_reply: false,
            pending_data: VecDeque::from([(Bytes::from_static(b"hello"), None, 0)]),
            pending_eof,
            pending_close,
        }
    }

    // flush_pending (single-channel path)

    #[test]
    fn flush_pending_replays_deferred_eof_once() {
        let channel_id = ChannelId(10);
        let mut encrypted = test_encrypted();
        encrypted
            .channels
            .insert(channel_id, test_channel(channel_id, 42, true, false));

        encrypted.flush_pending(channel_id).unwrap();
        assert_eq!(
            packet_types(&encrypted.write),
            vec![msg::CHANNEL_DATA, msg::CHANNEL_EOF]
        );
        assert!(!encrypted.channels[&channel_id].pending_eof);

        // Second flush must not re-emit EOF.
        encrypted.flush_pending(channel_id).unwrap();
        assert_eq!(
            packet_types(&encrypted.write),
            vec![msg::CHANNEL_DATA, msg::CHANNEL_EOF]
        );
    }

    #[test]
    fn flush_pending_replays_deferred_close_and_removes_channel() {
        let channel_id = ChannelId(11);
        let mut encrypted = test_encrypted();
        encrypted
            .channels
            .insert(channel_id, test_channel(channel_id, 43, true, true));

        encrypted.flush_pending(channel_id).unwrap();
        assert_eq!(
            packet_types(&encrypted.write),
            vec![msg::CHANNEL_DATA, msg::CHANNEL_EOF, msg::CHANNEL_CLOSE]
        );
        assert!(!encrypted.channels.contains_key(&channel_id));
    }

    #[test]
    fn flush_pending_no_controls_when_incomplete() {
        // Window smaller than data: flush is incomplete, EOF/CLOSE must not be sent.
        let channel_id = ChannelId(12);
        let mut encrypted = test_encrypted();
        encrypted.channels.insert(
            channel_id,
            test_channel_windowed(channel_id, 44, 3, true, true),
        );

        encrypted.flush_pending(channel_id).unwrap();
        // Only partial data fits; no EOF or CLOSE yet.
        assert_eq!(packet_types(&encrypted.write), vec![msg::CHANNEL_DATA]);
        assert!(encrypted.channels.contains_key(&channel_id));
        assert!(encrypted.channels[&channel_id].pending_eof);
        assert!(encrypted.channels[&channel_id].pending_close);
    }

    // flush_all_pending (multi-channel path)

    #[test]
    fn flush_all_pending_replays_deferred_eof_once() {
        let channel_id = ChannelId(1);
        let mut encrypted = test_encrypted();
        encrypted
            .channels
            .insert(channel_id, test_channel(channel_id, 42, true, false));

        encrypted.flush_all_pending().unwrap();
        assert_eq!(
            packet_types(&encrypted.write),
            vec![msg::CHANNEL_DATA, msg::CHANNEL_EOF]
        );
        assert!(!encrypted.channels[&channel_id].pending_eof);

        encrypted.flush_all_pending().unwrap();
        assert_eq!(
            packet_types(&encrypted.write),
            vec![msg::CHANNEL_DATA, msg::CHANNEL_EOF]
        );
    }

    #[test]
    fn flush_all_pending_replays_deferred_close_and_removes_channel() {
        let channel_id = ChannelId(2);
        let mut encrypted = test_encrypted();
        encrypted
            .channels
            .insert(channel_id, test_channel(channel_id, 43, true, true));

        encrypted.flush_all_pending().unwrap();
        assert_eq!(
            packet_types(&encrypted.write),
            vec![msg::CHANNEL_DATA, msg::CHANNEL_EOF, msg::CHANNEL_CLOSE]
        );
        assert!(!encrypted.channels.contains_key(&channel_id));
    }

    #[test]
    fn flush_all_pending_replays_deferred_controls_across_channels() {
        let channel_a = ChannelId(3);
        let channel_b = ChannelId(4);
        let mut encrypted = test_encrypted();
        encrypted
            .channels
            .insert(channel_a, test_channel(channel_a, 44, true, false));
        encrypted
            .channels
            .insert(channel_b, test_channel(channel_b, 45, false, true));

        encrypted.flush_all_pending().unwrap();

        let packet_types = packet_types(&encrypted.write);
        assert_eq!(
            packet_types
                .iter()
                .filter(|&&msg_type| msg_type == msg::CHANNEL_DATA)
                .count(),
            2
        );
        assert_eq!(
            packet_types
                .iter()
                .filter(|&&msg_type| msg_type == msg::CHANNEL_EOF)
                .count(),
            1
        );
        assert_eq!(
            packet_types
                .iter()
                .filter(|&&msg_type| msg_type == msg::CHANNEL_CLOSE)
                .count(),
            1
        );
        assert!(encrypted.channels.contains_key(&channel_a));
        assert!(!encrypted.channels.contains_key(&channel_b));
    }

    #[test]
    fn data_queues_behind_existing_pending_data_when_not_rekeying() {
        let channel_id = ChannelId(5);
        let mut encrypted = test_encrypted();
        encrypted
            .channels
            .insert(channel_id, test_channel(channel_id, 42, false, false));

        let channel = &encrypted.channels[&channel_id];
        let initial_pending = channel.pending_data.len();
        assert!(initial_pending > 0);
        let initial_front = channel.pending_data.front().unwrap();
        let initial_front_data = initial_front.0.to_vec();
        let initial_front_ext = initial_front.1;

        encrypted
            .data(channel_id, Bytes::from_static(b"new"), false)
            .unwrap();

        let channel = &encrypted.channels[&channel_id];
        assert_eq!(channel.pending_data.len(), initial_pending + 1);
        assert_eq!(
            channel.pending_data.front().unwrap().0.as_ref(),
            initial_front_data.as_slice()
        );
        assert_eq!(channel.pending_data.front().unwrap().1, initial_front_ext);
        assert_eq!(channel.pending_data.back().unwrap().0.as_ref(), b"new");
        assert_eq!(channel.pending_data.back().unwrap().1, None);
        assert!(encrypted.write.is_empty());
    }

    #[test]
    fn extended_data_queues_behind_existing_pending_data_when_not_rekeying() {
        let channel_id = ChannelId(6);
        let ext = 1;
        let mut encrypted = test_encrypted();
        encrypted
            .channels
            .insert(channel_id, test_channel(channel_id, 42, false, false));

        let channel = &encrypted.channels[&channel_id];
        let initial_pending = channel.pending_data.len();
        assert!(initial_pending > 0);
        let initial_front = channel.pending_data.front().unwrap();
        let initial_front_data = initial_front.0.to_vec();
        let initial_front_ext = initial_front.1;

        encrypted
            .extended_data(channel_id, ext, Bytes::from_static(b"new"), false)
            .unwrap();

        let channel = &encrypted.channels[&channel_id];
        assert_eq!(channel.pending_data.len(), initial_pending + 1);
        assert_eq!(
            channel.pending_data.front().unwrap().0.as_ref(),
            initial_front_data.as_slice()
        );
        assert_eq!(channel.pending_data.front().unwrap().1, initial_front_ext);
        assert_eq!(channel.pending_data.back().unwrap().0.as_ref(), b"new");
        assert_eq!(channel.pending_data.back().unwrap().1, Some(ext));
        assert!(encrypted.write.is_empty());
    }

    #[test]
    fn flush_pending_with_writer_matches_staged_channel_data() {
        let channel_id = ChannelId(7);
        let mut staged = test_encrypted();
        let mut direct = test_encrypted();
        staged
            .channels
            .insert(channel_id, test_channel(channel_id, 42, false, false));
        direct
            .channels
            .insert(channel_id, test_channel(channel_id, 42, false, false));

        let mut staged_writer = PacketWriter::clear();
        staged.flush_pending(channel_id).unwrap();
        staged
            .flush(&Limits::default(), &mut staged_writer, false)
            .unwrap();

        let mut direct_writer = PacketWriter::clear();
        direct
            .flush_pending_with_writer(&mut direct_writer, channel_id, false)
            .unwrap();

        assert_eq!(direct_writer.buffer().buffer, staged_writer.buffer().buffer);
        assert_eq!(
            direct.channels[&channel_id].recipient_window_size,
            staged.channels[&channel_id].recipient_window_size
        );
        assert!(direct.channels[&channel_id].pending_data.is_empty());
    }

    #[test]
    fn flush_pending_with_writer_matches_staged_extended_data() {
        let channel_id = ChannelId(8);
        let mut staged = test_encrypted();
        let mut direct = test_encrypted();
        let mut staged_channel = test_channel(channel_id, 42, false, false);
        staged_channel.pending_data = VecDeque::from([(Bytes::from_static(b"hello"), Some(1), 0)]);
        let mut direct_channel = test_channel(channel_id, 42, false, false);
        direct_channel.pending_data = VecDeque::from([(Bytes::from_static(b"hello"), Some(1), 0)]);
        staged.channels.insert(channel_id, staged_channel);
        direct.channels.insert(channel_id, direct_channel);

        let mut staged_writer = PacketWriter::clear();
        staged.flush_pending(channel_id).unwrap();
        staged
            .flush(&Limits::default(), &mut staged_writer, false)
            .unwrap();

        let mut direct_writer = PacketWriter::clear();
        direct
            .flush_pending_with_writer(&mut direct_writer, channel_id, false)
            .unwrap();

        assert_eq!(direct_writer.buffer().buffer, staged_writer.buffer().buffer);
        assert!(direct.channels[&channel_id].pending_data.is_empty());
    }

    #[test]
    fn flush_pending_with_writer_falls_back_when_write_queue_nonempty() {
        let channel_id = ChannelId(9);
        let mut encrypted = test_encrypted();
        encrypted
            .channels
            .insert(channel_id, test_channel(channel_id, 42, false, false));
        push_packet!(encrypted.write, encrypted.write.push(msg::REQUEST_SUCCESS));

        let mut writer = PacketWriter::clear();
        encrypted
            .flush_pending_with_writer(&mut writer, channel_id, false)
            .unwrap();

        assert!(writer.buffer().buffer.is_empty());
        assert_eq!(
            packet_types(&encrypted.write),
            vec![msg::REQUEST_SUCCESS, msg::CHANNEL_DATA]
        );
    }

    #[test]
    fn flush_pending_with_writer_preserves_partial_window_remainder() {
        let channel_id = ChannelId(13);
        let payload = Bytes::from_static(b"abcdef");
        let mut encrypted = test_encrypted();
        let mut channel = test_channel_windowed(channel_id, 42, 3, false, false);
        channel.pending_data = VecDeque::from([(payload.clone(), None, 0)]);
        encrypted.channels.insert(channel_id, channel);

        let mut writer = PacketWriter::clear();
        encrypted
            .flush_pending_with_writer(&mut writer, channel_id, false)
            .unwrap();

        let channel = &encrypted.channels[&channel_id];
        assert_eq!(
            clear_packet_types(&writer.buffer().buffer),
            vec![msg::CHANNEL_DATA]
        );
        assert_eq!(channel.recipient_window_size, 0);
        assert_eq!(channel.pending_data.len(), 1);
        let pending = channel.pending_data.back().unwrap();
        assert_eq!(pending.0, payload);
        assert_eq!(pending.1, None);
        assert_eq!(pending.2, 3);
    }

    #[test]
    fn flush_pending_with_writer_emits_controls_after_replayed_data() {
        let channel_id = ChannelId(14);
        let mut encrypted = test_encrypted();
        encrypted
            .channels
            .insert(channel_id, test_channel(channel_id, 42, true, true));

        let mut writer = PacketWriter::clear();
        encrypted
            .flush_pending_with_writer(&mut writer, channel_id, false)
            .unwrap();
        encrypted
            .flush(&Limits::default(), &mut writer, false)
            .unwrap();

        assert_eq!(
            clear_packet_types(&writer.buffer().buffer),
            vec![msg::CHANNEL_DATA, msg::CHANNEL_EOF, msg::CHANNEL_CLOSE]
        );
        assert!(!encrypted.channels.contains_key(&channel_id));
    }

    #[test]
    fn nothing_reaches_the_wire_while_rekeying() {
        // RFC 4253 s7.1: only transport-layer messages may go out between
        // KEXINIT and NEWKEYS. Regression test for #761.
        let channel_id = ChannelId(15);
        let mut encrypted = test_encrypted();
        encrypted
            .channels
            .insert(channel_id, test_channel(channel_id, 42, true, true));

        let mut writer = PacketWriter::clear();
        encrypted
            .flush_pending_with_writer(&mut writer, channel_id, true)
            .unwrap();
        encrypted
            .flush(&Limits::default(), &mut writer, true)
            .unwrap();
        assert!(clear_packet_types(&writer.buffer().buffer).is_empty());

        // ...and it all comes out, in order, once the kex is done.
        encrypted
            .flush(&Limits::default(), &mut writer, false)
            .unwrap();
        assert_eq!(
            clear_packet_types(&writer.buffer().buffer),
            vec![msg::CHANNEL_DATA, msg::CHANNEL_EOF, msg::CHANNEL_CLOSE]
        );
    }

    #[test]
    fn data_direct_matches_staged_channel_data() {
        let channel_id = ChannelId(20);
        let payload = Bytes::from_static(b"direct channel data");
        let mut staged = test_encrypted();
        let mut direct = test_encrypted();
        staged
            .channels
            .insert(channel_id, test_ready_channel(channel_id, 42));
        direct
            .channels
            .insert(channel_id, test_ready_channel(channel_id, 42));

        let mut staged_writer = PacketWriter::clear();
        staged.data(channel_id, payload.clone(), false).unwrap();
        staged
            .flush(&Limits::default(), &mut staged_writer, false)
            .unwrap();

        let mut direct_writer = PacketWriter::clear();
        direct
            .data_with_writer(&mut direct_writer, channel_id, payload, false)
            .unwrap();

        assert_eq!(direct_writer.buffer().buffer, staged_writer.buffer().buffer);
        assert_eq!(
            direct.channels[&channel_id].recipient_window_size,
            staged.channels[&channel_id].recipient_window_size
        );
        assert!(direct.channels[&channel_id].pending_data.is_empty());
    }

    #[test]
    fn extended_data_direct_matches_staged_channel_data() {
        let channel_id = ChannelId(21);
        let payload = Bytes::from_static(b"direct extended channel data");
        let mut staged = test_encrypted();
        let mut direct = test_encrypted();
        staged
            .channels
            .insert(channel_id, test_ready_channel(channel_id, 43));
        direct
            .channels
            .insert(channel_id, test_ready_channel(channel_id, 43));

        let mut staged_writer = PacketWriter::clear();
        staged
            .extended_data(channel_id, 1, payload.clone(), false)
            .unwrap();
        staged
            .flush(&Limits::default(), &mut staged_writer, false)
            .unwrap();

        let mut direct_writer = PacketWriter::clear();
        direct
            .extended_data_with_writer(&mut direct_writer, channel_id, 1, payload, false)
            .unwrap();

        assert_eq!(direct_writer.buffer().buffer, staged_writer.buffer().buffer);
        assert_eq!(
            direct.channels[&channel_id].recipient_window_size,
            staged.channels[&channel_id].recipient_window_size
        );
        assert!(direct.channels[&channel_id].pending_data.is_empty());
    }

    #[test]
    fn data_direct_is_disabled_when_write_queue_nonempty() {
        let channel_id = ChannelId(22);
        let mut encrypted = test_encrypted();
        encrypted
            .channels
            .insert(channel_id, test_ready_channel(channel_id, 44));
        push_packet!(encrypted.write, encrypted.write.push(msg::REQUEST_SUCCESS));

        let mut writer = PacketWriter::clear();
        encrypted
            .data_with_writer(&mut writer, channel_id, Bytes::from_static(b"new"), false)
            .unwrap();

        assert!(writer.buffer().buffer.is_empty());
        assert_eq!(
            packet_types(&encrypted.write),
            vec![msg::REQUEST_SUCCESS, msg::CHANNEL_DATA]
        );

        encrypted
            .flush(&Limits::default(), &mut writer, false)
            .unwrap();
        assert_eq!(
            clear_packet_types(&writer.buffer().buffer),
            vec![msg::REQUEST_SUCCESS, msg::CHANNEL_DATA]
        );
    }

    #[test]
    fn data_staged_large_payload_when_write_queue_nonempty_preserves_order_and_chunks() {
        let channel_id = ChannelId(26);
        let mut encrypted = test_encrypted();
        let mut channel = test_ready_channel(channel_id, 48);
        channel.recipient_window_size = 256 * 1024;
        channel.recipient_maximum_packet_size = 32 * 1024;
        encrypted.channels.insert(channel_id, channel);
        push_packet!(encrypted.write, encrypted.write.push(msg::REQUEST_SUCCESS));

        let mut writer = PacketWriter::clear();
        encrypted
            .data_with_writer(
                &mut writer,
                channel_id,
                Bytes::from(vec![0x5a; 256 * 1024]),
                false,
            )
            .unwrap();

        assert!(writer.buffer().buffer.is_empty());
        let packet_types = packet_types(&encrypted.write);
        assert_eq!(packet_types.first(), Some(&msg::REQUEST_SUCCESS));
        assert_eq!(packet_types.len(), 9);
        assert!(
            packet_types
                .iter()
                .skip(1)
                .all(|&msg_type| msg_type == msg::CHANNEL_DATA)
        );
        assert!(encrypted.channels[&channel_id].pending_data.is_empty());
        assert_eq!(encrypted.channels[&channel_id].recipient_window_size, 0);
    }

    #[test]
    fn data_staged_rejects_zero_recipient_max_packet_size() {
        let channel_id = ChannelId(27);
        let mut encrypted = test_encrypted();
        let mut channel = test_ready_channel(channel_id, 49);
        channel.recipient_maximum_packet_size = 0;
        encrypted.channels.insert(channel_id, channel);

        let result = encrypted.data(channel_id, Bytes::from_static(b"new"), false);

        assert!(matches!(result, Err(crate::Error::Inconsistent)));
        assert!(encrypted.write.is_empty());
        assert_eq!(encrypted.channels[&channel_id].recipient_window_size, 1024);
    }

    #[test]
    fn data_direct_rejects_zero_recipient_max_packet_size() {
        let channel_id = ChannelId(28);
        let mut encrypted = test_encrypted();
        let mut channel = test_ready_channel(channel_id, 50);
        channel.recipient_maximum_packet_size = 0;
        encrypted.channels.insert(channel_id, channel);

        let mut writer = PacketWriter::clear();
        let result =
            encrypted.data_with_writer(&mut writer, channel_id, Bytes::from_static(b"new"), false);

        assert!(matches!(result, Err(crate::Error::Inconsistent)));
        assert!(writer.buffer().buffer.is_empty());
        assert!(encrypted.write.is_empty());
        assert_eq!(encrypted.channels[&channel_id].recipient_window_size, 1024);
    }

    #[test]
    fn data_direct_is_disabled_while_rekeying() {
        let channel_id = ChannelId(23);
        let mut encrypted = test_encrypted();
        encrypted
            .channels
            .insert(channel_id, test_ready_channel(channel_id, 45));

        let mut writer = PacketWriter::clear();
        encrypted
            .data_with_writer(&mut writer, channel_id, Bytes::from_static(b"new"), true)
            .unwrap();

        let channel = &encrypted.channels[&channel_id];
        assert_eq!(channel.pending_data.len(), 1);
        assert_eq!(channel.pending_data.back().unwrap().0.as_ref(), b"new");
        assert_eq!(channel.pending_data.back().unwrap().1, None);
        assert!(encrypted.write.is_empty());
        assert!(writer.buffer().buffer.is_empty());
    }

    #[test]
    fn data_direct_queues_remainder_when_window_is_partial() {
        let channel_id = ChannelId(24);
        let payload = Bytes::from_static(b"abcdef");
        let mut encrypted = test_encrypted();
        let mut channel = test_ready_channel(channel_id, 46);
        channel.recipient_window_size = 3;
        encrypted.channels.insert(channel_id, channel);

        let mut writer = PacketWriter::clear();
        encrypted
            .data_with_writer(&mut writer, channel_id, payload.clone(), false)
            .unwrap();

        let channel = &encrypted.channels[&channel_id];
        assert_eq!(
            clear_packet_types(&writer.buffer().buffer),
            vec![msg::CHANNEL_DATA]
        );
        assert_eq!(channel.recipient_window_size, 0);
        assert_eq!(channel.pending_data.len(), 1);
        let pending = channel.pending_data.back().unwrap();
        assert_eq!(pending.0, payload);
        assert_eq!(pending.1, None);
        assert_eq!(pending.2, 3);
    }

    #[test]
    fn data_direct_disabled_behind_existing_pending_data() {
        let channel_id = ChannelId(25);
        let mut encrypted = test_encrypted();
        encrypted
            .channels
            .insert(channel_id, test_channel(channel_id, 47, false, false));

        let mut writer = PacketWriter::clear();
        encrypted
            .data_with_writer(&mut writer, channel_id, Bytes::from_static(b"new"), false)
            .unwrap();

        let channel = &encrypted.channels[&channel_id];
        assert_eq!(channel.pending_data.len(), 2);
        assert_eq!(channel.pending_data.front().unwrap().0.as_ref(), b"hello");
        assert_eq!(channel.pending_data.back().unwrap().0.as_ref(), b"new");
        assert!(encrypted.write.is_empty());
        assert!(writer.buffer().buffer.is_empty());
    }
}
