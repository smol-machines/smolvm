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
use std::convert::TryInto;
use std::ops::Deref;
use std::str::FromStr;

use bytes::Bytes;
use log::{debug, error, info, trace, warn};
use ssh_encoding::{Decode, Encode, Reader};
use ssh_key::{Algorithm, PublicKey, Signature};

use super::IncomingSshPacket;
use crate::auth::AuthRequest;
use crate::cert::PublicKeyOrCertificate;
use crate::client::{ChannelOpenHandle, Handler, Msg, Prompt, Reply, Session};
use crate::helpers::{AlgorithmExt, EncodedExt, NameList, sign_with_hash_alg};
use crate::keys::key::parse_public_key;
use crate::parsing::{ChannelOpenConfirmation, ChannelType, OpenChannelMessage, ensure_end};
use crate::session::{Encrypted, EncryptedState, GlobalRequestResponse};
use crate::{
    Channel, ChannelId, ChannelMsg, ChannelOpenFailure, ChannelParams, CryptoVec, Error, MethodSet,
    Sig, auth, map_err, msg,
};

/// Checks a `hostkeys-prove-00@openssh.com` reply: one signature per requested
/// key, in order, each over `string name || string session_id || string key_blob`.
fn verify_hostkeys_proof(
    session_id: &[u8],
    keys: &[PublicKey],
    mut r: &[u8],
) -> Result<(), crate::Error> {
    for key in keys {
        let signature = Bytes::decode(&mut r)?;
        let mut signature_reader = &signature[..];
        let signature = Signature::decode(&mut signature_reader)?;
        ensure_end(&signature_reader)?;

        // CryptoVec: the session id is key material and is zeroized on drop.
        let mut signed = CryptoVec::new();
        "hostkeys-prove-00@openssh.com".encode(&mut signed)?;
        session_id.encode(&mut signed)?;
        key.to_bytes()?.encode(&mut signed)?;
        signature::Verifier::verify(key, &signed, &signature)
            .map_err(|_| crate::Error::WrongServerSig)?;
    }
    ensure_end(&r)?;
    Ok(())
}

impl Session {
    pub(crate) async fn client_read_encrypted<H: Handler>(
        &mut self,
        client: &mut H,
        pkt: &mut IncomingSshPacket,
    ) -> Result<(), H::Error> {
        trace!(
            "client_read_encrypted, msg type {:?}, len {}",
            pkt.buffer.first(),
            pkt.buffer.len()
        );

        self.process_packet(client, &pkt.buffer).await
    }

    pub(crate) async fn process_packet<H: Handler>(
        &mut self,
        client: &mut H,
        buf: &[u8],
    ) -> Result<(), H::Error> {
        // If we've successfully read a packet.
        trace!("process_packet buf = {:?} bytes", buf.len());
        let mut is_authenticated = false;
        if let Some(ref mut enc) = self.common.encrypted {
            match enc.state {
                EncryptedState::WaitingAuthServiceRequest {
                    ref mut accepted, ..
                } => {
                    debug!(
                        "waiting service request, {:?} {:?}",
                        buf.first(),
                        msg::SERVICE_ACCEPT
                    );
                    match buf.split_first() {
                        Some((&msg::SERVICE_ACCEPT, mut r)) => {
                            if map_err!(Bytes::decode(&mut r))?.as_ref() == b"ssh-userauth" {
                                map_err!(ensure_end(&r))?;
                                *accepted = true;
                                if let Some(ref meth) = self.common.auth_method {
                                    let auth_request = AuthRequest::new(meth);
                                    if enc.write_auth_request(&self.common.auth_user, meth)? {
                                        debug!("enc: auth request written");
                                        enc.state = EncryptedState::WaitingAuthRequest(auth_request)
                                    }
                                } else {
                                    debug!("no auth method")
                                }
                            }
                        }
                        Some((&msg::EXT_INFO, mut r)) => {
                            return self.handle_ext_info(&mut r).map_err(Into::into);
                        }
                        other => {
                            debug!("unknown message: {other:?}");
                            return Err(crate::Error::Inconsistent.into());
                        }
                    }
                }
                EncryptedState::WaitingAuthRequest(ref mut auth_request) => {
                    trace!("waiting auth request, {:?}", buf.first(),);
                    match buf.split_first() {
                        Some((&msg::USERAUTH_SUCCESS, r)) => {
                            map_err!(ensure_end(&r))?;
                            debug!("userauth_success");
                            // Drop the credential as soon as it is no longer needed.
                            self.common.auth_method = None;
                            self.sender
                                .send(Reply::AuthSuccess)
                                .map_err(|_| crate::Error::SendError)?;
                            enc.state = EncryptedState::InitCompression;
                            if enc.server_compression.is_deferred() {
                                enc.server_compression.init_decompress(&mut enc.decompress);
                            }
                            return Ok(());
                        }
                        Some((&msg::USERAUTH_BANNER, mut r)) => {
                            let banner = map_err!(String::decode(&mut r))?;
                            let _language_tag = map_err!(String::decode(&mut r))?;
                            map_err!(ensure_end(&r))?;
                            client.auth_banner(&banner, self).await?;
                            return Ok(());
                        }
                        Some((&msg::USERAUTH_FAILURE, mut r)) => {
                            debug!("userauth_failure");

                            let remaining_methods: MethodSet =
                                (&map_err!(NameList::decode(&mut r))?).into();
                            let partial_success = map_err!(u8::decode(&mut r))? != 0;
                            map_err!(ensure_end(&r))?;
                            debug!(
                                "remaining methods {remaining_methods:?}, partial success {partial_success:?}"
                            );
                            auth_request.methods = remaining_methods.clone();

                            let no_more_methods = auth_request.methods.is_empty();
                            self.common.auth_method = None;
                            self.sender
                                .send(Reply::AuthFailure {
                                    proceed_with_methods: remaining_methods,
                                    partial_success,
                                })
                                .map_err(|_| crate::Error::SendError)?;

                            // If no other authentication method is allowed by the server, give up.
                            if no_more_methods {
                                return Err(crate::Error::NoAuthMethod.into());
                            }
                        }
                        Some((&msg::USERAUTH_INFO_REQUEST_OR_USERAUTH_PK_OK, mut r)) => {
                            if let Some(auth::CurrentRequest::GssapiWithMic) = auth_request.current
                            {
                                debug!("userauth_gssapi_response");
                                let selected_mechanism = map_err!(Bytes::decode(&mut r))?.to_vec();
                                map_err!(ensure_end(&r))?;
                                let mic_data = enc.client_make_gssapi_mic_data(
                                    &self.common.auth_user,
                                    &mut self.common.buffer,
                                )?;
                                self.sender
                                    .send(Reply::AuthGssapiResponse {
                                        selected_mechanism,
                                        mic_data,
                                    })
                                    .map_err(|_| crate::Error::SendError)?;
                                return Ok(());
                            } else if let Some(auth::CurrentRequest::PublicKey {
                                ref mut sent_pk_ok,
                                ..
                            }) = auth_request.current
                            {
                                debug!("userauth_pk_ok");
                                let _algo = map_err!(String::decode(&mut r))?;
                                let _key = map_err!(Bytes::decode(&mut r))?;
                                map_err!(ensure_end(&r))?;
                                *sent_pk_ok = true;
                            } else if let Some(auth::CurrentRequest::KeyboardInteractive {
                                ..
                            }) = auth_request.current
                            {
                                debug!("keyboard_interactive");

                                // read fields
                                let name = map_err!(String::decode(&mut r))?;

                                let instructions = map_err!(String::decode(&mut r))?;

                                let _lang = map_err!(String::decode(&mut r))?;
                                let n_prompts = map_err!(u32::decode(&mut r))?;

                                // read prompts
                                // Each prompt needs at least a 4-byte length plus a 1-byte echo flag.
                                let max_prompts = r.remaining_len() / 5;
                                let n_prompts = n_prompts as usize;
                                if n_prompts > max_prompts {
                                    return Err(crate::Error::Inconsistent.into());
                                }
                                let mut prompts = Vec::with_capacity(n_prompts);
                                for _i in 0..n_prompts {
                                    let prompt = map_err!(String::decode(&mut r))?;

                                    let echo = map_err!(u8::decode(&mut r))? != 0;
                                    prompts.push(Prompt {
                                        prompt: prompt.to_string(),
                                        echo,
                                    });
                                }
                                map_err!(ensure_end(&r))?;

                                // send challenges to caller
                                self.sender
                                    .send(Reply::AuthInfoRequest {
                                        name,
                                        instructions,
                                        prompts,
                                    })
                                    .map_err(|_| crate::Error::SendError)?;

                                // wait for response from handler
                                let responses = loop {
                                    match self.receiver.recv().await {
                                        Some(Msg::AuthInfoResponse { responses }) => {
                                            break responses;
                                        }
                                        None => return Err(crate::Error::RecvError.into()),
                                        _ => {}
                                    }
                                };
                                // write responses
                                enc.client_send_auth_response(&responses)?;
                                return Ok(());
                            }

                            // continue with userauth_pk_ok
                            match self.common.auth_method.take() {
                                Some(auth_method @ auth::Method::PublicKey { .. }) => {
                                    self.common.buffer.clear();
                                    enc.client_send_signature(
                                        &self.common.auth_user,
                                        &auth_method,
                                        &mut self.common.buffer,
                                    )?
                                }
                                Some(auth_method @ auth::Method::OpenSshCertificate { .. }) => {
                                    self.common.buffer.clear();
                                    enc.client_send_signature(
                                        &self.common.auth_user,
                                        &auth_method,
                                        &mut self.common.buffer,
                                    )?
                                }
                                Some(auth::Method::FuturePublicKey { ref key, hash_alg }) => {
                                    debug!("public key");
                                    self.common.buffer.clear();
                                    let i = enc.client_make_to_sign(
                                        &self.common.auth_user,
                                        &PublicKeyOrCertificate::PublicKey {
                                            key: key.clone(),
                                            hash_alg,
                                        },
                                        None,
                                        &mut self.common.buffer,
                                    )?;
                                    let len = self.common.buffer.len();
                                    let buf = std::mem::take(&mut self.common.buffer);

                                    self.sender
                                        .send(Reply::SignRequest {
                                            key: key.clone(),
                                            data: buf,
                                        })
                                        .map_err(|_| crate::Error::SendError)?;
                                    self.common.buffer = loop {
                                        match self.receiver.recv().await {
                                            Some(Msg::Signed { data }) => break data[..].to_vec(),
                                            // The signer could not sign. Leave the PK_OK
                                            // unanswered, as OpenSSH does when it cannot
                                            // sign: the server keeps waiting for a userauth
                                            // request and the next one (any method) replaces
                                            // this attempt. Going back to the main loop is
                                            // what lets that next request through.
                                            Some(Msg::SignFailed) => {
                                                debug!("signer failed, abandoning the request");
                                                return Ok(());
                                            }
                                            None => return Err(crate::Error::RecvError.into()),
                                            _ => {}
                                        }
                                    };
                                    if self.common.buffer.len() != len {
                                        // The buffer was modified.
                                        push_packet!(enc.write, {
                                            #[allow(clippy::indexing_slicing)] // length checked
                                            enc.write.extend_from_slice(&self.common.buffer[i..]);
                                        })
                                    }
                                }
                                Some(auth::Method::FutureCertificate { ref cert, hash_alg }) => {
                                    debug!("certificate");
                                    self.common.buffer.clear();
                                    let i = enc.client_make_to_sign(
                                        &self.common.auth_user,
                                        &PublicKeyOrCertificate::Certificate(cert.clone()),
                                        hash_alg,
                                        &mut self.common.buffer,
                                    )?;
                                    let len = self.common.buffer.len();
                                    let buf = std::mem::take(&mut self.common.buffer);

                                    self.sender
                                        .send(Reply::SignRequestCert {
                                            cert: cert.clone(),
                                            hash_alg,
                                            data: buf,
                                        })
                                        .map_err(|_| crate::Error::SendError)?;
                                    self.common.buffer = loop {
                                        match self.receiver.recv().await {
                                            Some(Msg::Signed { data }) => break data,
                                            // See the public key case above.
                                            Some(Msg::SignFailed) => {
                                                debug!("signer failed, abandoning the request");
                                                return Ok(());
                                            }
                                            None => return Err(crate::Error::RecvError.into()),
                                            _ => {}
                                        }
                                    };
                                    if self.common.buffer.len() != len {
                                        // The buffer was modified.
                                        push_packet!(enc.write, {
                                            #[allow(clippy::indexing_slicing)] // length checked
                                            enc.write.extend(&self.common.buffer[i..]);
                                        })
                                    }
                                }
                                _ => {}
                            }
                        }
                        Some((&msg::USERAUTH_GSSAPI_TOKEN, mut r)) => {
                            if let Some(auth::CurrentRequest::GssapiWithMic) = auth_request.current
                            {
                                debug!("userauth_gssapi_token");
                                let token = map_err!(Bytes::decode(&mut r))?.to_vec();
                                map_err!(ensure_end(&r))?;
                                let mic_data = enc.client_make_gssapi_mic_data(
                                    &self.common.auth_user,
                                    &mut self.common.buffer,
                                )?;
                                self.sender
                                    .send(Reply::AuthGssapiToken { token, mic_data })
                                    .map_err(|_| crate::Error::SendError)?;
                                return Ok(());
                            }
                            return Err(crate::Error::Inconsistent.into());
                        }
                        Some((&msg::USERAUTH_GSSAPI_ERROR, mut r)) => {
                            if let Some(auth::CurrentRequest::GssapiWithMic) = auth_request.current
                            {
                                let major_status = map_err!(u32::decode(&mut r))?;
                                let minor_status = map_err!(u32::decode(&mut r))?;
                                let message = map_err!(String::decode(&mut r))?;
                                let _language_tag = map_err!(String::decode(&mut r))?;
                                map_err!(ensure_end(&r))?;
                                warn!(
                                    "userauth_gssapi_error major={major_status} minor={minor_status}: {message}"
                                );
                                self.sender
                                    .send(Reply::AuthGssapiError {
                                        error: auth::GssapiError::Status {
                                            major_status,
                                            minor_status,
                                            message,
                                        },
                                    })
                                    .map_err(|_| crate::Error::SendError)?;
                                return Ok(());
                            }
                            return Err(crate::Error::Inconsistent.into());
                        }
                        Some((&msg::USERAUTH_GSSAPI_ERRTOK, mut r)) => {
                            if let Some(auth::CurrentRequest::GssapiWithMic) = auth_request.current
                            {
                                let token = map_err!(Bytes::decode(&mut r))?.to_vec();
                                map_err!(ensure_end(&r))?;
                                warn!("userauth_gssapi_errtok ({} bytes)", token.len());
                                self.sender
                                    .send(Reply::AuthGssapiError {
                                        error: auth::GssapiError::ErrorToken(token),
                                    })
                                    .map_err(|_| crate::Error::SendError)?;
                                return Ok(());
                            }
                            return Err(crate::Error::Inconsistent.into());
                        }
                        Some((&msg::EXT_INFO, mut r)) => {
                            return self.handle_ext_info(&mut r).map_err(Into::into);
                        }
                        other => {
                            debug!("unknown message: {other:?}");
                            return Err(crate::Error::Inconsistent.into());
                        }
                    }
                }
                EncryptedState::InitCompression => unreachable!(),
                EncryptedState::Authenticated => is_authenticated = true,
            }
        }
        if is_authenticated {
            self.client_read_authenticated(client, buf).await
        } else {
            Ok(())
        }
    }

    fn handle_ext_info(&mut self, r: &mut impl Reader) -> Result<(), Error> {
        // RFC 8308 §2.4: a server sends EXT_INFO at most twice per session.
        // Refusing more keeps `received_extensions` bounded.
        self.ext_info_count += 1;
        if self.ext_info_count > 2 {
            return Err(Error::Inconsistent);
        }
        let n_extensions = u32::decode(r)? as usize;
        debug!("Received EXT_INFO, {n_extensions:?} extensions");
        for _ in 0..n_extensions {
            let name = String::decode(r)?;
            if name == "server-sig-algs" {
                self.handle_server_sig_algs_ext(r)?;
            } else {
                let data = Vec::<u8>::decode(r)?;
                debug!("* {name:?} (unknown, data: {data:?})");
            }
            if let Some(ref mut enc) = self.common.encrypted {
                enc.received_extensions.push(name.clone());
                if let Some(mut senders) = enc.extension_info_awaiters.remove(&name) {
                    senders.drain(..).for_each(|w| {
                        let _ = w.send(());
                    });
                }
            }
        }
        ensure_end(r)?;
        Ok(())
    }

    fn handle_server_sig_algs_ext(&mut self, r: &mut impl Reader) -> Result<(), Error> {
        let algs = NameList::decode(r)?;
        debug!("* server-sig-algs");
        self.server_sig_algs = Some(
            algs.iter()
                .filter_map(|x| Algorithm::from_str(x).ok())
                .inspect(|x| {
                    debug!("  * {x:?}");
                })
                .collect::<Vec<_>>(),
        );
        Ok(())
    }

    async fn client_read_authenticated<H: Handler>(
        &mut self,
        client: &mut H,
        buf: &[u8],
    ) -> Result<(), H::Error> {
        match buf.split_first() {
            Some((&msg::CHANNEL_OPEN_CONFIRMATION, mut reader)) => {
                debug!("channel_open_confirmation");
                let msg = ChannelOpenConfirmation::parse(&mut reader)?;
                map_err!(ensure_end(&reader))?;
                let local_id = ChannelId(msg.recipient_channel);

                if let Some(ref mut enc) = self.common.encrypted {
                    if let Some(parameters) = enc.channels.get_mut(&local_id) {
                        parameters.confirm(&msg);
                    } else {
                        // We've not requested this channel, close connection.
                        return Err(crate::Error::Inconsistent.into());
                    }
                } else {
                    return Err(crate::Error::Inconsistent.into());
                };

                if let Some(channel) = self.channels.get(&local_id) {
                    channel
                        .send(ChannelMsg::Open {
                            id: local_id,
                            max_packet_size: msg.maximum_packet_size,
                            window_size: msg.initial_window_size,
                        })
                        .await
                        .unwrap_or(());
                } else {
                    error!("no channel for id {local_id:?}");
                }

                client
                    .channel_open_confirmation(
                        local_id,
                        msg.maximum_packet_size,
                        msg.initial_window_size,
                        self,
                    )
                    .await
            }
            Some((&msg::CHANNEL_CLOSE, mut r)) => {
                debug!("channel_close");
                let channel_num = map_err!(ChannelId::decode(&mut r))?;
                map_err!(ensure_end(&r))?;
                if !self.common.is_established_channel(channel_num) {
                    return Ok(());
                }
                if let Some(ref mut enc) = self.common.encrypted {
                    // The CHANNEL_CLOSE message must be sent to the server at this point or the session
                    // will not be released.
                    enc.close(channel_num)?;
                }
                // Forward the close to the channel before removing it, so that
                // consumers waiting on `Channel::wait()` receive an explicit
                // `ChannelMsg::Close` instead of just seeing `None`.
                if let Some(chan) = self.channels.get(&channel_num) {
                    let _ = chan.send(ChannelMsg::Close).await;
                }
                self.channels.remove(&channel_num);
                client.channel_close(channel_num, self).await
            }
            Some((&msg::CHANNEL_EOF, mut r)) => {
                debug!("channel_eof");
                let channel_num = map_err!(ChannelId::decode(&mut r))?;
                map_err!(ensure_end(&r))?;
                if !self.common.is_established_channel(channel_num) {
                    return Ok(());
                }
                if let Some(chan) = self.channels.get(&channel_num) {
                    let _ = chan.send(ChannelMsg::Eof).await;
                }
                client.channel_eof(channel_num, self).await
            }
            Some((&msg::CHANNEL_OPEN_FAILURE, mut r)) => {
                debug!("channel_open_failure");
                let channel_num = map_err!(ChannelId::decode(&mut r))?;
                let reason_code = ChannelOpenFailure::from_u32(map_err!(u32::decode(&mut r))?)
                    .unwrap_or(ChannelOpenFailure::AdministrativelyProhibited);
                let descr = map_err!(String::decode(&mut r))?;
                let language = map_err!(String::decode(&mut r))?;
                map_err!(ensure_end(&r))?;
                // Unlike other channel-scoped messages this arrives for a
                // channel the client opened but that is not yet confirmed, so
                // gate on existence in the encrypted table rather than
                // `is_established_channel` (which requires `confirmed`).
                let known = match self.common.encrypted {
                    Some(ref mut enc) => enc.channels.remove(&channel_num).is_some(),
                    None => false,
                };
                if !known {
                    return Ok(());
                }

                if let Some(sender) = self.channels.remove(&channel_num) {
                    let _ = sender
                        .send(ChannelMsg::OpenFailure(reason_code.clone()))
                        .await;
                }

                let _ = self.sender.send(Reply::ChannelOpenFailure);

                client
                    .channel_open_failure(channel_num, reason_code, &descr, &language, self)
                    .await
            }
            Some((&msg::CHANNEL_DATA, mut r)) => {
                trace!("channel_data");
                let channel_num = map_err!(ChannelId::decode(&mut r))?;
                let data = map_err!(Bytes::decode(&mut r))?;
                map_err!(ensure_end(&r))?;
                if !self.common.is_established_channel(channel_num) {
                    return Ok(());
                }
                let target = self.common.config.window_size;
                #[allow(clippy::collapsible_if)]
                if let Some(ref mut enc) = self.common.encrypted {
                    if enc.adjust_window_size(channel_num, &data, target)? {
                        let next_window =
                            client.adjust_window(channel_num, self.target_window_size);
                        if next_window > 0 {
                            self.target_window_size = next_window
                        }
                    }
                }

                if let Some(chan) = self.channels.get(&channel_num) {
                    let _ = chan.send(ChannelMsg::Data { data: data.clone() }).await;
                }

                client.data(channel_num, &data, self).await
            }
            Some((&msg::CHANNEL_EXTENDED_DATA, mut r)) => {
                debug!("channel_extended_data");
                let channel_num = map_err!(ChannelId::decode(&mut r))?;
                let extended_code = map_err!(u32::decode(&mut r))?;
                let data = map_err!(Bytes::decode(&mut r))?;
                map_err!(ensure_end(&r))?;
                if !self.common.is_established_channel(channel_num) {
                    return Ok(());
                }
                let target = self.common.config.window_size;
                #[allow(clippy::collapsible_if)]
                if let Some(ref mut enc) = self.common.encrypted {
                    if enc.adjust_window_size(channel_num, &data, target)? {
                        let next_window =
                            client.adjust_window(channel_num, self.target_window_size);
                        if next_window > 0 {
                            self.target_window_size = next_window
                        }
                    }
                }

                if let Some(chan) = self.channels.get(&channel_num) {
                    let _ = chan
                        .send(ChannelMsg::ExtendedData {
                            ext: extended_code,
                            data: data.clone(),
                        })
                        .await;
                }

                client
                    .extended_data(channel_num, extended_code, &data, self)
                    .await
            }
            Some((&msg::CHANNEL_REQUEST, mut r)) => {
                let channel_num = map_err!(ChannelId::decode(&mut r))?;
                let req = map_err!(String::decode(&mut r))?;
                debug!("channel_request: {channel_num:?} {req:?}",);
                if !self.common.is_established_channel(channel_num) {
                    return Ok(());
                }
                match req.as_str() {
                    "xon-xoff" => {
                        map_err!(u8::decode(&mut r))?; // should be 0.
                        let client_can_do = map_err!(u8::decode(&mut r))? != 0;
                        map_err!(ensure_end(&r))?;
                        if let Some(chan) = self.channels.get(&channel_num) {
                            let _ = chan.send(ChannelMsg::XonXoff { client_can_do }).await;
                        }
                        client.xon_xoff(channel_num, client_can_do, self).await
                    }
                    "exit-status" => {
                        map_err!(u8::decode(&mut r))?; // should be 0.
                        let exit_status = map_err!(u32::decode(&mut r))?;
                        map_err!(ensure_end(&r))?;
                        if let Some(chan) = self.channels.get(&channel_num) {
                            let _ = chan.send(ChannelMsg::ExitStatus { exit_status }).await;
                        }
                        client.exit_status(channel_num, exit_status, self).await
                    }
                    "exit-signal" => {
                        map_err!(u8::decode(&mut r))?; // should be 0.
                        let signal_name =
                            Sig::from_name(map_err!(String::decode(&mut r))?.as_str());
                        let core_dumped = map_err!(u8::decode(&mut r))? != 0;
                        let error_message = map_err!(String::decode(&mut r))?;
                        let lang_tag = map_err!(String::decode(&mut r))?;
                        map_err!(ensure_end(&r))?;
                        if let Some(chan) = self.channels.get(&channel_num) {
                            let _ = chan
                                .send(ChannelMsg::ExitSignal {
                                    signal_name: signal_name.clone(),
                                    core_dumped,
                                    error_message: error_message.to_string(),
                                    lang_tag: lang_tag.to_string(),
                                })
                                .await;
                        }
                        client
                            .exit_signal(
                                channel_num,
                                signal_name,
                                core_dumped,
                                &error_message,
                                &lang_tag,
                                self,
                            )
                            .await
                    }
                    "keepalive@openssh.com" => {
                        let wants_reply = map_err!(u8::decode(&mut r))?;
                        map_err!(ensure_end(&r))?;
                        if wants_reply == 1 {
                            if let Some(ref mut enc) = self.common.encrypted {
                                trace!("Received channel keep alive message: {req:?}",);
                                self.common.wants_reply = false;
                                if let Some(ch) = enc.channels.get(&channel_num) {
                                    push_packet!(enc.write, {
                                        map_err!(msg::CHANNEL_SUCCESS.encode(&mut enc.write))?;
                                        map_err!(ch.recipient_channel.encode(&mut enc.write))?;
                                    });
                                }
                            }
                        } else {
                            warn!("Received keepalive without reply request!");
                        }
                        Ok(())
                    }
                    _ => {
                        let wants_reply = map_err!(u8::decode(&mut r))?;
                        if wants_reply == 1
                            && let Some(ref mut enc) = self.common.encrypted
                        {
                            self.common.wants_reply = false;
                            if let Some(ch) = enc.channels.get(&channel_num) {
                                push_packet!(enc.write, {
                                    map_err!(msg::CHANNEL_FAILURE.encode(&mut enc.write))?;
                                    map_err!(ch.recipient_channel.encode(&mut enc.write))?;
                                })
                            }
                        }
                        info!("Unknown channel request {req:?} {wants_reply:?}",);
                        Ok(())
                    }
                }
            }
            Some((&msg::CHANNEL_WINDOW_ADJUST, mut r)) => {
                let channel_num = map_err!(ChannelId::decode(&mut r))?;
                let amount = map_err!(u32::decode(&mut r))?;
                map_err!(ensure_end(&r))?;
                if !self.common.is_established_channel(channel_num) {
                    return Ok(());
                }
                let mut new_size = 0;
                debug!("channel_window_adjust amount: {amount:?}");
                if let Some(ref mut enc) = self.common.encrypted {
                    if let Some(ref mut channel) = enc.channels.get_mut(&channel_num) {
                        new_size = channel.recipient_window_size.saturating_add(amount);
                        channel.recipient_window_size = new_size;
                    } else {
                        return Ok(());
                    }
                }

                let is_rekeying = self.kex.active();
                let common = &mut self.common;
                if let Some(enc) = common.encrypted.as_mut() {
                    new_size -= enc.flush_pending_with_writer(
                        &mut common.packet_writer,
                        channel_num,
                        is_rekeying,
                    )? as u32;
                }
                if let Some(chan) = self.channels.get(&channel_num) {
                    chan.window_size().grow(amount).await;
                    // Use try_send to avoid blocking the session loop when channel buffer is full.
                    // WindowAdjusted is informational - the critical side effect (updating
                    // WindowSizeRef and notifying ChannelTx) already happens in grow().
                    let _ = chan.try_send(ChannelMsg::WindowAdjusted { new_size });
                }
                client.window_adjusted(channel_num, new_size, self).await
            }
            Some((&msg::GLOBAL_REQUEST, mut r)) => {
                let req = map_err!(String::decode(&mut r))?;
                let wants_reply = map_err!(u8::decode(&mut r))?;
                if let Some(ref mut enc) = self.common.encrypted {
                    if req.starts_with("keepalive") {
                        map_err!(ensure_end(&r))?;
                        if wants_reply == 1 {
                            trace!("Received keep alive message: {req:?}",);
                            self.common.wants_reply = false;
                            push_packet!(enc.write, enc.write.push(msg::REQUEST_SUCCESS));
                        } else {
                            warn!("Received keepalive without reply request!");
                        }
                    } else if req == "hostkeys-00@openssh.com" {
                        let mut keys = vec![];
                        while !r.is_empty() {
                            let key_blob = map_err!(Bytes::decode(&mut r))?;
                            match parse_public_key(&key_blob) {
                                Ok(key) => keys.push(key),
                                Err(ref err) => {
                                    debug!(
                                        "failed to parse announced host key {key_blob:?}: {err:?}",
                                    )
                                }
                            }
                        }
                        map_err!(ensure_end(&r))?;
                        return client.openssh_ext_host_keys_announced(keys, self).await;
                    } else {
                        warn!("Unhandled global request: {req:?} {wants_reply:?}",);
                        self.common.wants_reply = false;
                        push_packet!(enc.write, enc.write.push(msg::REQUEST_FAILURE))
                    }
                }
                self.common.received_data = false;
                Ok(())
            }
            Some((&msg::CHANNEL_SUCCESS, mut r)) => {
                let channel_num = map_err!(ChannelId::decode(&mut r))?;
                map_err!(ensure_end(&r))?;
                if !self.common.is_established_channel(channel_num) {
                    return Ok(());
                }
                if let Some(chan) = self.channels.get(&channel_num) {
                    let _ = chan.send(ChannelMsg::Success).await;
                }
                client.channel_success(channel_num, self).await
            }
            Some((&msg::CHANNEL_FAILURE, mut r)) => {
                let channel_num = map_err!(ChannelId::decode(&mut r))?;
                map_err!(ensure_end(&r))?;
                if !self.common.is_established_channel(channel_num) {
                    return Ok(());
                }
                if let Some(chan) = self.channels.get(&channel_num) {
                    let _ = chan.send(ChannelMsg::Failure).await;
                }
                client.channel_failure(channel_num, self).await
            }
            Some((&msg::CHANNEL_OPEN, mut r)) => {
                let msg = OpenChannelMessage::parse(&mut r)?;

                let id = if let Some(ref mut enc) = self.common.encrypted {
                    enc.new_channel_id()
                } else {
                    return Err(crate::Error::Inconsistent.into());
                };

                let channel_params = ChannelParams {
                    recipient_channel: msg.recipient_channel,
                    sender_channel: id,
                    recipient_window_size: msg.recipient_window_size,
                    sender_window_size: self.common.config.window_size,
                    recipient_maximum_packet_size: msg.recipient_maximum_packet_size,
                    sender_maximum_packet_size: self.common.config.maximum_packet_size,
                    confirmed: true,
                    wants_reply: false,
                    pending_data: std::collections::VecDeque::new(),
                    pending_eof: false,
                    pending_close: false,
                };

                let (channel, channel_ref) = Channel::new(
                    id,
                    self.inbound_channel_sender.clone(),
                    channel_params.recipient_maximum_packet_size,
                    channel_params.recipient_window_size,
                    self.common.config.channel_buffer_size,
                );

                let pending = crate::PendingChannelOpen {
                    recipient_channel: msg.recipient_channel,
                    sender_channel: id,
                    window_size: self.common.config.window_size,
                    packet_size: self.common.config.maximum_packet_size,
                    channel_ref,
                    channel_params,
                };
                let reply = ChannelOpenHandle::new(
                    self.priority_sender.clone(),
                    pending,
                    |pending, result| Msg::ServerChannelOpenReply { pending, result },
                );

                match &msg.typ {
                    ChannelType::Session => {
                        client
                            .server_channel_open_session(channel, reply, self)
                            .await?
                    }
                    ChannelType::DirectTcpip(d) => {
                        client
                            .server_channel_open_direct_tcpip(
                                channel,
                                &d.host_to_connect,
                                d.port_to_connect,
                                &d.originator_address,
                                d.originator_port,
                                reply,
                                self,
                            )
                            .await?
                    }
                    ChannelType::DirectStreamLocal(d) => {
                        client
                            .server_channel_open_direct_streamlocal(
                                channel,
                                &d.socket_path,
                                reply,
                                self,
                            )
                            .await?
                    }
                    ChannelType::X11 {
                        originator_address,
                        originator_port,
                    } => {
                        client
                            .server_channel_open_x11(
                                channel,
                                originator_address,
                                *originator_port,
                                reply,
                                self,
                            )
                            .await?
                    }
                    ChannelType::ForwardedTcpIp(d) => {
                        client
                            .server_channel_open_forwarded_tcpip(
                                channel,
                                &d.host_to_connect,
                                d.port_to_connect,
                                &d.originator_address,
                                d.originator_port,
                                reply,
                                self,
                            )
                            .await?
                    }
                    ChannelType::ForwardedStreamLocal(d) => {
                        client
                            .server_channel_open_forwarded_streamlocal(
                                channel,
                                &d.socket_path,
                                reply,
                                self,
                            )
                            .await?
                    }
                    ChannelType::AgentForward => {
                        client
                            .server_channel_open_agent_forward(channel, reply, self)
                            .await?
                    }
                    ChannelType::Unknown { typ } => {
                        if client.should_accept_unknown_server_channel(id, typ).await {
                            client
                                .server_channel_open_unknown(channel, reply, self)
                                .await?;
                        } else {
                            debug!("unknown channel type: {typ}");
                            if let Some(ref mut enc) = self.common.encrypted {
                                msg.unknown_type(&mut enc.write)?;
                            }
                        }
                    }
                };
                Ok(())
            }
            Some((&msg::REQUEST_SUCCESS, mut r)) => {
                trace!("Global Request Success");
                match self.open_global_requests.pop_front() {
                    Some(GlobalRequestResponse::Keepalive) => {
                        map_err!(ensure_end(&r))?;
                        // ignore keepalives
                    }
                    Some(GlobalRequestResponse::Ping(return_channel)) => {
                        map_err!(ensure_end(&r))?;
                        let _ = return_channel.send(());
                    }
                    Some(GlobalRequestResponse::NoMoreSessions) => {
                        map_err!(ensure_end(&r))?;
                        debug!("no-more-sessions@openssh.com requests success");
                    }
                    Some(GlobalRequestResponse::TcpIpForward(return_channel)) => {
                        let result = if r.is_empty() {
                            // If a specific port was requested, the reply has no data
                            Some(0)
                        } else {
                            match u32::decode(&mut r) {
                                Ok(port) => {
                                    if let Err(e) = ensure_end(&r) {
                                        error!(
                                            "Error parsing port for TcpIpForward request: {e:?}"
                                        );
                                        None
                                    } else {
                                        Some(port)
                                    }
                                }
                                Err(e) => {
                                    error!("Error parsing port for TcpIpForward request: {e:?}");
                                    None
                                }
                            }
                        };
                        let _ = return_channel.send(result);
                    }
                    Some(GlobalRequestResponse::CancelTcpIpForward(return_channel)) => {
                        map_err!(ensure_end(&r))?;
                        let _ = return_channel.send(true);
                    }
                    Some(GlobalRequestResponse::StreamLocalForward(return_channel)) => {
                        map_err!(ensure_end(&r))?;
                        let _ = return_channel.send(true);
                    }
                    Some(GlobalRequestResponse::CancelStreamLocalForward(return_channel)) => {
                        map_err!(ensure_end(&r))?;
                        let _ = return_channel.send(true);
                    }
                    Some(GlobalRequestResponse::HostKeysProve {
                        return_channel,
                        keys,
                    }) => {
                        let result = match self.common.encrypted {
                            Some(ref enc) => verify_hostkeys_proof(&enc.session_id, &keys, r),
                            None => Err(crate::Error::Inconsistent),
                        };
                        if let Err(ref e) = result {
                            error!("hostkeys-prove-00@openssh.com reply rejected: {e:?}");
                        }
                        let _ = return_channel.send(result);
                    }
                    Some(GlobalRequestResponse::Other(return_channel)) => {
                        let _ = return_channel.send(Some(CryptoVec::from_slice(r)));
                    }
                    None => {
                        error!("Received global request failure for unknown request!")
                    }
                }
                Ok(())
            }
            Some((&msg::REQUEST_FAILURE, r)) => {
                trace!("global request failure");
                map_err!(ensure_end(&r))?;
                match self.open_global_requests.pop_front() {
                    Some(GlobalRequestResponse::Keepalive) => {
                        // ignore keepalives
                    }
                    Some(GlobalRequestResponse::Ping(return_channel)) => {
                        let _ = return_channel.send(());
                    }
                    Some(GlobalRequestResponse::NoMoreSessions) => {
                        warn!("no-more-sessions@openssh.com requests failure");
                    }
                    Some(GlobalRequestResponse::TcpIpForward(return_channel)) => {
                        let _ = return_channel.send(None);
                    }
                    Some(GlobalRequestResponse::CancelTcpIpForward(return_channel)) => {
                        let _ = return_channel.send(false);
                    }
                    Some(GlobalRequestResponse::StreamLocalForward(return_channel)) => {
                        let _ = return_channel.send(false);
                    }
                    Some(GlobalRequestResponse::CancelStreamLocalForward(return_channel)) => {
                        let _ = return_channel.send(false);
                    }
                    Some(GlobalRequestResponse::HostKeysProve { return_channel, .. }) => {
                        let _ = return_channel.send(Err(crate::Error::RequestDenied));
                    }
                    Some(GlobalRequestResponse::Other(return_channel)) => {
                        let _ = return_channel.send(None);
                    }
                    None => {
                        error!("Received global request failure for unknown request!")
                    }
                }
                Ok(())
            }
            m => {
                debug!("unknown message received: {m:?}");
                Ok(())
            }
        }
    }

    pub(crate) fn write_auth_request_if_needed(
        &mut self,
        user: &str,
        meth: auth::Method,
    ) -> Result<bool, crate::Error> {
        let mut is_waiting = false;
        if let Some(ref mut enc) = self.common.encrypted {
            is_waiting = match enc.state {
                EncryptedState::WaitingAuthRequest(_) => true,
                EncryptedState::WaitingAuthServiceRequest {
                    accepted,
                    ref mut sent,
                } => {
                    debug!("sending ssh-userauth service requset");
                    if !*sent {
                        self.common.packet_writer.write_packet(|w| {
                            msg::SERVICE_REQUEST.encode(w)?;
                            "ssh-userauth".encode(w)?;
                            Ok(())
                        })?;
                        *sent = true
                    }
                    accepted
                }
                EncryptedState::InitCompression | EncryptedState::Authenticated => false,
            };
            debug!("write_auth_request_if_needed: is_waiting = {is_waiting:?}");
            if is_waiting {
                enc.write_auth_request(user, &meth)?;
                let auth_request = AuthRequest::new(&meth);
                enc.state = EncryptedState::WaitingAuthRequest(auth_request);
            }
        }
        self.common.auth_user.clear();
        self.common.auth_user.push_str(user);
        self.common.auth_method = Some(meth);
        Ok(is_waiting)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::num::Wrapping;

    use byteorder::{BigEndian, ByteOrder};
    use ssh_encoding::{Decode, Encode};

    use super::*;
    use crate::compression::{Compression, Decompress};
    use crate::kex::{KEXES, NONE};
    use crate::session::Exchange;
    use crate::{CryptoVec, MethodKind};

    fn test_encrypted() -> Encrypted {
        Encrypted {
            state: EncryptedState::Authenticated,
            exchange: Some(Exchange::default()),
            kex: KEXES.get(&NONE).unwrap().make(),
            key: 0,
            client_mac: crate::mac::NONE,
            server_mac: crate::mac::NONE,
            session_id: CryptoVec::from(&b"session-id"[..]),
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

    fn payloads(buf: &[u8]) -> Vec<&[u8]> {
        let mut payloads = Vec::new();
        let mut cursor = 0;
        while cursor < buf.len() {
            let packet_len = BigEndian::read_u32(&buf[cursor..cursor + 4]) as usize;
            let payload_start = cursor + 4;
            let payload_end = payload_start + packet_len;
            payloads.push(&buf[payload_start..payload_end]);
            cursor = payload_end;
        }
        payloads
    }

    #[test]
    fn method_kind_parses_gssapi_with_mic() {
        assert_eq!(
            "gssapi-with-mic".parse::<MethodKind>(),
            Ok(MethodKind::GssapiWithMic)
        );
        assert_eq!(<&str>::from(&MethodKind::GssapiWithMic), "gssapi-with-mic");
    }

    #[test]
    fn write_auth_request_encodes_gssapi_with_mic() {
        let krb5_oid = b"\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02".to_vec();
        let mut encrypted = test_encrypted();
        let wrote = encrypted
            .write_auth_request(
                "alice",
                &auth::Method::GssapiWithMic {
                    mechanism_oids: vec![krb5_oid.clone()],
                },
            )
            .unwrap();
        assert!(wrote);

        let payloads = payloads(&encrypted.write);
        assert_eq!(payloads.len(), 1);
        let mut r = payloads[0];
        assert_eq!(u8::decode(&mut r).unwrap(), msg::USERAUTH_REQUEST);
        assert_eq!(String::decode(&mut r).unwrap(), "alice");
        assert_eq!(String::decode(&mut r).unwrap(), "ssh-connection");
        assert_eq!(String::decode(&mut r).unwrap(), "gssapi-with-mic");
        assert_eq!(u32::decode(&mut r).unwrap(), 1);
        assert_eq!(Vec::<u8>::decode(&mut r).unwrap(), krb5_oid);
        ensure_end(&r).unwrap();
    }

    #[test]
    fn client_make_gssapi_mic_data_matches_rfc_4462() {
        let mut encrypted = test_encrypted();
        let mut got = Vec::new();
        let mic_data = encrypted
            .client_make_gssapi_mic_data("alice", &mut got)
            .unwrap();

        let mut expected = Vec::new();
        b"session-id".as_slice().encode(&mut expected).unwrap();
        expected.push(msg::USERAUTH_REQUEST);
        "alice".encode(&mut expected).unwrap();
        "ssh-connection".encode(&mut expected).unwrap();
        "gssapi-with-mic".encode(&mut expected).unwrap();
        assert_eq!(mic_data, expected);
        assert_eq!(got, expected);
    }

    #[test]
    fn client_send_gssapi_mic_sends_optional_token_before_mic() {
        let mut encrypted = test_encrypted();
        encrypted
            .client_send_gssapi_mic(Some(b"context-token"), b"mic")
            .unwrap();

        let payloads = payloads(&encrypted.write);
        assert_eq!(payloads.len(), 2);

        let mut token = payloads[0];
        assert_eq!(u8::decode(&mut token).unwrap(), msg::USERAUTH_GSSAPI_TOKEN);
        assert_eq!(
            Vec::<u8>::decode(&mut token).unwrap(),
            b"context-token".to_vec()
        );
        ensure_end(&token).unwrap();

        let mut mic = payloads[1];
        assert_eq!(u8::decode(&mut mic).unwrap(), msg::USERAUTH_GSSAPI_MIC);
        assert_eq!(Vec::<u8>::decode(&mut mic).unwrap(), b"mic".to_vec());
        ensure_end(&mic).unwrap();
    }

    #[test]
    fn client_send_gssapi_exchange_complete_sends_optional_token_first() {
        let mut encrypted = test_encrypted();
        encrypted
            .client_send_gssapi_exchange_complete(Some(b"context-token"))
            .unwrap();

        let payloads = payloads(&encrypted.write);
        assert_eq!(payloads.len(), 2);

        let mut token = payloads[0];
        assert_eq!(u8::decode(&mut token).unwrap(), msg::USERAUTH_GSSAPI_TOKEN);
        assert_eq!(
            Vec::<u8>::decode(&mut token).unwrap(),
            b"context-token".to_vec()
        );
        ensure_end(&token).unwrap();

        let mut complete = payloads[1];
        assert_eq!(
            u8::decode(&mut complete).unwrap(),
            msg::USERAUTH_GSSAPI_EXCHANGE_COMPLETE
        );
        ensure_end(&complete).unwrap();
    }

    #[test]
    fn client_send_gssapi_mic_skips_empty_final_token() {
        let mut encrypted = test_encrypted();
        encrypted.client_send_gssapi_mic(Some(b""), b"mic").unwrap();

        let payloads = payloads(&encrypted.write);
        assert_eq!(payloads.len(), 1);
        let mut mic = payloads[0];
        assert_eq!(u8::decode(&mut mic).unwrap(), msg::USERAUTH_GSSAPI_MIC);
        assert_eq!(Vec::<u8>::decode(&mut mic).unwrap(), b"mic".to_vec());
        ensure_end(&mic).unwrap();
    }

    fn rsa_user_certificate() -> ssh_key::Certificate {
        let subject =
            ssh_key::PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Rsa { hash: None })
                .unwrap();
        let ca =
            ssh_key::PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let mut builder = ssh_key::certificate::Builder::new_with_random_nonce(
            &mut rand::rng(),
            subject.public_key(),
            0,
            u64::MAX,
        )
        .unwrap();
        builder.key_id("rsa-user-cert").unwrap();
        builder
            .cert_type(ssh_key::certificate::CertType::User)
            .unwrap();
        builder.valid_principal("alice").unwrap();
        builder.sign(&ca).unwrap()
    }

    fn decode_userauth_certificate_algorithm(
        mut request: &[u8],
        expected_has_signature: bool,
    ) -> String {
        assert_eq!(u8::decode(&mut request).unwrap(), msg::USERAUTH_REQUEST);
        assert_eq!(String::decode(&mut request).unwrap(), "alice");
        assert_eq!(String::decode(&mut request).unwrap(), "ssh-connection");
        assert_eq!(String::decode(&mut request).unwrap(), "publickey");
        assert_eq!(
            u8::decode(&mut request).unwrap(),
            u8::from(expected_has_signature)
        );
        let algorithm = String::decode(&mut request).unwrap();
        let _certificate = Vec::<u8>::decode(&mut request).unwrap();
        ensure_end(&request).unwrap();
        algorithm
    }

    #[cfg(feature = "rsa")]
    #[test]
    fn rsa_future_certificate_hash_is_encoded_in_probe_and_signed_requests() {
        let certificate = rsa_user_certificate();
        for (hash_alg, expected) in [
            (
                Some(ssh_key::HashAlg::Sha512),
                "rsa-sha2-512-cert-v01@openssh.com",
            ),
            (
                Some(ssh_key::HashAlg::Sha256),
                "rsa-sha2-256-cert-v01@openssh.com",
            ),
            (None, "ssh-rsa-cert-v01@openssh.com"),
        ] {
            let mut encrypted = test_encrypted();
            encrypted
                .write_auth_request(
                    "alice",
                    &auth::Method::FutureCertificate {
                        cert: certificate.clone(),
                        hash_alg,
                    },
                )
                .unwrap();
            let probe_payloads = payloads(&encrypted.write);
            assert_eq!(probe_payloads.len(), 1);
            assert_eq!(
                decode_userauth_certificate_algorithm(probe_payloads[0], false),
                expected
            );

            let mut signed = Vec::new();
            encrypted
                .client_make_to_sign(
                    "alice",
                    &PublicKeyOrCertificate::Certificate(certificate.clone()),
                    hash_alg,
                    &mut signed,
                )
                .unwrap();
            let mut signed_request = signed.as_slice();
            assert_eq!(
                Vec::<u8>::decode(&mut signed_request).unwrap(),
                b"session-id"
            );
            assert_eq!(
                decode_userauth_certificate_algorithm(signed_request, true),
                expected
            );
        }
    }
}

impl Encrypted {
    fn write_auth_request(
        &mut self,
        user: &str,
        auth_method: &auth::Method,
    ) -> Result<bool, crate::Error> {
        // The server is waiting for our USERAUTH_REQUEST.
        Ok(push_packet!(self.write, {
            self.write.push(msg::USERAUTH_REQUEST);

            match *auth_method {
                auth::Method::None => {
                    user.encode(&mut self.write)?;
                    "ssh-connection".encode(&mut self.write)?;
                    "none".encode(&mut self.write)?;
                    true
                }
                auth::Method::Password { ref password } => {
                    user.encode(&mut self.write)?;
                    "ssh-connection".encode(&mut self.write)?;
                    "password".encode(&mut self.write)?;
                    0u8.encode(&mut self.write)?;
                    password.encode(&mut self.write)?;
                    true
                }
                auth::Method::PublicKey { ref key } => {
                    user.encode(&mut self.write)?;
                    "ssh-connection".encode(&mut self.write)?;
                    "publickey".encode(&mut self.write)?;
                    self.write.push(0); // This is a probe

                    debug!("write_auth_request: key - {:?}", key.algorithm());
                    key.algorithm().as_str().encode(&mut self.write)?;
                    key.public_key().to_bytes()?.encode(&mut self.write)?;
                    true
                }
                auth::Method::OpenSshCertificate { ref cert, .. } => {
                    user.as_bytes().encode(&mut self.write)?;
                    "ssh-connection".encode(&mut self.write)?;
                    "publickey".encode(&mut self.write)?;
                    self.write.push(0); // This is a probe

                    debug!("write_auth_request: cert - {:?}", cert.algorithm());
                    cert.algorithm()
                        .to_certificate_type()
                        .encode(&mut self.write)?;
                    cert.to_bytes()?.as_slice().encode(&mut self.write)?;
                    true
                }
                auth::Method::FuturePublicKey { ref key, hash_alg } => {
                    user.as_bytes().encode(&mut self.write)?;
                    "ssh-connection".encode(&mut self.write)?;
                    "publickey".encode(&mut self.write)?;
                    self.write.push(0); // This is a probe

                    key.algorithm()
                        .with_hash_alg(hash_alg)
                        .as_str()
                        .encode(&mut self.write)?;

                    key.to_bytes()?.as_slice().encode(&mut self.write)?;
                    true
                }
                auth::Method::FutureCertificate { ref cert, hash_alg } => {
                    user.as_bytes().encode(&mut self.write)?;
                    "ssh-connection".encode(&mut self.write)?;
                    "publickey".encode(&mut self.write)?;
                    self.write.push(0); // This is a probe

                    cert.algorithm()
                        .with_hash_alg(hash_alg)
                        .to_certificate_type()
                        .encode(&mut self.write)?;
                    cert.to_bytes()?.as_slice().encode(&mut self.write)?;
                    true
                }
                auth::Method::KeyboardInteractive { ref submethods } => {
                    debug!("Keyboard interactive");
                    user.as_bytes().encode(&mut self.write)?;
                    "ssh-connection".encode(&mut self.write)?;
                    "keyboard-interactive".encode(&mut self.write)?;
                    "".encode(&mut self.write)?; // lang tag is deprecated. Should be empty
                    submethods.as_bytes().encode(&mut self.write)?;
                    true
                }
                auth::Method::GssapiWithMic { ref mechanism_oids } => {
                    user.as_bytes().encode(&mut self.write)?;
                    "ssh-connection".encode(&mut self.write)?;
                    "gssapi-with-mic".encode(&mut self.write)?;
                    (mechanism_oids.len() as u32).encode(&mut self.write)?;
                    for oid in mechanism_oids {
                        oid.as_slice().encode(&mut self.write)?;
                    }
                    true
                }
            }
        }))
    }

    fn client_make_gssapi_mic_data(
        &mut self,
        user: &str,
        buffer: &mut Vec<u8>,
    ) -> Result<Vec<u8>, crate::Error> {
        buffer.clear();
        self.session_id.as_ref().encode(buffer)?;
        buffer.push(msg::USERAUTH_REQUEST);
        user.encode(buffer)?;
        "ssh-connection".encode(buffer)?;
        "gssapi-with-mic".encode(buffer)?;
        Ok(buffer.clone())
    }

    pub(crate) fn client_send_gssapi_token(&mut self, token: &[u8]) -> Result<(), crate::Error> {
        push_packet!(self.write, {
            msg::USERAUTH_GSSAPI_TOKEN.encode(&mut self.write)?;
            token.encode(&mut self.write)?;
        });
        Ok(())
    }

    pub(crate) fn client_send_gssapi_mic(
        &mut self,
        token: Option<&[u8]>,
        mic: &[u8],
    ) -> Result<(), crate::Error> {
        if let Some(token) = token.filter(|t| !t.is_empty()) {
            self.client_send_gssapi_token(token)?;
        }
        push_packet!(self.write, {
            msg::USERAUTH_GSSAPI_MIC.encode(&mut self.write)?;
            mic.encode(&mut self.write)?;
        });
        Ok(())
    }

    pub(crate) fn client_send_gssapi_exchange_complete(
        &mut self,
        token: Option<&[u8]>,
    ) -> Result<(), crate::Error> {
        if let Some(token) = token.filter(|t| !t.is_empty()) {
            self.client_send_gssapi_token(token)?;
        }
        push_packet!(self.write, {
            msg::USERAUTH_GSSAPI_EXCHANGE_COMPLETE.encode(&mut self.write)?;
        });
        Ok(())
    }

    fn client_make_to_sign(
        &mut self,
        user: &str,
        key: &PublicKeyOrCertificate,
        certificate_hash_alg: Option<ssh_key::HashAlg>,
        buffer: &mut Vec<u8>,
    ) -> Result<usize, crate::Error> {
        buffer.clear();
        self.session_id.as_ref().encode(buffer)?;

        let i0 = buffer.len();
        buffer.push(msg::USERAUTH_REQUEST);
        user.encode(buffer)?;
        "ssh-connection".encode(buffer)?;
        "publickey".encode(buffer)?;
        1u8.encode(buffer)?;

        match key {
            PublicKeyOrCertificate::Certificate(cert) => {
                cert.algorithm()
                    .with_hash_alg(certificate_hash_alg)
                    .to_certificate_type()
                    .encode(buffer)?;
                cert.to_bytes()?.encode(buffer)?;
            }
            PublicKeyOrCertificate::PublicKey { key, hash_alg } => {
                key.algorithm().with_hash_alg(*hash_alg).encode(buffer)?;
                key.to_bytes()?.encode(buffer)?;
            }
        }
        Ok(i0)
    }

    fn client_send_signature(
        &mut self,
        user: &str,
        method: &auth::Method,
        buffer: &mut Vec<u8>,
    ) -> Result<(), crate::Error> {
        match method {
            auth::Method::PublicKey { key } => {
                let i0 = self.client_make_to_sign(
                    user,
                    &PublicKeyOrCertificate::from(key),
                    None,
                    buffer,
                )?;

                // Extend with self-signature.
                sign_with_hash_alg(key, buffer)?.encode(&mut *buffer)?;

                push_packet!(self.write, {
                    #[allow(clippy::indexing_slicing)] // length checked
                    self.write.extend_from_slice(&buffer[i0..]);
                })
            }
            auth::Method::OpenSshCertificate { key, cert } => {
                let i0 = self.client_make_to_sign(
                    user,
                    &PublicKeyOrCertificate::Certificate(cert.clone()),
                    None,
                    buffer,
                )?;

                // Extend with self-signature.
                signature::Signer::try_sign(key.deref(), buffer)?
                    .encoded()?
                    .encode(&mut *buffer)?;

                push_packet!(self.write, {
                    #[allow(clippy::indexing_slicing)] // length checked
                    self.write.extend_from_slice(&buffer[i0..]);
                })
            }
            _ => {}
        }
        Ok(())
    }

    fn client_send_auth_response(&mut self, responses: &[String]) -> Result<(), crate::Error> {
        push_packet!(self.write, {
            msg::USERAUTH_INFO_RESPONSE.encode(&mut self.write)?;
            (responses.len().try_into().unwrap_or(0) as u32).encode(&mut self.write)?; // number of responses

            for r in responses {
                r.encode(&mut self.write)?; // write the reponses
            }
        });
        Ok(())
    }
}
