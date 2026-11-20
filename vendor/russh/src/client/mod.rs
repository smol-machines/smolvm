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

//! # Implementing clients
//!
//! Maybe surprisingly, the data types used by Russh to implement
//! clients are relatively more complicated than for servers. This is
//! mostly related to the fact that clients are generally used both in
//! a synchronous way (in the case of SSH, we can think of sending a
//! shell command), and asynchronously (because the server may send
//! unsollicited messages), and hence need to handle multiple
//! interfaces.
//!
//! The [Session](client::Session) is passed to the [Handler](client::Handler)
//! when the client receives data.
//!
//! Check out the following examples:
//!
//! * [Client that connects to a server, runs a command and prints its output](https://github.com/warp-tech/russh/blob/main/russh/examples/client_exec_simple.rs)
//! * [Client that connects to a server, runs a command in a PTY and provides interactive input/output](https://github.com/warp-tech/russh/blob/main/russh/examples/client_exec_interactive.rs)
//! * [SFTP client (with `russh-sftp`)](https://github.com/warp-tech/russh/blob/main/russh/examples/sftp_client.rs)
//!
//! [Session]: client::Session

use std::borrow::Cow;
use std::collections::{HashMap, VecDeque};
use std::convert::TryInto;
use std::num::Wrapping;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures::Future;
use futures::task::{Context, Poll};
use kex::ClientKex;
use log::{debug, error, trace, warn};
use russh_util::time::Instant;
use ssh_encoding::{Decode, Encode};
use ssh_key::{Algorithm, Certificate, HashAlg, PrivateKey, PublicKey};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::pin;
use tokio::sync::mpsc::{
    Receiver, Sender, UnboundedReceiver, UnboundedSender, channel, unbounded_channel,
};
use tokio::sync::oneshot;

pub use crate::auth::AuthResult;
use crate::cert::PublicKeyOrCertificate;
use crate::channels::{
    Channel, ChannelMsg, ChannelReadHalf, ChannelRef, ChannelWriteHalf, WindowSizeRef,
};
use crate::cipher::{self, OpeningKey, clear};
use crate::kex::{KexAlgorithmImplementor, KexCause, KexProgress, SessionKexState};
use crate::keys::PrivateKeyWithHashAlg;
use crate::msg::{is_kex_msg, validate_server_msg_strict_kex};
use crate::session::{CommonSession, EncryptedState, GlobalRequestResponse, NewKeys};
use crate::ssh_read::SshRead;
use crate::sshbuffer::{IncomingSshPacket, PacketWriter, SSHBuffer, SshId};
use crate::{
    ChannelId, ChannelOpenFailure, CryptoVec, Disconnect, Error, Limits, MethodSet, Sig, auth,
    map_err, msg, negotiation,
};

mod encrypted;
mod kex;
mod session;

#[cfg(test)]
mod test;

/// Actual client session's state.
///
/// It is in charge of multiplexing and keeping track of various channels
/// that may get opened and closed during the lifetime of an SSH session and
/// allows sending messages to the server.
#[derive(Debug)]
pub struct Session {
    kex: SessionKexState<ClientKex>,
    common: CommonSession<Arc<Config>>,
    receiver: Receiver<Msg>,
    sender: UnboundedSender<Reply>,
    channels: HashMap<ChannelId, ChannelRef>,
    target_window_size: u32,
    pending_reads: Vec<Vec<u8>>,
    pending_len: u32,
    priority_sender: UnboundedSender<Msg>,
    priority_receiver: UnboundedReceiver<Msg>,
    inbound_channel_sender: Sender<Msg>,
    inbound_channel_receiver: Receiver<Msg>,
    open_global_requests: VecDeque<GlobalRequestResponse>,
    server_sig_algs: Option<Vec<Algorithm>>,
    /// Number of EXT_INFO messages received (RFC 8308 allows at most two).
    ext_info_count: u8,
}

impl Drop for Session {
    fn drop(&mut self) {
        debug!("drop session")
    }
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum Reply {
    AuthSuccess,
    AuthFailure {
        proceed_with_methods: MethodSet,
        partial_success: bool,
    },
    ChannelOpenFailure,
    SignRequest {
        key: ssh_key::PublicKey,
        data: Vec<u8>,
    },
    SignRequestCert {
        cert: Certificate,
        hash_alg: Option<HashAlg>,
        data: Vec<u8>,
    },
    AuthInfoRequest {
        name: String,
        instructions: String,
        prompts: Vec<Prompt>,
    },
    AuthGssapiResponse {
        selected_mechanism: Vec<u8>,
        mic_data: Vec<u8>,
    },
    AuthGssapiToken {
        token: Vec<u8>,
        mic_data: Vec<u8>,
    },
    AuthGssapiError {
        error: auth::GssapiError,
    },
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Msg {
    Authenticate {
        user: String,
        method: auth::Method,
    },
    AuthInfoResponse {
        responses: Vec<String>,
    },
    AuthGssapiToken {
        token: Vec<u8>,
    },
    AuthGssapiMic {
        token: Option<Vec<u8>>,
        mic: Vec<u8>,
    },
    AuthGssapiExchangeComplete {
        token: Option<Vec<u8>>,
    },
    Signed {
        data: Vec<u8>,
    },
    /// The [`Signer`][auth::Signer] could not produce the signature the
    /// session is waiting for after a `SSH_MSG_USERAUTH_PK_OK`. The session
    /// abandons that attempt and goes back to its main loop, so the next
    /// authentication request gets through.
    SignFailed,
    ChannelOpenSession {
        channel_ref: ChannelRef,
    },
    ChannelOpenX11 {
        originator_address: String,
        originator_port: u32,
        channel_ref: ChannelRef,
    },
    ChannelOpenDirectTcpIp {
        host_to_connect: String,
        port_to_connect: u32,
        originator_address: String,
        originator_port: u32,
        channel_ref: ChannelRef,
    },
    ChannelOpenDirectStreamLocal {
        socket_path: String,
        channel_ref: ChannelRef,
    },
    TcpIpForward {
        /// Provide a channel for the reply result to request a reply from the server
        reply_channel: Option<oneshot::Sender<Option<u32>>>,
        address: String,
        port: u32,
    },
    CancelTcpIpForward {
        /// Provide a channel for the reply result to request a reply from the server
        reply_channel: Option<oneshot::Sender<bool>>,
        address: String,
        port: u32,
    },
    StreamLocalForward {
        /// Provide a channel for the reply result to request a reply from the server
        reply_channel: Option<oneshot::Sender<bool>>,
        socket_path: String,
    },
    CancelStreamLocalForward {
        /// Provide a channel for the reply result to request a reply from the server
        reply_channel: Option<oneshot::Sender<bool>>,
        socket_path: String,
    },
    Close {
        id: ChannelId,
    },
    Disconnect {
        reason: Disconnect,
        description: String,
        language_tag: String,
    },
    Channel(ChannelId, ChannelMsg),
    ServerChannelOpenReply {
        pending: crate::PendingChannelOpen,
        result: Result<(), ChannelOpenFailure>,
    },
    Rekey,
    AwaitExtensionInfo {
        extension_name: String,
        reply_channel: oneshot::Sender<()>,
    },
    GetServerSigAlgs {
        reply_channel: oneshot::Sender<Option<Vec<Algorithm>>>,
    },
    /// Send a keepalive packet to the remote
    Keepalive {
        want_reply: bool,
    },
    Ping {
        reply_channel: oneshot::Sender<()>,
    },
    NoMoreSessions {
        want_reply: bool,
    },
    HostKeysProve {
        reply_channel: oneshot::Sender<Result<(), crate::Error>>,
        keys: Vec<PublicKey>,
    },
    /// Send a global request with a custom name to the remote
    SendGlobalRequest {
        name: String,
        data: CryptoVec,
        /// Provide a channel for the reply result to request a reply from the server
        reply_channel: Option<oneshot::Sender<Option<CryptoVec>>>,
    },
}

impl From<(ChannelId, ChannelMsg)> for Msg {
    fn from((id, msg): (ChannelId, ChannelMsg)) -> Self {
        Msg::Channel(id, msg)
    }
}

/// Internal state for a server-initiated channel-open request awaiting accept or reject.
/// A handle passed to `server_channel_open_*` callbacks that the handler uses to
/// accept or reject the server's channel request.
///
/// Dropping the handle without calling [`accept`](ChannelOpenHandle::accept) or
/// [`reject`](ChannelOpenHandle::reject) automatically sends an
/// `AdministrativelyProhibited` rejection to the server.
pub type ChannelOpenHandle = crate::ChannelOpenHandleInner<Msg>;

#[derive(Debug)]
pub enum KeyboardInteractiveAuthResponse {
    Success,
    Failure {
        /// The server suggests to proceed with these auth methods
        remaining_methods: MethodSet,
        /// The server says that though auth method has been accepted,
        /// further authentication is required
        partial_success: bool,
    },
    InfoRequest {
        name: String,
        instructions: String,
        prompts: Vec<Prompt>,
    },
}

#[derive(Debug)]
pub struct Prompt {
    pub prompt: String,
    pub echo: bool,
}

#[derive(Debug)]
pub struct RemoteDisconnectInfo {
    pub reason_code: crate::Disconnect,
    pub message: String,
    pub lang_tag: String,
}

#[derive(Debug)]
pub enum DisconnectReason<E: From<crate::Error> + Send> {
    ReceivedDisconnect(RemoteDisconnectInfo),
    Error(E),
}

/// Handle to a session, used to send messages to a client outside of
/// the request/response cycle.
pub struct Handle<H: Handler> {
    sender: Sender<Msg>,
    receiver: UnboundedReceiver<Reply>,
    join: russh_util::runtime::JoinHandle<Result<(), H::Error>>,
    channel_buffer_size: usize,
    agent_session_binding: Option<crate::keys::agent::AgentSessionBinding>,
}

impl<H: Handler> Drop for Handle<H> {
    fn drop(&mut self) {
        debug!("drop handle")
    }
}

impl<H: Handler> Handle<H> {
    pub fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }

    /// Return the initial key-exchange context for OpenSSH agent session
    /// binding.
    ///
    /// Pass this to [`crate::keys::agent::client::AgentClient::bind_session`]
    /// before requesting identities or relaying a forwarded agent socket.
    pub fn agent_session_binding(&self) -> Option<&crate::keys::agent::AgentSessionBinding> {
        self.agent_session_binding.as_ref()
    }

    /// Perform no authentication. This is useful for testing, but should not be
    /// used in most other circumstances.
    pub async fn authenticate_none<U: Into<String>>(
        &mut self,
        user: U,
    ) -> Result<AuthResult, crate::Error> {
        let user = user.into();
        self.sender
            .send(Msg::Authenticate {
                user,
                method: auth::Method::None,
            })
            .await
            .map_err(|_| crate::Error::SendError)?;
        self.wait_recv_reply().await
    }

    /// Perform password-based SSH authentication.
    pub async fn authenticate_password<U: Into<String>, P: Into<String>>(
        &mut self,
        user: U,
        password: P,
    ) -> Result<AuthResult, crate::Error> {
        let user = user.into();
        self.sender
            .send(Msg::Authenticate {
                user,
                method: auth::Method::Password {
                    password: password.into(),
                },
            })
            .await
            .map_err(|_| crate::Error::SendError)?;
        self.wait_recv_reply().await
    }

    /// Initiate Keyboard-Interactive based SSH authentication.
    ///
    /// * `submethods` - Hints to the server the preferred methods to be used for authentication
    pub async fn authenticate_keyboard_interactive_start<
        U: Into<String>,
        S: Into<Option<String>>,
    >(
        &mut self,
        user: U,
        submethods: S,
    ) -> Result<KeyboardInteractiveAuthResponse, crate::Error> {
        self.sender
            .send(Msg::Authenticate {
                user: user.into(),
                method: auth::Method::KeyboardInteractive {
                    submethods: submethods.into().unwrap_or_else(|| "".to_owned()),
                },
            })
            .await
            .map_err(|_| crate::Error::SendError)?;
        self.wait_recv_keyboard_interactive_reply().await
    }

    /// Respond to AuthInfoRequests from the server. A server can send any number of these Requests
    /// including empty requests. You may have to call this function multple times in order to
    /// complete Keyboard-Interactive based SSH authentication.
    ///
    /// * `responses` - The responses to each prompt. The number of responses must match the number
    ///   of prompts. If a prompt has an empty string, then the response should be an empty string.
    pub async fn authenticate_keyboard_interactive_respond(
        &mut self,
        responses: Vec<String>,
    ) -> Result<KeyboardInteractiveAuthResponse, crate::Error> {
        self.sender
            .send(Msg::AuthInfoResponse { responses })
            .await
            .map_err(|_| crate::Error::SendError)?;
        self.wait_recv_keyboard_interactive_reply().await
    }

    async fn wait_recv_keyboard_interactive_reply(
        &mut self,
    ) -> Result<KeyboardInteractiveAuthResponse, crate::Error> {
        loop {
            match self.receiver.recv().await {
                Some(Reply::AuthSuccess) => return Ok(KeyboardInteractiveAuthResponse::Success),
                Some(Reply::AuthFailure {
                    proceed_with_methods: remaining_methods,
                    partial_success,
                }) => {
                    return Ok(KeyboardInteractiveAuthResponse::Failure {
                        remaining_methods,
                        partial_success,
                    });
                }
                Some(Reply::AuthInfoRequest {
                    name,
                    instructions,
                    prompts,
                }) => {
                    return Ok(KeyboardInteractiveAuthResponse::InfoRequest {
                        name,
                        instructions,
                        prompts,
                    });
                }
                None => return Err(crate::Error::RecvError),
                _ => {}
            }
        }
    }

    /// Tells the session that the [`Signer`][auth::Signer] could not produce
    /// the signature it is waiting for. Without this the session keeps waiting
    /// for `Msg::Signed` and ignores everything else sent to it, so no later
    /// authentication attempt on this handle would get through.
    async fn abandon_sign_request(&mut self) {
        // A send error means the session is gone; the signer's error is still
        // the one the caller needs.
        let _ = self.sender.send(Msg::SignFailed).await;
    }

    async fn wait_recv_reply(&mut self) -> Result<AuthResult, crate::Error> {
        loop {
            match self.receiver.recv().await {
                Some(Reply::AuthSuccess) => return Ok(AuthResult::Success),
                Some(Reply::AuthFailure {
                    proceed_with_methods: remaining_methods,
                    partial_success,
                }) => {
                    return Ok(AuthResult::Failure {
                        remaining_methods,
                        partial_success,
                    });
                }
                None => {
                    return Ok(AuthResult::Failure {
                        remaining_methods: MethodSet::empty(),
                        partial_success: false,
                    });
                }
                _ => {}
            }
        }
    }

    /// Perform public key-based SSH authentication.
    ///
    /// For RSA keys, you'll need to decide on which hash algorithm to use.
    /// This is the difference between what is also known as
    /// `ssh-rsa`, `rsa-sha2-256`, and `rsa-sha2-512` "keys" in OpenSSH.
    /// You can use [Handle::best_supported_rsa_hash] to automatically
    /// figure out the best hash algorithm for RSA keys.
    pub async fn authenticate_publickey<U: Into<String>>(
        &mut self,
        user: U,
        key: PrivateKeyWithHashAlg,
    ) -> Result<AuthResult, crate::Error> {
        let user = user.into();
        self.sender
            .send(Msg::Authenticate {
                user,
                method: auth::Method::PublicKey { key },
            })
            .await
            .map_err(|_| crate::Error::SendError)?;
        self.wait_recv_reply().await
    }

    /// Perform public OpenSSH Certificate-based SSH authentication
    pub async fn authenticate_openssh_cert<U: Into<String>>(
        &mut self,
        user: U,
        key: Arc<PrivateKey>,
        cert: Certificate,
    ) -> Result<AuthResult, crate::Error> {
        let user = user.into();
        self.sender
            .send(Msg::Authenticate {
                user,
                method: auth::Method::OpenSshCertificate { key, cert },
            })
            .await
            .map_err(|_| crate::Error::SendError)?;
        self.wait_recv_reply().await
    }

    /// Authenticate using a custom method that implements the
    /// [`Signer`][auth::Signer] trait. Currently, this crate only provides an
    /// implementation for an [SSH agent][crate::keys::agent::client::AgentClient].
    ///
    /// If the signer fails (for example an agent that does not hold the key,
    /// or declines to sign), its error is returned and the attempt is
    /// abandoned. The handle stays usable: another authentication method can
    /// be tried on it.
    pub async fn authenticate_publickey_with<U: Into<String>, S: auth::Signer>(
        &mut self,
        user: U,
        key: ssh_key::PublicKey,
        hash_alg: Option<HashAlg>,
        signer: &mut S,
    ) -> Result<AuthResult, S::Error> {
        let user = user.into();
        if self
            .sender
            .send(Msg::Authenticate {
                user,
                method: auth::Method::FuturePublicKey { key, hash_alg },
            })
            .await
            .is_err()
        {
            return Err((crate::SendError {}).into());
        }
        loop {
            let reply = self.receiver.recv().await;
            match reply {
                Some(Reply::AuthSuccess) => return Ok(AuthResult::Success),
                Some(Reply::AuthFailure {
                    proceed_with_methods: remaining_methods,
                    partial_success,
                }) => {
                    return Ok(AuthResult::Failure {
                        remaining_methods,
                        partial_success,
                    });
                }
                Some(Reply::SignRequest { key, data }) => {
                    let data = signer.auth_sign(&key.into(), hash_alg, data).await;
                    let data = match data {
                        Ok(data) => data,
                        Err(e) => {
                            self.abandon_sign_request().await;
                            return Err(e);
                        }
                    };
                    if self.sender.send(Msg::Signed { data }).await.is_err() {
                        return Err((crate::SendError {}).into());
                    }
                }
                None => {
                    return Ok(AuthResult::Failure {
                        remaining_methods: MethodSet::empty(),
                        partial_success: false,
                    });
                }
                _ => {}
            }
        }
    }

    /// Authenticate using GSSAPI with MIC (RFC 4462).
    ///
    /// `mechanism_oids` contains DER-encoded GSSAPI mechanism OIDs advertised to
    /// the server. The provided authenticator owns the platform- or
    /// application-specific GSSAPI implementation and returns continuation
    /// tokens and, once complete, the MIC over russh's SSH userauth data.
    pub async fn authenticate_gssapi_with_mic<U: Into<String>, G: auth::GssapiAuthenticator>(
        &mut self,
        user: U,
        mechanism_oids: Vec<Vec<u8>>,
        authenticator: &mut G,
    ) -> Result<AuthResult, G::Error> {
        let user = user.into();
        if self
            .sender
            .send(Msg::Authenticate {
                user,
                method: auth::Method::GssapiWithMic { mechanism_oids },
            })
            .await
            .is_err()
        {
            return Err((crate::SendError {}).into());
        }
        loop {
            let reply = self.receiver.recv().await;
            match reply {
                Some(Reply::AuthSuccess) => return Ok(AuthResult::Success),
                Some(Reply::AuthFailure {
                    proceed_with_methods: remaining_methods,
                    partial_success,
                }) => {
                    return Ok(AuthResult::Failure {
                        remaining_methods,
                        partial_success,
                    });
                }
                Some(Reply::AuthGssapiResponse {
                    selected_mechanism,
                    mic_data,
                }) => {
                    let step = authenticator
                        .gssapi_step(Some(selected_mechanism), None, mic_data)
                        .await?;
                    self.send_gssapi_step(step).await?;
                }
                Some(Reply::AuthGssapiToken { token, mic_data }) => {
                    let step = authenticator
                        .gssapi_step(None, Some(token), mic_data)
                        .await?;
                    self.send_gssapi_step(step).await?;
                }
                Some(Reply::AuthGssapiError { error }) => {
                    authenticator.gssapi_error(error).await;
                }
                None => {
                    return Ok(AuthResult::Failure {
                        remaining_methods: MethodSet::empty(),
                        partial_success: false,
                    });
                }
                _ => {}
            }
        }
    }

    async fn send_gssapi_step(&mut self, step: auth::GssapiStep) -> Result<(), crate::SendError> {
        let msg = match step {
            auth::GssapiStep::Continue { token } => Msg::AuthGssapiToken { token },
            auth::GssapiStep::Complete {
                token,
                mic: Some(mic),
            } => Msg::AuthGssapiMic { token, mic },
            auth::GssapiStep::Complete { token, mic: None } => {
                Msg::AuthGssapiExchangeComplete { token }
            }
        };
        self.sender.send(msg).await.map_err(|_| crate::SendError {})
    }

    /// Authenticate using a certificate with a custom signer that implements the
    /// [`Signer`][auth::Signer] trait. This is for certificate-based authentication
    /// where the signing is delegated to an external signer (e.g., SSH agent).
    ///
    /// For RSA certificates, you can specify the hash algorithm to use.
    ///
    /// If the signer fails, its error is returned and the attempt is
    /// abandoned; the handle stays usable for further authentication attempts,
    /// as with [`Handle::authenticate_publickey_with`].
    pub async fn authenticate_certificate_with<U: Into<String>, S: auth::Signer>(
        &mut self,
        user: U,
        cert: Certificate,
        hash_alg: Option<HashAlg>,
        signer: &mut S,
    ) -> Result<AuthResult, S::Error> {
        let user = user.into();
        if self
            .sender
            .send(Msg::Authenticate {
                user,
                method: auth::Method::FutureCertificate { cert, hash_alg },
            })
            .await
            .is_err()
        {
            return Err((crate::SendError {}).into());
        }
        loop {
            let reply = self.receiver.recv().await;
            match reply {
                Some(Reply::AuthSuccess) => return Ok(AuthResult::Success),
                Some(Reply::AuthFailure {
                    proceed_with_methods: remaining_methods,
                    partial_success,
                }) => {
                    return Ok(AuthResult::Failure {
                        remaining_methods,
                        partial_success,
                    });
                }
                Some(Reply::SignRequestCert {
                    cert,
                    hash_alg,
                    data,
                }) => {
                    let data = signer.auth_sign(&cert.into(), hash_alg, data).await;
                    let data = match data {
                        Ok(data) => data,
                        Err(e) => {
                            self.abandon_sign_request().await;
                            return Err(e);
                        }
                    };
                    if self.sender.send(Msg::Signed { data }).await.is_err() {
                        return Err((crate::SendError {}).into());
                    }
                }
                None => {
                    return Ok(AuthResult::Failure {
                        remaining_methods: MethodSet::empty(),
                        partial_success: false,
                    });
                }
                _ => {}
            }
        }
    }

    /// Wait for confirmation that a channel is open
    async fn wait_channel_confirmation(
        &self,
        mut receiver: Receiver<ChannelMsg>,
        window_size_ref: WindowSizeRef,
    ) -> Result<Channel<Msg>, crate::Error> {
        loop {
            match receiver.recv().await {
                Some(ChannelMsg::Open {
                    id,
                    max_packet_size,
                    window_size,
                }) => {
                    window_size_ref.grow(window_size).await;

                    return Ok(Channel {
                        write_half: ChannelWriteHalf {
                            id,
                            sender: self.sender.clone(),
                            max_packet_size,
                            window_size: window_size_ref,
                        },
                        read_half: ChannelReadHalf { receiver },
                    });
                }
                Some(ChannelMsg::OpenFailure(reason)) => {
                    return Err(crate::Error::ChannelOpenFailure(reason));
                }
                None => {
                    debug!("channel confirmation sender was dropped");
                    return Err(crate::Error::Disconnect);
                }
                msg => {
                    debug!("msg = {msg:?}");
                }
            }
        }
    }

    /// See [`Handle::best_supported_rsa_hash`].
    #[cfg(not(target_arch = "wasm32"))]
    async fn await_extension_info(&self, extension_name: String) -> Result<(), crate::Error> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Msg::AwaitExtensionInfo {
                extension_name,
                reply_channel: sender,
            })
            .await
            .map_err(|_| crate::Error::SendError)?;
        let _ = tokio::time::timeout(Duration::from_secs(1), receiver).await;
        Ok(())
    }

    /// Returns the best RSA hash algorithm supported by the server,
    /// as indicated by the `server-sig-algs` extension.
    /// If the server does not support the extension,
    /// `None` is returned. In this case you may still attempt an authentication
    /// with `rsa-sha2-256` or `rsa-sha2-512` and hope for the best.
    /// If the server supports the extension, but does not support `rsa-sha2-*`,
    /// `Some(None)` is returned.
    ///
    /// Note that this method will wait for up to 1 second for the server to
    /// send the extension info if it hasn't done so yet (except when running under
    /// WebAssembly). Unfortunately the timing of the EXT_INFO message cannot be known
    /// in advance (RFC 8308).
    ///
    /// If this method returns `None` once, then for most SSH servers
    /// you can assume that it will return `None` every time.
    pub async fn best_supported_rsa_hash(&self) -> Result<Option<Option<HashAlg>>, Error> {
        // Wait for the extension info from the server
        #[cfg(not(target_arch = "wasm32"))]
        self.await_extension_info("server-sig-algs".into()).await?;

        let (sender, receiver) = oneshot::channel();

        self.sender
            .send(Msg::GetServerSigAlgs {
                reply_channel: sender,
            })
            .await
            .map_err(|_| crate::Error::SendError)?;

        if let Some(ssa) = receiver.await.map_err(|_| Error::Inconsistent)? {
            let possible_algs = [
                Some(ssh_key::HashAlg::Sha512),
                Some(ssh_key::HashAlg::Sha256),
                None,
            ];
            for alg in possible_algs.into_iter() {
                if ssa.contains(&Algorithm::Rsa { hash: alg }) {
                    return Ok(Some(alg));
                }
            }
        }

        Ok(None)
    }

    /// Request a session channel (the most basic type of
    /// channel). This function returns `Some(..)` immediately if the
    /// connection is authenticated, but the channel only becomes
    /// usable when it's confirmed by the server, as indicated by the
    /// `confirmed` field of the corresponding `Channel`.
    pub async fn channel_open_session(&self) -> Result<Channel<Msg>, crate::Error> {
        let (sender, receiver) = channel(self.channel_buffer_size);
        let channel_ref = ChannelRef::new(sender);
        let window_size_ref = channel_ref.window_size().clone();

        self.sender
            .send(Msg::ChannelOpenSession { channel_ref })
            .await
            .map_err(|_| crate::Error::SendError)?;
        self.wait_channel_confirmation(receiver, window_size_ref)
            .await
    }

    /// Request an X11 channel, on which the X11 protocol may be tunneled.
    pub async fn channel_open_x11<A: Into<String>>(
        &self,
        originator_address: A,
        originator_port: u32,
    ) -> Result<Channel<Msg>, crate::Error> {
        let (sender, receiver) = channel(self.channel_buffer_size);
        let channel_ref = ChannelRef::new(sender);
        let window_size_ref = channel_ref.window_size().clone();

        self.sender
            .send(Msg::ChannelOpenX11 {
                originator_address: originator_address.into(),
                originator_port,
                channel_ref,
            })
            .await
            .map_err(|_| crate::Error::SendError)?;
        self.wait_channel_confirmation(receiver, window_size_ref)
            .await
    }

    /// Open a TCP/IP forwarding channel. This is usually done when a
    /// connection comes to a locally forwarded TCP/IP port. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-7). The
    /// TCP/IP packets can then be tunneled through the channel using
    /// `.data()`. After writing a stream to a channel using
    /// [`.data()`][Channel::data], be sure to call [`.eof()`][Channel::eof] to
    /// indicate that no more data will be sent, or you may see hangs when
    /// writing large streams.
    pub async fn channel_open_direct_tcpip<A: Into<String>, B: Into<String>>(
        &self,
        host_to_connect: A,
        port_to_connect: u32,
        originator_address: B,
        originator_port: u32,
    ) -> Result<Channel<Msg>, crate::Error> {
        let (sender, receiver) = channel(self.channel_buffer_size);
        let channel_ref = ChannelRef::new(sender);
        let window_size_ref = channel_ref.window_size().clone();

        self.sender
            .send(Msg::ChannelOpenDirectTcpIp {
                host_to_connect: host_to_connect.into(),
                port_to_connect,
                originator_address: originator_address.into(),
                originator_port,
                channel_ref,
            })
            .await
            .map_err(|_| crate::Error::SendError)?;
        self.wait_channel_confirmation(receiver, window_size_ref)
            .await
    }

    pub async fn channel_open_direct_streamlocal<S: Into<String>>(
        &self,
        socket_path: S,
    ) -> Result<Channel<Msg>, crate::Error> {
        let (sender, receiver) = channel(self.channel_buffer_size);
        let channel_ref = ChannelRef::new(sender);
        let window_size_ref = channel_ref.window_size().clone();

        self.sender
            .send(Msg::ChannelOpenDirectStreamLocal {
                socket_path: socket_path.into(),
                channel_ref,
            })
            .await
            .map_err(|_| crate::Error::SendError)?;
        self.wait_channel_confirmation(receiver, window_size_ref)
            .await
    }

    /// Requests the server to open a TCP/IP forward channel
    ///
    /// If port == 0 the server will choose a port that will be returned, returns 0 otherwise
    pub async fn tcpip_forward<A: Into<String>>(
        &self,
        address: A,
        port: u32,
    ) -> Result<u32, crate::Error> {
        let (reply_send, reply_recv) = oneshot::channel();
        self.sender
            .send(Msg::TcpIpForward {
                reply_channel: Some(reply_send),
                address: address.into(),
                port,
            })
            .await
            .map_err(|_| crate::Error::SendError)?;

        match reply_recv.await {
            Ok(Some(port)) => Ok(port),
            Ok(None) => Err(crate::Error::RequestDenied),
            Err(e) => {
                error!("Unable to receive TcpIpForward result: {e:?}");
                Err(crate::Error::Disconnect)
            }
        }
    }

    // Requests the server to close a TCP/IP forward channel
    pub async fn cancel_tcpip_forward<A: Into<String>>(
        &self,
        address: A,
        port: u32,
    ) -> Result<(), crate::Error> {
        let (reply_send, reply_recv) = oneshot::channel();
        self.sender
            .send(Msg::CancelTcpIpForward {
                reply_channel: Some(reply_send),
                address: address.into(),
                port,
            })
            .await
            .map_err(|_| crate::Error::SendError)?;

        match reply_recv.await {
            Ok(true) => Ok(()),
            Ok(false) => Err(crate::Error::RequestDenied),
            Err(e) => {
                error!("Unable to receive CancelTcpIpForward result: {e:?}");
                Err(crate::Error::Disconnect)
            }
        }
    }

    // Requests the server to open a UDS forward channel
    pub async fn streamlocal_forward<A: Into<String>>(
        &self,
        socket_path: A,
    ) -> Result<(), crate::Error> {
        let (reply_send, reply_recv) = oneshot::channel();
        self.sender
            .send(Msg::StreamLocalForward {
                reply_channel: Some(reply_send),
                socket_path: socket_path.into(),
            })
            .await
            .map_err(|_| crate::Error::SendError)?;

        match reply_recv.await {
            Ok(true) => Ok(()),
            Ok(false) => Err(crate::Error::RequestDenied),
            Err(e) => {
                error!("Unable to receive StreamLocalForward result: {e:?}");
                Err(crate::Error::Disconnect)
            }
        }
    }

    // Requests the server to close a UDS forward channel
    pub async fn cancel_streamlocal_forward<A: Into<String>>(
        &self,
        socket_path: A,
    ) -> Result<(), crate::Error> {
        let (reply_send, reply_recv) = oneshot::channel();
        self.sender
            .send(Msg::CancelStreamLocalForward {
                reply_channel: Some(reply_send),
                socket_path: socket_path.into(),
            })
            .await
            .map_err(|_| crate::Error::SendError)?;

        match reply_recv.await {
            Ok(true) => Ok(()),
            Ok(false) => Err(crate::Error::RequestDenied),
            Err(e) => {
                error!("Unable to receive CancelStreamLocalForward result: {e:?}");
                Err(crate::Error::Disconnect)
            }
        }
    }

    /// Sends a disconnect message.
    pub async fn disconnect(
        &self,
        reason: Disconnect,
        description: &str,
        language_tag: &str,
    ) -> Result<(), crate::Error> {
        self.sender
            .send(Msg::Disconnect {
                reason,
                description: description.into(),
                language_tag: language_tag.into(),
            })
            .await
            .map_err(|_| crate::Error::SendError)?;
        Ok(())
    }

    /// Send data to the session referenced by this handler.
    ///
    /// This is useful for server-initiated channels; for channels created by
    /// the client, prefer to use the Channel returned from the `open_*` methods.
    pub async fn data(
        &self,
        id: ChannelId,
        data: impl Into<bytes::Bytes>,
    ) -> Result<(), bytes::Bytes> {
        let data = data.into();
        self.sender
            .send(Msg::Channel(id, ChannelMsg::Data { data }))
            .await
            .map_err(|e| match e.0 {
                Msg::Channel(_, ChannelMsg::Data { data, .. }) => data,
                _ => unreachable!(),
            })
    }

    /// Asynchronously perform a session re-key at the next opportunity
    pub async fn rekey_soon(&self) -> Result<(), Error> {
        self.sender
            .send(Msg::Rekey)
            .await
            .map_err(|_| Error::SendError)?;

        Ok(())
    }

    /// Send a keepalive package to the remote peer.
    pub async fn send_keepalive(&self, want_reply: bool) -> Result<(), Error> {
        self.sender
            .send(Msg::Keepalive { want_reply })
            .await
            .map_err(|_| Error::SendError)
    }

    /// Send a keepalive/ping package to the remote peer, and wait for the reply/pong.
    pub async fn send_ping(&self) -> Result<(), Error> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Msg::Ping {
                reply_channel: sender,
            })
            .await
            .map_err(|_| Error::SendError)?;
        let _ = receiver.await;
        Ok(())
    }

    /// Send a no-more-sessions request to the remote peer.
    pub async fn no_more_sessions(&self, want_reply: bool) -> Result<(), Error> {
        self.sender
            .send(Msg::NoMoreSessions { want_reply })
            .await
            .map_err(|_| Error::SendError)
    }

    /// Asks the server to prove it holds each host key it announced through `hostkeys-00@openssh.com` (see [`Handler::openssh_ext_host_keys_announced`]).
    ///
    /// Succeeds only if the server successfully proves ownereship of all keys announced. [`Error::RequestDenied`] means the server refused and [`Error::WrongServerSig`] means at least one signature did not verify.
    pub async fn hostkeys_prove(&self, keys: Vec<PublicKey>) -> Result<(), Error> {
        let (reply_channel, reply_recv) = oneshot::channel();
        self.sender
            .send(Msg::HostKeysProve {
                reply_channel,
                keys,
            })
            .await
            .map_err(|_| Error::SendError)?;
        reply_recv.await.unwrap_or(Err(Error::Disconnect))
    }

    /// Send a global request with a custom, non-standard name to the remote peer.
    ///
    /// `data` is the request-specific payload and is appended verbatim after the
    /// request name and the want-reply flag (see RFC 4254 section 4). When
    /// `want_reply` is true this waits for the peer's reply and returns its
    /// response-specific data, which may be empty. When it is false it returns
    /// `Ok(None)` without waiting for a reply.
    pub async fn send_global_request<A: Into<String>>(
        &self,
        name: A,
        data: &[u8],
        want_reply: bool,
    ) -> Result<Option<CryptoVec>, Error> {
        let (reply_channel, reply_recv) = if want_reply {
            let (send, recv) = oneshot::channel();
            (Some(send), Some(recv))
        } else {
            (None, None)
        };
        self.sender
            .send(Msg::SendGlobalRequest {
                name: name.into(),
                data: CryptoVec::from_slice(data),
                reply_channel,
            })
            .await
            .map_err(|_| Error::SendError)?;

        match reply_recv {
            Some(reply_recv) => match reply_recv.await {
                Ok(Some(data)) => Ok(Some(data)),
                Ok(None) => Err(Error::RequestDenied),
                Err(e) => {
                    error!("Unable to receive send_global_request result: {e:?}");
                    Err(Error::Disconnect)
                }
            },
            None => Ok(None),
        }
    }
}

impl<H: Handler> Future for Handle<H> {
    type Output = Result<(), H::Error>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        match Future::poll(Pin::new(&mut self.join), cx) {
            Poll::Ready(r) => Poll::Ready(match r {
                Ok(Ok(x)) => Ok(x),
                Err(e) => Err(crate::Error::from(e).into()),
                Ok(Err(e)) => Err(e),
            }),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Connect to a server at the address specified, using the [`Handler`]
/// (implemented by you) and [`Config`] specified. Returns a future that
/// resolves to a [`Handle`]. This handle can then be used to create channels,
/// which in turn can be used to tunnel TCP connections, request a PTY, execute
/// commands, etc. The future will resolve to an error if the connection fails.
/// This function creates a connection to the `addr` specified using a
/// [`tokio::net::TcpStream`] and then calls [`connect_stream`] under the hood.
#[cfg(not(target_arch = "wasm32"))]
pub async fn connect<H: Handler + Send + 'static, A: tokio::net::ToSocketAddrs>(
    config: Arc<Config>,
    addrs: A,
    handler: H,
) -> Result<Handle<H>, H::Error> {
    let socket = map_err!(tokio::net::TcpStream::connect(addrs).await)?;
    #[allow(clippy::collapsible_if)]
    if config.as_ref().nodelay {
        if let Err(e) = socket.set_nodelay(true) {
            warn!("set_nodelay() failed: {e:?}");
        }
    }

    connect_stream(config, socket, handler).await
}

/// Connect a stream to a server. This stream must implement
/// [`tokio::io::AsyncRead`] and [`tokio::io::AsyncWrite`], as well as [`Unpin`]
/// and [`Send`]. Typically, you may prefer to use [`connect`], which uses a
/// [`tokio::net::TcpStream`] and then calls this function under the hood.
pub async fn connect_stream<H, R>(
    config: Arc<Config>,
    mut stream: R,
    handler: H,
) -> Result<Handle<H>, H::Error>
where
    H: Handler + Send + 'static,
    R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Writing SSH id.
    let mut write_buffer = SSHBuffer::new();

    debug!("ssh id = {:?}", config.as_ref().client_id);

    write_buffer.send_ssh_id(&config.as_ref().client_id);
    map_err!(stream.write_all(&write_buffer.buffer).await)?;

    // Reading SSH id and allocating a session if correct.
    let mut stream = SshRead::new(stream);
    let sshid = stream.read_ssh_id().await?;

    let (handle_sender, session_receiver) = channel(10);
    let (session_sender, handle_receiver) = unbounded_channel();
    if config.maximum_packet_size > 65535 {
        error!(
            "Maximum packet size ({:?}) should not larger than a TCP packet (65535)",
            config.maximum_packet_size
        );
    }
    let channel_buffer_size = config.channel_buffer_size;
    let mut session = Session::new(
        config.window_size,
        CommonSession {
            packet_writer: PacketWriter::clear(),
            auth_user: String::new(),
            auth_attempts: 0,
            auth_method: None, // Client only.
            remote_to_local: Box::new(clear::Key),
            encrypted: None,
            config,
            wants_reply: false,
            disconnected: false,
            buffer: Vec::new(),
            strict_kex: false,
            alive_timeouts: 0,
            received_data: false,
            remote_sshid: sshid.into(),
        },
        session_receiver,
        session_sender,
    );
    session.begin_rekey()?;
    let (kex_done_signal, kex_done_signal_rx) = oneshot::channel();
    let join = russh_util::runtime::spawn(session.run(stream, handler, Some(kex_done_signal)));

    let agent_session_binding = match kex_done_signal_rx.await {
        Ok(binding) => binding,
        Err(err) => {
            // kex_done_signal Sender is dropped when the session
            // fails before a successful key exchange
            debug!("kex_done_signal sender was dropped {err:?}");
            join.await.map_err(crate::Error::Join)??;
            return Err(H::Error::from(crate::Error::Disconnect));
        }
    };

    Ok(Handle {
        sender: handle_sender,
        receiver: handle_receiver,
        join,
        channel_buffer_size,
        agent_session_binding,
    })
}

async fn start_reading<R: AsyncRead + Unpin>(
    mut stream_read: R,
    mut buffer: SSHBuffer,
    mut cipher: Box<dyn OpeningKey + Send>,
) -> Result<(usize, R, SSHBuffer, Box<dyn OpeningKey + Send>), crate::Error> {
    buffer.buffer.clear();
    let n = cipher::read(&mut stream_read, &mut buffer, &mut *cipher).await?;
    Ok((n, stream_read, buffer, cipher))
}

impl Session {
    fn maybe_decompress(&mut self, buffer: &SSHBuffer) -> Result<IncomingSshPacket, Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            let mut decomp = Vec::new();
            Ok(IncomingSshPacket {
                #[allow(clippy::indexing_slicing)] // length checked
                buffer: enc.decompress.decompress(
                    &buffer.buffer[5..],
                    &mut decomp,
                )?.into(),
                seqn: buffer.seqn,
            })
        } else {
            Ok(IncomingSshPacket {
                #[allow(clippy::indexing_slicing)] // length checked
                buffer: buffer.buffer[5..].into(),
                seqn: buffer.seqn,
            })
        }
    }

    fn new(
        target_window_size: u32,
        common: CommonSession<Arc<Config>>,
        receiver: Receiver<Msg>,
        sender: UnboundedSender<Reply>,
    ) -> Self {
        let (priority_sender, priority_receiver) = unbounded_channel();
        let (inbound_channel_sender, inbound_channel_receiver) = channel(10);
        Self {
            common,
            receiver,
            sender,
            kex: SessionKexState::Idle,
            target_window_size,
            priority_sender,
            priority_receiver,
            inbound_channel_sender,
            inbound_channel_receiver,
            channels: HashMap::new(),
            pending_reads: Vec::new(),
            pending_len: 0,
            open_global_requests: VecDeque::new(),
            server_sig_algs: None,
            ext_info_count: 0,
        }
    }

    async fn run<H: Handler + Send, R: AsyncRead + AsyncWrite + Unpin + Send>(
        mut self,
        stream: SshRead<R>,
        mut handler: H,
        mut kex_done_signal: Option<
            oneshot::Sender<Option<crate::keys::agent::AgentSessionBinding>>,
        >,
    ) -> Result<(), H::Error> {
        let (stream_read, mut stream_write) = stream.split();
        let result = self
            .run_inner(
                stream_read,
                &mut stream_write,
                &mut handler,
                &mut kex_done_signal,
            )
            .await;
        trace!("disconnected");
        self.receiver.close();
        self.priority_receiver.close();
        self.inbound_channel_receiver.close();
        map_err!(stream_write.shutdown().await)?;
        match result {
            Ok(v) => {
                handler
                    .disconnected(DisconnectReason::ReceivedDisconnect(v))
                    .await?;
                Ok(())
            }
            Err(e) => {
                if kex_done_signal.is_some() {
                    // The kex signal has not been consumed yet,
                    // so we can send return the concrete error to be propagated
                    // into the JoinHandle and returned from `connect_stream`
                    debug!("disconnected during handshake {e:?}");
                    Err(e)
                } else {
                    // The kex signal has been consumed, so no one is
                    // awaiting the result of this coroutine
                    // We're better off passing the error into the Handler
                    debug!("disconnected {e:?}");
                    handler.disconnected(DisconnectReason::Error(e)).await?;
                    Err(H::Error::from(crate::Error::Disconnect))
                }
            }
        }
    }

    async fn run_inner<H: Handler + Send, R: AsyncRead + AsyncWrite + Unpin + Send>(
        &mut self,
        stream_read: SshRead<ReadHalf<R>>,
        stream_write: &mut WriteHalf<R>,
        handler: &mut H,
        kex_done_signal: &mut Option<
            tokio::sync::oneshot::Sender<Option<crate::keys::agent::AgentSessionBinding>>,
        >,
    ) -> Result<RemoteDisconnectInfo, H::Error> {
        let mut result: Result<RemoteDisconnectInfo, H::Error> = Err(Error::Disconnect.into());
        self.flush()?;

        map_err!(self.common.packet_writer.flush_into(stream_write).await)?;

        let buffer = SSHBuffer::new();

        // Allow handing out references to the cipher
        let mut opening_cipher = Box::new(clear::Key) as Box<dyn OpeningKey + Send>;
        std::mem::swap(&mut opening_cipher, &mut self.common.remote_to_local);

        let keepalive_timer =
            crate::future_or_pending(self.common.config.keepalive_interval, tokio::time::sleep);
        pin!(keepalive_timer);

        let inactivity_timer =
            crate::future_or_pending(self.common.config.inactivity_timeout, tokio::time::sleep);
        pin!(inactivity_timer);

        let reading = start_reading(stream_read, buffer, opening_cipher);
        pin!(reading);

        #[allow(clippy::panic)] // false positive in select! macro
        while !self.common.disconnected {
            self.common.received_data = false;
            // Set whenever the keepalive timer elapses, even if no keepalive
            // could be sent yet, so that the timer is always re-armed below.
            let mut keepalive_elapsed = false;
            // Keep reading the network for window adjustments, but leave
            // application output in its bounded receivers while a channel is
            // window-blocked.
            let can_receive_outbound = !self.kex.active() && !self.common.has_any_pending_data();
            let rekey_timer =
                crate::future_or_pending(self.rekey_time_remaining(), tokio::time::sleep);
            pin!(rekey_timer);
            tokio::select! {
                r = &mut reading => {
                    let (stream_read, mut buffer, mut opening_cipher) = match r {
                        Ok((_, stream_read, buffer, opening_cipher)) => (stream_read, buffer, opening_cipher),
                        Err(e) => return Err(e.into())
                    };

                    std::mem::swap(&mut opening_cipher, &mut self.common.remote_to_local);

                    if buffer.buffer.len() < 5 {
                        break
                    }

                    let mut pkt = self.maybe_decompress(&buffer)?;
                    if !pkt.buffer.is_empty() {
                        #[allow(clippy::indexing_slicing)] // length checked
                        if pkt.buffer[0] == crate::msg::DISCONNECT {
                            debug!("received disconnect");
                            result = self.process_disconnect(&pkt).map_err(H::Error::from);
                        } else {
                            self.common.received_data = true;
                            let kex_was_active = self.kex.active();
                            reply(self, handler, kex_done_signal, &mut pkt).await?;
                            buffer.seqn = pkt.seqn; // TODO reply changes seqn internall, find cleaner way

                            if kex_was_active && !self.kex.active() {
                                buffer.bytes = 0;
                            } else if self.automatic_rekey_allowed()
                                && buffer.bytes >= self.common.config.limits.rekey_read_limit
                            {
                                debug!("rekey read limit reached after {} inbound bytes", buffer.bytes);
                                if let Some(enc) = self.common.encrypted.as_mut() {
                                    // flush checks this
                                    enc.rekey_wanted = true;
                                }
                            }
                        }
                    }

                    std::mem::swap(&mut opening_cipher, &mut self.common.remote_to_local);
                    reading.set(start_reading(stream_read, buffer, opening_cipher));
                }
                () = &mut rekey_timer => {
                    // The flush after the select sees the elapsed limit.
                    debug!("rekey time limit reached");
                }
                () = &mut keepalive_timer => {
                    keepalive_elapsed = true;
                    if let Some(ref mut enc) = self.common.encrypted
                        && matches!(enc.state, EncryptedState::Authenticated)
                    {
                        self.common.alive_timeouts = self.common.alive_timeouts.saturating_add(1);
                        if self.common.config.keepalive_max != 0 && self.common.alive_timeouts > self.common.config.keepalive_max {
                            debug!("Timeout, server not responding to keepalives");
                            return Err(crate::Error::KeepaliveTimeout.into());
                        }
                        self.send_keepalive(true)?;
                    }
                }
                () = &mut inactivity_timer => {
                    debug!("timeout");
                    return Err(crate::Error::InactivityTimeout.into());
                }
                msg = self.receiver.recv(), if can_receive_outbound => {
                    self.drain_priority_msgs()?;
                    match msg {
                        Some(msg) => self.handle_msg(msg)?,
                        None => {
                            self.common.disconnected = true;
                            break
                        }
                    };

                    // eagerly take all outgoing messages so writes are batched
                    while !self.kex.active() && !self.common.has_any_pending_data() {
                        self.drain_priority_msgs()?;
                        match self.receiver.try_recv() {
                            Ok(next) => self.handle_msg(next)?,
                            Err(_) => break
                        }
                    }
                }
                msg = self.priority_receiver.recv(), if !self.kex.active() => {
                    match msg {
                        Some(msg) => self.handle_msg(msg)?,
                        None => (),
                    }

                    // eagerly take all outgoing messages so writes are batched
                    self.drain_priority_msgs()?;
                }
                msg = self.inbound_channel_receiver.recv(), if can_receive_outbound => {
                    self.drain_priority_msgs()?;
                    match msg {
                        Some(msg) => self.handle_msg(msg)?,
                        None => (),
                    }

                    // eagerly take all outgoing messages so writes are batched
                    while !self.kex.active() && !self.common.has_any_pending_data() {
                        self.drain_priority_msgs()?;
                        match self.inbound_channel_receiver.try_recv() {
                            Ok(next) => self.handle_msg(next)?,
                            Err(_) => break
                        }
                    }
                }
            };

            self.flush()?;
            crate::flush_or_timeout(
                &mut self.common.packet_writer,
                stream_write,
                inactivity_timer.as_mut(),
            )
            .await?;

            if let Some(ref mut enc) = self.common.encrypted
                && let EncryptedState::InitCompression = enc.state
            {
                if enc.client_compression.is_deferred() {
                    enc.client_compression
                        .init_compress(self.common.packet_writer.compress());
                }
                enc.state = EncryptedState::Authenticated;
            }

            if self.common.received_data {
                // Reset the number of failed keepalive attempts. We don't
                // bother detecting keepalive response messages specifically
                // (OpenSSH_9.6p1 responds with REQUEST_FAILURE aka 82). Instead
                // we assume that the server is still alive if we receive any
                // data from it.
                self.common.alive_timeouts = 0;
            }
            if (self.common.received_data || keepalive_elapsed)
                && let (futures::future::Either::Right(ref mut sleep), Some(d)) = (
                    keepalive_timer.as_mut().as_pin_mut(),
                    self.common.config.keepalive_interval,
                )
            {
                sleep.as_mut().reset(tokio::time::Instant::now() + d);
            }
            if !keepalive_elapsed
                && let (futures::future::Either::Right(ref mut sleep), Some(d)) = (
                    inactivity_timer.as_mut().as_pin_mut(),
                    self.common.config.inactivity_timeout,
                )
            {
                sleep.as_mut().reset(tokio::time::Instant::now() + d);
            }
        }

        result
    }

    fn process_disconnect(
        &mut self,
        pkt: &IncomingSshPacket,
    ) -> Result<RemoteDisconnectInfo, Error> {
        let mut r = &pkt.buffer[..];
        u8::decode(&mut r)?; // skip message type
        self.common.disconnected = true;

        let reason_code = u32::decode(&mut r)?.try_into()?;
        let message = String::decode(&mut r)?;
        let lang_tag = String::decode(&mut r)?;

        Ok(RemoteDisconnectInfo {
            reason_code,
            message,
            lang_tag,
        })
    }

    /// Channel open replies must be dispatched before any channel traffic
    /// queued after them: the bounded receivers may hold data for a channel
    /// whose confirmation is still sitting in the priority queue, and
    /// dispatching that data first would silently drop it (the channel is
    /// only registered when its open reply is processed).
    fn drain_priority_msgs(&mut self) -> Result<(), crate::Error> {
        while !self.kex.active() {
            match self.priority_receiver.try_recv() {
                Ok(msg) => self.handle_msg(msg)?,
                Err(_) => break,
            }
        }
        Ok(())
    }

    fn handle_msg(&mut self, msg: Msg) -> Result<(), crate::Error> {
        match msg {
            Msg::Authenticate { user, method } => {
                self.write_auth_request_if_needed(&user, method)?;
            }
            Msg::Signed { .. } | Msg::SignFailed => {}
            Msg::AuthInfoResponse { .. } => {}
            Msg::AuthGssapiToken { token } => {
                if let Some(ref mut enc) = self.common.encrypted {
                    enc.client_send_gssapi_token(&token)?;
                }
            }
            Msg::AuthGssapiMic { token, mic } => {
                if let Some(ref mut enc) = self.common.encrypted {
                    enc.client_send_gssapi_mic(token.as_deref(), &mic)?;
                }
            }
            Msg::AuthGssapiExchangeComplete { token } => {
                if let Some(ref mut enc) = self.common.encrypted {
                    enc.client_send_gssapi_exchange_complete(token.as_deref())?;
                }
            }
            Msg::ChannelOpenSession { channel_ref } => {
                let id = self.channel_open_session()?;
                self.channels.insert(id, channel_ref);
            }
            Msg::ChannelOpenX11 {
                originator_address,
                originator_port,
                channel_ref,
            } => {
                let id = self.channel_open_x11(&originator_address, originator_port)?;
                self.channels.insert(id, channel_ref);
            }
            Msg::ChannelOpenDirectTcpIp {
                host_to_connect,
                port_to_connect,
                originator_address,
                originator_port,
                channel_ref,
            } => {
                let id = self.channel_open_direct_tcpip(
                    &host_to_connect,
                    port_to_connect,
                    &originator_address,
                    originator_port,
                )?;
                self.channels.insert(id, channel_ref);
            }
            Msg::ChannelOpenDirectStreamLocal {
                socket_path,
                channel_ref,
            } => {
                let id = self.channel_open_direct_streamlocal(&socket_path)?;
                self.channels.insert(id, channel_ref);
            }
            Msg::TcpIpForward {
                reply_channel,
                address,
                port,
            } => self.tcpip_forward(reply_channel, &address, port)?,
            Msg::CancelTcpIpForward {
                reply_channel,
                address,
                port,
            } => self.cancel_tcpip_forward(reply_channel, &address, port)?,
            Msg::StreamLocalForward {
                reply_channel,
                socket_path,
            } => self.streamlocal_forward(reply_channel, &socket_path)?,
            Msg::CancelStreamLocalForward {
                reply_channel,
                socket_path,
            } => self.cancel_streamlocal_forward(reply_channel, &socket_path)?,
            Msg::Disconnect {
                reason,
                description,
                language_tag,
            } => self.disconnect(reason, &description, &language_tag)?,
            Msg::Channel(id, ChannelMsg::Data { data }) => self.data(id, data)?,
            Msg::Channel(id, ChannelMsg::Eof) => {
                self.eof(id)?;
            }
            Msg::Channel(id, ChannelMsg::ExtendedData { data, ext }) => {
                self.extended_data(id, ext, data)?;
            }
            Msg::Channel(
                id,
                ChannelMsg::RequestPty {
                    want_reply,
                    term,
                    col_width,
                    row_height,
                    pix_width,
                    pix_height,
                    terminal_modes,
                },
            ) => self.request_pty(
                id,
                want_reply,
                &term,
                col_width,
                row_height,
                pix_width,
                pix_height,
                &terminal_modes,
            )?,
            Msg::Channel(
                id,
                ChannelMsg::WindowChange {
                    col_width,
                    row_height,
                    pix_width,
                    pix_height,
                },
            ) => self.window_change(id, col_width, row_height, pix_width, pix_height)?,
            Msg::Channel(
                id,
                ChannelMsg::RequestX11 {
                    want_reply,
                    single_connection,
                    x11_authentication_protocol,
                    x11_authentication_cookie,
                    x11_screen_number,
                },
            ) => self.request_x11(
                id,
                want_reply,
                single_connection,
                &x11_authentication_protocol,
                &x11_authentication_cookie,
                x11_screen_number,
            )?,
            Msg::Channel(
                id,
                ChannelMsg::SetEnv {
                    want_reply,
                    variable_name,
                    variable_value,
                },
            ) => self.set_env(id, want_reply, &variable_name, &variable_value)?,
            Msg::Channel(id, ChannelMsg::RequestShell { want_reply }) => {
                self.request_shell(want_reply, id)?
            }
            Msg::Channel(
                id,
                ChannelMsg::Exec {
                    want_reply,
                    command,
                },
            ) => self.exec(id, want_reply, &command)?,
            Msg::Channel(id, ChannelMsg::Signal { signal }) => self.signal(id, signal)?,
            Msg::Channel(id, ChannelMsg::RequestSubsystem { want_reply, name }) => {
                self.request_subsystem(want_reply, id, &name)?
            }
            Msg::Channel(id, ChannelMsg::AgentForward { want_reply }) => {
                self.agent_forward(id, want_reply)?
            }
            Msg::Channel(id, ChannelMsg::Close) => self.close(id)?,
            Msg::Rekey => self.initiate_rekey()?,
            Msg::AwaitExtensionInfo {
                extension_name,
                reply_channel,
            } => {
                if let Some(ref mut enc) = self.common.encrypted {
                    // Drop if the extension has been seen already
                    if !enc.received_extensions.contains(&extension_name) {
                        // There will be no new extension info after authentication
                        // has succeeded
                        if !matches!(enc.state, EncryptedState::Authenticated) {
                            enc.extension_info_awaiters
                                .entry(extension_name)
                                .or_insert(vec![])
                                .push(reply_channel);
                        }
                    }
                }
            }
            Msg::GetServerSigAlgs { reply_channel } => {
                let _ = reply_channel.send(self.server_sig_algs.clone());
            }
            Msg::Keepalive { want_reply } => {
                let _ = self.send_keepalive(want_reply);
            }
            Msg::Ping { reply_channel } => {
                let _ = self.send_ping(reply_channel);
            }
            Msg::NoMoreSessions { want_reply } => {
                let _ = self.no_more_sessions(want_reply);
            }
            Msg::HostKeysProve {
                reply_channel,
                keys,
            } => {
                self.request_hostkeys_prove(reply_channel, keys)?;
            }
            Msg::SendGlobalRequest {
                name,
                data,
                reply_channel,
            } => {
                let _ = self.send_global_request(reply_channel, &name, &data);
            }
            Msg::ServerChannelOpenReply { pending, result } => {
                self.finalize_server_channel_open_reply(pending, result)?;
            }
            msg => {
                // should be unreachable, since the receiver only gets
                // messages from methods implemented within russh
                unimplemented!("unimplemented (server-only?) message: {:?}", msg)
            }
        }
        Ok(())
    }

    fn finalize_server_channel_open_reply(
        &mut self,
        pending: crate::PendingChannelOpen,
        result: Result<(), ChannelOpenFailure>,
    ) -> Result<(), crate::Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            match result {
                Ok(()) => {
                    push_packet!(enc.write, {
                        msg::CHANNEL_OPEN_CONFIRMATION.encode(&mut enc.write)?;
                        pending.recipient_channel.encode(&mut enc.write)?;
                        pending.sender_channel.encode(&mut enc.write)?;
                        pending.window_size.encode(&mut enc.write)?;
                        pending.packet_size.encode(&mut enc.write)?;
                    });
                    enc.channels
                        .insert(pending.sender_channel, pending.channel_params);
                    self.channels
                        .insert(pending.sender_channel, pending.channel_ref);
                }
                Err(reason) => {
                    push_packet!(enc.write, {
                        msg::CHANNEL_OPEN_FAILURE.encode(&mut enc.write)?;
                        pending.recipient_channel.encode(&mut enc.write)?;
                        reason.code().encode(&mut enc.write)?;
                        reason.description().encode(&mut enc.write)?;
                        "en".encode(&mut enc.write)?;
                    });
                }
            }
        }
        Ok(())
    }

    fn begin_rekey(&mut self) -> Result<(), crate::Error> {
        debug!("beginning re-key");
        self.pending_len = 0;
        let mut kex = ClientKex::new(
            self.common.config.clone(),
            &self.common.config.client_id,
            &self.common.remote_sshid,
            match &self.common.encrypted {
                None => KexCause::Initial,
                Some(enc) => KexCause::Rekey {
                    strict: self.common.strict_kex,
                    session_id: enc.session_id.clone(),
                },
            },
        );

        kex.kexinit(&mut self.common.packet_writer)?;
        self.kex = SessionKexState::InProgress(kex);
        Ok(())
    }

    fn automatic_rekey_allowed(&self) -> bool {
        !self.kex.active()
            && self
                .common
                .encrypted
                .as_ref()
                .is_some_and(|enc| matches!(enc.state, EncryptedState::Authenticated))
    }

    fn rekey_time_remaining(&self) -> Option<Duration> {
        if cfg!(target_arch = "wasm32") || !self.automatic_rekey_allowed() {
            return None;
        }
        self.common
            .encrypted
            .as_ref()?
            .rekey_time_remaining(&self.common.config.limits, &self.common.packet_writer)
    }

    /// Flush the temporary cleartext buffer into the encryption
    /// buffer. This does *not* flush to the socket.
    fn flush(&mut self) -> Result<(), crate::Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            // Tearing down: get the queued packets (incl. DISCONNECT) out in
            // order, kex or not.
            let is_rekeying = self.kex.active() && !self.common.disconnected;
            let rekey_requested = enc.rekey_wanted; // enc.flush resets rekey_wanted
            if enc.flush(
                &self.common.config.as_ref().limits,
                &mut self.common.packet_writer,
                is_rekeying,
            )? && !self.kex.active()
                && (rekey_requested || matches!(enc.state, EncryptedState::Authenticated))
            {
                self.begin_rekey()?;
            }
        }
        Ok(())
    }

    /// Immediately trigger a session re-key after flushing all pending packets
    pub fn initiate_rekey(&mut self) -> Result<(), Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            enc.rekey_wanted = true;
            self.flush()?
        }
        Ok(())
    }
}

async fn reply<H: Handler>(
    session: &mut Session,
    handler: &mut H,
    kex_done_signal: &mut Option<
        tokio::sync::oneshot::Sender<Option<crate::keys::agent::AgentSessionBinding>>,
    >,
    pkt: &mut IncomingSshPacket,
) -> Result<(), H::Error> {
    if let Some(message_type) = pkt.buffer.first() {
        debug!(
            "< msg type {message_type:?}, seqn {:?}, len {}",
            pkt.seqn.0,
            pkt.buffer.len()
        );
        let strict_kex = match session.kex {
            SessionKexState::InProgress(ref kex) => kex.strict_kex(),
            _ => session.common.strict_kex,
        };
        if strict_kex && session.common.encrypted.is_none() {
            let seqno = pkt.seqn.0 - 1; // was incremented after read()
            validate_server_msg_strict_kex(*message_type, seqno as usize)?;
        }

        if [msg::IGNORE, msg::UNIMPLEMENTED, msg::DEBUG].contains(message_type) {
            return Ok(());
        }
    }

    if pkt.buffer.first() == Some(&msg::KEXINIT) && session.kex == SessionKexState::Idle {
        // Not currently in a rekey but received KEXINIT
        debug!("server has initiated re-key");
        session.begin_rekey()?;
        // Kex will consume the packet right away
    }

    let is_kex_msg = pkt.buffer.first().cloned().map(is_kex_msg).unwrap_or(false);

    // RFC 4253 s7.1: after a KEXINIT, only transport (1-19) and kex (20-49)
    // messages may flow until NEWKEYS. Non-transport messages (>= 50: auth and
    // channel traffic) are the DoS vector -- their replies queue on an
    // unbounded channel that is not drained until the rekey the peer may never
    // finish completes.
    //
    //   * Once the PEER's own KEXINIT has arrived, nothing of theirs is
    //     legitimately still in flight, so such a message is a protocol
    //     violation -- reject it.
    //   * Before it arrives (we initiated the rekey; the peer may not have seen
    //     our KEXINIT yet) their in-flight messages are legal. Handle them as
    //     usual, but bound the total so a peer that stalls the rekey and floods
    //     cannot grow memory without limit. `pending_len` is reset when the
    //     rekey completes (see `begin_rekey` and the kex-done path).
    #[allow(clippy::collapsible_if)]
    if !is_kex_msg && session.common.encrypted.is_some() {
        if let (Some(&msg_type), SessionKexState::InProgress(kex)) =
            (pkt.buffer.first(), &session.kex)
        {
            if msg_type >= msg::USERAUTH_REQUEST {
                if kex.peer_kexinit_received() {
                    return Err(crate::Error::Inconsistent.into());
                }
                session.pending_len = session.pending_len.saturating_add(pkt.buffer.len() as u32);
                if u64::from(session.pending_len) > 2 * u64::from(session.common.config.window_size)
                {
                    return Err(crate::Error::Pending.into());
                }
            }
        }
    }

    #[allow(clippy::collapsible_if)]
    if is_kex_msg {
        if let SessionKexState::InProgress(kex) = session.kex.take() {
            let progress = kex.step(Some(pkt), &mut session.common.packet_writer)?;

            match progress {
                KexProgress::NeedsReply { kex, reset_seqn } => {
                    debug!("kex impl continues: {kex:?}");
                    session.kex = SessionKexState::InProgress(kex);
                    if reset_seqn {
                        debug!("kex impl requests seqno reset");
                        session.common.reset_seqn();
                    }
                }
                KexProgress::Done {
                    server_host_key,
                    server_host_certificate,
                    agent_session_binding,
                    newkeys,
                } => {
                    debug!("kex impl has completed");
                    session.common.strict_kex =
                        session.common.strict_kex || newkeys.names.strict_kex();

                    if session.common.encrypted.is_some() {
                        // This is a rekey
                        handler
                            .kex_done(newkeys.kex.shared_secret_bytes(), &newkeys.names, session)
                            .await?;
                        {
                            let common = &mut session.common;
                            common.newkeys(newkeys);
                            if let Some(enc) = common.encrypted.as_mut() {
                                enc.last_rekey = Instant::now();
                                enc.flush_all_pending_with_writer(
                                    &mut common.packet_writer,
                                    false,
                                )?;
                            }
                        }

                        let mut pending = std::mem::take(&mut session.pending_reads);
                        for p in pending.drain(..) {
                            session.process_packet(handler, &p).await?;
                        }
                        session.pending_reads = pending;
                        session.pending_len = 0;
                    } else {
                        // This is the initial kex
                        // A certificate replaces the key check rather than
                        // adding to it. The key inside a certificate is not
                        // something the client was ever told to trust — asking
                        // about it as well would invite an implementation to
                        // answer yes to the wrong question.
                        if let Some(certificate) = server_host_certificate {
                            if !handler.check_server_key(&certificate.into()).await? {
                                return Err(crate::Error::UnknownKey.into());
                            }
                        } else if let Some(server_host_key) = server_host_key {
                            let check = handler.check_server_key(&server_host_key.into()).await?;
                            if !check {
                                return Err(crate::Error::UnknownKey.into());
                            }
                        }

                        handler
                            .kex_done(newkeys.kex.shared_secret_bytes(), &newkeys.names, session)
                            .await?;

                        session
                            .common
                            .encrypted(initial_encrypted_state(session), newkeys);

                        if let Some(sender) = kex_done_signal.take() {
                            sender.send(agent_session_binding).unwrap_or(());
                        }
                    }

                    session.kex = SessionKexState::Idle;

                    if session.common.strict_kex {
                        pkt.seqn = Wrapping(0);
                    }

                    debug!("kex done");
                }
            }

            session.flush()?;

            return Ok(());
        }
    }

    session.client_read_encrypted(handler, pkt).await
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, VecDeque};
    #[cfg(feature = "flate2")]
    use std::io::Write;
    use std::num::Wrapping;
    use std::sync::Arc;

    use ssh_encoding::Encode;
    use tokio::sync::mpsc::{channel, unbounded_channel};

    use super::*;
    use crate::auth::{AuthRequest, Method};
    use crate::compression::{Compression, Decompress};
    use crate::helpers::EncodedExt;
    use crate::kex::{KEXES, NONE};
    use crate::session::{CommonSession, Encrypted, EncryptedState, Exchange};
    use crate::sshbuffer::{IncomingSshPacket, PacketWriter, SSHBuffer};
    use crate::{CryptoVec, cipher, mac};

    struct TestHandler;

    impl Handler for TestHandler {
        type Error = crate::Error;

        async fn check_server_key(
            &mut self,
            _: &PublicKeyOrCertificate,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    fn keyboard_interactive_session() -> (
        Session,
        tokio::sync::mpsc::Sender<Msg>,
        tokio::sync::mpsc::UnboundedReceiver<Reply>,
    ) {
        let config = Arc::new(Config::default());
        let (sender, receiver) = channel(config.channel_buffer_size);
        let (reply_sender, reply_receiver) = unbounded_channel();
        let auth_request = AuthRequest::new(&Method::KeyboardInteractive {
            submethods: String::new(),
        });
        let session = Session::new(
            config.window_size,
            CommonSession {
                auth_user: "user".to_owned(),
                auth_attempts: 0,
                auth_method: Some(Method::KeyboardInteractive {
                    submethods: String::new(),
                }),
                remote_to_local: Box::new(cipher::clear::Key),
                encrypted: Some(Encrypted {
                    state: EncryptedState::WaitingAuthRequest(auth_request),
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
                }),
                config,
                wants_reply: false,
                disconnected: false,
                buffer: Vec::new(),
                strict_kex: false,
                alive_timeouts: 0,
                received_data: false,
                remote_sshid: b"SSH-2.0-test".to_vec(),
                packet_writer: PacketWriter::clear(),
            },
            receiver,
            reply_sender,
        );
        (session, sender, reply_receiver)
    }

    const HOSTKEYS_SESSION_ID: &[u8] = b"hostkeys-session-id";

    /// An authenticated session with one outstanding `hostkeys-prove-00` request.
    fn hostkeys_prove_session() -> (
        Session,
        tokio::sync::mpsc::Sender<Msg>,
        oneshot::Receiver<Result<(), crate::Error>>,
        PrivateKey,
    ) {
        let (mut session, sender, _replies) = keyboard_interactive_session();
        let enc = session.common.encrypted.as_mut().unwrap();
        enc.state = EncryptedState::Authenticated;
        enc.session_id = CryptoVec::from(HOSTKEYS_SESSION_ID);
        let host_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let (reply_channel, reply) = oneshot::channel();
        session
            .request_hostkeys_prove(reply_channel, vec![host_key.public_key().clone()])
            .unwrap();
        (session, sender, reply, host_key)
    }

    /// `SSH_MSG_REQUEST_SUCCESS` carrying one signature over the given session id.
    fn hostkeys_proof_packet(host_key: &PrivateKey, session_id: &[u8]) -> Vec<u8> {
        let mut signed = Vec::new();
        "hostkeys-prove-00@openssh.com".encode(&mut signed).unwrap();
        session_id.encode(&mut signed).unwrap();
        host_key
            .public_key()
            .to_bytes()
            .unwrap()
            .encode(&mut signed)
            .unwrap();
        let signature: ssh_key::Signature = signature::Signer::try_sign(host_key, &signed).unwrap();

        let mut packet = vec![crate::msg::REQUEST_SUCCESS];
        signature.encoded().unwrap().encode(&mut packet).unwrap();
        packet
    }

    #[test]
    fn hostkeys_prove_request_encodes_every_key_blob() {
        let (session, _sender, _reply, host_key) = hostkeys_prove_session();

        let written = session.common.encrypted.as_ref().unwrap().write.to_vec();
        let packet_len = u32::from_be_bytes(written[..4].try_into().unwrap()) as usize;
        let mut payload = &written[4..4 + packet_len];

        assert_eq!(
            u8::decode(&mut payload).unwrap(),
            crate::msg::GLOBAL_REQUEST
        );
        assert_eq!(
            String::decode(&mut payload).unwrap(),
            "hostkeys-prove-00@openssh.com"
        );
        assert_eq!(
            u8::decode(&mut payload).unwrap(),
            1,
            "want_reply must be set"
        );
        assert_eq!(
            Vec::<u8>::decode(&mut payload).unwrap(),
            host_key.public_key().to_bytes().unwrap()
        );
        assert!(payload.is_empty());

        assert!(matches!(
            session.open_global_requests.front(),
            Some(GlobalRequestResponse::HostKeysProve { .. })
        ));
    }

    #[test]
    fn hostkeys_prove_empty_key_list_resolves_without_a_request() {
        let (mut session, _sender, _replies) = keyboard_interactive_session();
        let (reply_channel, mut reply) = oneshot::channel();
        session
            .request_hostkeys_prove(reply_channel, vec![])
            .unwrap();

        assert!(matches!(reply.try_recv(), Ok(Ok(()))));
        assert!(session.common.encrypted.as_ref().unwrap().write.is_empty());
        assert!(session.open_global_requests.is_empty());
    }

    #[tokio::test]
    async fn third_ext_info_is_rejected() {
        let (mut session, _sender, _reply) = keyboard_interactive_session();
        let mut packet = vec![msg::EXT_INFO];
        1u32.encode(&mut packet).unwrap();
        "x".encode(&mut packet).unwrap();
        b"".as_slice().encode(&mut packet).unwrap();

        for _ in 0..2 {
            session
                .process_packet(&mut TestHandler, &packet)
                .await
                .unwrap();
        }
        assert!(session
            .process_packet(&mut TestHandler, &packet)
            .await
            .is_err());
        assert_eq!(
            session.common.encrypted.as_ref().unwrap().received_extensions.len(),
            2
        );
    }

    #[tokio::test]
    async fn hostkeys_prove_reply_verifies_signature() {
        let (mut session, _sender, mut reply, host_key) = hostkeys_prove_session();
        let packet = hostkeys_proof_packet(&host_key, HOSTKEYS_SESSION_ID);
        session
            .process_packet(&mut TestHandler, &packet)
            .await
            .unwrap();

        assert!(matches!(reply.try_recv(), Ok(Ok(()))));
        assert!(session.open_global_requests.is_empty());
    }

    #[tokio::test]
    async fn hostkeys_prove_reply_rejects_signature_over_other_session() {
        let (mut session, _sender, mut reply, host_key) = hostkeys_prove_session();
        let packet = hostkeys_proof_packet(&host_key, b"some-other-session");
        session
            .process_packet(&mut TestHandler, &packet)
            .await
            .unwrap();

        assert!(matches!(
            reply.try_recv(),
            Ok(Err(crate::Error::WrongServerSig))
        ));
    }

    #[tokio::test]
    async fn hostkeys_prove_reply_rejects_missing_signature() {
        let (mut session, _sender, mut reply, _host_key) = hostkeys_prove_session();
        session
            .process_packet(&mut TestHandler, &[crate::msg::REQUEST_SUCCESS])
            .await
            .unwrap();

        assert!(matches!(reply.try_recv(), Ok(Err(_))));
    }

    #[tokio::test]
    async fn hostkeys_prove_failure_reply_is_denied() {
        let (mut session, _sender, mut reply, _host_key) = hostkeys_prove_session();
        session
            .process_packet(&mut TestHandler, &[crate::msg::REQUEST_FAILURE])
            .await
            .unwrap();

        assert!(matches!(
            reply.try_recv(),
            Ok(Err(crate::Error::RequestDenied))
        ));
    }

    /// `keyboard_interactive_session` negotiates the `none` kex, which cannot
    /// be repeated; swap in one that can and install `limits`.
    fn allow_rekey(session: &mut Session, limits: crate::Limits) {
        Arc::get_mut(&mut session.common.config).unwrap().limits = limits;
        session.common.encrypted.as_mut().unwrap().kex =
            KEXES.get(&crate::kex::CURVE25519).unwrap().make();
    }

    #[test]
    fn limit_triggered_rekey_waits_for_authentication() {
        let (mut session, _sender, _replies) = keyboard_interactive_session();
        allow_rekey(&mut session, crate::Limits::new(0, 0, Duration::from_secs(3600)));

        session.flush().unwrap();
        assert!(!session.kex.active(), "write limit hit before authentication");
        assert_eq!(session.rekey_time_remaining(), None);

        session.common.encrypted.as_mut().unwrap().state = EncryptedState::Authenticated;
        assert_eq!(session.rekey_time_remaining(), Some(Duration::ZERO));
        session.flush().unwrap();
        assert!(session.kex.active());
    }

    #[test]
    fn explicit_rekey_is_not_gated_on_authentication() {
        // `keyboard_interactive_session` is still waiting for authentication.
        let (mut session, _sender, _replies) = keyboard_interactive_session();
        allow_rekey(&mut session, crate::Limits::default());

        session.initiate_rekey().unwrap();
        assert!(session.kex.active());
    }

    /// Drives the client event loop on one end of an in-memory stream and
    /// returns the type of the first packet it writes.
    async fn first_packet_from_event_loop(
        mut session: Session,
        peer: &mut tokio::io::DuplexStream,
        stream: tokio::io::DuplexStream,
    ) -> Option<u8> {
        let (stream_read, mut stream_write) = SshRead::new(stream).split();
        let mut handler = TestHandler;
        let mut kex_done_signal = None;
        let event_loop = session.run_inner(
            stream_read,
            &mut stream_write,
            &mut handler,
            &mut kex_done_signal,
        );
        tokio::pin!(event_loop);
        let mut buffer = SSHBuffer::new();
        let mut opening_key = cipher::clear::Key;
        let packet = cipher::read(peer, &mut buffer, &mut opening_key);
        tokio::select! {
            r = &mut event_loop => panic!("event loop ended before rekeying: {:?}", r.map(drop)),
            r = tokio::time::timeout(Duration::from_secs(5), packet) => {
                r.ok()?.unwrap();
                buffer.buffer.get(5).copied()
            }
        }
    }

    #[tokio::test]
    async fn read_limit_starts_rekey_from_the_event_loop() {
        let (mut session, _sender, _replies) = keyboard_interactive_session();
        allow_rekey(
            &mut session,
            crate::Limits::new(1 << 30, 16, Duration::from_secs(3600)),
        );
        session.common.encrypted.as_mut().unwrap().state = EncryptedState::Authenticated;
        let (mut peer, stream) = tokio::io::duplex(64 * 1024);
        let mut ignore = PacketWriter::clear();
        ignore.packet_raw(&[msg::IGNORE; 32]).unwrap();
        peer.write_all(&ignore.buffer().buffer).await.unwrap();

        assert_eq!(
            first_packet_from_event_loop(session, &mut peer, stream).await,
            Some(msg::KEXINIT)
        );
    }

    #[tokio::test]
    async fn time_limit_starts_rekey_from_the_event_loop() {
        let (mut session, _sender, _replies) = keyboard_interactive_session();
        allow_rekey(
            &mut session,
            crate::Limits::new(1 << 30, 1 << 30, Duration::from_millis(50)),
        );
        session.common.encrypted.as_mut().unwrap().state = EncryptedState::Authenticated;
        let (mut peer, stream) = tokio::io::duplex(64 * 1024);

        assert_eq!(
            first_packet_from_event_loop(session, &mut peer, stream).await,
            Some(msg::KEXINIT)
        );
    }

    #[cfg(feature = "flate2")]
    fn authenticated_session() -> Session {
        let config = Arc::new(Config::default());
        let (receiver_sender, receiver) = channel(config.channel_buffer_size);
        let (reply_sender, _) = unbounded_channel();
        let mut session = Session::new(
            config.window_size,
            CommonSession {
                auth_user: String::new(),
                auth_attempts: 0,
                auth_method: None,
                remote_to_local: Box::new(cipher::clear::Key),
                encrypted: Some(Encrypted {
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
                    decompress: Decompress::Zlib(flate2::Decompress::new(true)),
                    rekey_wanted: false,
                    received_extensions: Vec::new(),
                    extension_info_awaiters: HashMap::new(),
                }),
                config,
                wants_reply: false,
                disconnected: false,
                buffer: Vec::new(),
                strict_kex: false,
                alive_timeouts: 0,
                received_data: false,
                remote_sshid: b"SSH-2.0-test".to_vec(),
                packet_writer: PacketWriter::clear(),
            },
            receiver,
            reply_sender,
        );
        session.open_global_requests = VecDeque::new();
        let _ = receiver_sender;
        session
    }

    fn oversized_prompt_count_packet() -> Vec<u8> {
        let mut packet = Vec::new();
        msg::USERAUTH_INFO_REQUEST_OR_USERAUTH_PK_OK
            .encode(&mut packet)
            .unwrap();
        "name".encode(&mut packet).unwrap();
        "instructions".encode(&mut packet).unwrap();
        "".encode(&mut packet).unwrap();
        u32::MAX.encode(&mut packet).unwrap();
        packet
    }

    #[tokio::test]
    async fn oversized_keyboard_interactive_prompt_count_is_rejected() {
        let (mut session, _sender, mut replies) = keyboard_interactive_session();
        let mut handler = TestHandler;
        let err = session
            .process_packet(&mut handler, &oversized_prompt_count_packet())
            .await
            .expect_err("malformed prompt count must fail");

        assert!(matches!(err, crate::Error::Inconsistent));
        assert!(
            replies.try_recv().is_err(),
            "malformed packet must not emit a reply"
        );
    }

    #[cfg(feature = "flate2")]
    fn compressed_debug_payload(payload_len: usize) -> Vec<u8> {
        let mut payload = vec![b'A'; payload_len];
        payload[0] = crate::msg::DEBUG;

        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(&payload).unwrap();
        let compressed = encoder.finish().unwrap();
        assert!(compressed.len() < 256 * 1024);
        compressed
    }

    #[cfg(feature = "flate2")]
    fn incoming_packet(compressed: Vec<u8>) -> SSHBuffer {
        let mut buffer = SSHBuffer::new();
        buffer.buffer.extend_from_slice(&[0; 5]);
        buffer.buffer.extend_from_slice(&compressed);
        buffer
    }

    #[cfg(feature = "flate2")]
    #[tokio::test]
    async fn compressed_debug_is_ignored_after_client_parses_it() {
        let mut session = authenticated_session();
        let mut handler = TestHandler;
        let mut kex_done_signal = None;
        let buffer = incoming_packet(compressed_debug_payload(200 * 1024));
        let mut pkt: IncomingSshPacket = session.maybe_decompress(&buffer).unwrap();

        super::reply(&mut session, &mut handler, &mut kex_done_signal, &mut pkt)
            .await
            .unwrap();

        assert!(!session.common.disconnected);
    }

    #[cfg(feature = "flate2")]
    #[test]
    fn oversized_compressed_debug_is_rejected_before_client_ignores_it() {
        let mut session = authenticated_session();
        let oversized = crate::cipher::MAXIMUM_DECOMPRESSED_PACKET_LEN + 1024;
        let buffer = incoming_packet(compressed_debug_payload(oversized));

        let err = session.maybe_decompress(&buffer).unwrap_err();
        assert!(
            matches!(err, crate::Error::PacketSize(len) if len > crate::cipher::MAXIMUM_DECOMPRESSED_PACKET_LEN)
        );
    }
}

fn initial_encrypted_state(session: &Session) -> EncryptedState {
    if session.common.config.anonymous {
        EncryptedState::Authenticated
    } else {
        EncryptedState::WaitingAuthServiceRequest {
            accepted: false,
            sent: false,
        }
    }
}

/// Parameters for dynamic group Diffie-Hellman key exchanges.
#[derive(Debug, Clone)]
pub struct GexParams {
    /// Minimum DH group size (in bits)
    min_group_size: usize,
    /// Preferred DH group size (in bits)
    preferred_group_size: usize,
    /// Maximum DH group size (in bits)
    max_group_size: usize,
}

impl GexParams {
    pub fn new(
        min_group_size: usize,
        preferred_group_size: usize,
        max_group_size: usize,
    ) -> Result<Self, Error> {
        Self::for_client_config(min_group_size, preferred_group_size, max_group_size)
    }

    pub fn for_client_config(
        min_group_size: usize,
        preferred_group_size: usize,
        max_group_size: usize,
    ) -> Result<Self, Error> {
        Self::build(
            min_group_size,
            preferred_group_size,
            max_group_size,
            ValidationKind::ClientConfig,
        )
    }

    fn validate(&self, kind: ValidationKind) -> Result<(), Error> {
        match kind {
            ValidationKind::ClientConfig => {
                if self.min_group_size < 2048 {
                    return Err(Error::InvalidConfig(format!(
                        "min_group_size must be at least 2048 bits. We got {} bits",
                        self.min_group_size
                    )));
                }
            }
            ValidationKind::PeerRequest => {
                if self.max_group_size < 2048 {
                    return Err(Error::InvalidConfig(format!(
                        "max_group_size must be at least 2048 bits. We got {} bits",
                        self.max_group_size
                    )));
                }
            }
        }

        if self.preferred_group_size < self.min_group_size {
            return Err(Error::InvalidConfig(format!(
                "preferred_group_size must be at least as large as min_group_size. We have preferred_group_size = {} < min_group_size = {}",
                self.preferred_group_size, self.min_group_size
            )));
        }
        if self.max_group_size < self.preferred_group_size {
            return Err(Error::InvalidConfig(format!(
                "max_group_size must be at least as large as preferred_group_size. We have max_group_size = {} < preferred_group_size = {}",
                self.max_group_size, self.preferred_group_size
            )));
        }

        Ok(())
    }

    pub(crate) fn from_peer_request(
        min_group_size: usize,
        preferred_group_size: usize,
        max_group_size: usize,
    ) -> Result<Self, Error> {
        Self::build(
            min_group_size,
            preferred_group_size,
            max_group_size,
            ValidationKind::PeerRequest,
        )
    }

    fn build(
        min_group_size: usize,
        preferred_group_size: usize,
        max_group_size: usize,
        kind: ValidationKind,
    ) -> Result<Self, Error> {
        let this = Self {
            min_group_size,
            preferred_group_size,
            max_group_size,
        };
        this.validate(kind)?;
        Ok(this)
    }

    pub fn min_group_size(&self) -> usize {
        self.min_group_size
    }

    pub fn preferred_group_size(&self) -> usize {
        self.preferred_group_size
    }

    pub fn max_group_size(&self) -> usize {
        self.max_group_size
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ValidationKind {
    ClientConfig,
    PeerRequest,
}

impl Default for GexParams {
    fn default() -> GexParams {
        GexParams {
            min_group_size: 3072,
            preferred_group_size: 8192,
            max_group_size: 8192,
        }
    }
}

/// The configuration of clients.
#[derive(Debug)]
pub struct Config {
    /// The client ID string sent at the beginning of the protocol.
    pub client_id: SshId,
    /// The bytes and time limits before key re-exchange.
    pub limits: Limits,
    /// The initial size of a channel (used for flow control).
    pub window_size: u32,
    /// The maximal size of a single packet.
    pub maximum_packet_size: u32,
    /// Buffer size for each channel (a number of unprocessed messages to store before propagating backpressure to the TCP stream)
    pub channel_buffer_size: usize,
    /// Lists of preferred algorithms.
    pub preferred: negotiation::Preferred,
    /// Time after which the connection is garbage-collected.
    pub inactivity_timeout: Option<std::time::Duration>,
    /// If nothing is received from the server for this amount of time, send a keepalive message.
    pub keepalive_interval: Option<std::time::Duration>,
    /// If this many keepalives have been sent without reply, close the connection.
    pub keepalive_max: usize,
    /// Whether to expect and wait for an authentication call.
    pub anonymous: bool,
    /// DH dynamic group exchange parameters.
    pub gex: GexParams,
    /// If active, invoke `set_nodelay(true)` on the ssh socket; disabled by default (i.e. Nagle's algorithm is active).
    pub nodelay: bool,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            client_id: SshId::Standard(Cow::Borrowed(concat!(
                "SSH-2.0-",
                env!("CARGO_PKG_NAME"),
                "_",
                env!("CARGO_PKG_VERSION")
            ))),
            limits: Limits::default(),
            window_size: 2097152,
            maximum_packet_size: 32768,
            channel_buffer_size: 100,
            preferred: Default::default(),
            inactivity_timeout: None,
            keepalive_interval: None,
            keepalive_max: 3,
            anonymous: false,
            gex: Default::default(),
            nodelay: false,
        }
    }
}

/// A client handler. Note that messages can be received from the
/// server at any time during a session.
///
/// You must at the very least implement the `check_server_key` fn.
/// The default implementation rejects all keys.
///
/// Note: this is an async trait. The trait functions return `impl Future`,
/// and you can simply define them as `async fn` instead.
pub trait Handler: Sized + Send {
    type Error: From<crate::Error> + Send + core::fmt::Debug;

    /// Called when the server sends us an authentication banner. This
    /// is usually meant to be shown to the user, see
    /// [RFC4252](https://tools.ietf.org/html/rfc4252#section-5.4) for
    /// more details.
    #[allow(unused_variables)]
    fn auth_banner(
        &mut self,
        banner: &str,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called to check the server's public key or certificate.
    /// This is a very important step to help prevent man-in-the-middle attacks.
    /// The default implementation rejects all keys, and you must override it.
    ///
    /// The library verifies the key exchange signature before this call,
    /// but it's up to the implementation to decide whether the key or certificate
    /// is trusted.
    #[allow(unused_variables)]
    fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send {
        async { Ok(false) }
    }

    /// Called when key exchange has completed.
    ///
    /// For the initial key exchange this runs only after
    /// [`check_server_key`](Self::check_server_key) has accepted the server,
    /// so the shared secret never reaches the application for a server that
    /// is about to be rejected.
    ///
    /// This callback provides access to the raw shared secret from the KEX,
    /// which is useful for protocols that derive additional keys from the
    /// SSH shared secret (e.g., for secondary encrypted channels).
    ///
    /// The `names` parameter contains all negotiated algorithms (kex, cipher, mac, etc.).
    ///
    /// **Security Warning:** The shared secret is sensitive cryptographic material.
    /// Handle it with care and zero it after use if stored.
    ///
    /// # Arguments
    ///
    /// * `kex_algorithm` - Name of the key exchange algorithm used
    /// * `shared_secret` - The raw shared secret bytes from the key exchange.
    ///   For some algorithms (like `none`), this may be `None`.
    /// * `names` - The negotiated algorithm names
    /// * `session` - The current session
    #[allow(unused_variables)]
    fn kex_done(
        &mut self,
        shared_secret: Option<&[u8]>,
        names: &negotiation::Names,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called when the server confirmed our request to open a
    /// channel. A channel can only be written to after receiving this
    /// message (this library panics otherwise).
    #[allow(unused_variables)]
    fn channel_open_confirmation(
        &mut self,
        id: ChannelId,
        max_packet_size: u32,
        window_size: u32,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called when the server signals success.
    #[allow(unused_variables)]
    fn channel_success(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called when the server signals failure.
    #[allow(unused_variables)]
    fn channel_failure(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called when the server closes a channel.
    #[allow(unused_variables)]
    fn channel_close(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called when the server sends EOF to a channel.
    #[allow(unused_variables)]
    fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called when the server rejected our request to open a channel.
    #[allow(unused_variables)]
    fn channel_open_failure(
        &mut self,
        channel: ChannelId,
        reason: ChannelOpenFailure,
        description: &str,
        language: &str,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called when the server opens a channel for a new remote port forwarding connection.
    ///
    /// Call [`reply.accept().await`](ChannelOpenHandle::accept) to confirm, or
    /// [`reply.reject(reason).await`](ChannelOpenHandle::reject) to decline.
    /// Dropping `reply` automatically rejects.
    #[allow(unused_variables)]
    #[allow(clippy::too_many_arguments)]
    fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async move {
            reply.accept().await;
            Ok(())
        }
    }

    /// Called when the server opens a channel for a new remote UDS forwarding connection.
    ///
    /// Call [`reply.accept().await`](ChannelOpenHandle::accept) to confirm, or
    /// [`reply.reject(reason).await`](ChannelOpenHandle::reject) to decline.
    /// Dropping `reply` automatically rejects.
    #[allow(unused_variables)]
    fn server_channel_open_forwarded_streamlocal(
        &mut self,
        channel: Channel<Msg>,
        socket_path: &str,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async move {
            reply.accept().await;
            Ok(())
        }
    }

    /// Called when the server opens an agent forwarding channel.
    ///
    /// Call [`reply.accept().await`](ChannelOpenHandle::accept) to confirm, or
    /// [`reply.reject(reason).await`](ChannelOpenHandle::reject) to decline.
    /// Dropping `reply` automatically rejects.
    #[allow(unused_variables)]
    fn server_channel_open_agent_forward(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async move {
            reply.accept().await;
            Ok(())
        }
    }

    /// Called when the server attempts to open a channel of unknown type. It may return `true`,
    /// if the channel of unknown type should be accepted. In this case,
    /// [Handler::server_channel_open_unknown] will be called soon after. If it returns `false`,
    /// the channel will not be created and a rejection message will be sent to the server.
    #[allow(unused_variables)]
    fn should_accept_unknown_server_channel(
        &mut self,
        id: ChannelId,
        channel_type: &str,
    ) -> impl Future<Output = bool> + Send {
        async { false }
    }

    /// Called when the server opens an unknown channel (after
    /// [`should_accept_unknown_server_channel`](Handler::should_accept_unknown_server_channel)
    /// returned `true`).
    ///
    /// Call [`reply.accept().await`](ChannelOpenHandle::accept) to confirm, or
    /// [`reply.reject(reason).await`](ChannelOpenHandle::reject) to decline.
    /// Dropping `reply` automatically rejects.
    #[allow(unused_variables)]
    fn server_channel_open_unknown(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called when the server opens a session channel.
    ///
    /// Call [`reply.accept().await`](ChannelOpenHandle::accept) to confirm, or
    /// [`reply.reject(reason).await`](ChannelOpenHandle::reject) to decline.
    /// Dropping `reply` automatically rejects.
    #[allow(unused_variables)]
    fn server_channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async move {
            reply.accept().await;
            Ok(())
        }
    }

    /// Called when the server opens a direct tcp/ip channel (non-standard).
    ///
    /// Call [`reply.accept().await`](ChannelOpenHandle::accept) to confirm, or
    /// [`reply.reject(reason).await`](ChannelOpenHandle::reject) to decline.
    /// Dropping `reply` automatically rejects.
    #[allow(unused_variables)]
    #[allow(clippy::too_many_arguments)]
    fn server_channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async move {
            reply.accept().await;
            Ok(())
        }
    }

    /// Called when the server opens a direct-streamlocal channel (non-standard).
    ///
    /// Call [`reply.accept().await`](ChannelOpenHandle::accept) to confirm, or
    /// [`reply.reject(reason).await`](ChannelOpenHandle::reject) to decline.
    /// Dropping `reply` automatically rejects.
    #[allow(unused_variables)]
    fn server_channel_open_direct_streamlocal(
        &mut self,
        channel: Channel<Msg>,
        socket_path: &str,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async move {
            reply.accept().await;
            Ok(())
        }
    }

    /// Called when the server opens an X11 channel.
    ///
    /// Call [`reply.accept().await`](ChannelOpenHandle::accept) to confirm, or
    /// [`reply.reject(reason).await`](ChannelOpenHandle::reject) to decline.
    /// Dropping `reply` automatically rejects.
    #[allow(unused_variables)]
    fn server_channel_open_x11(
        &mut self,
        channel: Channel<Msg>,
        originator_address: &str,
        originator_port: u32,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async move {
            reply.accept().await;
            Ok(())
        }
    }

    /// Called when the server sends us data. The `extended_code`
    /// parameter is a stream identifier, `None` is usually the
    /// standard output, and `Some(1)` is the standard error. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-5.2).
    #[allow(unused_variables)]
    fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called when the server sends us data. The `extended_code`
    /// parameter is a stream identifier, `None` is usually the
    /// standard output, and `Some(1)` is the standard error. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-5.2).
    #[allow(unused_variables)]
    fn extended_data(
        &mut self,
        channel: ChannelId,
        ext: u32,
        data: &[u8],
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// The server informs this client of whether the client may
    /// perform control-S/control-Q flow control. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-6.8).
    #[allow(unused_variables)]
    fn xon_xoff(
        &mut self,
        channel: ChannelId,
        client_can_do: bool,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// The remote process has exited, with the given exit status.
    #[allow(unused_variables)]
    fn exit_status(
        &mut self,
        channel: ChannelId,
        exit_status: u32,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// The remote process exited upon receiving a signal.
    #[allow(unused_variables)]
    fn exit_signal(
        &mut self,
        channel: ChannelId,
        signal_name: Sig,
        core_dumped: bool,
        error_message: &str,
        lang_tag: &str,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called when the network window is adjusted, meaning that we
    /// can send more bytes. This is useful if this client wants to
    /// send huge amounts of data, for instance if we have called
    /// `Session::data` before, and it returned less than the
    /// full amount of data.
    #[allow(unused_variables)]
    fn window_adjusted(
        &mut self,
        channel: ChannelId,
        new_size: u32,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called when this client adjusts the network window. Return the
    /// next target window and maximum packet size.
    #[allow(unused_variables)]
    fn adjust_window(&mut self, channel: ChannelId, window: u32) -> u32 {
        window
    }

    /// Called when the server announces its host keys
    /// (`hostkeys-00@openssh.com`, sent by OpenSSH after authentication).
    ///
    /// Announced keys must not be trusted until the server proves it holds
    /// them: hand them to [`Handle::hostkeys_prove`] from another task, or
    /// call [`Session::request_hostkeys_prove`] here and forward the receiver.
    /// Do not await the proof inside this callback.
    #[allow(unused_variables)]
    fn openssh_ext_host_keys_announced(
        &mut self,
        keys: Vec<PublicKey>,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async move {
            debug!("openssh_ext_hostkeys_announced: {keys:?}");
            Ok(())
        }
    }

    /// Called when the server sent a disconnect message
    ///
    /// If reason is an Error, this function should re-return the error so the join can also evaluate it
    #[allow(unused_variables)]
    fn disconnected(
        &mut self,
        reason: DisconnectReason<Self::Error>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async {
            debug!("disconnected: {reason:?}");
            match reason {
                DisconnectReason::ReceivedDisconnect(_) => Ok(()),
                DisconnectReason::Error(e) => Err(e),
            }
        }
    }
}
