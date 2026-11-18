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

use std::future::Future;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;

use ssh_key::{Certificate, HashAlg, PrivateKey};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::Zeroize;

use crate::helpers::NameList;
use crate::keys::PrivateKeyWithHashAlg;
use crate::keys::agent::AgentIdentity;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodKind {
    None,
    Password,
    PublicKey,
    HostBased,
    KeyboardInteractive,
    GssapiWithMic,
}

impl From<&MethodKind> for &'static str {
    fn from(value: &MethodKind) -> Self {
        match value {
            MethodKind::None => "none",
            MethodKind::Password => "password",
            MethodKind::PublicKey => "publickey",
            MethodKind::HostBased => "hostbased",
            MethodKind::KeyboardInteractive => "keyboard-interactive",
            MethodKind::GssapiWithMic => "gssapi-with-mic",
        }
    }
}

impl FromStr for MethodKind {
    fn from_str(b: &str) -> Result<MethodKind, Self::Err> {
        match b {
            "none" => Ok(MethodKind::None),
            "password" => Ok(MethodKind::Password),
            "publickey" => Ok(MethodKind::PublicKey),
            "hostbased" => Ok(MethodKind::HostBased),
            "keyboard-interactive" => Ok(MethodKind::KeyboardInteractive),
            "gssapi-with-mic" => Ok(MethodKind::GssapiWithMic),
            _ => Err(()),
        }
    }

    type Err = ();
}

impl From<&MethodKind> for String {
    fn from(value: &MethodKind) -> Self {
        <&str>::from(value).to_string()
    }
}

/// An ordered set of authentication methods.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodSet(Vec<MethodKind>);

impl Deref for MethodSet {
    type Target = [MethodKind];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<&[MethodKind]> for MethodSet {
    fn from(value: &[MethodKind]) -> Self {
        let mut this = Self::empty();
        for method in value {
            this.push(*method);
        }
        this
    }
}

impl From<&MethodSet> for NameList {
    fn from(value: &MethodSet) -> Self {
        Self(value.iter().map(|x| x.into()).collect())
    }
}

impl From<&NameList> for MethodSet {
    fn from(value: &NameList) -> Self {
        Self(
            value
                .iter()
                .filter_map(|x| MethodKind::from_str(x).ok())
                .collect(),
        )
    }
}

impl MethodSet {
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    pub fn client_supported() -> Self {
        Self(vec![
            MethodKind::None,
            MethodKind::Password,
            MethodKind::PublicKey,
            MethodKind::HostBased,
            MethodKind::KeyboardInteractive,
            MethodKind::GssapiWithMic,
        ])
    }

    pub fn server_supported() -> Self {
        Self(vec![
            MethodKind::None,
            MethodKind::Password,
            MethodKind::PublicKey,
            MethodKind::HostBased,
            MethodKind::KeyboardInteractive,
        ])
    }

    pub fn remove(&mut self, method: MethodKind) {
        self.0.retain(|x| *x != method);
    }

    /// Push a method to the end of the list.
    /// If the method is already in the list, it is moved to the end.
    pub fn push(&mut self, method: MethodKind) {
        self.remove(method);
        self.0.push(method);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthResult {
    Success,
    Failure {
        /// The server suggests to proceed with these auth methods
        remaining_methods: MethodSet,
        /// The server says that though auth method has been accepted,
        /// further authentication is required
        partial_success: bool,
    },
}

impl AuthResult {
    pub fn success(&self) -> bool {
        matches!(self, AuthResult::Success)
    }
}

pub trait Signer: Sized {
    type Error: From<crate::SendError>;

    fn auth_sign(
        &mut self,
        key: &AgentIdentity,
        hash_alg: Option<HashAlg>,
        to_sign: Vec<u8>,
    ) -> impl Future<Output = Result<Vec<u8>, Self::Error>> + Send;
}

/// One step of a GSSAPI security context exchange, as produced by a
/// [`GssapiAuthenticator`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GssapiStep {
    /// The context is not established yet; send `token` to the server and
    /// wait for its next token.
    Continue {
        token: Vec<u8>,
    },
    /// The context is established. `token` is the final output token, if any.
    /// `mic` is the MIC computed over the `mic_data` passed to
    /// [`GssapiAuthenticator::gssapi_step`]. Implementations MUST produce a
    /// MIC whenever the established context supports integrity protection
    /// (RFC 4462, Section 3.5); `None` falls back to
    /// `SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE`.
    Complete {
        token: Option<Vec<u8>>,
        mic: Option<Vec<u8>>,
    },
}

/// A GSS-API error reported by the server during `gssapi-with-mic`
/// authentication. Informational: the server follows up with an
/// authentication failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GssapiError {
    /// `SSH_MSG_USERAUTH_GSSAPI_ERROR` (RFC 4462, Section 3.8).
    Status {
        major_status: u32,
        minor_status: u32,
        message: String,
    },
    /// `SSH_MSG_USERAUTH_GSSAPI_ERRTOK` (RFC 4462, Section 3.10). May be
    /// passed to `GSS_Init_sec_context()` to obtain mechanism-specific
    /// error details.
    ErrorToken(Vec<u8>),
}

pub trait GssapiAuthenticator: Sized {
    type Error: From<crate::SendError>;

    /// Advance the GSSAPI security context.
    ///
    /// `selected_mechanism` is `Some` on the first step and carries the
    /// DER-encoded OID of the mechanism the server selected; implementations
    /// must verify it is one of the mechanisms they offered (RFC 4462,
    /// Section 3.3). It is `None` on subsequent steps.
    ///
    /// `input_token` is the token received from the server, if any.
    /// `mic_data` is the data to compute the final MIC over once the context
    /// is established.
    fn gssapi_step(
        &mut self,
        selected_mechanism: Option<Vec<u8>>,
        input_token: Option<Vec<u8>>,
        mic_data: Vec<u8>,
    ) -> impl Future<Output = Result<GssapiStep, Self::Error>> + Send;

    /// Called when the server reports a GSS-API error; the server follows up
    /// with an authentication failure. The default implementation ignores
    /// the error.
    fn gssapi_error(&mut self, _error: GssapiError) -> impl Future<Output = ()> + Send {
        async {}
    }
}

#[derive(Debug, Error)]
pub enum AgentAuthError {
    #[error(transparent)]
    Send(#[from] crate::SendError),
    #[error(transparent)]
    Key(#[from] crate::keys::Error),
}

impl<R: AsyncRead + AsyncWrite + Unpin + Send> Signer
    for crate::keys::agent::client::AgentClient<R>
{
    type Error = AgentAuthError;

    #[allow(clippy::manual_async_fn)]
    fn auth_sign(
        &mut self,
        key: &AgentIdentity,
        hash_alg: Option<HashAlg>,
        to_sign: Vec<u8>,
    ) -> impl Future<Output = Result<Vec<u8>, Self::Error>> {
        async move {
            self.sign_request(key, hash_alg, to_sign)
                .await
                .map_err(Into::into)
        }
    }
}

#[allow(clippy::large_enum_variant)]
pub enum Method {
    None,
    Password {
        password: String,
    },
    PublicKey {
        key: PrivateKeyWithHashAlg,
    },
    OpenSshCertificate {
        key: Arc<PrivateKey>,
        cert: Certificate,
    },
    FuturePublicKey {
        key: ssh_key::PublicKey,
        hash_alg: Option<HashAlg>,
    },
    /// Certificate-based authentication using an external signer (e.g., SSH agent).
    /// The certificate is sent to the server, but signing is delegated to the signer.
    FutureCertificate {
        cert: Certificate,
        hash_alg: Option<HashAlg>,
    },
    KeyboardInteractive {
        submethods: String,
    },
    GssapiWithMic {
        mechanism_oids: Vec<Vec<u8>>,
    },
    // Hostbased,
}

impl Drop for Method {
    fn drop(&mut self) {
        if let Method::Password { password } = self {
            password.zeroize();
        }
    }
}

impl std::fmt::Debug for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Method::None => f.write_str("None"),
            Method::Password { .. } => f
                .debug_struct("Password")
                .field("password", &"<redacted>")
                .finish(),
            Method::PublicKey { key } => f.debug_struct("PublicKey").field("key", key).finish(),
            Method::OpenSshCertificate { key, cert } => f
                .debug_struct("OpenSshCertificate")
                .field("key", key)
                .field("cert", cert)
                .finish(),
            Method::FuturePublicKey { key, hash_alg } => f
                .debug_struct("FuturePublicKey")
                .field("key", key)
                .field("hash_alg", hash_alg)
                .finish(),
            Method::FutureCertificate { cert, hash_alg } => f
                .debug_struct("FutureCertificate")
                .field("cert", cert)
                .field("hash_alg", hash_alg)
                .finish(),
            Method::KeyboardInteractive { submethods } => f
                .debug_struct("KeyboardInteractive")
                .field("submethods", submethods)
                .finish(),
            Method::GssapiWithMic { mechanism_oids } => f
                .debug_struct("GssapiWithMic")
                .field("mechanism_oids", mechanism_oids)
                .finish(),
        }
    }
}

#[doc(hidden)]
#[derive(Debug)]
pub struct AuthRequest {
    initial_methods: MethodSet,
    pub methods: MethodSet,
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub partial_success: bool,
    pub current: Option<CurrentRequest>,
    pub(crate) principal: Option<AuthPrincipal>,
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub rejection_count: usize,
}

#[doc(hidden)]
#[derive(Debug)]
pub(crate) struct AuthPrincipal {
    user: String,
    service: String,
}

#[doc(hidden)]
#[derive(Debug)]
pub enum CurrentRequest {
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    PublicKey {
        #[allow(dead_code)]
        key: Vec<u8>,
        #[allow(dead_code)]
        algo: Vec<u8>,
        sent_pk_ok: bool,
    },
    KeyboardInteractive {
        #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
        submethods: String,
    },
    GssapiWithMic,
}

impl AuthRequest {
    pub(crate) fn server(methods: MethodSet) -> Self {
        Self {
            initial_methods: methods.clone(),
            methods,
            partial_success: false,
            current: None,
            principal: None,
            rejection_count: 0,
        }
    }

    pub(crate) fn new(method: &Method) -> Self {
        let current = match method {
            Method::KeyboardInteractive { submethods } => {
                Some(CurrentRequest::KeyboardInteractive {
                    submethods: submethods.to_string(),
                })
            }
            Method::GssapiWithMic { .. } => Some(CurrentRequest::GssapiWithMic),
            _ => None,
        };
        Self {
            initial_methods: MethodSet::client_supported(),
            methods: MethodSet::client_supported(),
            partial_success: false,
            current,
            principal: None,
            rejection_count: 0,
        }
    }

    pub(crate) fn bind_or_reset_principal(&mut self, user: &str, service: &str) -> bool {
        match &self.principal {
            Some(bound) if bound.user == user && bound.service == service => false,
            _ => {
                self.principal = Some(AuthPrincipal {
                    user: user.to_owned(),
                    service: service.to_owned(),
                });
                self.methods = self.initial_methods.clone();
                self.partial_success = false;
                self.current = None;
                true
            }
        }
    }
}
