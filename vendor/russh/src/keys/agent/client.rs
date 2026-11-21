use core::str;

use byteorder::{BigEndian, ByteOrder};
use bytes::Bytes;
use log::{debug, error};
use ssh_encoding::{Decode, Encode, Reader};
use ssh_key::{Algorithm, Certificate, HashAlg, PrivateKey, PublicKey, Signature};
use tokio;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{AgentIdentity, AgentSessionBinding, Constraint, msg};
use crate::CryptoVec;
use crate::helpers::EncodedExt;
use crate::keys::{Error, key};

pub trait AgentStream: AsyncRead + AsyncWrite {}

impl<S: AsyncRead + AsyncWrite> AgentStream for S {}

const MAX_AGENT_FRAME_LEN: usize = 256 * 1024;

/// SSH agent client.
pub struct AgentClient<S: AgentStream> {
    stream: S,
    buf: Vec<u8>,
}

impl<S: AgentStream + Send + Unpin> AgentClient<S> {
    /// Wraps the internal stream in a Box<dyn _>, allowing different client
    /// implementations to have the same type
    pub fn dynamic<'a>(self) -> AgentClient<Box<dyn AgentStream + Send + Unpin + 'a>>
    where
        S: 'a,
    {
        AgentClient {
            stream: Box::new(self.stream),
            buf: self.buf,
        }
    }

    pub fn into_inner<'a>(self) -> Box<dyn AgentStream + Send + Unpin + 'a>
    where
        S: 'a,
    {
        Box::new(self.stream)
    }
}

// https://tools.ietf.org/html/draft-miller-ssh-agent-00#section-4.1
impl<S: AgentStream + Unpin> AgentClient<S> {
    /// Build a future that connects to an SSH agent via the provided
    /// stream (on Unix, usually a Unix-domain socket).
    pub fn connect(stream: S) -> Self {
        AgentClient {
            stream,
            buf: Vec::new(),
        }
    }
}

#[cfg(unix)]
impl AgentClient<tokio::net::UnixStream> {
    /// Connect to an SSH agent via the provided
    /// stream (on Unix, usually a Unix-domain socket).
    pub async fn connect_uds<P: AsRef<std::path::Path>>(path: P) -> Result<Self, Error> {
        let stream = tokio::net::UnixStream::connect(path).await?;
        Ok(AgentClient {
            stream,
            buf: Vec::new(),
        })
    }

    /// Connect to an SSH agent specified by the SSH_AUTH_SOCK
    /// environment variable.
    pub async fn connect_env() -> Result<Self, Error> {
        let var = if let Ok(var) = std::env::var("SSH_AUTH_SOCK") {
            var
        } else {
            return Err(Error::EnvVar("SSH_AUTH_SOCK"));
        };
        match Self::connect_uds(var).await {
            Err(Error::IO(io_err)) if io_err.kind() == std::io::ErrorKind::NotFound => {
                Err(Error::BadAuthSock)
            }
            owise => owise,
        }
    }
}

#[cfg(windows)]
const ERROR_PIPE_BUSY: u32 = 231u32;

#[cfg(windows)]
impl AgentClient<pageant::PageantStream> {
    /// Connect to a running Pageant instance
    pub async fn connect_pageant() -> Result<Self, Error> {
        Ok(Self::connect(pageant::PageantStream::new().await?))
    }
}

#[cfg(windows)]
impl AgentClient<tokio::net::windows::named_pipe::NamedPipeClient> {
    /// Connect to an SSH agent via a Windows named pipe
    pub async fn connect_named_pipe<P: AsRef<std::ffi::OsStr>>(path: P) -> Result<Self, Error> {
        let stream = loop {
            match tokio::net::windows::named_pipe::ClientOptions::new().open(path.as_ref()) {
                Ok(client) => break client,
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => (),
                Err(e) => return Err(e.into()),
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        };

        Ok(AgentClient {
            stream,
            buf: Vec::new(),
        })
    }
}

impl<S: AgentStream + Unpin> AgentClient<S> {
    async fn read_frame(&mut self) -> Result<(), Error> {
        self.buf.clear();
        self.buf.resize(4, 0);
        self.stream.read_exact(&mut self.buf).await?;

        let len = BigEndian::read_u32(&self.buf) as usize;
        if len > MAX_AGENT_FRAME_LEN {
            return Err(Error::AgentProtocolError);
        }

        self.buf.clear();
        self.buf.resize(len, 0);
        self.stream.read_exact(&mut self.buf).await?;
        Ok(())
    }

    async fn read_response(&mut self) -> Result<(), Error> {
        // Writing the message
        self.stream.write_all(&self.buf).await?;
        self.stream.flush().await?;
        self.read_frame().await
    }

    async fn read_success(&mut self) -> Result<(), Error> {
        self.read_response().await?;
        if self.buf.first() == Some(&msg::SUCCESS) {
            Ok(())
        } else {
            Err(Error::AgentFailure)
        }
    }

    /// Bind this agent connection to an authenticated SSH server session.
    ///
    /// OpenSSH agents require `session-bind@openssh.com` before they expose or
    /// use destination-constrained identities. Call this before requesting
    /// identities. Set `forwarding` to `false` for direct client
    /// authentication and to `true` before relaying a forwarded agent socket.
    pub async fn bind_session(
        &mut self,
        binding: &AgentSessionBinding,
        forwarding: bool,
    ) -> Result<(), Error> {
        self.buf.clear();
        self.buf.resize(4, 0);
        msg::EXTENSION.encode(&mut self.buf)?;
        "session-bind@openssh.com".encode(&mut self.buf)?;
        binding.host_key.as_slice().encode(&mut self.buf)?;
        binding.session_id.encode(&mut self.buf)?;
        binding.signature.as_slice().encode(&mut self.buf)?;
        u8::from(forwarding).encode(&mut self.buf)?;
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf, len as u32);
        self.read_success().await
    }

    /// Send a key to the agent, with a (possibly empty) slice of
    /// constraints to apply when using the key to sign.
    pub async fn add_identity(
        &mut self,
        key: &PrivateKey,
        constraints: &[Constraint],
    ) -> Result<(), Error> {
        // See IETF draft-miller-ssh-agent-13, section 3.2 for format.
        // https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent
        self.buf.clear();
        self.buf.resize(4, 0);
        if constraints.is_empty() {
            self.buf.push(msg::ADD_IDENTITY)
        } else {
            self.buf.push(msg::ADD_ID_CONSTRAINED)
        }

        key.key_data().encode(&mut self.buf)?;
        "".encode(&mut self.buf)?; // comment field

        if !constraints.is_empty() {
            for cons in constraints {
                match *cons {
                    Constraint::KeyLifetime { seconds } => {
                        msg::CONSTRAIN_LIFETIME.encode(&mut self.buf)?;
                        seconds.encode(&mut self.buf)?;
                    }
                    Constraint::Confirm => self.buf.push(msg::CONSTRAIN_CONFIRM),
                    Constraint::Extensions {
                        ref name,
                        ref details,
                    } => {
                        msg::CONSTRAIN_EXTENSION.encode(&mut self.buf)?;
                        name.encode(&mut self.buf)?;
                        details.encode(&mut self.buf)?;
                    }
                }
            }
        }
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[..], len as u32);

        self.read_success().await
    }

    /// Add a smart card to the agent, with a (possibly empty) set of
    /// constraints to apply when signing.
    pub async fn add_smartcard_key(
        &mut self,
        id: &str,
        pin: &[u8],
        constraints: &[Constraint],
    ) -> Result<(), Error> {
        self.buf.clear();
        self.buf.resize(4, 0);
        if constraints.is_empty() {
            self.buf.push(msg::ADD_SMARTCARD_KEY)
        } else {
            self.buf.push(msg::ADD_SMARTCARD_KEY_CONSTRAINED)
        }
        id.encode(&mut self.buf)?;
        pin.encode(&mut self.buf)?;
        if !constraints.is_empty() {
            (constraints.len() as u32).encode(&mut self.buf)?;
            for cons in constraints {
                match *cons {
                    Constraint::KeyLifetime { seconds } => {
                        msg::CONSTRAIN_LIFETIME.encode(&mut self.buf)?;
                        seconds.encode(&mut self.buf)?;
                    }
                    Constraint::Confirm => self.buf.push(msg::CONSTRAIN_CONFIRM),
                    Constraint::Extensions {
                        ref name,
                        ref details,
                    } => {
                        msg::CONSTRAIN_EXTENSION.encode(&mut self.buf)?;
                        name.encode(&mut self.buf)?;
                        details.encode(&mut self.buf)?;
                    }
                }
            }
        }
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[..], len as u32);
        self.read_success().await
    }

    /// Lock the agent, making it refuse to sign until unlocked.
    pub async fn lock(&mut self, passphrase: &[u8]) -> Result<(), Error> {
        self.buf.clear();
        self.buf.resize(4, 0);
        self.buf.push(msg::LOCK);
        passphrase.encode(&mut self.buf)?;
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[..], len as u32);
        self.read_success().await
    }

    /// Unlock the agent, allowing it to sign again.
    pub async fn unlock(&mut self, passphrase: &[u8]) -> Result<(), Error> {
        self.buf.clear();
        self.buf.resize(4, 0);
        msg::UNLOCK.encode(&mut self.buf)?;
        passphrase.encode(&mut self.buf)?;
        let len = self.buf.len() - 4;
        #[allow(clippy::indexing_slicing)] // static length
        BigEndian::write_u32(&mut self.buf[..], len as u32);
        self.read_success().await
    }

    /// Ask the agent for a list of identities, including certificates.
    pub async fn request_identities(&mut self) -> Result<Vec<AgentIdentity>, Error> {
        self.buf.clear();
        self.buf.resize(4, 0);
        msg::REQUEST_IDENTITIES.encode(&mut self.buf)?;
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[..], len as u32);

        self.read_response().await?;
        debug!("identities: {:?}", &self.buf[..]);
        let mut identities = Vec::new();

        #[allow(clippy::indexing_slicing)] // static length
        if let Some((&msg::IDENTITIES_ANSWER, mut r)) = self.buf.split_first() {
            let n = u32::decode(&mut r)?;
            for _ in 0..n {
                let key_blob = Bytes::decode(&mut r)?;
                let comment = String::decode(&mut r)?;

                // Check if blob starts with a certificate algorithm by reading the algorithm string.
                // Certificate algorithms end with "-cert-v01@openssh.com".
                // This avoids parsing the blob twice for regular keys.
                key::check_cert_nesting(&key_blob)?;
                let identity = if Self::is_certificate_blob(&key_blob) {
                    match Certificate::decode(&mut key_blob.as_ref()) {
                        Ok(cert) => AgentIdentity::Certificate {
                            certificate: cert,
                            comment,
                        },
                        Err(_) => {
                            // Fallback to public key if certificate parsing fails
                            let key = key::parse_public_key(&key_blob)?;
                            AgentIdentity::PublicKey { key, comment }
                        }
                    }
                } else {
                    let key = key::parse_public_key(&key_blob)?;
                    AgentIdentity::PublicKey { key, comment }
                };
                identities.push(identity);
            }
        }

        Ok(identities)
    }

    /// Check if a key blob appears to be a certificate by examining the algorithm prefix.
    /// Certificate algorithms end with "-cert-v01@openssh.com".
    fn is_certificate_blob(blob: &[u8]) -> bool {
        // The blob starts with a length-prefixed string containing the algorithm name.
        // Read the length (4 bytes, big-endian) and then the algorithm string.
        let Some(len_bytes) = blob.get(..4) else {
            return false;
        };
        let alg_len = BigEndian::read_u32(len_bytes) as usize;
        let Some(alg_bytes) = blob.get(4..4 + alg_len) else {
            return false;
        };
        if let Ok(alg_str) = str::from_utf8(alg_bytes) {
            alg_str.ends_with("-cert-v01@openssh.com")
        } else {
            false
        }
    }

    /// Ask the agent to sign the supplied piece of data.
    pub async fn sign_request(
        &mut self,
        identity: &AgentIdentity,
        hash_alg: Option<HashAlg>,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, Error> {
        match identity {
            AgentIdentity::PublicKey { key, .. } => self.sign_request_pk(key, hash_alg, data).await,
            AgentIdentity::Certificate { certificate, .. } => {
                self.sign_request_cert(certificate, hash_alg, data).await
            }
        }
    }

    async fn sign_request_pk(
        &mut self,
        public: &PublicKey,
        hash_alg: Option<HashAlg>,
        mut data: Vec<u8>,
    ) -> Result<Vec<u8>, Error> {
        debug!("sign_request: {data:?}");
        let hash = self.prepare_sign_request(public, hash_alg, &data)?;

        self.read_response().await?;

        match self.buf.split_first() {
            Some((&msg::SIGN_RESPONSE, mut r)) => {
                self.write_signature(&mut r, hash, &mut data)?;
                Ok(data)
            }
            Some((&msg::FAILURE, _)) => Err(Error::AgentFailure),
            _ => {
                debug!("self.buf = {:?}", &self.buf[..]);
                Err(Error::AgentProtocolError)
            }
        }
    }

    /// Ask the agent to sign data using a certificate identity.
    ///
    /// This sends the certificate blob to the agent (not just the public key),
    /// allowing the agent to match it to the correct private key.
    ///
    /// For RSA certificates, you can specify the hash algorithm to use.
    async fn sign_request_cert(
        &mut self,
        cert: &Certificate,
        hash_alg: Option<HashAlg>,
        mut data: Vec<u8>,
    ) -> Result<Vec<u8>, Error> {
        debug!("sign_request_cert: {data:?}");

        self.buf.clear();
        self.buf.resize(4, 0);
        msg::SIGN_REQUEST.encode(&mut self.buf)?;
        cert.to_bytes()?.encode(&mut self.buf)?;
        data.encode(&mut self.buf)?;

        // Calculate hash flag for RSA certificates (same logic as prepare_sign_request)
        let hash = match cert.algorithm() {
            Algorithm::Rsa { .. } => match hash_alg {
                Some(HashAlg::Sha256) => 2,
                Some(HashAlg::Sha512) => 4,
                _ => 0,
            },
            _ => 0,
        };

        hash.encode(&mut self.buf)?;

        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[..], len as u32);

        self.read_response().await?;

        match self.buf.split_first() {
            Some((&msg::SIGN_RESPONSE, mut r)) => {
                self.write_signature(&mut r, hash, &mut data)?;
                Ok(data)
            }
            Some((&msg::FAILURE, _)) => Err(Error::AgentFailure),
            _ => {
                debug!("self.buf = {:?}", &self.buf[..]);
                Err(Error::AgentProtocolError)
            }
        }
    }

    fn prepare_sign_request(
        &mut self,
        public: &ssh_key::PublicKey,
        hash_alg: Option<HashAlg>,
        data: &[u8],
    ) -> Result<u32, Error> {
        self.buf.clear();
        self.buf.resize(4, 0);
        msg::SIGN_REQUEST.encode(&mut self.buf)?;
        public.key_data().encoded()?.encode(&mut self.buf)?;
        data.encode(&mut self.buf)?;
        debug!("public = {public:?}");

        let hash = match public.algorithm() {
            Algorithm::Rsa { .. } => match hash_alg {
                Some(HashAlg::Sha256) => 2,
                Some(HashAlg::Sha512) => 4,
                _ => 0,
            },
            _ => 0,
        };

        hash.encode(&mut self.buf)?;
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[..], len as u32);
        Ok(hash)
    }

    fn write_signature<R: Reader>(
        &self,
        r: &mut R,
        hash: u32,
        data: &mut Vec<u8>,
    ) -> Result<(), Error> {
        let mut resp = &Bytes::decode(r)?[..];
        let t = String::decode(&mut resp)?;
        if (hash == 2 && t == "rsa-sha2-256") || (hash == 4 && t == "rsa-sha2-512") || hash == 0 {
            let sig = Bytes::decode(&mut resp)?;
            let is_sk_signature = t.starts_with("sk-");
            (t.len() + sig.len() + 8 + if is_sk_signature { 5 } else { 0 }).encode(data)?;
            t.encode(data)?;
            sig.encode(data)?;
            if is_sk_signature {
                let flags = u8::decode(&mut resp)?;
                let counter = u32::decode(&mut resp)?;
                flags.encode(data)?;
                counter.encode(data)?;
            }
            Ok(())
        } else {
            error!("unexpected agent signature type: {t:?}");
            Err(Error::AgentProtocolError)
        }
    }

    /// Ask the agent to sign the supplied piece of data.
    pub fn sign_request_base64(
        mut self,
        public: &ssh_key::PublicKey,
        hash_alg: Option<HashAlg>,
        data: &[u8],
    ) -> impl futures::Future<Output = (Self, Result<String, Error>)> {
        debug!("sign_request: {data:?}");
        let r = self.prepare_sign_request(public, hash_alg, data);
        async move {
            if let Err(e) = r {
                return (self, Err(e));
            }

            let resp = self.read_response().await;
            if let Err(e) = resp {
                return (self, Err(e));
            }

            #[allow(clippy::indexing_slicing)] // length is checked
            if !self.buf.is_empty() && self.buf[0] == msg::SIGN_RESPONSE {
                let base64 = data_encoding::BASE64_NOPAD.encode(&self.buf[1..]);
                (self, Ok(base64))
            } else {
                (self, Ok(String::new()))
            }
        }
    }

    /// Ask the agent to sign the supplied piece of data, and return a `Signature`.
    pub async fn sign_request_signature(
        &mut self,
        public: &ssh_key::PublicKey,
        hash_alg: Option<HashAlg>,
        data: &[u8],
    ) -> Result<Signature, Error> {
        debug!("sign_request: {data:?}");

        self.prepare_sign_request(public, hash_alg, data)?;
        self.read_response().await?;

        match self.buf.split_first() {
            Some((&msg::SIGN_RESPONSE, mut r)) => {
                let mut resp = &Bytes::decode(&mut r)?[..];
                let sig = Signature::decode(&mut resp)?;
                Ok(sig)
            }
            _ => Err(Error::AgentProtocolError),
        }
    }

    /// Ask the agent to remove a key from its memory.
    pub async fn remove_identity(&mut self, public: &ssh_key::PublicKey) -> Result<(), Error> {
        self.buf.clear();
        self.buf.resize(4, 0);
        self.buf.push(msg::REMOVE_IDENTITY);
        public.key_data().encoded()?.encode(&mut self.buf)?;
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[..], len as u32);
        self.read_success().await
    }

    /// Ask the agent to remove a smartcard from its memory.
    pub async fn remove_smartcard_key(&mut self, id: &str, pin: &[u8]) -> Result<(), Error> {
        self.buf.clear();
        self.buf.resize(4, 0);
        msg::REMOVE_SMARTCARD_KEY.encode(&mut self.buf)?;
        id.encode(&mut self.buf)?;
        pin.encode(&mut self.buf)?;
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[..], len as u32);
        self.read_success().await
    }

    /// Ask the agent to forget all known keys.
    pub async fn remove_all_identities(&mut self) -> Result<(), Error> {
        self.buf.clear();
        self.buf.resize(4, 0);
        msg::REMOVE_ALL_IDENTITIES.encode(&mut self.buf)?;
        1u32.encode(&mut self.buf)?;
        self.read_success().await
    }

    /// Send a custom message to the agent.
    pub async fn extension(&mut self, typ: &[u8], ext: &[u8]) -> Result<(), Error> {
        self.buf.clear();
        self.buf.resize(4, 0);
        msg::EXTENSION.encode(&mut self.buf)?;
        typ.encode(&mut self.buf)?;
        ext.encode(&mut self.buf)?;
        let len = self.buf.len() - 4;
        (len as u32).encode(&mut self.buf)?;
        self.read_response().await?;
        // draft-miller-ssh-agent 4.7: a supported extension may reply with
        // SUCCESS or EXTENSION_RESPONSE; anything else is a failure.
        match self.buf.first() {
            Some(&msg::SUCCESS) | Some(&msg::EXTENSION_RESPONSE) => Ok(()),
            _ => Err(Error::AgentFailure),
        }
    }

    /// Ask the agent what extensions about supported extensions.
    pub async fn query_extension(&mut self, typ: &[u8], mut ext: CryptoVec) -> Result<bool, Error> {
        self.buf.clear();
        self.buf.resize(4, 0);
        msg::EXTENSION.encode(&mut self.buf)?;
        typ.encode(&mut self.buf)?;
        let len = self.buf.len() - 4;
        (len as u32).encode(&mut self.buf)?;
        self.read_response().await?;

        match self.buf.split_first() {
            Some((&msg::SUCCESS, mut r)) => {
                ext.extend(&Bytes::decode(&mut r)?);
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use byteorder::{BigEndian, ByteOrder};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::{msg, AgentClient, MAX_AGENT_FRAME_LEN};
    use crate::keys::Error;

    /// Runs `op` against an agent that answers every request with `reply`.
    fn with_reply<F, T>(reply: &'static [u8], op: F) -> Result<T, Error>
    where
        F: for<'a> FnOnce(
            &'a mut AgentClient<tokio::io::DuplexStream>,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<T, Error>> + 'a>,
        >,
    {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (mut writer, reader) = tokio::io::duplex(64);
            tokio::spawn(async move {
                let mut frame = [0u8; 4];
                writer.read_exact(&mut frame).await?;
                let mut body = vec![0; BigEndian::read_u32(&frame) as usize];
                writer.read_exact(&mut body).await?;
                BigEndian::write_u32(&mut frame, reply.len() as u32);
                writer.write_all(&frame).await?;
                writer.write_all(reply).await?;
                Ok::<(), std::io::Error>(())
            });
            let mut client = AgentClient::connect(reader);
            op(&mut client).await
        })
    }

    #[test]
    fn failure_reply_is_an_error() {
        let err = with_reply(&[msg::FAILURE], |c| Box::pin(c.lock(b"pw"))).unwrap_err();
        assert!(matches!(err, Error::AgentFailure));
        let err = with_reply(&[msg::FAILURE], |c| Box::pin(c.extension(b"x", b""))).unwrap_err();
        assert!(matches!(err, Error::AgentFailure));
    }

    #[test]
    fn extension_accepts_success_and_extension_response() {
        with_reply(&[msg::SUCCESS], |c| Box::pin(c.extension(b"x", b""))).unwrap();
        with_reply(&[msg::EXTENSION_RESPONSE, 1, 2, 3], |c| {
            Box::pin(c.extension(b"x", b""))
        })
        .unwrap();
    }

    #[test]
    fn oversized_agent_response_is_rejected_before_allocation() -> std::io::Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        runtime.block_on(async {
            let (mut writer, reader) = tokio::io::duplex(64);
            let server = tokio::spawn(async move {
                let mut frame = [0u8; 4];
                writer.read_exact(&mut frame).await?;
                let len = BigEndian::read_u32(&frame) as usize;
                let mut body = vec![0; len];
                writer.read_exact(&mut body).await?;

                BigEndian::write_u32(&mut frame, (MAX_AGENT_FRAME_LEN + 1) as u32);
                writer.write_all(&frame).await?;
                Ok::<(), std::io::Error>(())
            });

            let mut client = AgentClient::connect(reader);
            let err = client.request_identities().await.unwrap_err();
            assert!(matches!(err, Error::AgentProtocolError));
            server.await.expect("server task")?;
            Ok::<(), std::io::Error>(())
        })?;

        Ok(())
    }
}
