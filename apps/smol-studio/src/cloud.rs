//! Account-scoped cloud access. Credentials never cross the worker/UI boundary.
use reqwest::{Method, blocking::Client};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use smol_cloud::{
    Credentials,
    credentials::{CLIENT_ID, DEFAULT_BASE_URL, DEFAULT_ISSUER},
    types::{CreateMachine, Machine},
};
use std::{
    io::Read,
    sync::mpsc,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const BODY_LIMIT: u64 = 4 * 1024 * 1024;
const SCOPE: &str = "openid profile email offline_access machine:read machine:create machine:exec machine:delete machine:files usage:read billing:read app:write volume:read volume:create volume:delete ops:read";
type Result<T> = std::result::Result<T, String>;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    pub subject: String,
    pub tenant_id: Option<String>,
    pub tenant_name: Option<String>,
    pub tenant_status: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    pub registry_namespace: Option<String>,
}
impl Identity {
    pub fn allows(&self, scope: &str) -> bool {
        self.tenant_status.as_deref() == Some("active")
            && self.scopes.iter().any(|s| s == scope || s == "*")
    }
    pub fn label(&self) -> &str {
        self.tenant_name.as_deref().unwrap_or("Personal account")
    }
}
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Membership {
    pub tenant_id: String,
    pub name: String,
    pub display_name: Option<String>,
    pub role: String,
    pub status: String,
}
impl Membership {
    pub fn label(&self) -> &str {
        self.display_name.as_deref().unwrap_or(&self.name)
    }
}
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub identity: Option<Identity>,
    pub memberships: Vec<Membership>,
    pub machines: Vec<Machine>,
    pub account: Option<Value>,
    pub warnings: Vec<String>,
}
#[derive(Clone)]
pub enum Action {
    Restore,
    UseCli,
    Login,
    CancelLogin,
    Logout,
    Refresh {
        tenant: Option<String>,
    },
    Machine {
        tenant: Option<String>,
        id: String,
        action: MachineAction,
    },
    Create {
        tenant: Option<String>,
        request: Box<CreateMachine>,
    },
}
#[derive(Clone, Debug)]
pub enum MachineAction {
    Start,
    Stop,
    Resume,
    Delete,
    Logs,
    Exec(String),
}
impl Action {
    pub fn mutates(&self) -> bool {
        matches!(
            self,
            Self::Create { .. }
                | Self::Machine {
                    action: MachineAction::Start
                        | MachineAction::Stop
                        | MachineAction::Resume
                        | MachineAction::Delete
                        | MachineAction::Exec(_),
                    ..
                }
        )
    }
}
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum OutputKind {
    Logs,
}

pub enum Event {
    SignedOut,
    Device {
        code: String,
        url: String,
        expires: Instant,
    },
    Snapshot {
        tenant: Option<String>,
        snapshot: Box<Snapshot>,
    },
    Created {
        tenant: Option<String>,
        id: String,
    },
    Output {
        kind: OutputKind,
        tenant: Option<String>,
        id: String,
        text: String,
    },
    CommandFinished {
        tenant: Option<String>,
        id: String,
        result: Result<smol_cloud::types::CommandOutput>,
    },
    LogError {
        tenant: Option<String>,
        id: String,
        error: String,
    },
    Completed,
    Error(String),
}

/// Cloud console snapshots use SSE frames containing tracing records, as in the CLI.
/// Preserve unrecognized payloads instead of hiding diagnostics.
fn console_logs(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    if !text.lines().any(|line| line.starts_with("data:")) {
        return text.into_owned();
    }
    let mut output = String::new();
    let mut data = Vec::new();
    let flush = |data: &mut Vec<&str>, output: &mut String| {
        if data.is_empty() {
            return;
        }
        let payload = data.join("\n");
        data.clear();
        if let Ok(value) = serde_json::from_str::<Value>(&payload)
            && let Some(message) = value["message"]
                .as_str()
                .or_else(|| value["fields"]["message"].as_str())
        {
            if let Some(timestamp) = value["timestamp"].as_str() {
                output.push_str(timestamp);
                output.push(' ');
            }
            if let Some(level) = value["level"].as_str() {
                output.push('[');
                output.push_str(level);
                output.push_str("] ");
            }
            output.push_str(message);
        } else {
            output.push_str(&payload);
        }
        output.push('\n');
    };
    for line in text.lines() {
        if line.is_empty() {
            flush(&mut data, &mut output);
        } else if let Some(value) = line.strip_prefix("data:") {
            data.push(value.strip_prefix(' ').unwrap_or(value));
        }
    }
    flush(&mut data, &mut output);
    output
}

/// Only the OAuth session is stored here; CLI sessions remain owned by the CLI,
/// whose shared credentials implementation serializes refresh-token rotation.
#[derive(Serialize, Deserialize)]
struct Session {
    access_token: String,
    refresh_token: Option<String>,
    expires_at: u64,
}
trait SessionStore: Send {
    fn load(&self) -> Result<Option<Session>>;
    fn save(&self, session: &Session) -> Result<()>;
    fn clear(&self) -> Result<()>;
}
struct Keychain;
fn entry() -> Result<keyring::Entry> {
    keyring::Entry::new("com.smolmachines.studio", "cloud-session")
        .map_err(|_| "Cannot open the system credential store.".into())
}
impl SessionStore for Keychain {
    fn load(&self) -> Result<Option<Session>> {
        match entry()?.get_password() {
            Ok(s) => serde_json::from_str(&s)
                .map(Some)
                .map_err(|_| "Saved sign-in is invalid. Sign in again.".into()),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(_) => {
                Err("System credential store unavailable or locked. Start or unlock your desktop keyring, then retry.".into())
            }
        }
    }
    fn save(&self, session: &Session) -> Result<()> {
        let text =
            serde_json::to_string(session).map_err(|_| "Cannot encode sign-in.".to_string())?;
        entry()?.set_password(&text).map_err(|_| {
            "Cannot save sign-in. Unlock your system credential store and try again.".into()
        })
    }
    fn clear(&self) -> Result<()> {
        match entry()?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err("Cannot remove saved sign-in. Unlock your system credential store and sign out again.".into()),
        }
    }
}
#[derive(Deserialize)]
struct DeviceResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: Option<String>,
    expires_in: u64,
    interval: Option<u64>,
}
struct PendingLogin {
    device: DeviceResponse,
    expires: Instant,
    next: Instant,
    interval: Duration,
}
#[derive(Deserialize)]
struct Tokens {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: u64,
}
impl Tokens {
    fn session(self, old_refresh: Option<String>) -> Result<Session> {
        if self.access_token.is_empty() || self.expires_in == 0 {
            return Err("Identity provider returned an invalid sign-in.".into());
        }
        Ok(Session {
            access_token: self.access_token,
            refresh_token: self.refresh_token.or(old_refresh),
            expires_at: now().saturating_add(self.expires_in),
        })
    }
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn http_client() -> Result<Client> {
    Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("smol-studio/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|_| "Cannot initialize cloud networking.".into())
}
fn network_error(_: reqwest::Error) -> String {
    "Cloud connection failed or timed out. Check your connection and refresh; an operation may already have completed.".into()
}
fn body(mut response: reqwest::blocking::Response) -> Result<(u16, Vec<u8>)> {
    let status = response.status().as_u16();
    let mut bytes = Vec::new();
    Read::by_ref(&mut response)
        .take(BODY_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Cloud response interrupted.".to_string())?;
    if bytes.len() as u64 > BODY_LIMIT {
        return Err("Cloud response exceeded the 4 MiB limit.".into());
    }
    Ok((status, bytes))
}
fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes)
        .map_err(|_| "Cloud returned an unexpected response format.".into())
}
fn status_error(status: u16) -> String {
    match status {
        401 => "Your cloud sign-in expired. Sign in again.".into(),
        403 => "This account does not permit that action. Check account membership and permissions.".into(),
        404 => "That cloud resource is no longer available. Refresh the account.".into(),
        409 => "The machine changed state or conflicts with an existing resource. Refresh and try again.".into(),
        422 => "The cloud rejected these settings. Check the image, resources and account limits.".into(),
        429 => "Cloud rate limit reached. Wait before trying again.".into(),
        _ => format!("Cloud request failed (HTTP {status}). Refresh to check its current state."),
    }
}
/// Refuse redirects and insecure/custom endpoint credential forwarding.
fn validate_endpoint(endpoint: &str) -> Result<()> {
    let url = reqwest::Url::parse(endpoint).map_err(|_| "Invalid cloud endpoint.".to_string())?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(
            "Cloud endpoints must use HTTPS without embedded credentials, query or fragment."
                .into(),
        );
    }
    Ok(())
}
fn segment(id: &str) -> Result<&str> {
    if id.is_empty()
        || id.len() > 256
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        Err("Invalid cloud resource ID.".into())
    } else {
        Ok(id)
    }
}
struct Backend {
    http: Client,
    endpoint: String,
    issuer: String,
    store: Box<dyn SessionStore>,
    session: Option<Session>,
    cli: Option<Credentials>,
    login: Option<PendingLogin>,
    remember_preferences: bool,
}
impl Backend {
    fn new(store: Box<dyn SessionStore>) -> Result<Self> {
        Ok(Self {
            http: http_client()?,
            endpoint: DEFAULT_BASE_URL.into(),
            issuer: DEFAULT_ISSUER.into(),
            store,
            session: None,
            cli: None,
            login: None,
            remember_preferences: true,
        })
    }
    fn token(&mut self, rejected: bool) -> Result<String> {
        if let Some(cli) = &self.cli {
            if rejected {
                cli.renew_after_rejection(&cli.api_key())
                    .map_err(|_| "CLI sign-in could not be renewed. Sign in again.".to_string())?;
            } else {
                cli.renew_if_expiring()
                    .map_err(|_| "CLI sign-in could not be renewed. Sign in again.".to_string())?;
            }
            return Ok(cli.api_key());
        }
        let session = self
            .session
            .as_ref()
            .ok_or("Sign in to Smol Cloud first.")?;
        if rejected || session.expires_at <= now() + 60 {
            let refresh = session
                .refresh_token
                .clone()
                .ok_or("Your sign-in expired. Sign in again.")?;
            let (status, bytes) = body(
                self.http
                    .post(format!("{}/oauth/token", self.issuer))
                    .form(&[
                        ("grant_type", "refresh_token"),
                        ("client_id", CLIENT_ID),
                        ("refresh_token", &refresh),
                    ])
                    .send()
                    .map_err(network_error)?,
            )?;
            if status != 200 {
                return Err("Your sign-in could not be renewed. Sign in again.".into());
            }
            let session = decode::<Tokens>(&bytes)?.session(Some(refresh))?;
            // Keep the rotated token in memory even if the credential store becomes locked.
            self.session = Some(session);
            self.store.save(self.session.as_ref().unwrap())?;
        }
        Ok(self.session.as_ref().unwrap().access_token.clone())
    }
    fn request(
        &mut self,
        method: Method,
        path: &str,
        tenant: Option<&str>,
        value: Option<&Value>,
    ) -> Result<Vec<u8>> {
        self.request_with_status_error(method, path, tenant, value, status_error)
    }
    fn request_with_status_error(
        &mut self,
        method: Method,
        path: &str,
        tenant: Option<&str>,
        value: Option<&Value>,
        explain_status: fn(u16) -> String,
    ) -> Result<Vec<u8>> {
        if let Some(id) = tenant {
            segment(id)?;
        }
        for attempt in 0..2 {
            let token = self.token(attempt == 1)?;
            let mut req = self
                .http
                .request(method.clone(), format!("{}{path}", self.endpoint))
                .bearer_auth(token)
                .timeout(Duration::from_secs(if method == Method::GET {
                    20
                } else {
                    120
                }));
            if let Some(tenant) = tenant {
                req = req.header("Smol-Tenant", tenant);
            }
            if let Some(value) = value {
                req = req.json(value);
            }
            let (status, bytes) = body(req.send().map_err(network_error)?)?;
            if status == 401 && attempt == 0 {
                continue;
            }
            if !(200..300).contains(&status) {
                return Err(explain_status(status));
            }
            return Ok(bytes);
        }
        Err(explain_status(401))
    }
    fn snapshot(&mut self, tenant: Option<String>) -> Result<Event> {
        let identity: Identity =
            decode(&self.request(Method::GET, "/v1/me", tenant.as_deref(), None)?)?;
        if tenant.is_some() && identity.tenant_id != tenant {
            return Err(
                "Cloud returned a different account. No machine actions are available.".into(),
            );
        }
        let mut snapshot = Snapshot {
            identity: Some(identity.clone()),
            ..Default::default()
        };
        match self
            .request(Method::GET, "/v1/org/memberships", None, None)
            .and_then(|b| decode(&b))
        {
            Ok(m) => snapshot.memberships = m,
            Err(e) => snapshot.warnings.push(format!("Organizations: {e}")),
        }
        if identity.allows("machine:read") {
            snapshot.machines =
                decode(&self.request(Method::GET, "/v1/machines", tenant.as_deref(), None)?)?;
            snapshot
                .machines
                .sort_by(|a, b| a.display_name().cmp(b.display_name()));
        }
        if identity.allows("billing:read") {
            match self
                .request(Method::GET, "/v1/account", tenant.as_deref(), None)
                .and_then(|b| decode(&b))
            {
                Ok(a) => snapshot.account = Some(a),
                Err(e) => snapshot.warnings.push(format!("Account usage: {e}")),
            }
        }
        Ok(Event::Snapshot {
            tenant,
            snapshot: Box::new(snapshot),
        })
    }
    fn act(&mut self, action: Action) -> Result<Event> {
        match action {
            Action::Restore => {
                if crate::preferences::Preferences::load()?.use_cli_session {
                    return self.act(Action::UseCli);
                }
                self.session = self.store.load()?;
                if self.session.is_none() {
                    Ok(Event::SignedOut)
                } else {
                    self.snapshot(None)
                }
            }
            Action::UseCli => {
                // Resolve renewal at the CLI's own endpoint, never retarget a stored token.
                let cli = Credentials::resolve(None, None)
                    .map_err(|_| "No usable CLI sign-in. Use Sign in instead.".to_string())?;
                validate_endpoint(cli.base_url())?;
                self.endpoint = cli.base_url().into();
                self.cli = Some(cli);
                self.session = None;
                self.login = None;
                let snapshot = self.snapshot(None)?;
                if self.remember_preferences {
                    crate::preferences::Preferences::remember_cli(true)?;
                }
                Ok(snapshot)
            }
            Action::Login => {
                let (status, bytes) = body(
                    self.http
                        .post(format!("{}/oauth/device/code", self.issuer))
                        .form(&[
                            ("client_id", CLIENT_ID),
                            ("audience", DEFAULT_BASE_URL),
                            ("scope", SCOPE),
                        ])
                        .send()
                        .map_err(network_error)?,
                )?;
                if status != 200 {
                    return Err("Could not begin sign-in. Try again later.".into());
                }
                let device: DeviceResponse = decode(&bytes)?;
                let url = device
                    .verification_uri_complete
                    .clone()
                    .unwrap_or_else(|| device.verification_uri.clone());
                validate_endpoint(&device.verification_uri)?;
                // Device links can have a user_code query; only permit the configured issuer origin.
                let parsed =
                    reqwest::Url::parse(&url).map_err(|_| "Invalid sign-in link.".to_string())?;
                if parsed.origin() != reqwest::Url::parse(&self.issuer).unwrap().origin() {
                    return Err("Identity provider returned an unexpected sign-in link.".into());
                }
                let interval = Duration::from_secs(device.interval.unwrap_or(5).clamp(1, 60));
                let expires = Instant::now() + Duration::from_secs(device.expires_in.min(1800));
                let event = Event::Device {
                    code: device.user_code.clone(),
                    url,
                    expires,
                };
                self.login = Some(PendingLogin {
                    device,
                    expires,
                    next: Instant::now() + interval,
                    interval,
                });
                Ok(event)
            }
            Action::CancelLogin => {
                self.login = None;
                Ok(Event::Completed)
            }
            Action::Logout => {
                self.login = None;
                self.session = None;
                self.cli = None;
                self.store.clear()?;
                if self.remember_preferences {
                    crate::preferences::Preferences::remember_cli(false)?;
                }
                self.endpoint = DEFAULT_BASE_URL.into();
                Ok(Event::SignedOut)
            }
            Action::Refresh { tenant } => self.snapshot(tenant),
            Action::Create { tenant, request } => {
                let bytes = self.request(
                    Method::POST,
                    "/v1/machines",
                    tenant.as_deref(),
                    Some(
                        &serde_json::to_value(request)
                            .map_err(|_| "Invalid machine settings.".to_string())?,
                    ),
                )?;
                let machine: Machine = decode(&bytes)?;
                segment(&machine.id)?;
                Ok(Event::Created {
                    tenant,
                    id: machine.id,
                })
            }
            Action::Machine { tenant, id, action } => {
                let base = format!("/v1/machines/{}", segment(&id)?);
                let (method, suffix, value) = match &action {
                    MachineAction::Start => (Method::POST, "/start?waitReady=true", None),
                    MachineAction::Stop => (Method::POST, "/stop", None),
                    MachineAction::Resume => (Method::POST, "/resume", None),
                    MachineAction::Delete => (Method::DELETE, "", None),
                    MachineAction::Logs => (Method::GET, "/logs?tail=200&follow=false", None),
                    MachineAction::Exec(command) => (
                        Method::POST,
                        "/exec",
                        Some(json!({"command":["/bin/sh","-lc",command],"timeoutSeconds":60})),
                    ),
                };
                let response = self.request_with_status_error(
                    method,
                    &format!("{base}{suffix}"),
                    tenant.as_deref(),
                    value.as_ref(),
                    if matches!(action, MachineAction::Logs) {
                        |status| {
                            if status == 404 {
                                "Console logs are not available for this machine.".into()
                            } else {
                                status_error(status)
                            }
                        }
                    } else {
                        status_error
                    },
                );
                if matches!(action, MachineAction::Exec(_)) {
                    return Ok(Event::CommandFinished {
                        tenant,
                        id,
                        result: response.and_then(|bytes| decode(&bytes)),
                    });
                }
                let bytes = match response {
                    Ok(bytes) => bytes,
                    Err(error) if matches!(action, MachineAction::Logs) => {
                        return Ok(Event::LogError { tenant, id, error });
                    }
                    Err(error) => return Err(error),
                };
                match action {
                    MachineAction::Logs => Ok(Event::Output {
                        kind: OutputKind::Logs,
                        tenant,
                        id,
                        text: console_logs(&bytes),
                    }),
                    _ => Ok(Event::Completed),
                }
            }
        }
    }
    fn poll_login(&mut self) -> Result<Option<Event>> {
        let Some(pending) = self.login.as_ref() else {
            return Ok(None);
        };
        if Instant::now() >= pending.expires {
            self.login = None;
            return Err("Sign-in expired. Start sign-in again.".into());
        }
        let response = self
            .http
            .post(format!("{}/oauth/token", self.issuer))
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("client_id", CLIENT_ID),
                ("device_code", &pending.device.device_code),
            ])
            .send()
            .map_err(network_error)?;
        let (status, bytes) = body(response)?;
        if status == 200 {
            let session = decode::<Tokens>(&bytes)?.session(None)?;
            self.store.save(&session)?;
            if self.remember_preferences {
                crate::preferences::Preferences::remember_cli(false)?;
            }
            self.session = Some(session);
            self.cli = None;
            self.login = None;
            self.endpoint = DEFAULT_BASE_URL.into();
            return self.snapshot(None).map(Some);
        }
        let error: Value = decode(&bytes)?;
        match error["error"].as_str() {
            Some("authorization_pending" | "slow_down") => {
                let pending = self.login.as_mut().unwrap();
                if error["error"] == "slow_down" {
                    pending.interval += Duration::from_secs(5);
                }
                pending.next = Instant::now() + pending.interval;
                Ok(None)
            }
            _ => {
                self.login = None;
                Err("Sign-in was denied or expired. Start sign-in again.".into())
            }
        }
    }
}

pub struct CloudWorker {
    sender: mpsc::SyncSender<Action>,
    pub events: mpsc::Receiver<Event>,
}
impl CloudWorker {
    pub fn new(wake: impl Fn() + Send + 'static) -> Self {
        let (sender, requests) = mpsc::sync_channel(2);
        let (responses, events) = mpsc::channel();
        thread::spawn(move || {
            let mut backend = match Backend::new(Box::new(Keychain)) {
                Ok(b) => b,
                Err(e) => {
                    let _ = responses.send(Event::Error(e));
                    wake();
                    return;
                }
            };
            loop {
                let wait = backend
                    .login
                    .as_ref()
                    .map(|p| p.next.saturating_duration_since(Instant::now()))
                    .unwrap_or(Duration::from_secs(86_400));
                let result = match requests.recv_timeout(wait) {
                    Ok(action) => backend.act(action).map(Some),
                    Err(mpsc::RecvTimeoutError::Timeout) => backend.poll_login(),
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                };
                match result {
                    Ok(Some(event)) => {
                        if responses.send(event).is_err() {
                            break;
                        }
                        wake();
                    }
                    Ok(None) => {}
                    Err(e) => {
                        backend.login = None;
                        if responses.send(Event::Error(e)).is_err() {
                            break;
                        }
                        wake();
                    }
                }
            }
        });
        Self { sender, events }
    }
    pub fn submit(&self, action: Action) -> Result<()> {
        self.sender
            .try_send(action)
            .map_err(|_| "Cloud worker is busy or unavailable.".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Write,
        net::TcpListener,
        sync::{Arc, Mutex},
    };
    #[derive(Clone, Default)]
    struct MemoryStore(Arc<Mutex<Option<String>>>);
    impl SessionStore for MemoryStore {
        fn load(&self) -> Result<Option<Session>> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .as_ref()
                .map(|s| serde_json::from_str(s).unwrap()))
        }
        fn save(&self, s: &Session) -> Result<()> {
            *self.0.lock().unwrap() = Some(serde_json::to_string(s).unwrap());
            Ok(())
        }
        fn clear(&self) -> Result<()> {
            *self.0.lock().unwrap() = None;
            Ok(())
        }
    }
    fn server(
        replies: Vec<(u16, String)>,
    ) -> (String, mpsc::Receiver<String>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (tx, rx) = mpsc::channel();
        let join = thread::spawn(move || {
            for (status, body) in replies {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut bytes = vec![];
                let mut buf = [0; 4096];
                loop {
                    let n = socket.read(&mut buf).unwrap();
                    if n == 0 {
                        break;
                    }
                    bytes.extend_from_slice(&buf[..n]);
                    if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&bytes[..end]).to_lowercase();
                        let len = headers
                            .lines()
                            .find_map(|line| {
                                line.strip_prefix("content-length:")
                                    .and_then(|s| s.trim().parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        if bytes.len() >= end + 4 + len {
                            break;
                        }
                    }
                }
                let _ = tx.send(String::from_utf8(bytes).unwrap());
                write!(socket, "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
        });
        (endpoint, rx, join)
    }
    fn backend(endpoint: &str) -> Backend {
        let mut backend = Backend::new(Box::new(MemoryStore::default())).unwrap();
        backend.remember_preferences = false;
        backend.http = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        backend.endpoint = endpoint.into();
        backend.session = Some(Session {
            access_token: "test-access".into(),
            refresh_token: Some("test-refresh".into()),
            expires_at: now() + 3600,
        });
        backend
    }
    #[test]
    fn command_failures_are_scoped_and_retry_keeps_exit_status_separate() {
        let (url, requests, join) = server(vec![
            (503, "private server diagnostics".into()),
            (200, "malformed result".into()),
            (
                200,
                json!({"stdout":"hello\n", "stderr":"problem\n", "exitCode":7}).to_string(),
            ),
        ]);
        let mut backend = backend(&url);
        let action = Action::Machine {
            tenant: Some("t-team".into()),
            id: "m-owned".into(),
            action: MachineAction::Exec("printf hello; exit 7".into()),
        };
        for _ in 0..2 {
            match backend.act(action.clone()).unwrap() {
                Event::CommandFinished {
                    tenant,
                    id,
                    result: Err(error),
                } => {
                    assert_eq!(tenant.as_deref(), Some("t-team"));
                    assert_eq!(id, "m-owned");
                    assert!(!error.contains("private server diagnostics"));
                }
                _ => panic!("command errors must remain scoped to the selected machine"),
            }
        }
        match backend.act(action).unwrap() {
            Event::CommandFinished {
                result: Ok(output), ..
            } => {
                assert_eq!(output.exit_code, Some(7));
                assert_eq!(output.stdout_bytes(), b"hello\n");
                assert_eq!(output.stderr_bytes(), b"problem\n");
            }
            _ => panic!("expected a completed nonzero command, not an account failure"),
        }
        join.join().unwrap();
        let requests: Vec<_> = requests.try_iter().collect();
        assert_eq!(
            requests.len(),
            3,
            "a failed command is never automatically replayed"
        );
        for request in requests {
            assert!(request.starts_with("POST /v1/machines/m-owned/exec "));
            assert!(request.to_lowercase().contains("smol-tenant: t-team"));
            assert!(request.contains("\"timeoutSeconds\":60"));
        }
    }
    #[test]
    fn failed_log_reads_keep_their_machine_scope_and_can_be_retried() {
        let (url, requests, join) = server(vec![
            (503, "unavailable".into()),
            (404, "no logs".into()),
            (200, "data: {\"message\":\"recovered output\"}\n\n".into()),
        ]);
        let mut b = backend(&url);
        let action = Action::Machine {
            tenant: Some("t-team".into()),
            id: "m-id".into(),
            action: MachineAction::Logs,
        };
        match b.act(action.clone()).unwrap() {
            Event::LogError { tenant, id, error } => {
                assert_eq!(tenant.as_deref(), Some("t-team"));
                assert_eq!(id, "m-id");
                assert!(!error.is_empty());
            }
            _ => panic!("Expected a machine-scoped log failure"),
        }
        match b.act(action.clone()).unwrap() {
            Event::LogError { error, .. } => {
                assert_eq!(error, "Console logs are not available for this machine.");
            }
            _ => panic!("Expected a log-specific missing-output error"),
        }
        match b.act(action).unwrap() {
            Event::Output {
                kind: OutputKind::Logs,
                tenant,
                id,
                text,
            } => {
                assert_eq!(tenant.as_deref(), Some("t-team"));
                assert_eq!(id, "m-id");
                assert_eq!(text, "recovered output\n");
            }
            _ => panic!("Expected successful log retry"),
        }
        join.join().unwrap();
        let requests: Vec<_> = requests.try_iter().collect();
        assert_eq!(requests.len(), 3);
        for request in requests {
            assert!(request.starts_with("GET /v1/machines/m-id/logs?tail=200&follow=false "));
            assert!(request.to_lowercase().contains("smol-tenant: t-team\r\n"));
        }
    }
    #[test]
    fn every_machine_action_carries_account_and_stable_id() {
        let (url, requests, join) = server(vec![(204, String::new()), (200, "logs".into())]);
        let mut b = backend(&url);
        b.act(Action::Machine {
            tenant: Some("t-team".into()),
            id: "m-id".into(),
            action: MachineAction::Stop,
        })
        .unwrap();
        let logs = b
            .act(Action::Machine {
                tenant: Some("t-team".into()),
                id: "m-id".into(),
                action: MachineAction::Logs,
            })
            .unwrap();
        assert!(matches!(
            logs,
            Event::Output {
                kind: OutputKind::Logs,
                ..
            }
        ));
        join.join().unwrap();
        let first = requests.recv().unwrap().to_lowercase();
        assert!(first.starts_with("post /v1/machines/m-id/stop "));
        assert!(first.contains("smol-tenant: t-team\r\n"));
        assert!(
            requests
                .recv()
                .unwrap()
                .to_lowercase()
                .contains("smol-tenant: t-team\r\n")
        );
    }
    #[test]
    fn create_retries_keep_account_and_return_created_identity() {
        let (url, requests, join) = server(vec![
            (400, "invalid resources".into()),
            (
                201,
                json!({"id":"m-new", "name":"draft", "state":"created"}).to_string(),
            ),
        ]);
        let mut b = backend(&url);
        let action = Action::Create {
            tenant: Some("t-team".into()),
            request: Box::new(CreateMachine {
                name: Some("draft".into()),
                ..Default::default()
            }),
        };
        assert!(b.act(action.clone()).is_err());
        match b.act(action).unwrap() {
            Event::Created { tenant, id } => {
                assert_eq!(tenant.as_deref(), Some("t-team"));
                assert_eq!(id, "m-new");
            }
            _ => panic!("expected created identity"),
        }
        join.join().unwrap();
        for _ in 0..2 {
            let request = requests.recv().unwrap();
            assert!(request.starts_with("POST /v1/machines "));
            assert!(request.to_lowercase().contains("smol-tenant: t-team\r\n"));
            assert!(request.contains("\"name\":\"draft\""));
        }
    }
    #[test]
    fn console_snapshots_unwrap_sse_without_losing_unknown_payloads() {
        assert_eq!(console_logs(b"plain\n\noutput\n"), "plain\n\noutput\n");
        let input = b": heartbeat\r\n\r\ndata: {\"timestamp\":\"time\",\"level\":\"WARN\",\"fields\":{\"message\":\"ready\"}}\r\n\r\ndata: first\ndata: second\n\ndata: {not-json}\n";
        assert_eq!(
            console_logs(input),
            "time [WARN] ready\nfirst\nsecond\n{not-json}\n"
        );
    }
    #[test]
    fn forbidden_account_never_falls_back_to_personal() {
        let (url, requests, join) = server(vec![(403, "secret server detail".into())]);
        let mut b = backend(&url);
        let error = b.snapshot(Some("t-forbidden".into())).err().unwrap();
        assert!(!error.contains("secret"));
        join.join().unwrap();
        assert!(requests.recv().unwrap().contains("t-forbidden"));
        assert!(requests.try_recv().is_err());
    }
    #[test]
    fn mismatched_account_is_rejected_before_loading_machines() {
        let (url, _, join) = server(vec![(
            200,
            json!({"subject":"user","tenantId":"t-other","scopes":[]}).to_string(),
        )]);
        assert!(
            backend(&url)
                .snapshot(Some("t-requested".into()))
                .err()
                .unwrap()
                .contains("different account")
        );
        join.join().unwrap();
    }
    #[test]
    fn refresh_rotates_and_persists_before_retrying_once() {
        let (url, requests, join) = server(vec![
            (401, String::new()),
            (
                200,
                json!({"access_token":"rotated","refresh_token":"new-refresh","expires_in":3600})
                    .to_string(),
            ),
            (200, "[]".into()),
        ]);
        let store = MemoryStore::default();
        let mut b = backend(&url);
        b.issuer = url;
        b.store = Box::new(store.clone());
        assert_eq!(
            b.request(Method::GET, "/v1/machines", Some("t-team"), None)
                .unwrap(),
            b"[]"
        );
        join.join().unwrap();
        let rows: Vec<_> = requests.try_iter().collect();
        assert!(rows[0].contains("Bearer test-access"));
        assert!(rows[1].contains("grant_type=refresh_token"));
        assert!(rows[2].contains("Bearer rotated"));
        assert!(rows[2].to_lowercase().contains("smol-tenant: t-team"));
        let saved = store.load().unwrap().unwrap();
        assert_eq!(saved.refresh_token.as_deref(), Some("new-refresh"));
    }
    #[test]
    fn mutation_is_not_retried_after_server_failure() {
        let (url, requests, join) = server(vec![(503, String::new())]);
        assert!(
            backend(&url)
                .request(Method::POST, "/v1/machines", None, Some(&json!({})))
                .is_err()
        );
        join.join().unwrap();
        assert_eq!(requests.try_iter().count(), 1);
    }
    #[test]
    fn device_flow_backs_off_and_can_be_cancelled() {
        let (url, requests, join) = server(vec![(400, json!({"error":"slow_down"}).to_string())]);
        let mut b = backend(&url);
        b.issuer = url;
        b.login = Some(PendingLogin {
            device: DeviceResponse {
                device_code: "device-secret".into(),
                user_code: "ABCD".into(),
                verification_uri: "https://example.test".into(),
                verification_uri_complete: None,
                expires_in: 300,
                interval: Some(5),
            },
            expires: Instant::now() + Duration::from_secs(300),
            next: Instant::now(),
            interval: Duration::from_secs(5),
        });
        assert!(b.poll_login().unwrap().is_none());
        assert_eq!(b.login.as_ref().unwrap().interval, Duration::from_secs(10));
        b.act(Action::CancelLogin).unwrap();
        assert!(b.login.is_none());
        join.join().unwrap();
        assert!(
            requests
                .recv()
                .unwrap()
                .contains("device_code=device-secret")
        );
    }
    #[test]
    fn logout_removes_persisted_and_in_memory_sessions() {
        let store = MemoryStore::default();
        let mut b = backend("https://example.test");
        store.save(b.session.as_ref().unwrap()).unwrap();
        b.store = Box::new(store.clone());
        b.act(Action::Logout).unwrap();
        assert!(b.session.is_none() && b.cli.is_none() && store.load().unwrap().is_none());
    }
    #[test]
    fn path_and_endpoint_validation_prevent_credential_redirection() {
        for value in ["a/b", "..", "a?b", "a\r\nb", ""] {
            assert!(segment(value).is_err());
        }
        for value in [
            "http://example.test",
            "https://user:pass@example.test",
            "https://example.test?token=x",
        ] {
            assert!(validate_endpoint(value).is_err());
        }
        assert!(validate_endpoint("https://api.smolmachines.com").is_ok());
    }
    #[test]
    #[ignore = "requires an existing Smol CLI sign-in; performs read-only cloud requests"]
    fn live_cli_account_inventory() {
        let mut b = Backend::new(Box::new(MemoryStore::default())).unwrap();
        b.remember_preferences = false;
        match b.act(Action::UseCli).unwrap_or_else(|e| panic!("{e}")) {
            Event::Snapshot { snapshot, .. } => {
                assert!(snapshot.identity.is_some());
                println!(
                    "Cloud identity verified; {} organizations, {} machines, account usage available: {}",
                    snapshot.memberships.len(),
                    snapshot.machines.len(),
                    snapshot.account.is_some()
                );
                for warning in snapshot.warnings {
                    println!("{warning}");
                }
            }
            _ => panic!("Expected authenticated account inventory"),
        }
    }
    #[test]
    #[ignore = "contacts the production identity provider; cancels without completing sign-in"]
    fn live_device_authorization_contract() {
        let mut b = Backend::new(Box::new(MemoryStore::default())).unwrap();
        b.remember_preferences = false;
        match b.act(Action::Login).unwrap_or_else(|e| panic!("{e}")) {
            Event::Device { code, url, expires } => {
                assert!(!code.is_empty());
                assert!(url.starts_with(DEFAULT_ISSUER));
                assert!(expires > Instant::now());
            }
            _ => panic!("Expected device authorization"),
        }
        b.act(Action::CancelLogin).unwrap();
        assert!(b.login.is_none());
    }
    #[test]
    #[ignore = "creates one short-lived cloud machine; requires SMOL_STUDIO_LIVE_MUTATION=1"]
    fn live_owned_machine_lifecycle() {
        assert_eq!(
            std::env::var("SMOL_STUDIO_LIVE_MUTATION").as_deref(),
            Ok("1")
        );
        let mut b = Backend::new(Box::new(MemoryStore::default())).unwrap();
        b.remember_preferences = false;
        b.act(Action::UseCli).unwrap_or_else(|e| panic!("{e}"));
        let created = b.request(Method::POST, "/v1/machines", None, Some(&json!({
            "name":format!("studio-smoke-{}", now()), "source":{"type":"image","reference":"alpine:3.22"},
            "resources":{"cpus":1,"memoryMb":512}, "network":{"mode":"blocked"}, "ttlSeconds":300,
        }))).unwrap_or_else(|e| panic!("Create: {e}"));
        let machine: Machine = decode(&created).unwrap();
        let result: Result<()> = (|| {
            b.act(Action::Machine {
                tenant: None,
                id: machine.id.clone(),
                action: MachineAction::Start,
            })?;
            match b.act(Action::Machine {
                tenant: None,
                id: machine.id.clone(),
                action: MachineAction::Exec("printf studio-cloud-ok; uname -s".into()),
            })? {
                Event::CommandFinished {
                    result: Ok(output), ..
                } if String::from_utf8_lossy(&output.stdout_bytes())
                    .contains("studio-cloud-okLinux")
                    && output.exit_code == Some(0) => {}
                _ => return Err("Cloud command returned unexpected output".into()),
            }
            b.act(Action::Machine {
                tenant: None,
                id: machine.id.clone(),
                action: MachineAction::Logs,
            })?;
            b.act(Action::Machine {
                tenant: None,
                id: machine.id.clone(),
                action: MachineAction::Stop,
            })?;
            Ok(())
        })();
        // Cleanup is attempted regardless of which lifecycle assertion failed.
        let cleanup = b.act(Action::Machine {
            tenant: None,
            id: machine.id,
            action: MachineAction::Delete,
        });
        cleanup.unwrap_or_else(|e| panic!("Cleanup failed (TTL is 300s): {e}"));
        result.unwrap_or_else(|e| panic!("Lifecycle: {e}"));
        println!(
            "Created, started, executed, read logs, stopped and deleted the owned cloud test machine."
        );
    }
    #[test]
    #[ignore = "requires an unlocked native desktop credential store"]
    fn live_native_credential_store() {
        let entry =
            keyring::Entry::new("com.smolmachines.studio.test", &format!("smoke-{}", now()))
                .unwrap();
        entry.set_password("temporary-studio-test-value").unwrap();
        let result = entry.get_password();
        entry.delete_credential().unwrap();
        assert_eq!(result.unwrap(), "temporary-studio-test-value");
        assert!(matches!(entry.get_password(), Err(keyring::Error::NoEntry)));
    }
}
