//! Browser destinations come from actual published bindings or cloud ingress.
//! Building a link never publishes a port or changes who can access it.
use crate::{container_details::PublishedPort, model::MachinePort};

#[derive(Clone, Debug, PartialEq)]
pub struct Endpoint {
    pub address: String,
    pub detail: String,
    pub browser_url: Option<String>,
}

impl Endpoint {
    pub fn machine(port: &MachinePort) -> Self {
        let browser_url = (port.protocol.eq_ignore_ascii_case("tcp") && port.host != 0)
            .then(|| format!("http://127.0.0.1:{}/", port.host));
        Self {
            address: browser_url
                .clone()
                .unwrap_or_else(|| format!("127.0.0.1:{}", port.host)),
            detail: format!(
                "{} · guest port {}",
                port.protocol.to_uppercase(),
                port.guest
            ),
            browser_url,
        }
    }

    pub fn container(port: &PublishedPort) -> Self {
        let browser_url = port.browser_url();
        Self {
            address: browser_url.clone().unwrap_or_else(|| {
                format!(
                    "{}:{}",
                    port.host_ip,
                    if port.host_port.is_empty() {
                        "automatic"
                    } else {
                        &port.host_port
                    }
                )
            }),
            detail: format!("Container port {}", port.container),
            browser_url,
        }
    }

    /// Use only the advertised ingress URL. The authenticated API bridge is
    /// not a browser URL and must never gain an access token in its query.
    pub fn cloud(url: &str) -> Option<Self> {
        if url.len() > 8192 || url.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return None;
        }
        let parsed = reqwest::Url::parse(url).ok()?;
        if !matches!(parsed.scheme(), "https" | "http")
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return None;
        }
        Some(Self {
            address: parsed.to_string(),
            detail: "Cloud app".into(),
            browser_url: Some(parsed.to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn local_url_reaches_the_published_host_port() {
        let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let host = server.local_addr().unwrap().port();
        let endpoint = Endpoint::machine(&MachinePort {
            host,
            guest: 3000,
            protocol: "tcp".into(),
        });
        let worker = std::thread::spawn(move || {
            let (mut connection, _) = server.accept().unwrap();
            connection
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut request = [0; 1024];
            let n = connection.read(&mut request).unwrap();
            assert!(request[..n].starts_with(b"GET / HTTP/1.1"));
            connection
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\napp")
                .unwrap();
        });
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        assert_eq!(
            client
                .get(endpoint.browser_url.unwrap())
                .send()
                .unwrap()
                .text()
                .unwrap(),
            "app"
        );
        worker.join().unwrap();
    }

    #[test]
    fn only_browser_destinations_get_open_actions() {
        for protocol in ["udp", "sctp", "unknown"] {
            assert!(
                Endpoint::machine(&MachinePort {
                    host: 8080,
                    guest: 80,
                    protocol: protocol.into()
                })
                .browser_url
                .is_none()
            );
        }
        assert!(
            Endpoint::machine(&MachinePort {
                host: 0,
                guest: 80,
                protocol: "tcp".into()
            })
            .browser_url
            .is_none()
        );
        let ipv6 = Endpoint::container(&PublishedPort {
            container: "8080/tcp".into(),
            host_ip: "::".into(),
            host_port: "9000".into(),
        });
        assert_eq!(ipv6.browser_url.as_deref(), Some("http://[::1]:9000/"));
        for url in [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "https://user:password@example.com",
            "https://example.com/?t=secret",
            "https://example.com/#token",
            "https://example.com/\n",
            "//example.com",
        ] {
            assert!(Endpoint::cloud(url).is_none(), "{url}");
        }
        assert_eq!(
            Endpoint::cloud("https://my-app.example.com")
                .unwrap()
                .address,
            "https://my-app.example.com/"
        );
    }
}
