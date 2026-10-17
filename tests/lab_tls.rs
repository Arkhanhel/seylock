// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi
//! Real TLS end to end, with a test certificate authority trusted through the
//! `lab-roots` feature:
//!
//! - a trusted certificate is accepted on the `ip` path;
//! - a certificate from another authority, or for another name, is refused;
//! - the volunteer `proxy` path carries TLS inside TLS.
//!
//! ```text
//! cargo test --features lab-roots --test lab_tls
//! ```

use std::net::Ipv4Addr;
use std::sync::{Arc, OnceLock};

use seylock::endpoints::{EndpointList, PathSpec};
use seylock::proxy::{self, HEADER_SERVICE, HEADER_TRANSPORT_TOKEN, Policy};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

struct Authority {
    key: rcgen::KeyPair,
    cert: rcgen::Certificate,
}

impl Authority {
    fn new() -> Authority {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "SeyLock test CA");
        let cert = params.self_signed(&key).unwrap();
        Authority { key, cert }
    }

    /// A server configuration with a certificate for `names`.
    fn server(&self, names: &[&str]) -> TlsAcceptor {
        let key = rcgen::KeyPair::generate().unwrap();
        let names = names.iter().map(|n| n.to_string()).collect::<Vec<_>>();
        let leaf = rcgen::CertificateParams::new(names)
            .unwrap()
            .signed_by(&key, &self.cert, &self.key)
            .unwrap();
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .unwrap();
        TlsAcceptor::from(Arc::new(config))
    }
}

/// The authority every test trusts; added once, before any proxy starts.
fn trusted() -> &'static Authority {
    static CA: OnceLock<Authority> = OnceLock::new();
    CA.get_or_init(|| {
        let ca = Authority::new();
        seylock::lab::add_root(ca.cert.der().to_vec());
        ca
    })
}

/// An HTTPS server on loopback answering every request with 200.
async fn https_server(tls: TlsAcceptor) -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let tls = tls.clone();
            tokio::spawn(async move {
                let mut stream = tls.accept(tcp).await.ok()?;
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = stream.read(&mut chunk).await.ok()?;
                    if n == 0 {
                        return None;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await
                    .ok()?;
                stream.shutdown().await.ok()
            });
        }
    });
    port
}

/// A volunteer proxy on loopback: ends the outer TLS and passes the bytes,
/// the inner TLS, on to `upstream`.
async fn volunteer_proxy(tls: TlsAcceptor, upstream: u16) -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let tls = tls.clone();
            tokio::spawn(async move {
                let mut outer = tls.accept(tcp).await.ok()?;
                let mut server = TcpStream::connect((Ipv4Addr::LOCALHOST, upstream))
                    .await
                    .ok()?;
                tokio::io::copy_bidirectional(&mut outer, &mut server)
                    .await
                    .ok()
            });
        }
    });
    port
}

/// One request for the service `api`, served at `base`, through a fresh
/// proxy that knows only `path`. Returns the status line and the path header.
async fn request(base: String, path: PathSpec) -> (String, Option<String>) {
    let list = EndpointList::v2(
        1,
        i64::MAX / 2,
        [("api".to_string(), base)].into_iter().collect(),
        vec![path],
    );
    let handle = proxy::start({
        let mut policy = Policy::new(list);
        policy.network_id = "test".into();
        policy
    })
    .await
    .unwrap();
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, handle.port))
        .await
        .unwrap();
    let head = format!(
        "GET /health HTTP/1.1\r\nHost: test\r\n{HEADER_TRANSPORT_TOKEN}: {}\r\n{HEADER_SERVICE}: api\r\nConnection: close\r\n\r\n",
        handle.token
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let text = String::from_utf8_lossy(&response).to_string();
    let status = text.lines().next().unwrap_or_default().to_string();
    let path = text.lines().find_map(|l| {
        let (name, value) = l.split_once(':')?;
        name.eq_ignore_ascii_case("x-transport-path")
            .then(|| value.trim().to_string())
    });
    (status, path)
}

fn ip_path() -> PathSpec {
    PathSpec::Ip {
        ip: "127.0.0.1".into(),
    }
}

#[tokio::test]
async fn trusted_certificate_is_accepted() {
    let port = https_server(trusted().server(&["api.lab.test"])).await;
    let (status, path) = request(format!("https://api.lab.test:{port}"), ip_path()).await;
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    assert_eq!(path.as_deref(), Some("ip"));
}

#[tokio::test]
async fn certificate_from_another_authority_is_refused() {
    trusted();
    let stranger = Authority::new();
    let port = https_server(stranger.server(&["api.lab.test"])).await;
    let (status, _) = request(format!("https://api.lab.test:{port}"), ip_path()).await;
    assert!(!status.starts_with("HTTP/1.1 200"), "{status}");
}

#[tokio::test]
async fn certificate_for_another_name_is_refused() {
    let port = https_server(trusted().server(&["other.lab.test"])).await;
    let (status, _) = request(format!("https://api.lab.test:{port}"), ip_path()).await;
    assert!(!status.starts_with("HTTP/1.1 200"), "{status}");
}

#[tokio::test]
async fn volunteer_proxy_carries_tls_inside_tls() {
    let server = https_server(trusted().server(&["api.lab.test"])).await;
    let proxy_port = volunteer_proxy(trusted().server(&["localhost"]), server).await;
    // The service's own name never resolves: only the proxy is reachable.
    let (status, path) = request(
        "https://api.lab.test".into(),
        PathSpec::Proxy {
            host: "localhost".into(),
            port: proxy_port,
        },
    )
    .await;
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    assert_eq!(path.as_deref(), Some("proxy"));
}

#[tokio::test]
async fn volunteer_proxy_with_an_untrusted_certificate_is_refused() {
    trusted();
    let server = https_server(trusted().server(&["api.lab.test"])).await;
    let proxy_port = volunteer_proxy(Authority::new().server(&["localhost"]), server).await;
    let (status, _) = request(
        "https://api.lab.test".into(),
        PathSpec::Proxy {
            host: "localhost".into(),
            port: proxy_port,
        },
    )
    .await;
    assert!(!status.starts_with("HTTP/1.1 200"), "{status}");
}
