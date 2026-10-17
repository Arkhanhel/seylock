// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi
//! Signed list of entry points.
//!
//! The list tells the client how else to reach the same logical servers when
//! direct names or addresses are blocked. It can arrive from anywhere (a
//! server, a mirror, a DNS TXT record, another person's QR code), so the only
//! thing the client trusts is the signature made with the configuration signing
//! key (the same Ed25519 key that signs `/v1/config`).
//!
//! The signature covers the RAW bytes of the document, not the parsed JSON:
//! JSON canonicalisation is a source of disagreement between languages, and
//! here the signature may be checked from more than one language.
//!
//! Acceptance rule: the signature is valid, the version is known, the list has
//! not expired, and `issued_at_ms` is strictly greater than that of the list
//! already accepted. Otherwise a server (or anyone who captured an old signed
//! list) could roll the client back to entry points that are already blocked.
//!
//! Two formats are accepted. Format 1 names exactly two services, `keys` and
//! `relay`, in `logical`. Format 2 names any services in `services`, so the
//! library can serve applications other than the one it was written for.
//! Each format has its own signing context, so a signature made for one is
//! never valid for the other.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::{Deserialize, Serialize};

/// Signing context of format 1: the first bytes of the signed message. It
/// separates the purposes of a single key: a configuration signature is not
/// valid for an endpoint list, and vice versa.
pub const SIGNING_CONTEXT: &[u8] = b"secretly-endpoints-v1\n";

/// Signing context of format 2. It names no product, so renaming the library
/// or the application never invalidates signed lists.
pub const SIGNING_CONTEXT_V2: &[u8] = b"transport-endpoints-v2\n";

/// Most services a format 2 list may name.
pub const MAX_SERVICES: usize = 16;

/// Longest service name in a format 2 list, in bytes.
pub const MAX_SERVICE_NAME_LEN: usize = 32;

/// Most Tor bridge lines a format 2 list may carry.
pub const MAX_TOR_BRIDGES: usize = 32;

/// Longest Tor bridge line, in bytes.
pub const MAX_TOR_BRIDGE_LEN: usize = 2048;

/// The two services of format 1. Format 2 names services with plain strings;
/// [`Upstream::as_str`] gives the name these two have there.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Upstream {
    /// The key directory service, the base URL in `logical.keys`.
    Keys,
    /// The message relay, the base URL in `logical.relay`.
    Relay,
}

impl Upstream {
    /// The service name: `keys` or `relay`.
    pub fn as_str(self) -> &'static str {
        match self {
            Upstream::Keys => "keys",
            Upstream::Relay => "relay",
        }
    }
}

/// Whether `name` is a valid format 2 service name: 1 to
/// [`MAX_SERVICE_NAME_LEN`] bytes of lowercase ASCII letters, digits and `-`,
/// not starting with `-`. Lowercase only, because the proxy lowercases the
/// header that names the service.
pub fn is_valid_service_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_SERVICE_NAME_LEN
        && b[0] != b'-'
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// Base addresses of the logical servers. These are the addresses a client
/// binds a profile to; the paths below are only ways of reaching them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Logical {
    /// Base URL of the key directory service, for example
    /// `https://keys.example.org`. Uses `https` (`http` is for local testing);
    /// a path prefix is allowed and is prepended to every forwarded request
    /// path. Must not be empty in an accepted list.
    pub keys: String,
    /// Base URL of the message relay, with the same rules as `keys`. Must not
    /// be empty in an accepted list.
    pub relay: String,
}

/// One path to the servers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PathSpec {
    /// Connect by name, the ordinary way.
    Direct,
    /// Connect to an IP address with the real name in SNI: protects against DNS
    /// failure, not against blocking by address.
    Ip {
        /// Server IP address (textual IPv4 or IPv6) to connect to. TLS and
        /// `Host` still use the `logical` host, and the port is the `logical`
        /// port.
        ip: String,
    },
    /// Another name (and possibly an address) of the same server. Base
    /// addresses are given per logical server, because a mirror may separate
    /// them by path or by name.
    Mirror {
        /// Format 1: base URL of the mirror for the key directory. TLS name and
        /// `Host` come from this URL's host, and a path prefix in it is
        /// prepended to request paths. Required in format 1, absent in format 2.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        keys: Option<String>,
        /// Format 1: base URL of the mirror for the relay, with the same rules
        /// as `keys`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        relay: Option<String>,
        /// Format 2: base URL of the mirror for each service it serves, with
        /// the same rules as `keys`. A service missing here is not served by
        /// this mirror, and requests for it skip the path.
        #[serde(
            default,
            skip_serializing_if = "BTreeMap::is_empty",
            deserialize_with = "unique_keys"
        )]
        targets: BTreeMap<String, String>,
        /// Optional IP address to connect to instead of resolving the mirror's
        /// host. The TLS name and `Host` stay the mirror's host.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ip: Option<String>,
    },
    /// A name behind a CDN. Attachments do not go through it (body size limit).
    Cdn {
        /// Format 1: base URL of the CDN-fronted name for the key directory.
        /// TLS name and `Host` come from this URL's host.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        keys: Option<String>,
        /// Format 1: base URL of the CDN-fronted name for the relay, with the
        /// same rules as `keys`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        relay: Option<String>,
        /// Format 2: base URL of the CDN-fronted name for each service, as for
        /// `mirror`.
        #[serde(
            default,
            skip_serializing_if = "BTreeMap::is_empty",
            deserialize_with = "unique_keys"
        )]
        targets: BTreeMap<String, String>,
    },
    /// A TLS proxy in the Signal format: outer TLS to `host`, with TLS to the
    /// real names inside.
    Proxy {
        /// Host name of the volunteer proxy. It is both the TCP target and the
        /// TLS name of the outer connection.
        host: String,
        /// TCP port of the volunteer proxy. Defaults to 443 when omitted from
        /// the JSON.
        #[serde(default = "default_https_port")]
        port: u16,
    },
    /// An arbitrary SOCKS5 proxy (Tor via Orbot, a VPN proxy). A list from the
    /// server normally has none; this is a user setting.
    Socks {
        /// Socket address of the SOCKS5 proxy as `ip:port`. The proxy is asked
        /// to connect to the `logical` host by name, and TLS to that host runs
        /// inside the tunnel.
        addr: String,
    },
    /// Built-in Tor. The last resort, used only with the person's explicit
    /// consent.
    Tor,
}

fn default_https_port() -> u16 {
    443
}

impl PathSpec {
    /// Returns the parameterless [`PathKind`] of this path.
    pub fn kind(&self) -> PathKind {
        match self {
            PathSpec::Direct => PathKind::Direct,
            PathSpec::Ip { .. } => PathKind::Ip,
            PathSpec::Mirror { .. } => PathKind::Mirror,
            PathSpec::Cdn { .. } => PathKind::Cdn,
            PathSpec::Proxy { .. } => PathKind::Proxy,
            PathSpec::Socks { .. } => PathKind::Socks,
            PathSpec::Tor => PathKind::Tor,
        }
    }

    /// For `mirror` and `cdn`, the base URL this path uses for `service`, or
    /// `None` when the path does not serve it. Other kinds have no addresses
    /// of their own and return `None`; they reach the service's own base URL.
    pub fn target_base(&self, service: &str) -> Option<&str> {
        match self {
            PathSpec::Mirror {
                keys,
                relay,
                targets,
                ..
            }
            | PathSpec::Cdn {
                keys,
                relay,
                targets,
            } => {
                let v1 = match service {
                    "keys" => keys.as_deref(),
                    "relay" => relay.as_deref(),
                    _ => None,
                };
                v1.or_else(|| targets.get(service).map(String::as_str))
                    .filter(|b| !b.is_empty())
            }
            _ => None,
        }
    }
}

/// Path kind without parameters, for memory and for reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathKind {
    /// Connect by name to the `logical` host; TLS name and `Host` are that
    /// host. Connect timeout: 6 seconds.
    Direct,
    /// Connect to a pinned IP at the `logical` port, with the `logical` host as
    /// TLS name and `Host`. Connect timeout: 6 seconds.
    Ip,
    /// Another domain serving the same API, optionally at a pinned IP. TLS name
    /// and `Host` are the mirror URL's host. Connect timeout: 12 seconds.
    Mirror,
    /// A name served by a third-party CDN; TLS name and `Host` are the CDN
    /// URL's host. Connect timeout: 12 seconds.
    Cdn,
    /// TLS to a volunteer proxy, then TLS to the `logical` host inside that
    /// tunnel (TLS in TLS). Connect timeout: 12 seconds.
    Proxy,
    /// SOCKS5 proxy that connects to the `logical` host by name, then TLS to
    /// that host. Tried only when the application allows it. Connect timeout:
    /// 12 seconds.
    Socks,
    /// Through Tor, by the connector a companion crate installs (see
    /// [`crate::tor`]; `seylock-tor` provides one). Tried only when the
    /// application allows it; without a connector it fails at once. Connect
    /// timeout: 60 seconds, for a cold start.
    Tor,
}

impl PathKind {
    /// Default probe order, from cheapest to most expensive.
    pub const DEFAULT_ORDER: [PathKind; 7] = [
        PathKind::Direct,
        PathKind::Ip,
        PathKind::Mirror,
        PathKind::Cdn,
        PathKind::Proxy,
        PathKind::Socks,
        PathKind::Tor,
    ];

    /// Returns the lowercase wire name of the kind, the same as its `kind`
    /// value in the JSON list and the `x-secretly-path` response header.
    pub fn as_str(self) -> &'static str {
        match self {
            PathKind::Direct => "direct",
            PathKind::Ip => "ip",
            PathKind::Mirror => "mirror",
            PathKind::Cdn => "cdn",
            PathKind::Proxy => "proxy",
            PathKind::Socks => "socks",
            PathKind::Tor => "tor",
        }
    }
}

/// Reads a map of strings, refusing a key that appears twice. Objects that
/// map to structs already refuse repeated fields; maps would keep the last
/// copy, and another parser might keep the first, so one signed list could be
/// read two ways.
fn unique_keys<'de, D>(deserializer: D) -> Result<BTreeMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct UniqueKeys;
    impl<'de> Visitor<'de> for UniqueKeys {
        type Value = BTreeMap<String, String>;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a map of strings without repeated keys")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut out = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<String, String>()? {
                if out.contains_key(&key) {
                    return Err(de::Error::custom(format!("repeated key `{key}`")));
                }
                out.insert(key, value);
            }
            Ok(out)
        }
    }
    deserializer.deserialize_map(UniqueKeys)
}

/// A parsed list.
///
/// Lists normally come from [`verify_and_parse`]. To build one in Rust (for
/// signing, or in tests), start from [`EndpointList::v2`]; new fields may be
/// added in later versions of the format.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct EndpointList {
    /// Format version: 1 or 2 ([`crate::ENDPOINT_LIST_VERSION`] is the
    /// newest). Any other value is rejected with code 5.
    pub v: u32,
    /// When the list was made, in Unix milliseconds. Must be strictly greater
    /// than that of the list already accepted, and at most
    /// [`CLOCK_SKEW_TOLERANCE_MS`] ahead of the client clock.
    pub issued_at_ms: i64,
    /// Moment after which the list is refused, in Unix milliseconds. A list
    /// with `expires_at_ms <= now_ms` is rejected.
    pub expires_at_ms: i64,
    /// Format 1: canonical base URLs of the two servers. The application
    /// addresses its requests to these. Required in format 1, absent in
    /// format 2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logical: Option<Logical>,
    /// Format 2: canonical base URL of each service, by name (see
    /// [`is_valid_service_name`]). At least one, at most [`MAX_SERVICES`].
    #[serde(
        default,
        skip_serializing_if = "BTreeMap::is_empty",
        deserialize_with = "unique_keys"
    )]
    pub services: BTreeMap<String, String>,
    /// Ways to reach the servers, in any order; the probe order is set by
    /// [`crate::paths`]. A list with no paths is rejected.
    pub paths: Vec<PathSpec>,
    /// Format 2: Tor bridge lines (`obfs4 ...`, `webtunnel ...`), handed to
    /// the installed Tor connector (see [`crate::tor`]) so that bridges are
    /// distributed and rotated like the other ways in. At most
    /// [`MAX_TOR_BRIDGES`], each 1 to [`MAX_TOR_BRIDGE_LEN`] bytes of
    /// printable ASCII. The library does not parse them; the connector does.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tor_bridges: Vec<String>,
}

impl EndpointList {
    /// A format 2 list of `services` (name to base URL) reachable by `paths`,
    /// with no Tor bridges. It still has to pass the checks of
    /// [`verify_and_parse`] once signed.
    pub fn v2(
        issued_at_ms: i64,
        expires_at_ms: i64,
        services: BTreeMap<String, String>,
        paths: Vec<PathSpec>,
    ) -> EndpointList {
        EndpointList {
            v: 2,
            issued_at_ms,
            expires_at_ms,
            logical: None,
            services,
            paths,
            tor_bridges: Vec::new(),
        }
    }

    /// A format 1 list: the `keys` and `relay` servers of `logical`
    /// reachable by `paths`.
    pub fn v1(
        issued_at_ms: i64,
        expires_at_ms: i64,
        logical: Logical,
        paths: Vec<PathSpec>,
    ) -> EndpointList {
        EndpointList {
            v: 1,
            issued_at_ms,
            expires_at_ms,
            logical: Some(logical),
            services: BTreeMap::new(),
            paths,
            tor_bridges: Vec::new(),
        }
    }

    /// Canonical base URL of `service`, or `None` when the list has no such
    /// service. Format 1 knows `keys` and `relay`.
    pub fn service_base(&self, service: &str) -> Option<&str> {
        let v1 = self.logical.as_ref().and_then(|l| match service {
            "keys" => Some(l.keys.as_str()),
            "relay" => Some(l.relay.as_str()),
            _ => None,
        });
        v1.or_else(|| self.services.get(service).map(String::as_str))
            .filter(|b| !b.is_empty())
    }
}

/// A signed envelope: the document is a string holding the list's JSON; the
/// signature covers `SIGNING_CONTEXT || doc`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedEndpointList {
    /// The list document as a JSON string, exactly as signed. It is parsed only
    /// after the signature has been verified.
    pub doc: String,
    /// Standard base64 of the 64-byte Ed25519 signature over the signed
    /// message built by [`signing_message`].
    pub sig_b64: String,
}

/// Why a signed list was rejected. The checks run in the order of the
/// variants, and each variant has a numeric [`code`](EndpointError::code) for
/// the C ABI that equals the number of the acceptance rule it enforces.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EndpointError {
    /// The envelope cannot be parsed. Code 1.
    Envelope,
    /// The key or signature has the wrong format: not valid base64, not 32 and
    /// 64 bytes long, or a key that is not a valid Ed25519 point. Code 2.
    KeyFormat,
    /// The signature does not match. Code 3.
    Signature,
    /// The document cannot be parsed (after the signature check). Code 4.
    Document,
    /// Unknown format version; carries the version found. Code 5.
    Version(u32),
    /// The list has expired (or is not valid yet, because of the clock): it
    /// expired already, or `issued_at_ms` is more than
    /// [`CLOCK_SKEW_TOLERANCE_MS`] ahead of the client clock. Code 6.
    Expired,
    /// Not newer than the list already accepted: `issued_at_ms` must be
    /// strictly greater, which stops replay of old lists. Code 7.
    NotNewer,
    /// No paths, or no logical addresses. Code 8.
    Empty,
    /// Format 2: a service name is not valid, or there are more than
    /// [`MAX_SERVICES`] services. Code 9.
    ServiceName,
    /// Format 2: a path gives an address for a service the list does not
    /// name. Code 10.
    UnknownService,
    /// Format 2: more than [`MAX_TOR_BRIDGES`] Tor bridge lines, or one that
    /// is empty, too long or not printable ASCII. Code 11.
    TorBridge,
}

impl EndpointError {
    /// Code for the C ABI.
    pub fn code(&self) -> i32 {
        match self {
            EndpointError::Envelope => 1,
            EndpointError::KeyFormat => 2,
            EndpointError::Signature => 3,
            EndpointError::Document => 4,
            EndpointError::Version(_) => 5,
            EndpointError::Expired => 6,
            EndpointError::NotNewer => 7,
            EndpointError::Empty => 8,
            EndpointError::ServiceName => 9,
            EndpointError::UnknownService => 10,
            EndpointError::TorBridge => 11,
        }
    }
}

/// Verifies and parses a signed list.
///
/// `current_issued_at_ms` is the `issued_at_ms` of the list already accepted (0
/// if none). `now_ms` is the client clock; a server-supplied clock correction
/// is deliberately not passed in, because a response carrying `Date` may have
/// come through a foreign node.
pub fn verify_and_parse(
    signed_json: &str,
    verifying_key_b64: &str,
    now_ms: i64,
    current_issued_at_ms: i64,
) -> Result<EndpointList, EndpointError> {
    let envelope: SignedEndpointList =
        serde_json::from_str(signed_json).map_err(|_| EndpointError::Envelope)?;
    let key = decode_key(verifying_key_b64)?;
    let sig_bytes = B64
        .decode(envelope.sig_b64.trim())
        .map_err(|_| EndpointError::KeyFormat)?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|_| EndpointError::KeyFormat)?;
    let doc = envelope.doc.as_bytes();
    // The version is unknown until the document is parsed, and it may be
    // parsed only after the signature checks out. So the signature is tried
    // under both contexts, and the context that matched must agree with the
    // version inside.
    let signed_as = if key
        .verify(&signing_message_for(SIGNING_CONTEXT, doc), &signature)
        .is_ok()
    {
        1
    } else if key
        .verify(&signing_message_for(SIGNING_CONTEXT_V2, doc), &signature)
        .is_ok()
    {
        2
    } else {
        return Err(EndpointError::Signature);
    };

    let list: EndpointList =
        serde_json::from_str(&envelope.doc).map_err(|_| EndpointError::Document)?;
    if list.v != 1 && list.v != 2 {
        return Err(EndpointError::Version(list.v));
    }
    if list.v != signed_as {
        // A format 1 signature does not vouch for a format 2 document, and
        // the other way round.
        return Err(EndpointError::Signature);
    }
    // Saturating: `now_ms` comes from the caller and may be anything.
    if list.expires_at_ms <= now_ms
        || list.issued_at_ms > now_ms.saturating_add(CLOCK_SKEW_TOLERANCE_MS)
    {
        return Err(EndpointError::Expired);
    }
    if list.issued_at_ms <= current_issued_at_ms {
        return Err(EndpointError::NotNewer);
    }
    check_shape(&list)?;
    Ok(list)
}

/// Checks that the list uses its own format's fields and nothing else, and
/// that every service a path refers to exists.
fn check_shape(list: &EndpointList) -> Result<(), EndpointError> {
    if list.v == 1 {
        if !list.services.is_empty() || !list.tor_bridges.is_empty() {
            return Err(EndpointError::Document);
        }
        for p in &list.paths {
            // Format 1 mirrors and CDN names carry exactly `keys` and `relay`.
            if let PathSpec::Mirror {
                keys,
                relay,
                targets,
                ..
            }
            | PathSpec::Cdn {
                keys,
                relay,
                targets,
            } = p
                && (keys.is_none() || relay.is_none() || !targets.is_empty())
            {
                return Err(EndpointError::Document);
            }
        }
        let logical = list.logical.as_ref().ok_or(EndpointError::Empty)?;
        if list.paths.is_empty() || logical.keys.is_empty() || logical.relay.is_empty() {
            return Err(EndpointError::Empty);
        }
        return Ok(());
    }

    if list.logical.is_some() {
        return Err(EndpointError::Document);
    }
    for p in &list.paths {
        if let PathSpec::Mirror {
            keys,
            relay,
            targets,
            ..
        }
        | PathSpec::Cdn {
            keys,
            relay,
            targets,
        } = p
            && (keys.is_some() || relay.is_some() || targets.is_empty())
        {
            return Err(EndpointError::Document);
        }
    }
    if list.paths.is_empty()
        || list.services.is_empty()
        || list.services.values().any(String::is_empty)
    {
        return Err(EndpointError::Empty);
    }
    if list.services.len() > MAX_SERVICES || !list.services.keys().all(|n| is_valid_service_name(n))
    {
        return Err(EndpointError::ServiceName);
    }
    for p in &list.paths {
        if let PathSpec::Mirror { targets, .. } | PathSpec::Cdn { targets, .. } = p
            && targets
                .iter()
                .any(|(name, base)| !list.services.contains_key(name) || base.is_empty())
        {
            return Err(EndpointError::UnknownService);
        }
    }
    let bridge_ok = |b: &String| {
        !b.is_empty()
            && b.len() <= MAX_TOR_BRIDGE_LEN
            && b.bytes().all(|c| (0x20..=0x7e).contains(&c))
    };
    if list.tor_bridges.len() > MAX_TOR_BRIDGES || !list.tor_bridges.iter().all(bridge_ok) {
        return Err(EndpointError::TorBridge);
    }
    Ok(())
}

/// How far `issued_at_ms` may be ahead of the client clock. Phone clocks can be
/// off by days, so the tolerance is generous.
pub const CLOCK_SKEW_TOLERANCE_MS: i64 = 7 * 24 * 60 * 60 * 1000;

/// Builds the exact byte string signed for a format 1 list:
/// [`SIGNING_CONTEXT`] followed by the raw bytes of `doc`.
pub fn signing_message(doc: &[u8]) -> Vec<u8> {
    signing_message_for(SIGNING_CONTEXT, doc)
}

/// Builds the exact byte string signed for a format 2 list:
/// [`SIGNING_CONTEXT_V2`] followed by the raw bytes of `doc`.
pub fn signing_message_v2(doc: &[u8]) -> Vec<u8> {
    signing_message_for(SIGNING_CONTEXT_V2, doc)
}

fn signing_message_for(context: &[u8], doc: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(context.len() + doc.len());
    out.extend_from_slice(context);
    out.extend_from_slice(doc);
    out
}

fn decode_key(b64: &str) -> Result<VerifyingKey, EndpointError> {
    let bytes = B64
        .decode(b64.trim())
        .map_err(|_| EndpointError::KeyFormat)?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| EndpointError::KeyFormat)?;
    VerifyingKey::from_bytes(&arr).map_err(|_| EndpointError::KeyFormat)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn key() -> SigningKey {
        // `rand 0.9` and `ed25519-dalek 2` use different `rand_core`
        // versions; 32 random bytes work with both.
        SigningKey::from_bytes(&rand::random::<[u8; 32]>())
    }

    fn pub_b64(k: &SigningKey) -> String {
        B64.encode(k.verifying_key().to_bytes())
    }

    fn doc(issued: i64, expires: i64) -> String {
        serde_json::to_string(&EndpointList {
            v: 1,
            issued_at_ms: issued,
            expires_at_ms: expires,
            logical: Some(Logical {
                keys: "https://keys.example.com".into(),
                relay: "https://relay.example.com".into(),
            }),
            services: Default::default(),
            paths: vec![
                PathSpec::Direct,
                PathSpec::Ip {
                    ip: "203.0.113.5".into(),
                },
                PathSpec::Mirror {
                    keys: Some("https://m1.example.net/k".into()),
                    relay: Some("https://m1.example.net/r".into()),
                    targets: Default::default(),
                    ip: None,
                },
                PathSpec::Proxy {
                    host: "vol.example.org".into(),
                    port: 443,
                },
                PathSpec::Tor,
            ],
            tor_bridges: Vec::new(),
        })
        .unwrap()
    }

    fn sign(k: &SigningKey, doc: &str) -> String {
        let sig = k.sign(&signing_message(doc.as_bytes()));
        serde_json::to_string(&SignedEndpointList {
            doc: doc.to_string(),
            sig_b64: B64.encode(sig.to_bytes()),
        })
        .unwrap()
    }

    #[test]
    fn accepts_a_fresh_signed_list() {
        let k = key();
        let signed = sign(&k, &doc(1_000, 2_000_000));
        let list = verify_and_parse(&signed, &pub_b64(&k), 1_500, 0).unwrap();
        assert_eq!(list.paths.len(), 5);
        assert_eq!(list.paths[3].kind(), PathKind::Proxy);
        assert_eq!(
            list.service_base("relay"),
            Some("https://relay.example.com")
        );
    }

    #[test]
    fn rejects_a_tampered_document() {
        let k = key();
        let signed = sign(&k, &doc(1_000, 2_000_000));
        let tampered = signed.replace("203.0.113.5", "198.51.100.9");
        assert_eq!(
            verify_and_parse(&tampered, &pub_b64(&k), 1_500, 0),
            Err(EndpointError::Signature)
        );
    }

    #[test]
    fn rejects_a_foreign_key() {
        let k = key();
        let other = key();
        let signed = sign(&k, &doc(1_000, 2_000_000));
        assert_eq!(
            verify_and_parse(&signed, &pub_b64(&other), 1_500, 0),
            Err(EndpointError::Signature)
        );
    }

    #[test]
    fn rejects_rollback_to_an_older_list() {
        let k = key();
        let signed = sign(&k, &doc(1_000, 2_000_000));
        assert_eq!(
            verify_and_parse(&signed, &pub_b64(&k), 1_500, 1_000),
            Err(EndpointError::NotNewer)
        );
        assert!(verify_and_parse(&signed, &pub_b64(&k), 1_500, 999).is_ok());
    }

    #[test]
    fn rejects_expired_and_far_future_lists() {
        let k = key();
        let expired = sign(&k, &doc(1_000, 1_400));
        assert_eq!(
            verify_and_parse(&expired, &pub_b64(&k), 1_500, 0),
            Err(EndpointError::Expired)
        );
        let future = sign(&k, &doc(1_500 + CLOCK_SKEW_TOLERANCE_MS + 1, i64::MAX / 2));
        assert_eq!(
            verify_and_parse(&future, &pub_b64(&k), 1_500, 0),
            Err(EndpointError::Expired)
        );
    }

    #[test]
    fn rejects_unknown_version_and_empty_lists() {
        let k = key();
        let v9 = doc(1_000, 2_000_000).replace("\"v\":1", "\"v\":9");
        assert_eq!(
            verify_and_parse(&sign(&k, &v9), &pub_b64(&k), 1_500, 0),
            Err(EndpointError::Version(9))
        );
        let empty = serde_json::to_string(&EndpointList {
            v: 1,
            issued_at_ms: 1_000,
            expires_at_ms: 2_000_000,
            logical: Some(Logical {
                keys: "https://k".into(),
                relay: "https://r".into(),
            }),
            services: Default::default(),
            paths: vec![],
            tor_bridges: Vec::new(),
        })
        .unwrap();
        assert_eq!(
            verify_and_parse(&sign(&k, &empty), &pub_b64(&k), 1_500, 0),
            Err(EndpointError::Empty)
        );
    }

    #[test]
    fn signature_context_separates_purposes() {
        // A signature over the bare document, without the context, is refused.
        let k = key();
        let d = doc(1_000, 2_000_000);
        let sig = k.sign(d.as_bytes());
        let signed = serde_json::to_string(&SignedEndpointList {
            doc: d,
            sig_b64: B64.encode(sig.to_bytes()),
        })
        .unwrap();
        assert_eq!(
            verify_and_parse(&signed, &pub_b64(&k), 1_500, 0),
            Err(EndpointError::Signature)
        );
    }

    fn v2_doc(services: &[(&str, &str)], paths: serde_json::Value) -> String {
        let services: serde_json::Map<String, serde_json::Value> = services
            .iter()
            .map(|(k, v)| (k.to_string(), serde_json::Value::from(*v)))
            .collect();
        serde_json::json!({
            "v": 2,
            "issued_at_ms": 1_000,
            "expires_at_ms": 2_000_000,
            "services": services,
            "paths": paths,
        })
        .to_string()
    }

    fn sign_v2(k: &SigningKey, doc: &str) -> String {
        let sig = k.sign(&signing_message_v2(doc.as_bytes()));
        serde_json::to_string(&SignedEndpointList {
            doc: doc.to_string(),
            sig_b64: B64.encode(sig.to_bytes()),
        })
        .unwrap()
    }

    #[test]
    fn accepts_a_v2_list_with_named_services() {
        let k = key();
        let d = v2_doc(
            &[
                ("api", "https://api.example.org"),
                ("media", "https://media.example.org"),
            ],
            serde_json::json!([
                {"kind": "direct"},
                {"kind": "mirror", "targets": {"api": "https://m.example.net/a"}},
            ]),
        );
        let list = verify_and_parse(&sign_v2(&k, &d), &pub_b64(&k), 1_500, 0).unwrap();
        assert_eq!(list.v, 2);
        assert_eq!(list.service_base("api"), Some("https://api.example.org"));
        assert_eq!(list.service_base("keys"), None);
        assert_eq!(
            list.paths[1].target_base("api"),
            Some("https://m.example.net/a")
        );
        assert_eq!(
            list.paths[1].target_base("media"),
            None,
            "mirror does not serve media"
        );
    }

    #[test]
    fn a_signature_is_valid_only_for_its_own_format() {
        let k = key();
        // A format 2 document signed under the format 1 context.
        let d2 = v2_doc(
            &[("api", "https://a")],
            serde_json::json!([{"kind": "direct"}]),
        );
        assert_eq!(
            verify_and_parse(&sign(&k, &d2), &pub_b64(&k), 1_500, 0),
            Err(EndpointError::Signature)
        );
        // A format 1 document signed under the format 2 context.
        let d1 = doc(1_000, 2_000_000);
        assert_eq!(
            verify_and_parse(&sign_v2(&k, &d1), &pub_b64(&k), 1_500, 0),
            Err(EndpointError::Signature)
        );
    }

    #[test]
    fn v2_rejects_bad_or_too_many_service_names() {
        let k = key();
        let direct = serde_json::json!([{"kind": "direct"}]);
        for bad in ["Api", "-api", "a_b", "", &"x".repeat(33)] {
            let d = v2_doc(&[(bad, "https://a")], direct.clone());
            assert_eq!(
                verify_and_parse(&sign_v2(&k, &d), &pub_b64(&k), 1_500, 0),
                Err(EndpointError::ServiceName),
                "{bad:?}"
            );
        }
        let names: Vec<String> = (0..17).map(|i| format!("s{i}")).collect();
        let many: Vec<(&str, &str)> = names.iter().map(|n| (n.as_str(), "https://a")).collect();
        let d = v2_doc(&many, direct);
        assert_eq!(
            verify_and_parse(&sign_v2(&k, &d), &pub_b64(&k), 1_500, 0),
            Err(EndpointError::ServiceName)
        );
        assert!(is_valid_service_name("api-2"));
        assert!(is_valid_service_name(&"x".repeat(32)));
    }

    #[test]
    fn v2_rejects_a_target_for_an_unknown_service() {
        let k = key();
        let d = v2_doc(
            &[("api", "https://a")],
            serde_json::json!([{"kind": "cdn", "targets": {"media": "https://c"}}]),
        );
        assert_eq!(
            verify_and_parse(&sign_v2(&k, &d), &pub_b64(&k), 1_500, 0),
            Err(EndpointError::UnknownService)
        );
    }

    #[test]
    fn each_format_rejects_the_other_formats_fields() {
        let k = key();
        // Format 2 with format 1 mirror fields.
        let d = v2_doc(
            &[("api", "https://a")],
            serde_json::json!([{"kind": "mirror", "keys": "https://k", "relay": "https://r"}]),
        );
        assert_eq!(
            verify_and_parse(&sign_v2(&k, &d), &pub_b64(&k), 1_500, 0),
            Err(EndpointError::Document)
        );
        // Format 2 with `logical`.
        let d = serde_json::json!({
            "v": 2, "issued_at_ms": 1_000, "expires_at_ms": 2_000_000,
            "logical": {"keys": "https://k", "relay": "https://r"},
            "services": {"api": "https://a"},
            "paths": [{"kind": "direct"}],
        })
        .to_string();
        assert_eq!(
            verify_and_parse(&sign_v2(&k, &d), &pub_b64(&k), 1_500, 0),
            Err(EndpointError::Document)
        );
        // Format 1 with `services`, and with a mirror that lacks `relay`.
        let d = doc(1_000, 2_000_000).replace(
            "\"paths\"",
            "\"services\":{\"api\":\"https://a\"},\"paths\"",
        );
        assert_eq!(
            verify_and_parse(&sign(&k, &d), &pub_b64(&k), 1_500, 0),
            Err(EndpointError::Document)
        );
        let d = doc(1_000, 2_000_000).replace(",\"relay\":\"https://m1.example.net/r\"", "");
        assert_eq!(
            verify_and_parse(&sign(&k, &d), &pub_b64(&k), 1_500, 0),
            Err(EndpointError::Document)
        );
    }

    #[test]
    fn v2_tor_bridges_are_checked_but_not_parsed() {
        let k = key();
        let base = |bridges: serde_json::Value| {
            let mut d: serde_json::Value = serde_json::from_str(&v2_doc(
                &[("api", "https://a")],
                serde_json::json!([{"kind": "tor"}]),
            ))
            .unwrap();
            d["tor_bridges"] = bridges;
            sign_v2(&k, &d.to_string())
        };
        let line =
            "obfs4 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=AAAA iat-mode=0";
        let list =
            verify_and_parse(&base(serde_json::json!([line])), &pub_b64(&k), 1_500, 0).unwrap();
        assert_eq!(list.tor_bridges, vec![line.to_string()]);
        let too_many: Vec<&str> = std::iter::repeat_n(line, MAX_TOR_BRIDGES + 1).collect();
        let long = "x".repeat(MAX_TOR_BRIDGE_LEN + 1);
        for bad in [
            serde_json::json!(too_many),
            serde_json::json!([""]),
            serde_json::json!(["obfs4 a\nb"]),
            serde_json::json!(["obfs4 caf\u{e9}"]),
            serde_json::json!([long]),
        ] {
            assert_eq!(
                verify_and_parse(&base(bad.clone()), &pub_b64(&k), 1_500, 0),
                Err(EndpointError::TorBridge),
                "{bad}"
            );
        }
        // Format 1 has no bridges.
        let d1 =
            doc(1_000, 2_000_000).replace("\"paths\"", "\"tor_bridges\":[\"obfs4 x\"],\"paths\"");
        assert_eq!(
            verify_and_parse(&sign(&k, &d1), &pub_b64(&k), 1_500, 0),
            Err(EndpointError::Document)
        );
    }

    #[test]
    fn v1_json_shape_is_unchanged() {
        // The application builds and stores format 1 lists; adding format 2
        // must not change a single byte of how format 1 is written.
        assert_eq!(
            doc(1, 2),
            concat!(
                r#"{"v":1,"issued_at_ms":1,"expires_at_ms":2,"#,
                r#""logical":{"keys":"https://keys.example.com","relay":"https://relay.example.com"},"#,
                r#""paths":[{"kind":"direct"},{"kind":"ip","ip":"203.0.113.5"},"#,
                r#"{"kind":"mirror","keys":"https://m1.example.net/k","relay":"https://m1.example.net/r"},"#,
                r#"{"kind":"proxy","host":"vol.example.org","port":443},{"kind":"tor"}]}"#
            )
        );
    }

    #[test]
    fn path_json_shape_is_stable() {
        // The JSON shape is part of the protocol: servers, clients and people
        // read it.
        let p = PathSpec::Proxy {
            host: "vol.example.org".into(),
            port: 443,
        };
        assert_eq!(
            serde_json::to_string(&p).unwrap(),
            r#"{"kind":"proxy","host":"vol.example.org","port":443}"#
        );
        let parsed: PathSpec = serde_json::from_str(r#"{"kind":"proxy","host":"h"}"#).unwrap();
        assert_eq!(
            parsed,
            PathSpec::Proxy {
                host: "h".into(),
                port: 443
            }
        );
        let tor: PathSpec = serde_json::from_str(r#"{"kind":"tor"}"#).unwrap();
        assert_eq!(tor, PathSpec::Tor);
    }
}
