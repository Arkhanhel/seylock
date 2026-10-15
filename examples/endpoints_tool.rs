// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi
//! Operator tool for signed endpoint lists, and a way to try the local proxy.
//!
//! ```text
//! cargo run --example endpoints_tool -- keygen  <secret.key>
//! cargo run --example endpoints_tool -- sign    <secret.key> <list.json> [out.signed.json]
//! cargo run --example endpoints_tool -- verify  <public.b64> <list.signed.json>
//! cargo run --example endpoints_tool -- serve   <public.b64> <list.signed.json>
//! ```
//!
//! `keygen` writes a base64 Ed25519 secret key (keep it offline) and prints
//! the public key that clients pin. `sign` wraps a list document into the
//! signed envelope. `verify` checks it the way a client does. `serve` starts
//! the loopback proxy with that list and prints a ready `curl` command.

use std::io::BufRead as _;
use std::process::ExitCode;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signer as _, SigningKey};
use seylock::endpoints::{self, EndpointList, SignedEndpointList};
use seylock::paths::PathMemory;
use seylock::proxy::{self, HEADER_SERVICE, HEADER_TRANSPORT_TOKEN, Policy, Race};

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn read(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))
}

fn signing_key(path: &str) -> Result<SigningKey, String> {
    let bytes = B64
        .decode(read(path)?.trim())
        .map_err(|_| "secret key: not base64".to_string())?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "secret key: expected 32 bytes".to_string())?;
    Ok(SigningKey::from_bytes(&arr))
}

fn keygen(out: &str) -> Result<(), String> {
    if std::path::Path::new(out).exists() {
        return Err(format!("{out} already exists; refusing to overwrite a key"));
    }
    let key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    std::fs::write(out, B64.encode(key.to_bytes())).map_err(|e| format!("{out}: {e}"))?;
    println!("secret key written to {out} (keep it offline)");
    println!("public key: {}", B64.encode(key.verifying_key().to_bytes()));
    Ok(())
}

fn sign(secret: &str, list_path: &str, out: Option<&str>) -> Result<(), String> {
    let key = signing_key(secret)?;
    let raw = read(list_path)?;
    // Parse first, so a typo never gets signed; sign the compact form.
    let list: EndpointList =
        serde_json::from_str(&raw).map_err(|e| format!("{list_path}: not a list: {e}"))?;
    let doc = serde_json::to_string(&list).map_err(|e| e.to_string())?;
    // Each format has its own signing context.
    let message = match list.v {
        1 => endpoints::signing_message(doc.as_bytes()),
        2 => endpoints::signing_message_v2(doc.as_bytes()),
        v => return Err(format!("unsupported list version {v}")),
    };
    let sig = key.sign(&message);
    let signed = SignedEndpointList {
        doc,
        sig_b64: B64.encode(sig.to_bytes()),
    };
    let json = serde_json::to_string_pretty(&signed).map_err(|e| e.to_string())?;
    match out {
        Some(path) => {
            std::fs::write(path, json).map_err(|e| format!("{path}: {e}"))?;
            println!("signed list written to {path}");
        }
        None => println!("{json}"),
    }
    Ok(())
}

fn verify(public: &str, signed_path: &str) -> Result<EndpointList, String> {
    endpoints::verify_and_parse(&read(signed_path)?, public, now_ms(), 0)
        .map_err(|e| format!("rejected: {e:?} (code {})", e.code()))
}

fn serve(public: &str, signed_path: &str) -> Result<(), String> {
    let list = verify(public, signed_path)?;
    let list_services: Vec<String> = list.services.keys().cloned().collect();
    let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    let handle = runtime
        .block_on(proxy::start(Policy {
            list,
            memory: PathMemory::default(),
            network_id: "cli".into(),
            allow_tor: false,
            allow_socks: true,
            current: None,
            race: Race::default(),
        }))
        .map_err(|e| e.to_string())?;
    println!("proxy listening on 127.0.0.1:{}", handle.port);
    // A format 1 list has no `services`; its services are `keys` and `relay`.
    let service = list_services
        .first()
        .cloned()
        .unwrap_or_else(|| "relay".to_string());
    println!("try:");
    println!(
        "  curl -s -H '{HEADER_TRANSPORT_TOKEN}: {}' -H '{HEADER_SERVICE}: {service}' http://127.0.0.1:{}/health -D -",
        handle.token, handle.port
    );
    println!("the response header x-transport-path names the path that worked.");
    println!("press Enter to stop");
    let _ = std::io::stdin().lock().read_line(&mut String::new());
    drop(handle);
    Ok(())
}

fn run(args: &[String]) -> Result<(), String> {
    let arg = |i: usize| args.get(i).map(String::as_str);
    match (arg(1), arg(2), arg(3)) {
        (Some("keygen"), Some(out), _) => keygen(out),
        (Some("sign"), Some(secret), Some(list)) => sign(secret, list, arg(4)),
        (Some("verify"), Some(public), Some(signed)) => {
            let list = verify(public, signed)?;
            println!(
                "ok: format {}, {} path(s), issued {}, expires {}",
                list.v,
                list.paths.len(),
                list.issued_at_ms,
                list.expires_at_ms
            );
            for name in list.services.keys() {
                println!("  service {name}");
            }
            for (i, p) in list.paths.iter().enumerate() {
                println!("  [{i}] {}", p.kind().as_str());
            }
            Ok(())
        }
        (Some("serve"), Some(public), Some(signed)) => serve(public, signed),
        _ => Err("usage: endpoints_tool keygen <secret.key> | sign <secret.key> <list.json> [out] | verify <public.b64> <signed.json> | serve <public.b64> <signed.json>".into()),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
