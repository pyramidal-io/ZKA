// Copyright 2026 ZKA Contributors
// SPDX-License-Identifier: Apache-2.0

//! Fail-closed transport policy for every settlement RPC endpoint.
//!
//! Adapter client stacks accept any URL they can parse, including a cleartext
//! `http` / `ws` scheme pointing at an arbitrary remote host. That is not an
//! acceptable settlement posture on any chain: every observation an adapter
//! makes over that channel is security-relevant -- chain id, deployment code
//! hashes, event and log history, root windows, nullifier sets, confirmation
//! and finality depth -- and submission paths push signed transactions across
//! the same channel. On a cleartext channel an on-path attacker can forge all
//! of it: withhold or fabricate events, replay a stale root window, or lie
//! about confirmations so a submission looks final when it is not. TLS is what
//! binds those answers to the endpoint the operator pinned.
//!
//! This module is the single place that decides which endpoints any adapter
//! may talk to. It lives in the registry -- beside the finality floors it
//! complements -- so every adapter shares one policy without taking on another
//! adapter's dependency tree:
//!
//! * schemes are allowlisted per [`TransportProfile`]; anything outside the
//!   profile fails closed,
//! * the encrypted schemes (`https`, `wss`) are accepted for any host, and the
//!   cleartext ones (`http`, `ws`) only for an explicit loopback authority
//!   (`127.0.0.0/8`, `[::1]`, or `localhost`) so devnet flows keep working,
//!   and only under [`PlaintextPolicy::LoopbackOnly`],
//! * credentials embedded in the URL authority (username, password, or both) fail closed --
//!   they leak through every diagnostic that renders an endpoint,
//! * a validated endpoint renders (`Debug`/`Display`/[`RpcEndpoint::redacted`])
//!   as `scheme://host[:port]` only, so path- or query-carried provider API
//!   keys never reach logs, errors, or health output.
//!
//! Validation is shape-only: it never probes the endpoint.

use std::fmt;

use thiserror::Error;
use url::{Host, Url};

/// A transport-policy rejection.
///
/// Adapters map this into their own configuration error. The message never
/// echoes an endpoint's path, query, or credentials.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[error("{0}")]
pub struct TransportPolicyError(String);

/// Result of a transport-policy check.
pub type TransportResult<T> = std::result::Result<T, TransportPolicyError>;

/// Wire schemes a settlement adapter client stack can speak.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcScheme {
    /// Cleartext JSON-RPC over HTTP (loopback only).
    Http,
    /// JSON-RPC over TLS.
    Https,
    /// Cleartext JSON-RPC over WebSocket (loopback only).
    Ws,
    /// JSON-RPC over WebSocket Secure.
    Wss,
}

impl RpcScheme {
    fn from_scheme(scheme: &str) -> Option<Self> {
        match scheme {
            "http" => Some(Self::Http),
            "https" => Some(Self::Https),
            "ws" => Some(Self::Ws),
            "wss" => Some(Self::Wss),
            _ => None,
        }
    }

    /// Whether the scheme authenticates and encrypts the channel.
    pub const fn is_encrypted(self) -> bool {
        matches!(self, Self::Https | Self::Wss)
    }

    /// Canonical lowercase scheme name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
            Self::Ws => "ws",
            Self::Wss => "wss",
        }
    }

    /// The encrypted scheme that must be used instead of this one.
    const fn encrypted_counterpart(self) -> &'static str {
        match self {
            Self::Http | Self::Https => "https://",
            Self::Ws | Self::Wss => "wss://",
        }
    }
}

/// Which wire schemes an adapter's client stack can actually dial.
///
/// This is a capability statement, not a preference: an adapter whose client
/// is a plain HTTP JSON-RPC poster must reject `ws`/`wss` outright rather than
/// accept an endpoint it could never dial.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TransportProfile {
    /// HTTP(S) only -- CometBFT JSON-RPC, gRPC-JSON gateways, view/custody
    /// services, and any other `reqwest`-style POST client.
    #[default]
    Http,
    /// HTTP(S) plus WebSocket -- stacks with a subscription transport, such as
    /// the ethers provider stack built with its `ws` feature.
    HttpOrWebSocket,
}

impl TransportProfile {
    const fn accepts(self, scheme: RpcScheme) -> bool {
        match self {
            Self::Http => matches!(scheme, RpcScheme::Http | RpcScheme::Https),
            Self::HttpOrWebSocket => true,
        }
    }

    /// Human-readable allowlist, used in rejection messages.
    const fn allowlist(self) -> &'static str {
        match self {
            Self::Http => "https",
            Self::HttpOrWebSocket => "https/wss",
        }
    }

    /// The cleartext schemes this profile tolerates on loopback.
    const fn loopback_hint(self) -> &'static str {
        match self {
            Self::Http => "http only on loopback",
            Self::HttpOrWebSocket => "http/ws only on loopback",
        }
    }
}

/// How much cleartext the calling deployment tolerates.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PlaintextPolicy {
    /// Cleartext is permitted only for an explicit loopback authority. This is
    /// the default: it keeps local devnet flows working while every remote
    /// endpoint must be TLS.
    #[default]
    LoopbackOnly,
    /// Cleartext is rejected for every authority, loopback included. Use this
    /// where the deployment declares itself non-local (for example a holder
    /// adapter running with `local_integration = false`).
    Forbidden,
}

/// A settlement RPC endpoint that satisfied the transport policy.
///
/// `Debug` and `Display` render the redacted authority only, so an endpoint
/// can be logged without leaking a provider API key carried in the path or
/// query.
#[derive(Clone, PartialEq, Eq)]
pub struct RpcEndpoint {
    url: Url,
    scheme: RpcScheme,
    loopback: bool,
}

impl RpcEndpoint {
    /// Validate an endpoint for an HTTP(S)-only client stack under the default
    /// [`PlaintextPolicy::LoopbackOnly`].
    ///
    /// `field` names the configuration key in the error message.
    pub fn parse_http(field: &str, raw: &str) -> TransportResult<Self> {
        Self::parse(
            field,
            raw,
            TransportProfile::Http,
            PlaintextPolicy::default(),
        )
    }

    /// Validate an endpoint against an explicit profile and plaintext policy.
    pub fn parse(
        field: &str,
        raw: &str,
        profile: TransportProfile,
        policy: PlaintextPolicy,
    ) -> TransportResult<Self> {
        if raw.is_empty() {
            return Err(err(format!("{field} is empty")));
        }
        if raw.trim() != raw {
            return Err(err(format!(
                "{field} must not carry leading or trailing whitespace"
            )));
        }
        let url = Url::parse(raw).map_err(|e| err(format!("{field} is not a valid URL: {e}")))?;
        let scheme = RpcScheme::from_scheme(url.scheme())
            .filter(|scheme| profile.accepts(*scheme))
            .ok_or_else(|| {
                err(format!(
                    "{field} must be an {} endpoint ({}), got scheme `{}`",
                    profile.allowlist(),
                    profile.loopback_hint(),
                    url.scheme()
                ))
            })?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(err(format!(
                "{field} must not embed credentials in the URL; supply RPC credentials \
                 out of band (header or environment) so they never reach logs"
            )));
        }
        let host = url
            .host()
            .ok_or_else(|| err(format!("{field} must name a host")))?;
        let loopback = host_is_loopback(&host);
        let endpoint = Self {
            url: url.clone(),
            scheme,
            loopback,
        };
        if !scheme.is_encrypted() {
            match policy {
                PlaintextPolicy::LoopbackOnly if loopback => {}
                PlaintextPolicy::LoopbackOnly => {
                    return Err(err(format!(
                        "{field} must use {} for the non-loopback endpoint {endpoint}: \
                         cleartext RPC is permitted only for an explicit loopback \
                         authority (127.0.0.0/8, [::1], localhost)",
                        scheme.encrypted_counterpart()
                    )));
                }
                PlaintextPolicy::Forbidden => {
                    return Err(err(format!(
                        "{field} must use {} for endpoint {endpoint}: cleartext \
                         RPC is disabled for this deployment",
                        scheme.encrypted_counterpart()
                    )));
                }
            }
        }
        Ok(endpoint)
    }

    /// The exact endpoint string the client should be built from.
    ///
    /// Never log this: it may carry a provider API key in the path or query.
    /// Use [`Self::redacted`] (or `Display`) for anything operator-visible.
    pub fn as_str(&self) -> &str {
        self.url.as_str()
    }

    /// The validated URL.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Consume the endpoint and yield the validated URL.
    pub fn into_url(self) -> Url {
        self.url
    }

    /// The validated wire scheme.
    pub const fn scheme(&self) -> RpcScheme {
        self.scheme
    }

    /// Whether the authority is an explicit loopback authority.
    pub const fn is_loopback(&self) -> bool {
        self.loopback
    }

    /// Whether the channel is authenticated and encrypted.
    pub const fn is_encrypted(&self) -> bool {
        self.scheme.is_encrypted()
    }

    /// `scheme://host[:port]` -- safe to log, diagnose, and surface in health
    /// output. Path, query, fragment, and any credential are dropped.
    pub fn redacted(&self) -> String {
        let mut out = String::from(self.scheme.as_str());
        out.push_str("://");
        out.push_str(self.url.host_str().unwrap_or_default());
        if let Some(port) = self.url.port() {
            out.push(':');
            out.push_str(&port.to_string());
        }
        out
    }
}

impl fmt::Display for RpcEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.redacted())
    }
}

impl fmt::Debug for RpcEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RpcEndpoint")
            .field("endpoint", &self.redacted())
            .field("loopback", &self.loopback)
            .field("encrypted", &self.is_encrypted())
            .finish()
    }
}

/// Best-effort redaction of an unvalidated endpoint string, for diagnostics on
/// a value that never passed [`RpcEndpoint::parse`].
pub fn redact_endpoint(raw: &str) -> String {
    match Url::parse(raw.trim()) {
        Ok(url) => {
            let mut out = String::from(url.scheme());
            out.push_str("://");
            out.push_str(url.host_str().unwrap_or_default());
            if let Some(port) = url.port() {
                out.push(':');
                out.push_str(&port.to_string());
            }
            out
        }
        Err(_) => "<unparsable endpoint>".to_owned(),
    }
}

fn host_is_loopback(host: &Host<&str>) -> bool {
    match host {
        // `localhost` is the one name the policy accepts: it is reserved to
        // loopback (RFC 6761 6.3) and every devnet config in this tree uses
        // it. Named hosts otherwise resolve through DNS and cannot be treated
        // as loopback.
        Host::Domain(name) => {
            name.eq_ignore_ascii_case("localhost") || name.eq_ignore_ascii_case("localhost.")
        }
        Host::Ipv4(ip) => ip.is_loopback(),
        Host::Ipv6(ip) => ip.is_loopback(),
    }
}

fn err(message: String) -> TransportPolicyError {
    TransportPolicyError(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    const WS: TransportProfile = TransportProfile::HttpOrWebSocket;
    const HTTP: TransportProfile = TransportProfile::Http;

    fn parse(field: &str, raw: &str, profile: TransportProfile) -> TransportResult<RpcEndpoint> {
        RpcEndpoint::parse(field, raw, profile, PlaintextPolicy::LoopbackOnly)
    }

    #[test]
    fn tls_endpoints_are_accepted_for_any_host() {
        for raw in [
            "https://mainnet.base.org",
            "https://eth-mainnet.example.com/v2/key",
            "https://127.0.0.1:8545",
        ] {
            let endpoint = parse("rpc_url", raw, HTTP).unwrap();
            assert!(endpoint.is_encrypted(), "{raw}");
            assert_eq!(endpoint.as_str().trim_end_matches('/'), raw);
        }
        // wss is accepted only by the WebSocket-capable profile.
        assert!(parse("rpc_url", "wss://mainnet.base.org/ws", WS).is_ok());
    }

    #[test]
    fn cleartext_is_accepted_only_on_explicit_loopback() {
        for raw in [
            "http://localhost:26657",
            "http://LOCALHOST:26657",
            "http://127.0.0.1:8545",
            "http://127.0.0.2:8545",
            "http://[::1]:8545",
        ] {
            let endpoint = parse("rpc_url", raw, HTTP).unwrap();
            assert!(endpoint.is_loopback(), "{raw}");
            assert!(!endpoint.is_encrypted(), "{raw}");
        }
        // Cleartext WebSocket accepted ONLY on loopback is what this asserts;
        // the literal is an input to the policy, never a connection.
        // nosemgrep: javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket
        assert!(parse("rpc_url", "ws://127.0.0.1:8546", WS)
            .unwrap()
            .is_loopback());
    }

    #[test]
    fn cleartext_to_a_remote_host_fails_closed() {
        for raw in [
            "http://settlement-node:26657",
            "http://pd-gateway:8080",
            "http://10.0.0.5:8545",
            "http://[2001:db8::1]:8545",
            // Not loopback: a name that merely *contains* `localhost`.
            "http://localhost.attacker.example",
        ] {
            let err = parse("rpc_url", raw, HTTP).unwrap_err().to_string();
            assert!(err.contains("rpc_url must use"), "{raw}: {err}");
            assert!(err.contains("loopback"), "{raw}: {err}");
        }
        // Negative case: a remote cleartext WebSocket endpoint is REJECTED.
        // nosemgrep: javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket
        let err = parse("rpc_url", "ws://mainnet.base.org/ws", WS)
            .unwrap_err()
            .to_string();
        assert!(err.contains("wss://"), "{err}");
    }

    #[test]
    fn profile_rejects_schemes_the_client_cannot_dial() {
        // A CometBFT / gateway client speaks HTTP only: a WebSocket endpoint
        // it could never dial is rejected outright, loopback or not.
        // Negative case: an HTTP-only profile rejects WebSocket endpoints it
        // could never dial. The literals are inputs to the policy.
        // nosemgrep: javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket
        for raw in ["ws://localhost:26657", "wss://node.example.com"] {
            let err = parse("rpc_url", raw, HTTP).unwrap_err().to_string();
            assert!(err.contains("must be an https endpoint"), "{raw}: {err}");
        }
        // The same endpoints are fine for a WebSocket-capable stack.
        assert!(parse("rpc_url", "wss://node.example.com", WS).is_ok());
    }

    #[test]
    fn forbidden_policy_rejects_loopback_cleartext_too() {
        let err = RpcEndpoint::parse(
            "rpc_url",
            "http://127.0.0.1:8545",
            HTTP,
            PlaintextPolicy::Forbidden,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("cleartext RPC is disabled"), "{err}");

        RpcEndpoint::parse(
            "rpc_url",
            "https://node.example.com",
            HTTP,
            PlaintextPolicy::Forbidden,
        )
        .unwrap();
    }

    #[test]
    fn non_rpc_schemes_fail_closed() {
        for raw in [
            "ftp://not-http",
            "file:///etc/passwd",
            "grpc://gateway:8080",
        ] {
            let err = parse("rpc_url", raw, HTTP).unwrap_err().to_string();
            assert!(err.contains("must be an https endpoint"), "{raw}: {err}");
        }
    }

    #[test]
    fn embedded_credentials_fail_closed() {
        // Construct synthetic userinfo explicitly; these are dummy fixtures,
        // never an endpoint or credential supplied by an operator.
        for (username, password) in [
            ("fixture-user", Some("fixture-password")),
            ("fixture-user", None),
            ("", Some("fixture-password")),
        ] {
            let mut endpoint = Url::parse("https://node.example.com").unwrap();
            endpoint.set_username(username).unwrap();
            endpoint.set_password(password).unwrap();
            assert_eq!(endpoint.username(), username);
            assert_eq!(endpoint.password(), password);
            let err = parse("rpc_url", endpoint.as_str(), HTTP)
                .unwrap_err()
                .to_string();
            assert!(err.contains("must not embed credentials"), "{err}");
            if !username.is_empty() {
                assert!(!err.contains(username), "{err}");
            }
            if let Some(password) = password {
                assert!(!err.contains(password), "{err}");
            }
        }
    }

    #[test]
    fn empty_and_malformed_endpoints_fail_closed() {
        assert!(parse("rpc_url", "", HTTP)
            .unwrap_err()
            .to_string()
            .contains("is empty"));
        assert!(parse("rpc_url", " https://x.example ", HTTP)
            .unwrap_err()
            .to_string()
            .contains("whitespace"));
        assert!(parse("rpc_url", "not-a-url", HTTP)
            .unwrap_err()
            .to_string()
            .contains("not a valid URL"));
        // A scheme with no authority at all.
        assert!(parse("rpc_url", "https://", HTTP).is_err());
    }

    #[test]
    fn rendering_never_leaks_path_query_or_credentials() {
        let endpoint = parse(
            "rpc_url",
            "https://rpc.example.com:8443/v2/API-KEY?token=SECRET",
            HTTP,
        )
        .unwrap();
        let rendered = format!("{endpoint} {endpoint:?} {}", endpoint.redacted());
        assert!(rendered.contains("https://rpc.example.com:8443"));
        assert!(!rendered.contains("API-KEY"), "{rendered}");
        assert!(!rendered.contains("SECRET"), "{rendered}");
        // The exact endpoint is still available for the client itself.
        assert!(endpoint.as_str().contains("API-KEY"));
    }

    #[test]
    fn redaction_of_unvalidated_input_is_best_effort() {
        assert_eq!(
            redact_endpoint("https://rpc.example.com/v2/API-KEY"),
            "https://rpc.example.com"
        );
        assert_eq!(redact_endpoint("nonsense"), "<unparsable endpoint>");
    }
}
