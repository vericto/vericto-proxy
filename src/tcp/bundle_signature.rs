// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Ed25519 verification of the `/sync/rules` bundle (since 4.16.0; design
//! "Business policy rules" §13, "Policy tampering").
//!
//! With `VERICTO_POLICY_RULES` on, the bundle carries business policies that can
//! block, flag or exempt statements, so whoever can alter it in transit or at rest
//! (a TLS-intercepting middlebox, a tampered rules cache on a shared volume)
//! decides what the database runs. The control plane signs the exact body it sends
//! to a proxy that announces `cel/1`; this module checks that signature before the
//! rule sync swaps anything in. A bundle that does not verify is never applied: the
//! last good one stays in effect (in memory, and in the rules cache, which is only
//! written with a verified body and is verified again when it is loaded).
//!
//! **Format** (vericto-fmw `utils/bundle-signing.ts`, whose `verifyBundle` is the
//! reference check). One response header:
//!
//! ```text
//! X-Vericto-Bundle-Signature: scheme=ed25519-sha256; key-id=<id>; sha256=<hex digest>; sig=<base64>
//! ```
//!
//! The digest is SHA-256 over `vericto-sync-bundle/1\n` followed by the body bytes
//! exactly as received. The domain prefix keeps a signature over an audit export
//! (same signing key, same scheme) from ever verifying as a bundle. Ed25519 signs
//! the 32-byte digest as its message.
//!
//! **Keys.** Only public keys live here. The proxy trusts a keyring of
//! `(key id, Ed25519 public key)` pairs and the header's `key-id` picks one:
//!
//! * by default, the key the Vericto API at that address publishes, embedded in
//!   the binary and selected by `VERICTO_API_URL` (production or staging);
//! * `VERICTO_BUNDLE_SIGNING_KEYS` (JSON) or `VERICTO_BUNDLE_SIGNING_KEYS_FILE` (a
//!   path to the same JSON) replace that set, for a self-hosted control plane or a
//!   rotation ahead of a release. A malformed override is a startup error, never a
//!   silent fallback to the embedded keys.
//!
//! Any other API address with no override has no trusted key, and every bundle is
//! refused (`no_trusted_key`): an unknown control plane is never trusted by default.
//!
//! **Rotation.** Several keys may be trusted at once. First the new public key
//! reaches the proxies (a release that embeds both, or the override with both);
//! then the control plane switches its active signing key (the old public key goes
//! to its retired list); the old key is dropped from the proxies later. A bundle
//! signed by a key id the proxy does not hold is refused (`unknown_key_id`), so
//! switching the control plane first would leave proxies on their last good bundle
//! until they learn the new key: safe, but stale.
//!
//! Sync time only: nothing here runs per statement, and with the flag off nothing
//! here runs at all (no header read, no hash, no keyring).

use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::Deserialize;

/// The response header that carries the signature.
pub const SIGNATURE_HEADER: &str = "X-Vericto-Bundle-Signature";
/// The only scheme there is: Ed25519 over a SHA-256 digest.
pub const SCHEME: &str = "ed25519-sha256";
/// Prefix of the signed digest's input (domain separation).
const DOMAIN: &[u8] = b"vericto-sync-bundle/1\n";

/// The keyring override, JSON (`[{"key_id": …, "public_key": …}]`).
pub const KEYS_ENV: &str = "VERICTO_BUNDLE_SIGNING_KEYS";
/// A path to a file holding the same JSON.
pub const KEYS_FILE_ENV: &str = "VERICTO_BUNDLE_SIGNING_KEYS_FILE";

/// DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410), before the 32 key bytes.
const SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// The public keys each Vericto API signs bundles with, as published at its
/// `GET /api/v1/meta/export-signing-key` (read 2026-10-23). Origin, key id, and
/// the base64 of the key's SubjectPublicKeyInfo (the body of its PEM).
const EMBEDDED: &[(&str, &str, &str)] = &[
    (
        "https://api.vericto.com",
        "vericto-production-2026",
        "MCowBQYDK2VwAyEA9mKOkJB71O7ipsgmqy/TZNO6Zxhcj9K0GxZlwobevMU=",
    ),
    (
        "https://api-staging.vericto.com",
        "vericto-staging-2026",
        "MCowBQYDK2VwAyEAwGlu0bzL9L0CBGZtpqsvBIwv/AEnFQiJC/DNJUOJUHE=",
    ),
];

/// One trusted public key.
#[derive(Clone, PartialEq, Eq)]
pub struct TrustedKey {
    pub key_id: String,
    public_key: [u8; 32],
}

impl fmt::Debug for TrustedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustedKey")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl TrustedKey {
    /// A key from its id and raw 32 bytes.
    pub fn new(key_id: impl Into<String>, public_key: [u8; 32]) -> Self {
        Self {
            key_id: key_id.into(),
            public_key,
        }
    }
}

/// Where the keyring came from, for the startup log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySource {
    /// The keys embedded for this API address.
    Embedded,
    /// `VERICTO_BUNDLE_SIGNING_KEYS`.
    Env,
    /// `VERICTO_BUNDLE_SIGNING_KEYS_FILE`.
    File(PathBuf),
    /// Neither: an API address with no embedded key and no override.
    None,
}

/// The public keys a bundle may be signed with.
#[derive(Debug, Clone)]
pub struct Keyring {
    keys: Vec<TrustedKey>,
    source: KeySource,
}

#[derive(Deserialize)]
struct RawKey {
    key_id: String,
    public_key: String,
}

impl Keyring {
    /// A keyring of exactly `keys`.
    pub fn new(keys: Vec<TrustedKey>, source: KeySource) -> Self {
        Self { keys, source }
    }

    pub fn source(&self) -> &KeySource {
        &self.source
    }

    pub fn key_ids(&self) -> Vec<&str> {
        self.keys.iter().map(|k| k.key_id.as_str()).collect()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// The keyring for a proxy linked to `api_url`: the override when one is set
    /// (`var` reads the environment), else the keys embedded for that address, else
    /// none. A malformed override, or both overrides at once, is an error.
    pub fn from_vars(api_url: &str, var: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let env = var(KEYS_ENV).filter(|v| !v.trim().is_empty());
        let file = var(KEYS_FILE_ENV).filter(|v| !v.trim().is_empty());
        match (env, file) {
            (Some(_), Some(_)) => Err(format!(
                "{KEYS_ENV} and {KEYS_FILE_ENV} are both set: set one of them"
            )),
            (Some(json), None) => Ok(Self::new(parse_keys(&json, KEYS_ENV)?, KeySource::Env)),
            (None, Some(path)) => {
                let path = PathBuf::from(path.trim());
                let json = std::fs::read_to_string(&path).map_err(|e| {
                    format!("{KEYS_FILE_ENV}={}: cannot read it: {e}", path.display())
                })?;
                Ok(Self::new(
                    parse_keys(&json, KEYS_FILE_ENV)?,
                    KeySource::File(path),
                ))
            }
            (None, None) => Ok(Self::embedded_for(api_url)),
        }
    }

    /// The keys embedded for `api_url` (scheme and host compared case-insensitively,
    /// a trailing slash ignored); an empty keyring for any other address.
    pub fn embedded_for(api_url: &str) -> Self {
        let origin = api_url.trim().trim_end_matches('/').to_ascii_lowercase();
        let keys: Vec<TrustedKey> = EMBEDDED
            .iter()
            .filter(|(o, _, _)| *o == origin)
            .map(|(_, id, spki)| {
                TrustedKey::new(
                    *id,
                    decode_public_key(spki).expect("embedded bundle-signing keys are valid"),
                )
            })
            .collect();
        let source = if keys.is_empty() {
            KeySource::None
        } else {
            KeySource::Embedded
        };
        Self::new(keys, source)
    }

    /// Checks `header` against `body` (the bytes exactly as received). `Ok` names
    /// the key that signed it.
    pub fn verify(&self, body: &[u8], header: Option<&str>) -> Result<String, Rejection> {
        let header = header.ok_or(Rejection::Missing)?;
        let sig = ParsedSignature::parse(header).ok_or(Rejection::Malformed)?;
        if sig.scheme != SCHEME {
            return Err(Rejection::UnsupportedScheme);
        }
        if self.keys.is_empty() {
            return Err(Rejection::NoTrustedKey);
        }
        let digest = bundle_digest(body);
        if !hex_eq(digest.as_ref(), sig.sha256) {
            return Err(Rejection::DigestMismatch);
        }
        let Some(key) = self.keys.iter().find(|k| k.key_id == sig.key_id) else {
            return Err(Rejection::UnknownKeyId(sig.key_id.to_string()));
        };
        let signature = BASE64
            .decode(sig.sig.trim())
            .map_err(|_| Rejection::Malformed)?;
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key.public_key)
            .verify(digest.as_ref(), &signature)
            .map_err(|_| Rejection::BadSignature(key.key_id.clone()))?;
        Ok(key.key_id.clone())
    }
}

/// SHA-256 over the domain prefix and `body`: what a bundle signature signs.
pub fn bundle_digest(body: &[u8]) -> ring::digest::Digest {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    ctx.update(DOMAIN);
    ctx.update(body);
    ctx.finish()
}

/// Whether `hex` (any case) spells exactly `bytes`.
fn hex_eq(bytes: &[u8], hex: &str) -> bool {
    let hex = hex.as_bytes();
    if hex.len() != bytes.len() * 2 {
        return false;
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    bytes.iter().zip(hex.chunks(2)).all(|(b, pair)| {
        matches!((nibble(pair[0]), nibble(pair[1])), (Some(h), Some(l)) if (h << 4 | l) == *b)
    })
}

/// The header's fields. `;`-separated `name=value` pairs; all four are required.
struct ParsedSignature<'a> {
    scheme: &'a str,
    key_id: &'a str,
    sha256: &'a str,
    sig: &'a str,
}

impl<'a> ParsedSignature<'a> {
    fn parse(header: &'a str) -> Option<Self> {
        let (mut scheme, mut key_id, mut sha256, mut sig) = (None, None, None, None);
        for part in header.split(';') {
            let (name, value) = part.split_once('=')?;
            let (name, value) = (name.trim(), value.trim());
            if name.is_empty() {
                return None;
            }
            match name {
                "scheme" => scheme = Some(value),
                "key-id" => key_id = Some(value),
                "sha256" => sha256 = Some(value),
                "sig" => sig = Some(value),
                _ => {}
            }
        }
        let s = Self {
            scheme: scheme.filter(|v| !v.is_empty())?,
            key_id: key_id.filter(|v| !v.is_empty())?,
            sha256: sha256.filter(|v| !v.is_empty())?,
            sig: sig.filter(|v| !v.is_empty())?,
        };
        Some(s)
    }
}

/// Parses the override JSON. Every entry must be valid and every key id unique:
/// a typo in a trust anchor is a startup error, not a key silently skipped.
pub fn parse_keys(json: &str, origin: &str) -> Result<Vec<TrustedKey>, String> {
    let raw: Vec<RawKey> = serde_json::from_str(json).map_err(|e| {
        format!(
            "{origin} must be a JSON array of {{\"key_id\": …, \"public_key\": …}} objects: {e}"
        )
    })?;
    if raw.is_empty() {
        return Err(format!(
            "{origin} lists no key: every bundle would be refused. Unset it to use the keys \
             embedded for the Vericto API"
        ));
    }
    let mut keys: Vec<TrustedKey> = Vec::with_capacity(raw.len());
    for (i, k) in raw.into_iter().enumerate() {
        let key_id = k.key_id.trim().to_string();
        if key_id.is_empty() {
            return Err(format!("{origin}[{i}]: key_id is empty"));
        }
        if keys.iter().any(|t| t.key_id == key_id) {
            return Err(format!("{origin}[{i}]: key_id {key_id:?} is listed twice"));
        }
        let public_key = decode_public_key(&k.public_key).map_err(|e| {
            format!("{origin}[{i}] ({key_id}): public_key is not an Ed25519 public key: {e}")
        })?;
        keys.push(TrustedKey::new(key_id, public_key));
    }
    Ok(keys)
}

/// An Ed25519 public key from a PEM (`-----BEGIN PUBLIC KEY-----`, newlines real or
/// escaped as `\n`), the base64 of its SubjectPublicKeyInfo, or the base64 of the
/// raw 32 bytes.
pub fn decode_public_key(text: &str) -> Result<[u8; 32], String> {
    let text = text.replace("\\n", "\n");
    let b64: String = if text.contains("-----BEGIN") {
        let begin = "-----BEGIN PUBLIC KEY-----";
        let end = "-----END PUBLIC KEY-----";
        let start = text
            .find(begin)
            .ok_or("only a PUBLIC KEY PEM is accepted (never a private key)")?
            + begin.len();
        let stop = text[start..].find(end).ok_or("the PEM has no END line")? + start;
        text[start..stop].split_whitespace().collect()
    } else {
        text.split_whitespace().collect()
    };
    let der = BASE64
        .decode(b64.as_bytes())
        .map_err(|e| format!("not base64: {e}"))?;
    let raw: &[u8] = match der.len() {
        32 => &der,
        44 if der[..12] == SPKI_PREFIX => &der[12..],
        44 => return Err("not an Ed25519 SubjectPublicKeyInfo".into()),
        n => return Err(format!("{n} bytes; an Ed25519 public key has 32")),
    };
    let mut out = [0u8; 32];
    out.copy_from_slice(raw);
    Ok(out)
}

/// Why a bundle was refused. `reason()` is the log field and the metric label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejection {
    /// No signature header.
    Missing,
    /// The header (or its signature) cannot be read.
    Malformed,
    /// A scheme other than `ed25519-sha256`.
    UnsupportedScheme,
    /// The header's digest is not the body's: the body changed after signing.
    DigestMismatch,
    /// Signed with a key this proxy does not trust.
    UnknownKeyId(String),
    /// The signature does not verify with the key it names.
    BadSignature(String),
    /// This proxy trusts no key (an API address with no embedded key, no override).
    NoTrustedKey,
}

/// Every [`Rejection::reason`], in metric order.
pub const REASONS: [&str; 7] = [
    "missing",
    "malformed",
    "unsupported_scheme",
    "digest_mismatch",
    "unknown_key_id",
    "bad_signature",
    "no_trusted_key",
];

impl Rejection {
    pub fn reason(&self) -> &'static str {
        REASONS[self.index()]
    }

    fn index(&self) -> usize {
        match self {
            Self::Missing => 0,
            Self::Malformed => 1,
            Self::UnsupportedScheme => 2,
            Self::DigestMismatch => 3,
            Self::UnknownKeyId(_) => 4,
            Self::BadSignature(_) => 5,
            Self::NoTrustedKey => 6,
        }
    }

    /// The key id the header named, when it got that far.
    pub fn key_id(&self) -> Option<&str> {
        match self {
            Self::UnknownKeyId(k) | Self::BadSignature(k) => Some(k),
            _ => None,
        }
    }
}

/// Where a refused bundle came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleSource {
    /// A `/sync/rules` response.
    Sync,
    /// The rules cache on disk, at startup.
    Cache,
}

impl BundleSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sync => "sync",
            Self::Cache => "cache",
        }
    }
}

/// Counters of the verification, for `/metrics` (process lifetime). Only exists
/// with policy rules on, so a proxy with the flag off exposes nothing new.
#[derive(Debug, Default)]
pub struct SignatureStats {
    accepted: AtomicU64,
    rejected: [AtomicU64; 7],
    /// 1 once a verified bundle is in effect.
    verified_in_effect: AtomicU64,
}

impl SignatureStats {
    pub fn record_accepted(&self) {
        self.accepted.fetch_add(1, Ordering::Relaxed);
        self.verified_in_effect.store(1, Ordering::Relaxed);
    }

    pub fn record_rejected(&self, r: &Rejection) {
        self.rejected[r.index()].fetch_add(1, Ordering::Relaxed);
    }

    pub fn accepted(&self) -> u64 {
        self.accepted.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub fn rejected(&self, reason: &str) -> u64 {
        REASONS
            .iter()
            .position(|r| *r == reason)
            .map_or(0, |i| self.rejected[i].load(Ordering::Relaxed))
    }

    pub fn verified_in_effect(&self) -> bool {
        self.verified_in_effect.load(Ordering::Relaxed) == 1
    }

    /// The Prometheus text of these counters (appended to `/metrics`).
    pub fn render_prometheus(&self) -> String {
        use std::fmt::Write as _;
        let p = crate::telemetry::metrics::PREFIX;
        let mut out = String::with_capacity(1024);
        let _ = writeln!(
            out,
            "# HELP {p}bundle_signature_verified 1 when the rules in effect come from a sync bundle whose Ed25519 signature verified; 0 while the built-in ruleset is in effect.\n\
             # TYPE {p}bundle_signature_verified gauge\n\
             {p}bundle_signature_verified {}",
            self.verified_in_effect.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "# HELP {p}bundle_signature_accepted_total Sync bundles (responses and the rules cache) whose signature verified since the process started.\n\
             # TYPE {p}bundle_signature_accepted_total counter\n\
             {p}bundle_signature_accepted_total {}",
            self.accepted()
        );
        let _ = writeln!(
            out,
            "# HELP {p}bundle_signature_rejected_total Sync bundles refused for their signature since the process started, by reason; the last good bundle stayed in effect.\n\
             # TYPE {p}bundle_signature_rejected_total counter"
        );
        for (i, reason) in REASONS.iter().enumerate() {
            let _ = writeln!(
                out,
                "{p}bundle_signature_rejected_total{{reason=\"{reason}\"}} {}",
                self.rejected[i].load(Ordering::Relaxed)
            );
        }
        out
    }
}

/// What the rule sync needs to verify: the keyring and the counters.
#[derive(Debug)]
pub struct BundleVerifier {
    pub keyring: Keyring,
    pub stats: std::sync::Arc<SignatureStats>,
}

impl BundleVerifier {
    pub fn new(keyring: Keyring) -> Self {
        Self {
            keyring,
            stats: Default::default(),
        }
    }

    /// Verifies one bundle and records the outcome: the log line and the counter.
    pub fn check(&self, body: &[u8], header: Option<&str>, source: BundleSource) -> bool {
        match self.keyring.verify(body, header) {
            Ok(key_id) => {
                self.stats.record_accepted();
                tracing::debug!(key_id = %key_id, source = source.as_str(), "Sync bundle signature verified");
                true
            }
            Err(r) => {
                self.stats.record_rejected(&r);
                tracing::warn!(
                    alert = "bundle_signature_rejected",
                    reason = r.reason(),
                    key_id = r.key_id().unwrap_or(""),
                    source = source.as_str(),
                    trusted_key_ids = ?self.keyring.key_ids(),
                    verified_bundle_in_effect = self.stats.verified_in_effect(),
                    "Sync bundle refused: its Ed25519 signature does not verify. It was not applied; \
                     the last good bundle stays in effect (the built-in ruleset if there is none yet)"
                );
                false
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    /// A throwaway signing key, generated per test: no private key is committed.
    pub struct TestSigner {
        pub key_id: String,
        pair: Ed25519KeyPair,
    }

    impl TestSigner {
        pub fn new(key_id: &str) -> Self {
            let rng = ring::rand::SystemRandom::new();
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
            Self {
                key_id: key_id.to_string(),
                pair: Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap(),
            }
        }

        pub fn trusted(&self) -> TrustedKey {
            let mut k = [0u8; 32];
            k.copy_from_slice(self.pair.public_key().as_ref());
            TrustedKey::new(self.key_id.clone(), k)
        }

        /// The PEM of the public key, as the control plane publishes it.
        pub fn public_pem(&self) -> String {
            let mut der = SPKI_PREFIX.to_vec();
            der.extend_from_slice(self.pair.public_key().as_ref());
            format!(
                "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
                BASE64.encode(der)
            )
        }

        pub fn raw_b64(&self) -> String {
            BASE64.encode(self.pair.public_key().as_ref())
        }

        /// The header value the control plane would send for `body`.
        pub fn header(&self, body: &[u8]) -> String {
            let digest = bundle_digest(body);
            let hex: String = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();
            let sig = self.pair.sign(digest.as_ref());
            format!(
                "scheme={SCHEME}; key-id={}; sha256={hex}; sig={}",
                self.key_id,
                BASE64.encode(sig.as_ref())
            )
        }
    }

    pub fn ring_of(signers: &[&TestSigner]) -> Keyring {
        Keyring::new(
            signers.iter().map(|s| s.trusted()).collect(),
            KeySource::Env,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    const BODY: &[u8] = br#"{"version":"v1","rules":[]}"#;

    #[test]
    fn a_valid_signature_verifies_and_names_its_key() {
        let s = TestSigner::new("k1");
        let ring = ring_of(&[&s]);
        assert_eq!(ring.verify(BODY, Some(&s.header(BODY))), Ok("k1".into()));
    }

    #[test]
    fn a_tampered_body_is_a_digest_mismatch() {
        let s = TestSigner::new("k1");
        let header = s.header(BODY);
        let tampered = br#"{"version":"v1","rules":[] }"#;
        assert_eq!(
            ring_of(&[&s]).verify(tampered, Some(&header)),
            Err(Rejection::DigestMismatch)
        );
    }

    #[test]
    fn a_digest_that_matches_but_a_forged_signature_fails() {
        let s = TestSigner::new("k1");
        let mut header = s.header(BODY);
        // Replace the signature with another body's (valid base64, wrong message).
        let other = s.header(b"other");
        let forged = other.rsplit("sig=").next().unwrap().to_string();
        let at = header.find("sig=").unwrap();
        header.replace_range(at.., &format!("sig={forged}"));
        assert_eq!(
            ring_of(&[&s]).verify(BODY, Some(&header)),
            Err(Rejection::BadSignature("k1".into()))
        );
    }

    #[test]
    fn a_wrong_key_under_the_trusted_id_fails() {
        let attacker = TestSigner::new("k1");
        let real = TestSigner::new("k1");
        assert_eq!(
            ring_of(&[&real]).verify(BODY, Some(&attacker.header(BODY))),
            Err(Rejection::BadSignature("k1".into()))
        );
    }

    #[test]
    fn an_untrusted_key_id_is_refused() {
        let other = TestSigner::new("other");
        let real = TestSigner::new("k1");
        assert_eq!(
            ring_of(&[&real]).verify(BODY, Some(&other.header(BODY))),
            Err(Rejection::UnknownKeyId("other".into()))
        );
    }

    #[test]
    fn rotation_trusts_every_key_in_the_ring() {
        let old = TestSigner::new("2026");
        let new = TestSigner::new("2027");
        let both = ring_of(&[&old, &new]);
        assert_eq!(
            both.verify(BODY, Some(&old.header(BODY))),
            Ok("2026".into())
        );
        assert_eq!(
            both.verify(BODY, Some(&new.header(BODY))),
            Ok("2027".into())
        );
        let after = ring_of(&[&new]);
        assert_eq!(
            after.verify(BODY, Some(&old.header(BODY))),
            Err(Rejection::UnknownKeyId("2026".into()))
        );
    }

    #[test]
    fn missing_malformed_and_foreign_headers_are_refused() {
        let s = TestSigner::new("k1");
        let ring = ring_of(&[&s]);
        assert_eq!(ring.verify(BODY, None), Err(Rejection::Missing));
        for bad in [
            "",
            "garbage",
            "scheme=ed25519-sha256; key-id=k1",
            "=x; scheme=a",
        ] {
            assert_eq!(
                ring.verify(BODY, Some(bad)),
                Err(Rejection::Malformed),
                "{bad}"
            );
        }
        let header = s.header(BODY).replace(SCHEME, "rsa-sha256");
        assert_eq!(
            ring.verify(BODY, Some(&header)),
            Err(Rejection::UnsupportedScheme)
        );
        let header = s.header(BODY).replace("sig=", "sig=!!");
        assert_eq!(ring.verify(BODY, Some(&header)), Err(Rejection::Malformed));
        let empty = Keyring::new(Vec::new(), KeySource::None);
        assert_eq!(
            empty.verify(BODY, Some(&s.header(BODY))),
            Err(Rejection::NoTrustedKey)
        );
    }

    #[test]
    fn embedded_keys_follow_the_api_address() {
        let prod = Keyring::embedded_for("https://api.vericto.com/");
        assert_eq!(prod.key_ids(), vec!["vericto-production-2026"]);
        assert_eq!(prod.source(), &KeySource::Embedded);
        let staging = Keyring::embedded_for("HTTPS://API-STAGING.vericto.com");
        assert_eq!(staging.key_ids(), vec!["vericto-staging-2026"]);
        let other = Keyring::embedded_for("https://vericto.internal.example");
        assert!(other.is_empty());
        assert_eq!(other.source(), &KeySource::None);
    }

    #[test]
    fn overrides_replace_the_embedded_keys() {
        let a = TestSigner::new("a");
        let b = TestSigner::new("b");
        // PEM with escaped newlines (as SSM stores it) and raw base64.
        let json = serde_json::json!([
            {"key_id": "a", "public_key": a.public_pem().replace('\n', "\\n")},
            {"key_id": "b", "public_key": b.raw_b64()},
        ])
        .to_string();
        let vars = |k: &str| (k == KEYS_ENV).then(|| json.clone());
        let ring = Keyring::from_vars("https://api.vericto.com", vars).unwrap();
        assert_eq!(ring.key_ids(), vec!["a", "b"]);
        assert_eq!(ring.source(), &KeySource::Env);
        assert_eq!(ring.verify(BODY, Some(&b.header(BODY))), Ok("b".into()));

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.json");
        std::fs::write(&path, &json).unwrap();
        let p = path.to_string_lossy().into_owned();
        let vars = |k: &str| (k == KEYS_FILE_ENV).then(|| p.clone());
        let ring = Keyring::from_vars("https://api.vericto.com", vars).unwrap();
        assert_eq!(ring.source(), &KeySource::File(path.clone()));
        assert_eq!(ring.verify(BODY, Some(&a.header(BODY))), Ok("a".into()));
    }

    #[test]
    fn a_malformed_override_is_an_error_never_a_fallback() {
        let s = TestSigner::new("a");
        let cases = [
            "not json".to_string(),
            "[]".to_string(),
            r#"[{"key_id": "", "public_key": "x"}]"#.to_string(),
            r#"[{"key_id": "a", "public_key": "bm90IGEga2V5"}]"#.to_string(),
            format!(
                r#"[{{"key_id": "a", "public_key": "{0}"}}, {{"key_id": "a", "public_key": "{0}"}}]"#,
                s.raw_b64()
            ),
            r#"[{"key_id": "a", "public_key": "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"}]"#
                .to_string(),
        ];
        for json in cases {
            let vars = |k: &str| (k == KEYS_ENV).then(|| json.clone());
            assert!(
                Keyring::from_vars("https://api.vericto.com", vars).is_err(),
                "{json}"
            );
        }
        let both = |k: &str| Some(format!("{k}-set"));
        let err = Keyring::from_vars("https://api.vericto.com", both).unwrap_err();
        assert!(err.contains("both set"), "{err}");
        let missing = |k: &str| (k == KEYS_FILE_ENV).then(|| "/nonexistent/keys.json".to_string());
        assert!(Keyring::from_vars("https://api.vericto.com", missing).is_err());
    }

    #[test]
    fn the_counters_render_every_reason() {
        let stats = SignatureStats::default();
        stats.record_rejected(&Rejection::DigestMismatch);
        stats.record_rejected(&Rejection::Missing);
        stats.record_rejected(&Rejection::Missing);
        let page = stats.render_prometheus();
        assert!(page.contains("vericto_proxy_bundle_signature_verified 0"));
        assert!(
            page.contains("vericto_proxy_bundle_signature_rejected_total{reason=\"missing\"} 2")
        );
        assert!(page.contains(
            "vericto_proxy_bundle_signature_rejected_total{reason=\"digest_mismatch\"} 1"
        ));
        stats.record_accepted();
        let page = stats.render_prometheus();
        assert!(page.contains("vericto_proxy_bundle_signature_verified 1"));
        assert!(page.contains("vericto_proxy_bundle_signature_accepted_total 1"));
        assert_eq!(
            page.matches("rejected_total{reason=").count(),
            REASONS.len()
        );
    }
}
