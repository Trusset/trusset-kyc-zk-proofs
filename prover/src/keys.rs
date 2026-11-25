//! Operator key material for the prover and the registry binary.
//!
//! Two sources, in this order:
//!
//! 1. **The CLI, over stdin.** When `TRUSSET_KYC_KEYS_STDIN=1`, the first line
//!    of stdin is `{"masterKey":"<64 hex>","signingKey":"<64 hex>"}` and the
//!    rest is the job. The CLI decrypts the operator's key file (or reads the
//!    macOS keychain) and writes that line; the keys never enter an
//!    environment variable or a file. Either key may be omitted when the
//!    command does not need it.
//! 2. **Environment variables**, `TRUSSET_KYC_MASTER_KEY` and
//!    `TRUSSET_KYC_SIGNING_KEY`. Kept for CI and for scripted test runs. An
//!    operator machine should use the key file or the keychain.

use crate::errors::{ErrorCode, ProverError, Result};
use crate::sign::SigningSecret;
use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

pub const ENV_KEYS_STDIN: &str = "TRUSSET_KYC_KEYS_STDIN";
pub const ENV_MASTER_KEY: &str = "TRUSSET_KYC_MASTER_KEY";
pub const ENV_SIGNING_KEY: &str = "TRUSSET_KYC_SIGNING_KEY";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyLine {
    #[serde(rename = "masterKey", default)]
    master_key: Option<String>,
    #[serde(rename = "signingKey", default)]
    signing_key: Option<String>,
}

impl Drop for KeyLine {
    fn drop(&mut self) {
        if let Some(k) = self.master_key.as_mut() {
            k.zeroize();
        }
        if let Some(k) = self.signing_key.as_mut() {
            k.zeroize();
        }
    }
}

/// Keys handed over by the CLI on stdin, if any.
#[derive(Default)]
pub struct StdinKeys {
    master: Option<Zeroizing<[u8; 32]>>,
    signing: Option<SigningSecret>,
}

impl std::fmt::Debug for StdinKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StdinKeys(<redacted>)")
    }
}

/// Whether the CLI announced keys on stdin.
#[must_use]
pub fn keys_on_stdin() -> bool {
    std::env::var(ENV_KEYS_STDIN)
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// Split the key line off the front of `input` when keys are on stdin. The
/// key line is wiped from `input`; what is left is the job.
pub fn take_stdin_keys(input: &mut String) -> Result<StdinKeys> {
    if !keys_on_stdin() {
        return Ok(StdinKeys::default());
    }
    let Some(nl) = input.find('\n') else {
        input.zeroize();
        return Err(ProverError::new(
            ErrorCode::KeyMissing,
            format!(
                "{}=1 but stdin carries no key line. The CLI writes it; run the prover through \
                 the CLI or unset {}.",
                ENV_KEYS_STDIN, ENV_KEYS_STDIN
            ),
        ));
    };
    let mut line: String = input[..nl].to_string();
    let rest = input[nl + 1..].to_string();
    input.zeroize();
    *input = rest;
    let parsed: std::result::Result<KeyLine, _> = serde_json::from_str(&line);
    line.zeroize();
    let parsed = parsed.map_err(|_| {
        ProverError::new(
            ErrorCode::KeyMalformed,
            "the key line on stdin is not {\"masterKey\":\"<hex>\",\"signingKey\":\"<hex>\"}",
        )
    })?;
    let master = match parsed.master_key.as_deref() {
        Some(h) => Some(parse_key32(h, "masterKey")?),
        None => None,
    };
    let signing = match parsed.signing_key.as_deref() {
        Some(h) => Some(SigningSecret::from_hex(h)?),
        None => None,
    };
    Ok(StdinKeys { master, signing })
}

impl StdinKeys {
    /// The master key: from stdin when the CLI sent it, else from the
    /// environment.
    pub fn master_key(&self) -> Result<Zeroizing<[u8; 32]>> {
        if let Some(k) = self.master.as_ref() {
            return Ok(k.clone());
        }
        let mut hex = std::env::var(ENV_MASTER_KEY).map_err(|_| missing(ENV_MASTER_KEY))?;
        let out = parse_key32(&hex, ENV_MASTER_KEY);
        hex.zeroize();
        out
    }

    /// The signing key: from stdin when the CLI sent it, else from the
    /// environment.
    pub fn signing_key(&mut self) -> Result<SigningSecret> {
        if let Some(k) = self.signing.take() {
            return Ok(k);
        }
        let mut hex = std::env::var(ENV_SIGNING_KEY).map_err(|_| missing(ENV_SIGNING_KEY))?;
        let out = SigningSecret::from_hex(&hex);
        hex.zeroize();
        out
    }
}

fn missing(env: &str) -> ProverError {
    ProverError::new(
        ErrorCode::KeyMissing,
        format!(
            "no key material: run through the CLI, which reads your encrypted key file or the \
             keychain, or (CI only) set {} to 32 bytes of hex",
            env
        ),
    )
}

fn parse_key32(hex_str: &str, name: &str) -> Result<Zeroizing<[u8; 32]>> {
    let mut bytes = hex::decode(hex_str.trim().trim_start_matches("0x"))
        .map_err(|_| ProverError::new(ErrorCode::KeyMalformed, format!("{} is not hex", name)))?;
    if bytes.len() != 32 {
        let n = bytes.len();
        bytes.zeroize();
        return Err(ProverError::new(
            ErrorCode::KeyMalformed,
            format!("{} must be 32 bytes (64 hex chars), got {}", name, n),
        ));
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&bytes);
    bytes.zeroize();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_line_parses_and_rejects_garbage() {
        let line = format!(
            "{{\"masterKey\":\"{}\",\"signingKey\":\"{}\"}}",
            "11".repeat(32),
            "42".repeat(32)
        );
        let parsed: KeyLine = serde_json::from_str(&line).unwrap();
        assert!(parse_key32(parsed.master_key.as_deref().unwrap(), "m").is_ok());
        assert!(SigningSecret::from_hex(parsed.signing_key.as_deref().unwrap()).is_ok());
        assert!(serde_json::from_str::<KeyLine>("{\"other\":1}").is_err());
        assert!(parse_key32("abcd", "m").is_err());
        assert!(parse_key32("zz", "m").is_err());
    }
}
