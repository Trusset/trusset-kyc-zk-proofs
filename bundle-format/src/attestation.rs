//! v3.1 `attestation.json`: the values the issuer app turns into the hub's
//! `attest` calldata for one subject.
//!
//! Every value is derived from the signed manifest, never supplied
//! separately, so a verifier can rebuild it and compare it with what the hub
//! holds:
//!
//! - `investorClass`: `publicInputs.minTier` of the single `INVESTOR_CLASS`
//!   leaf.
//! - `predicates`: `KYC_DONE` plus the bit of every leaf predicate, as a
//!   decimal `uint128`. `predicateNames` lists the same bits in bit order.
//! - `softExpiry` / `hardExpiry`: unix seconds,
//!   `(epochDays + passthrough.<x>ExpiryDays) * 86400`, or 0 when the day
//!   count is 0 (the hub reads 0 as "none").
//! - `attester`, `chainId`, `hub`, `keyId`: the manifest's `chain` block.

use serde::{Deserialize, Serialize};

use crate::manifest::{is_v31, Manifest};
use crate::predicates::{bit_of, mask_of, names_of, INVESTOR_CLASS, KYC_DONE};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AttestationFile {
    pub version: String,
    pub subject: String,
    pub root: String,
    #[serde(rename = "investorClass")]
    pub investor_class: u8,
    /// Decimal `uint128`, because the mask does not fit a JSON number.
    pub predicates: String,
    #[serde(rename = "predicateNames")]
    pub predicate_names: Vec<String>,
    #[serde(rename = "softExpiry")]
    pub soft_expiry: u32,
    #[serde(rename = "hardExpiry")]
    pub hard_expiry: u32,
    pub attester: String,
    #[serde(rename = "chainId")]
    pub chain_id: u64,
    pub hub: String,
    #[serde(rename = "keyId")]
    pub key_id: u32,
}

const SECONDS_PER_DAY: u64 = 86_400;

fn expiry(epoch_days: u64, days: u64, label: &str) -> Result<u32, String> {
    if days == 0 {
        return Ok(0);
    }
    let secs = epoch_days
        .checked_add(days)
        .and_then(|d| d.checked_mul(SECONDS_PER_DAY))
        .ok_or_else(|| format!("{} overflows", label))?;
    u32::try_from(secs).map_err(|_| format!("{} {} does not fit the hub's uint32", label, secs))
}

fn passthrough_days(manifest: &Manifest, key: &str) -> Result<u64, String> {
    manifest
        .passthrough
        .get(key)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| {
            format!(
                "manifest.passthrough.{} is missing or not a whole number",
                key
            )
        })
}

impl AttestationFile {
    /// Derive the attestation from a 3.1.0 manifest.
    pub fn from_manifest(manifest: &Manifest) -> Result<Self, String> {
        if !is_v31(&manifest.version) {
            return Err(format!(
                "attestation.json exists for 3.1.0 manifests only, this one is {}",
                manifest.version
            ));
        }
        let chain = manifest
            .chain
            .as_ref()
            .ok_or("a 3.1.0 manifest must carry a chain block")?;

        let mut names: Vec<&str> = vec![KYC_DONE];
        let mut class: Option<u8> = None;
        for leaf in &manifest.leaves {
            let Some(pred) = leaf.binding.as_ref().and_then(|b| b.predicate.as_deref()) else {
                continue;
            };
            if pred == INVESTOR_CLASS {
                if class.is_some() {
                    return Err("more than one INVESTOR_CLASS leaf".to_string());
                }
                let t = leaf
                    .public_inputs
                    .get("minTier")
                    .and_then(|v| v.as_u64())
                    .filter(|t| (1..=3).contains(t))
                    .ok_or("the INVESTOR_CLASS leaf has no minTier in 1..=3")?;
                class = Some(t as u8);
                continue;
            }
            if bit_of(pred).is_none() {
                return Err(format!("leaf predicate {} is not in the table", pred));
            }
            names.push(pred);
        }
        let investor_class =
            class.ok_or("no INVESTOR_CLASS leaf, so there is no investor class to attest")?;
        let mask = mask_of(names.iter().copied())?;

        let soft_days = passthrough_days(manifest, "softExpiryDays")?;
        let hard_days = passthrough_days(manifest, "hardExpiryDays")?;
        let soft_expiry = expiry(manifest.epoch_days, soft_days, "softExpiry")?;
        let hard_expiry = expiry(manifest.epoch_days, hard_days, "hardExpiry")?;
        if soft_expiry != 0 && hard_expiry != 0 && soft_expiry >= hard_expiry {
            return Err(
                "softExpiry must come before hardExpiry; the hub refuses the attestation otherwise"
                    .to_string(),
            );
        }

        Ok(AttestationFile {
            version: manifest.version.clone(),
            subject: manifest.wallet_address.to_ascii_lowercase(),
            root: manifest.kyc_hash.clone(),
            investor_class,
            predicates: mask.to_string(),
            predicate_names: names_of(mask).into_iter().map(str::to_string).collect(),
            soft_expiry,
            hard_expiry,
            attester: chain.attester.to_ascii_lowercase(),
            chain_id: chain.chain_id,
            hub: chain.hub.to_ascii_lowercase(),
            key_id: chain.key_id,
        })
    }

    /// Pretty JSON with sorted keys.
    pub fn to_json_bytes(&self) -> serde_json::Result<Vec<u8>> {
        let value = serde_json::to_value(self)?;
        let mut out = serde_json::to_vec_pretty(&value)?;
        out.retain(|b| *b != b'\r');
        out.push(b'\n');
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_is_unix_seconds_from_the_batch_date() {
        assert_eq!(expiry(20_000, 0, "x").unwrap(), 0);
        assert_eq!(expiry(20_000, 365, "x").unwrap(), (20_365 * 86_400) as u32);
        assert!(expiry(60_000, 1, "x").is_err());
    }
}
