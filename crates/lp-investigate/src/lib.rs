//! Pump.fun launch investigator.
//!
//! From a mint and its bonding curve address it finds the creator, the wallets
//! that bought in the first slots, where their SOL came from, the creator's
//! earlier launches, and turns that into the numbers of a LaunchProof
//! attestation. Every number comes from on-chain data listed in the evidence.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Result};
use lp_attest::{flags, Attestation, MAX_BPS};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use solana_rpc_client::rpc_client::RpcClient;
use solana_rpc_client_api::request::RpcRequest;

/// Slots after creation that count as "launch" (about one minute).
pub const EARLY_SLOT_WINDOW: u64 = 150;
/// Pages of bonding curve history read when looking for the creation.
pub const CURVE_MAX_PAGES: usize = 20;
/// A funder with a full page of recent signatures is treated as neutral
/// (exchange, faucet): it funds unrelated people.
pub const HIGH_ACTIVITY_SIGNATURES: usize = 1000;
/// How far back the funding chain is followed.
pub const FUNDING_HOPS: usize = 2;
/// Oldest transactions of a wallet inspected to find its first funding.
pub const FUNDING_TX_SCAN: usize = 10;
/// Recent creator transactions inspected for earlier launches.
pub const CREATOR_SCAN: usize = 100;
/// Earlier launches checked for activity.
pub const MAX_PRIOR_CHECK: usize = 50;
/// An earlier launch older than this whose bonding curve never completed counts as dead.
pub const DEAD_AFTER_SECS: i64 = 24 * 3600;
/// Earlier launches that make the creator a serial launcher (warning).
pub const SERIAL_LAUNCHER: usize = 5;
/// Launch transactions fetched at most.
pub const EARLY_TX_LIMIT: usize = 200;
/// Largest launch buyers whose funding is traced.
pub const MAX_FUNDING_CHECKS: usize = 40;
/// Attempts for an RPC call that hits a rate limit or timeout.
const RPC_ATTEMPTS: u32 = 5;

const PAGE: usize = 1000;
const PUMP: &str = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P";
const PUMP_IDL: &str = include_str!("../../../idls/pump.json");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EarlyBuy {
    pub wallet: String,
    pub tokens: u64,
    pub signature: String,
    pub slot: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FundingEdge {
    pub from: String,
    pub to: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkedWallet {
    pub wallet: String,
    /// Empty for the creator itself.
    pub funding_path: Vec<FundingEdge>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Report {
    pub mint: String,
    pub creator: String,
    pub creation_signature: String,
    pub creation_slot: u64,
    pub total_supply: u64,
    pub early_buys: Vec<EarlyBuy>,
    pub linked_wallets: Vec<LinkedWallet>,
    pub linked_initial_tokens: u64,
    pub linked_now_tokens: u64,
    pub linked_initial_bps: u16,
    pub linked_now_bps: u16,
    pub creator_prior_launches: Vec<String>,
    pub creator_dead_launches: Vec<String>,
    pub mint_authority_active: bool,
    pub freeze_authority_active: bool,
    pub partial_reasons: Vec<String>,
    pub evidence_hash: String,
    #[serde(skip)]
    evidence_hash_bytes: [u8; 32],
}

impl Report {
    pub fn flags(&self) -> u32 {
        let mut f = 0;
        if self.mint_authority_active {
            f |= flags::MINT_AUTHORITY_ACTIVE;
        }
        if self.freeze_authority_active {
            f |= flags::FREEZE_AUTHORITY_ACTIVE;
        }
        if !self.partial_reasons.is_empty() {
            f |= flags::ANALYSIS_PARTIAL;
        }
        f
    }

    pub fn attestation(&self, network: u8, issued_at: i64) -> Result<Attestation> {
        let mint: [u8; 32] = bs58::decode(&self.mint)
            .into_vec()?
            .try_into()
            .map_err(|_| anyhow!("mint is not 32 bytes"))?;
        let clamp = |n: usize| u16::try_from(n).unwrap_or(u16::MAX);
        Ok(Attestation {
            network,
            mint,
            linked_initial_bps: if launch_unanalyzed(&self.partial_reasons) { MAX_BPS } else { self.linked_initial_bps },
            linked_now_bps: if launch_unanalyzed(&self.partial_reasons) { MAX_BPS } else { self.linked_now_bps },
            creator_prior: clamp(self.creator_prior_launches.len()),
            creator_dead: clamp(self.creator_dead_launches.len()),
            flags: self.flags(),
            issued_at,
            evidence_hash: self.evidence_hash_bytes,
        })
    }
}

#[derive(Debug, Clone)]
enum Funding {
    Funded { by: String, signature: String },
    HighActivity,
    Unknown,
}

pub fn to_bps(part: u64, total: u64) -> u16 {
    if total == 0 {
        return 0;
    }
    (u128::from(part) * u128::from(MAX_BPS) / u128::from(total)).min(u128::from(MAX_BPS)) as u16
}

fn discriminators() -> Result<HashMap<String, Vec<u8>>> {
    let idl: Value = serde_json::from_str(PUMP_IDL)?;
    let mut out = HashMap::new();
    for ix in idl["instructions"].as_array().ok_or_else(|| anyhow!("bad idl"))? {
        if let (Some(name), Some(d)) = (ix["name"].as_str(), ix["discriminator"].as_array()) {
            out.insert(name.to_string(), d.iter().filter_map(|b| b.as_u64().map(|v| v as u8)).collect());
        }
    }
    Ok(out)
}

/// Top-level and inner instructions of a jsonParsed transaction.
fn all_instructions(tx: &Value) -> Vec<&Value> {
    let mut out: Vec<&Value> = tx["transaction"]["message"]["instructions"]
        .as_array()
        .map(|a| a.iter().collect())
        .unwrap_or_default();
    if let Some(groups) = tx["meta"]["innerInstructions"].as_array() {
        for group in groups {
            if let Some(list) = group["instructions"].as_array() {
                out.extend(list.iter());
            }
        }
    }
    out
}

/// Source of a system transfer or account creation that sent SOL to `wallet`.
pub fn incoming_transfer(tx: &Value, wallet: &str) -> Option<String> {
    for ix in all_instructions(tx) {
        if ix["program"] != "system" {
            continue;
        }
        let info = &ix["parsed"]["info"];
        let (src, dst) = match ix["parsed"]["type"].as_str() {
            Some("transfer") | Some("transferWithSeed") => (info["source"].as_str(), info["destination"].as_str()),
            Some("createAccount") | Some("createAccountWithSeed") => (info["source"].as_str(), info["newAccount"].as_str()),
            _ => continue,
        };
        if let (Some(s), Some(d)) = (src, dst) {
            if d == wallet && s != wallet {
                return Some(s.to_string());
            }
        }
    }
    None
}

fn raw_amount(balance: &Value) -> i128 {
    balance["uiTokenAmount"]["amount"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0)
}

/// Net token change of `mint` per owner in one transaction.
pub fn token_deltas(tx: &Value, mint: &str) -> BTreeMap<String, i128> {
    let mut pre: HashMap<u64, (String, i128)> = HashMap::new();
    for b in tx["meta"]["preTokenBalances"].as_array().into_iter().flatten() {
        if b["mint"] == mint {
            if let (Some(i), Some(owner)) = (b["accountIndex"].as_u64(), b["owner"].as_str()) {
                pre.insert(i, (owner.to_string(), raw_amount(b)));
            }
        }
    }
    let mut out: BTreeMap<String, i128> = BTreeMap::new();
    for b in tx["meta"]["postTokenBalances"].as_array().into_iter().flatten() {
        if b["mint"] == mint {
            if let (Some(i), Some(owner)) = (b["accountIndex"].as_u64(), b["owner"].as_str()) {
                let before = pre.remove(&i).map(|(_, a)| a).unwrap_or(0);
                *out.entry(owner.to_string()).or_default() += raw_amount(b) - before;
            }
        }
    }
    for (_, (owner, amount)) in pre {
        *out.entry(owner).or_default() -= amount;
    }
    out
}

struct Ctx<'a> {
    rpc: &'a RpcClient,
    discs: HashMap<String, Vec<u8>>,
    funding_cache: HashMap<String, Funding>,
    partial: BTreeSet<String>,
}

impl Ctx<'_> {
    /// RPC call with retries and growing waits on rate limits and timeouts.
    fn call(&self, request: RpcRequest, params: Value) -> Result<Value> {
        let label = format!("{request:?}");
        let mut wait = Duration::from_millis(500);
        let mut attempt = 1;
        loop {
            match self.rpc.send::<Value>(request, params.clone()) {
                Ok(value) => return Ok(value),
                Err(e) => {
                    let text = e.to_string();
                    let retry = text.contains("429") || text.contains("Too Many Requests") || text.contains("timed out");
                    if !retry || attempt == RPC_ATTEMPTS {
                        bail!("{label} failed: {}", redact(&text));
                    }
                    std::thread::sleep(wait);
                    wait *= 2;
                    attempt += 1;
                }
            }
        }
    }

    /// Creator of `mint` when `tx` contains its Pump.fun create instruction.
    fn creator_in(&self, tx: &Value, mint: &str) -> Option<String> {
        all_instructions(tx).into_iter().find_map(|ix| self.pump_create(ix).filter(|(m, _)| m == mint).map(|(_, user)| user))
    }

    fn signatures(&self, address: &str, limit: usize, before: Option<&str>) -> Result<Vec<Value>> {
        let mut cfg = json!({ "limit": limit, "commitment": "confirmed" });
        if let Some(b) = before {
            cfg["before"] = json!(b);
        }
        Ok(self.call(RpcRequest::GetSignaturesForAddress, json!([address, cfg]))?.as_array().cloned().unwrap_or_default())
    }

    /// History newest first, capped at `max_pages`; the flag says whether it is complete.
    fn history(&mut self, address: &str, max_pages: usize) -> Result<(Vec<Value>, bool)> {
        let mut all = Vec::new();
        for _ in 0..max_pages {
            let before = all.last().and_then(|s: &Value| s["signature"].as_str()).map(str::to_string);
            let batch = self.signatures(address, PAGE, before.as_deref())?;
            let full = batch.len() == PAGE;
            all.extend(batch);
            if !full {
                return Ok((all, true));
            }
        }
        Ok((all, false))
    }

    fn transaction(&self, signature: &str) -> Result<Value> {
        let cfg = json!({ "encoding": "jsonParsed", "maxSupportedTransactionVersion": 1, "commitment": "confirmed" });
        let tx = self.call(RpcRequest::GetTransaction, json!([signature, cfg]))?;
        if tx.is_null() {
            bail!("transaction {signature} not found");
        }
        Ok(tx)
    }

    /// (mint, user) when `ix` is a Pump.fun create or create_v2 instruction.
    fn pump_create(&self, ix: &Value) -> Option<(String, String)> {
        if ix["programId"] != PUMP {
            return None;
        }
        let data = bs58::decode(ix["data"].as_str()?).into_vec().ok()?;
        let accounts: Vec<&str> = ix["accounts"].as_array()?.iter().filter_map(|a| a.as_str()).collect();
        let user_index = if data.starts_with(self.discs.get("create_v2")?) {
            5
        } else if data.starts_with(self.discs.get("create")?) {
            7
        } else {
            return None;
        };
        Some((accounts.first()?.to_string(), accounts.get(user_index)?.to_string()))
    }

    /// Bonding curve account of a Pump.fun create instruction (third account in create and create_v2).
    fn create_curve(&self, ix: &Value) -> Option<String> {
        self.pump_create(ix)?;
        ix["accounts"].as_array()?.get(2)?.as_str().map(str::to_string)
    }

    /// Whether a bonding curve completed (graduated): byte 48 of the account data.
    fn curve_complete(&self, curve: &str) -> Result<Option<bool>> {
        let v = self.call(RpcRequest::GetAccountInfo, json!([curve, { "encoding": "base64", "commitment": "confirmed" }]))?;
        let Some(b64) = v["value"]["data"][0].as_str() else { return Ok(None) };
        let data = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64)?;
        Ok(data.get(48).map(|b| *b != 0))
    }

    fn funding(&mut self, wallet: &str) -> Result<Funding> {
        if let Some(f) = self.funding_cache.get(wallet) {
            return Ok(f.clone());
        }
        let sigs = self.signatures(wallet, HIGH_ACTIVITY_SIGNATURES, None)?;
        let mut result = Funding::Unknown;
        if sigs.len() >= HIGH_ACTIVITY_SIGNATURES {
            result = Funding::HighActivity;
        } else {
            for s in sigs.iter().rev().take(FUNDING_TX_SCAN) {
                let Some(sig) = s["signature"].as_str() else { continue };
                if !s["err"].is_null() {
                    continue;
                }
                if let Some(by) = incoming_transfer(&self.transaction(sig)?, wallet) {
                    result = Funding::Funded { by, signature: sig.to_string() };
                    break;
                }
            }
        }
        self.funding_cache.insert(wallet.to_string(), result.clone());
        Ok(result)
    }

    fn is_neutral(&mut self, wallet: &str) -> Result<bool> {
        Ok(matches!(self.funding(wallet)?, Funding::HighActivity))
    }

    fn funding_path(&mut self, wallet: &str) -> Result<Vec<FundingEdge>> {
        let mut path = Vec::new();
        let mut current = wallet.to_string();
        for _ in 0..FUNDING_HOPS {
            match self.funding(&current)? {
                Funding::Funded { by, signature } => {
                    path.push(FundingEdge { from: by.clone(), to: current.clone(), signature });
                    current = by;
                }
                _ => break,
            }
        }
        Ok(path)
    }

    fn holding(&self, owner: &str, mint: &str) -> Result<u64> {
        let params = json!([owner, { "mint": mint }, { "encoding": "jsonParsed", "commitment": "confirmed" }]);
        let v = self.call(RpcRequest::GetTokenAccountsByOwner, params)?;
        Ok(v["value"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|a| a["account"]["data"]["parsed"]["info"]["tokenAmount"]["amount"].as_str()?.parse::<u64>().ok())
            .sum())
    }
}

/// Investigates a Pump.fun launch. `bonding_curve` is the PDA
/// ["bonding-curve", mint]; `creation_hints` are accounts only the creation
/// touches (see lp_tx::creation_hints), used to find it in one lookup.
pub fn investigate(rpc: &RpcClient, mint: &str, bonding_curve: &str, creation_hints: &[String]) -> Result<Report> {
    let mut ctx = Ctx { rpc, discs: discriminators()?, funding_cache: HashMap::new(), partial: BTreeSet::new() };

    // 1. Creation: first from accounts only the creation touches, then from the curve history.
    let mut creation: Option<(String, u64, String)> = None;
    for hint in creation_hints {
        let sigs = ctx.signatures(hint, PAGE, None)?;
        if sigs.is_empty() || sigs.len() >= PAGE {
            continue;
        }
        if let Some(s) = sigs.iter().rev().find(|s| s["err"].is_null()) {
            if let Some(sig) = s["signature"].as_str() {
                let tx = ctx.transaction(sig)?;
                if let Some(creator) = ctx.creator_in(&tx, mint) {
                    creation = Some((sig.to_string(), tx["slot"].as_u64().unwrap_or(0), creator));
                    break;
                }
            }
        }
    }
    let (curve_history, curve_complete) = ctx.history(bonding_curve, CURVE_MAX_PAGES)?;
    if creation.is_none() && curve_complete {
        if let Some(sig) = curve_history.last().and_then(|s| s["signature"].as_str()) {
            let tx = ctx.transaction(sig)?;
            if let Some(creator) = ctx.creator_in(&tx, mint) {
                creation = Some((sig.to_string(), tx["slot"].as_u64().unwrap_or(0), creator));
            }
        }
    }
    let (creation_signature, creation_slot, creator) = match creation {
        Some(found) => found,
        None if curve_history.is_empty() => {
            bail!("this token was not launched on the Pump.fun bonding curve (its bonding curve account has no history), so there is no launch to investigate")
        }
        None => bail!("the Pump.fun creation transaction of this token was not found"),
    };

    // 2. Early buys: positive token changes in the first slots, excluding the curve itself.
    let mut early_buys = Vec::new();
    if curve_complete {
        let mut fetched = 0;
        for s in curve_history.iter().rev() {
            let slot = s["slot"].as_u64().unwrap_or(u64::MAX);
            if slot > creation_slot + EARLY_SLOT_WINDOW {
                break;
            }
            let Some(sig) = s["signature"].as_str() else { continue };
            if !s["err"].is_null() {
                continue;
            }
            if fetched == EARLY_TX_LIMIT {
                ctx.partial.insert(format!("only the first {EARLY_TX_LIMIT} launch transactions were analyzed"));
                break;
            }
            fetched += 1;
            let tx = ctx.transaction(sig)?;
            for (owner, delta) in token_deltas(&tx, mint) {
                if delta > 0 && owner != bonding_curve {
                    early_buys.push(EarlyBuy { wallet: owner, tokens: u64::try_from(delta)?, signature: sig.to_string(), slot });
                }
            }
        }
    } else {
        ctx.partial.insert(format!(
            "token history is longer than {} transactions; launch buyers were not analyzed",
            CURVE_MAX_PAGES * PAGE
        ));
    }

    // 3. Funding links to the creator, for the largest launch buyers.
    let creator_path = ctx.funding_path(&creator)?;
    let mut creator_funders = BTreeSet::new();
    for edge in &creator_path {
        if !ctx.is_neutral(&edge.from)? {
            creator_funders.insert(edge.from.clone());
        }
    }
    let mut totals: BTreeMap<String, u64> = BTreeMap::new();
    for b in early_buys.iter().filter(|b| b.wallet != creator) {
        *totals.entry(b.wallet.clone()).or_default() += b.tokens;
    }
    let mut buyers: Vec<(String, u64)> = totals.into_iter().collect();
    buyers.sort_by(|a, b| b.1.cmp(&a.1));
    if buyers.len() > MAX_FUNDING_CHECKS {
        ctx.partial.insert(format!("funding was checked for the {MAX_FUNDING_CHECKS} largest of {} launch buyers", buyers.len()));
        buyers.truncate(MAX_FUNDING_CHECKS);
    }
    let mut linked_wallets = vec![LinkedWallet { wallet: creator.clone(), funding_path: vec![] }];
    for (buyer, _) in &buyers {
        let path = ctx.funding_path(buyer)?;
        let mut linked = path.iter().any(|e| e.from == creator);
        for edge in &path {
            if !linked && creator_funders.contains(&edge.from) && !ctx.is_neutral(&edge.from)? {
                linked = true;
            }
        }
        if linked {
            linked_wallets.push(LinkedWallet { wallet: buyer.clone(), funding_path: path });
        }
    }
    let linked_set: BTreeSet<&str> = linked_wallets.iter().map(|l| l.wallet.as_str()).collect();
    let linked_initial_tokens: u64 = early_buys.iter().filter(|b| linked_set.contains(b.wallet.as_str())).map(|b| b.tokens).sum();
    let mut linked_now_tokens = 0u64;
    for wallet in &linked_set {
        linked_now_tokens += ctx.holding(wallet, mint)?;
    }

    // 4. Supply and authorities.
    let supply = ctx.call(RpcRequest::GetTokenSupply, json!([mint, { "commitment": "confirmed" }]))?;
    let total_supply: u64 = supply["value"]["amount"].as_str().and_then(|s| s.parse().ok()).ok_or_else(|| anyhow!("token supply missing"))?;
    let account = ctx.call(RpcRequest::GetAccountInfo, json!([mint, { "encoding": "jsonParsed", "commitment": "confirmed" }]))?;
    let info = &account["value"]["data"]["parsed"]["info"];
    if info.is_null() {
        ctx.partial.insert("mint account could not be parsed".to_string());
    }
    let mint_authority_active = !info["mintAuthority"].is_null();
    let freeze_authority_active = !info["freezeAuthority"].is_null();

    // 5. Creator's earlier launches and whether they died.
    let creator_sigs = ctx.signatures(&creator, CREATOR_SCAN, None)?;
    if creator_sigs.len() >= CREATOR_SCAN {
        ctx.partial.insert(format!("creator has more than {CREATOR_SCAN} transactions; older launches not checked"));
    }
    // mint -> (bonding curve, creation time)
    let mut prior: BTreeMap<String, (String, i64)> = BTreeMap::new();
    for s in &creator_sigs {
        let slot = s["slot"].as_u64().unwrap_or(u64::MAX);
        let Some(sig) = s["signature"].as_str() else { continue };
        if slot >= creation_slot || !s["err"].is_null() {
            continue;
        }
        let tx = ctx.transaction(sig)?;
        let created = tx["blockTime"].as_i64().unwrap_or(0);
        for ix in all_instructions(&tx) {
            if let (Some((m, user)), Some(curve)) = (ctx.pump_create(ix), ctx.create_curve(ix)) {
                if user == creator && m != mint {
                    prior.insert(m, (curve, created));
                }
            }
        }
    }
    if prior.len() > MAX_PRIOR_CHECK {
        ctx.partial.insert(format!("only {MAX_PRIOR_CHECK} earlier launches checked for completion"));
    }
    // Dead: launched more than DEAD_AFTER_SECS ago and the bonding curve never completed.
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let mut dead = Vec::new();
    for (m, (curve, created)) in prior.iter().take(MAX_PRIOR_CHECK) {
        if now - created > DEAD_AFTER_SECS && ctx.curve_complete(curve)? == Some(false) {
            dead.push(m.clone());
        }
    }
    let creator_prior_launches: Vec<String> = prior.into_keys().collect();

    // 6. Evidence and its hash.
    let evidence = json!({
        "mint": mint,
        "creator": creator,
        "creation_signature": creation_signature,
        "creation_slot": creation_slot,
        "early_slot_window": EARLY_SLOT_WINDOW,
        "total_supply": total_supply,
        "early_buys": early_buys,
        "linked_wallets": linked_wallets,
        "creator_prior_launches": creator_prior_launches,
        "creator_dead_launches": dead,
    });
    let evidence_hash_bytes: [u8; 32] = Sha256::digest(serde_json::to_vec(&evidence)?).into();
    let evidence_hash = evidence_hash_bytes.iter().map(|b| format!("{b:02x}")).collect();

    Ok(Report {
        mint: mint.to_string(),
        creator,
        creation_signature,
        creation_slot,
        total_supply,
        linked_initial_bps: to_bps(linked_initial_tokens, total_supply),
        linked_now_bps: to_bps(linked_now_tokens, total_supply),
        early_buys,
        linked_wallets,
        linked_initial_tokens,
        linked_now_tokens,
        creator_prior_launches,
        creator_dead_launches: dead,
        mint_authority_active,
        freeze_authority_active,
        partial_reasons: ctx.partial.into_iter().collect(),
        evidence_hash,
        evidence_hash_bytes,
    })
}

/// Removes API keys from error text before it is logged or returned.
pub fn redact(text: &str) -> String {
    let mut out = text.to_string();
    for marker in ["api-key=", "api_key="] {
        let mut from = 0;
        while let Some(i) = out[from..].find(marker) {
            let start = from + i + marker.len();
            let end = out[start..]
                .find(|c: char| c == '&' || c == ')' || c == '"' || c.is_whitespace())
                .map(|j| start + j)
                .unwrap_or(out.len());
            out.replace_range(start..end, "REDACTED");
            from = start + "REDACTED".len();
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bps_is_bounded() {
        assert_eq!(to_bps(250, 1_000), 2_500);
        assert_eq!(to_bps(5, 0), 0);
        assert_eq!(to_bps(2_000, 1_000), MAX_BPS);
    }

    #[test]
    fn finds_incoming_transfer_in_inner_instructions() {
        let tx = json!({
            "transaction": { "message": { "instructions": [] } },
            "meta": { "innerInstructions": [ { "instructions": [
                { "program": "system", "parsed": { "type": "transfer", "info": { "source": "FUNDER", "destination": "WALLET", "lamports": 5 } } }
            ] } ] }
        });
        assert_eq!(incoming_transfer(&tx, "WALLET").as_deref(), Some("FUNDER"));
        assert_eq!(incoming_transfer(&tx, "OTHER"), None);
    }

    #[test]
    fn ignores_self_transfer_and_other_programs() {
        let tx = json!({
            "transaction": { "message": { "instructions": [
                { "program": "system", "parsed": { "type": "transfer", "info": { "source": "WALLET", "destination": "WALLET" } } },
                { "program": "spl-token", "parsed": { "type": "transfer", "info": { "source": "X", "destination": "WALLET" } } }
            ] } },
            "meta": {}
        });
        assert_eq!(incoming_transfer(&tx, "WALLET"), None);
    }

    #[test]
    fn token_deltas_per_owner() {
        let bal = |i: u64, owner: &str, amount: &str| json!({ "accountIndex": i, "mint": "M", "owner": owner, "uiTokenAmount": { "amount": amount } });
        let tx = json!({ "meta": {
            "preTokenBalances": [ bal(1, "CURVE", "1000"), bal(2, "OLD", "50") ],
            "postTokenBalances": [ bal(1, "CURVE", "700"), bal(3, "BUYER", "300") ]
        }});
        let d = token_deltas(&tx, "M");
        assert_eq!(d["CURVE"], -300);
        assert_eq!(d["BUYER"], 300);
        assert_eq!(d["OLD"], -50);
    }
}

/// Rebuilds the attestation from a report previously serialized to JSON (cache).
pub fn attestation_from_report_json(value: &Value, network: u8, issued_at: i64) -> Result<Attestation> {
    #[derive(serde::Deserialize)]
    struct Cached {
        mint: String,
        linked_initial_bps: u16,
        linked_now_bps: u16,
        creator_prior_launches: Vec<String>,
        creator_dead_launches: Vec<String>,
        mint_authority_active: bool,
        freeze_authority_active: bool,
        partial_reasons: Vec<String>,
        evidence_hash: String,
    }
    let c: Cached = serde_json::from_value(value.clone())?;
    if c.evidence_hash.len() != 64 {
        bail!("evidence hash must be 64 hex characters");
    }
    let mut evidence_hash = [0u8; 32];
    for (i, byte) in evidence_hash.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&c.evidence_hash[2 * i..2 * i + 2], 16)?;
    }
    let mint: [u8; 32] = bs58::decode(&c.mint).into_vec()?.try_into().map_err(|_| anyhow!("mint is not 32 bytes"))?;
    let mut f = 0;
    if c.mint_authority_active {
        f |= flags::MINT_AUTHORITY_ACTIVE;
    }
    if c.freeze_authority_active {
        f |= flags::FREEZE_AUTHORITY_ACTIVE;
    }
    if !c.partial_reasons.is_empty() {
        f |= flags::ANALYSIS_PARTIAL;
    }
    let clamp = |n: usize| u16::try_from(n).unwrap_or(u16::MAX);
    Ok(Attestation {
        network,
        mint,
        linked_initial_bps: if launch_unanalyzed(&c.partial_reasons) { MAX_BPS } else { c.linked_initial_bps },
        linked_now_bps: if launch_unanalyzed(&c.partial_reasons) { MAX_BPS } else { c.linked_now_bps },
        creator_prior: clamp(c.creator_prior_launches.len()),
        creator_dead: clamp(c.creator_dead_launches.len()),
        flags: f,
        issued_at,
        evidence_hash,
    })
}

/// Severity of a finding.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Info,
    Warning,
    Danger,
}

/// One plain-language sentence about a launch, with the on-chain proof behind it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub level: Level,
    pub text: String,
    /// Transaction signatures that prove the sentence.
    pub transactions: Vec<String>,
    /// Account addresses the sentence refers to.
    pub accounts: Vec<String>,
}

/// Share bought at launch by linked wallets that is reported as danger.
pub const DANGER_LINKED_BPS: u16 = 2_000;
/// Share that is reported as a warning.
pub const WARNING_BPS: u16 = 1_000;
/// Dead earlier launches reported as danger.
pub const DANGER_DEAD_LAUNCHES: usize = 2;
const MAX_WALLET_FINDINGS: usize = 10;

fn pct(bps: u16) -> String {
    format!("{:.2}%", f64::from(bps) / 100.0)
}

impl Report {
    /// Deterministic explanation built only from the report data.
    pub fn explain(&self) -> Vec<Finding> {
        let finding = |level: Level, text: String, transactions: Vec<String>, accounts: Vec<String>| Finding {
            level,
            text,
            transactions,
            accounts,
        };
        let name = |address: &str| {
            if address == self.creator {
                "the creator".to_string()
            } else {
                address.to_string()
            }
        };
        let mut out = vec![finding(
            Level::Info,
            format!("Created by {} in slot {}.", self.creator, self.creation_slot),
            vec![self.creation_signature.clone()],
            vec![self.creator.clone()],
        )];

        let mut bought: BTreeMap<&str, (u64, Vec<String>)> = BTreeMap::new();
        for b in &self.early_buys {
            let entry = bought.entry(b.wallet.as_str()).or_default();
            entry.0 += b.tokens;
            entry.1.push(b.signature.clone());
        }

        if let Some((tokens, sigs)) = bought.get(self.creator.as_str()) {
            let bps = to_bps(*tokens, self.total_supply);
            let level = if bps >= WARNING_BPS { Level::Warning } else { Level::Info };
            out.push(finding(level, format!("The creator bought {} of the supply at launch.", pct(bps)), sigs.clone(), vec![self.creator.clone()]));
        }

        let others: Vec<&LinkedWallet> = self.linked_wallets.iter().filter(|l| l.wallet != self.creator).collect();
        if others.is_empty() && launch_unanalyzed(&self.partial_reasons) {
            out.push(finding(
                Level::Danger,
                "The launch could not be analyzed because this token has too many transactions, so who bought at launch is unknown. Attestations treat this as the worst case.".to_string(),
                vec![],
                vec![],
            ));
        } else if others.is_empty() {
            out.push(finding(
                Level::Info,
                "No wallet that bought at launch was funded by the creator or by the creator's funding source.".to_string(),
                vec![],
                vec![],
            ));
        } else {
            let level = if self.linked_initial_bps >= DANGER_LINKED_BPS {
                Level::Danger
            } else if self.linked_initial_bps >= WARNING_BPS {
                Level::Warning
            } else {
                Level::Info
            };
            let accounts = others.iter().map(|l| l.wallet.clone()).collect();
            let transactions = others.iter().flat_map(|l| l.funding_path.iter().map(|e| e.signature.clone())).collect();
            out.push(finding(
                level,
                format!(
                    "{} wallets that bought at launch were funded by the creator or by the creator's funding source. Together with the creator they bought {} of the supply.",
                    others.len(),
                    pct(self.linked_initial_bps)
                ),
                transactions,
                accounts,
            ));
            for l in others.iter().take(MAX_WALLET_FINDINGS) {
                let (tokens, mut transactions) = bought.get(l.wallet.as_str()).cloned().unwrap_or_default();
                let chain: Vec<String> = l.funding_path.iter().map(|e| format!("{} received SOL from {}", name(&e.to), name(&e.from))).collect();
                transactions.extend(l.funding_path.iter().map(|e| e.signature.clone()));
                out.push(finding(
                    Level::Warning,
                    format!(
                        "Wallet {} bought {} of the supply at launch. {}.",
                        l.wallet,
                        pct(to_bps(tokens, self.total_supply)),
                        chain.join("; ")
                    ),
                    transactions,
                    vec![l.wallet.clone()],
                ));
            }
            if others.len() > MAX_WALLET_FINDINGS {
                out.push(finding(
                    Level::Info,
                    format!("{} more linked wallets are listed in the evidence.", others.len() - MAX_WALLET_FINDINGS),
                    vec![],
                    vec![],
                ));
            }
        }

        if self.linked_now_bps > 0 {
            let level = if self.linked_now_bps >= WARNING_BPS { Level::Warning } else { Level::Info };
            out.push(finding(
                level,
                format!("The creator and linked wallets still hold {} of the supply.", pct(self.linked_now_bps)),
                vec![],
                self.linked_wallets.iter().map(|l| l.wallet.clone()).collect(),
            ));
        }

        if !self.creator_prior_launches.is_empty() {
            let dead = self.creator_dead_launches.len();
            let level = if dead >= DANGER_DEAD_LAUNCHES {
                Level::Danger
            } else if dead == 1 || self.creator_prior_launches.len() >= SERIAL_LAUNCHER {
                Level::Warning
            } else {
                Level::Info
            };
            out.push(finding(
                level,
                format!(
                    "The creator launched {} other tokens before this one; {} of them are more than 24 hours old and never completed their bonding curve.",
                    self.creator_prior_launches.len(),
                    dead
                ),
                vec![],
                self.creator_prior_launches.clone(),
            ));
        }

        if self.mint_authority_active {
            out.push(finding(Level::Danger, "The mint authority is still active: more tokens can be created.".to_string(), vec![], vec![self.mint.clone()]));
        }
        if self.freeze_authority_active {
            out.push(finding(Level::Danger, "The freeze authority is active: token accounts can be frozen.".to_string(), vec![], vec![self.mint.clone()]));
        }
        for reason in &self.partial_reasons {
            out.push(finding(Level::Warning, format!("Partial analysis: {reason}."), vec![], vec![]));
        }
        out
    }
}

#[cfg(test)]
mod explain_tests {
    use super::*;

    fn report(linked: Vec<LinkedWallet>, buys: Vec<EarlyBuy>, linked_bps: u16) -> Report {
        Report {
            mint: "MINT".into(),
            creator: "CREATOR".into(),
            creation_signature: "CREATE_SIG".into(),
            creation_slot: 10,
            total_supply: 1_000,
            early_buys: buys,
            linked_wallets: linked,
            linked_initial_tokens: 0,
            linked_now_tokens: 0,
            linked_initial_bps: linked_bps,
            linked_now_bps: 0,
            creator_prior_launches: vec![],
            creator_dead_launches: vec![],
            mint_authority_active: false,
            freeze_authority_active: false,
            partial_reasons: vec![],
            evidence_hash: String::new(),
            evidence_hash_bytes: [0; 32],
        }
    }

    #[test]
    fn bundle_is_danger_and_cites_funding_transaction() {
        let creator = LinkedWallet { wallet: "CREATOR".into(), funding_path: vec![] };
        let bundle = LinkedWallet {
            wallet: "W1".into(),
            funding_path: vec![FundingEdge { from: "CREATOR".into(), to: "W1".into(), signature: "FUND_SIG".into() }],
        };
        let buys = vec![EarlyBuy { wallet: "W1".into(), tokens: 300, signature: "BUY_SIG".into(), slot: 11 }];
        let findings = report(vec![creator, bundle], buys, 3_000).explain();
        let summary = findings.iter().find(|f| f.text.starts_with("1 wallets")).expect("summary finding");
        assert_eq!(summary.level, Level::Danger);
        assert!(summary.transactions.contains(&"FUND_SIG".to_string()));
        let wallet = findings.iter().find(|f| f.text.starts_with("Wallet W1")).expect("wallet finding");
        assert!(wallet.text.contains("30.00%"));
        assert!(wallet.text.contains("W1 received SOL from the creator"));
        assert!(wallet.transactions.contains(&"BUY_SIG".to_string()));
    }

    #[test]
    fn clean_launch_states_no_linked_buyers() {
        let creator = LinkedWallet { wallet: "CREATOR".into(), funding_path: vec![] };
        let findings = report(vec![creator], vec![], 0).explain();
        assert!(findings.iter().any(|f| f.text.starts_with("No wallet that bought at launch")));
        assert!(findings.iter().all(|f| f.level != Level::Danger));
    }
}

#[cfg(test)]
mod redact_tests {
    use super::redact;

    #[test]
    fn removes_api_keys() {
        let text = "error sending request for url (https://mainnet.helius-rpc.com/?api-key=abc-123&x=1) and api-key=zzz";
        let out = redact(text);
        assert!(!out.contains("abc-123") && !out.contains("zzz"));
        assert!(out.contains("api-key=REDACTED&x=1"));
    }
}

/// Partial-analysis text used when the launch is beyond the reachable history.
const LAUNCH_NOT_ANALYZED: &str = "launch buyers were not analyzed";

/// True when launch buyers could not be read. Unknown is never reported as
/// clean: attestations then carry the worst case so the guard blocks purchases.
pub fn launch_unanalyzed(partial_reasons: &[String]) -> bool {
    partial_reasons.iter().any(|r| r.contains(LAUNCH_NOT_ANALYZED))
}

#[cfg(test)]
mod unanalyzed_tests {
    use super::*;

    #[test]
    fn unanalyzed_launch_is_worst_case_in_attestation() {
        let report = json!({
            "mint": "11111111111111111111111111111111",
            "linked_initial_bps": 0,
            "linked_now_bps": 0,
            "creator_prior_launches": [],
            "creator_dead_launches": [],
            "mint_authority_active": false,
            "freeze_authority_active": false,
            "partial_reasons": ["token history is longer than 20000 transactions; launch buyers were not analyzed"],
            "evidence_hash": "00".repeat(32),
        });
        let att = attestation_from_report_json(&report, lp_attest::network::MAINNET, 1).unwrap();
        assert_eq!(att.linked_initial_bps, MAX_BPS);
        assert_eq!(att.linked_now_bps, MAX_BPS);
        assert!(att.flags & flags::ANALYSIS_PARTIAL != 0);
    }
}
