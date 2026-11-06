//! Pump.fun launch investigator.
//!
//! From a mint and its bonding curve address it finds the creator, the wallets
//! that bought in the first slots, where their SOL came from, the creator's
//! earlier launches, and turns that into the numbers of a LaunchProof
//! attestation. Every number comes from on-chain data listed in the evidence.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Result};
use lp_attest::{flags, Attestation, MAX_BPS};
use serde::Serialize;
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
/// A launch with no activity for this long counts as dead.
pub const DEAD_AFTER_SECS: i64 = 24 * 3600;

const PAGE: usize = 1000;
const PUMP: &str = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P";
const PUMP_IDL: &str = include_str!("../../../idls/pump.json");

#[derive(Debug, Clone, Serialize)]
pub struct EarlyBuy {
    pub wallet: String,
    pub tokens: u64,
    pub signature: String,
    pub slot: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct FundingEdge {
    pub from: String,
    pub to: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinkedWallet {
    pub wallet: String,
    /// Empty for the creator itself.
    pub funding_path: Vec<FundingEdge>,
}

#[derive(Debug, Serialize)]
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
            linked_initial_bps: self.linked_initial_bps,
            linked_now_bps: self.linked_now_bps,
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
    fn call(&self, request: RpcRequest, params: Value) -> Result<Value> {
        let label = format!("{request:?}");
        self.rpc.send::<Value>(request, params).map_err(|e| anyhow!("{label} failed: {e}"))
    }

    fn signatures(&self, address: &str, limit: usize, before: Option<&str>) -> Result<Vec<Value>> {
        let mut cfg = json!({ "limit": limit, "commitment": "confirmed" });
        if let Some(b) = before {
            cfg["before"] = json!(b);
        }
        Ok(self.call(RpcRequest::GetSignaturesForAddress, json!([address, cfg]))?.as_array().cloned().unwrap_or_default())
    }

    /// Full history, newest first, capped at `max_pages`.
    fn history(&mut self, address: &str, max_pages: usize) -> Result<Vec<Value>> {
        let mut all = Vec::new();
        for page in 0..max_pages {
            let before = all.last().and_then(|s: &Value| s["signature"].as_str()).map(str::to_string);
            let batch = self.signatures(address, PAGE, before.as_deref())?;
            let full = batch.len() == PAGE;
            all.extend(batch);
            if !full {
                return Ok(all);
            }
            if page + 1 == max_pages {
                self.partial.insert(format!("history of {address} exceeds {} transactions", max_pages * PAGE));
            }
        }
        Ok(all)
    }

    fn transaction(&self, signature: &str) -> Result<Value> {
        let cfg = json!({ "encoding": "jsonParsed", "maxSupportedTransactionVersion": 0, "commitment": "confirmed" });
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
/// ["bonding-curve", mint] of the Pump.fun program.
pub fn investigate(rpc: &RpcClient, mint: &str, bonding_curve: &str) -> Result<Report> {
    let mut ctx = Ctx { rpc, discs: discriminators()?, funding_cache: HashMap::new(), partial: BTreeSet::new() };

    // 1. Creation: the oldest transaction of the bonding curve.
    let curve_history = ctx.history(bonding_curve, CURVE_MAX_PAGES)?;
    let oldest = curve_history.last().and_then(|s| s["signature"].as_str()).ok_or_else(|| anyhow!("no history for bonding curve"))?;
    let creation_tx = ctx.transaction(oldest)?;
    let creation_slot = creation_tx["slot"].as_u64().ok_or_else(|| anyhow!("creation slot missing"))?;
    let creator = all_instructions(&creation_tx)
        .into_iter()
        .find_map(|ix| ctx.pump_create(ix).filter(|(m, _)| m == mint).map(|(_, user)| user))
        .ok_or_else(|| anyhow!("oldest reachable transaction is not the creation; history too long to analyze"))?;
    let creation_signature = oldest.to_string();

    // 2. Early buys: positive token changes in the first slots, excluding the curve itself.
    let mut early_buys = Vec::new();
    for s in curve_history.iter().rev() {
        let slot = s["slot"].as_u64().unwrap_or(u64::MAX);
        if slot > creation_slot + EARLY_SLOT_WINDOW {
            break;
        }
        let Some(sig) = s["signature"].as_str() else { continue };
        if !s["err"].is_null() {
            continue;
        }
        let tx = ctx.transaction(sig)?;
        for (owner, delta) in token_deltas(&tx, mint) {
            if delta > 0 && owner != bonding_curve {
                early_buys.push(EarlyBuy { wallet: owner, tokens: u64::try_from(delta)?, signature: sig.to_string(), slot });
            }
        }
    }

    // 3. Funding links to the creator.
    let creator_path = ctx.funding_path(&creator)?;
    let mut creator_funders = BTreeSet::new();
    for edge in &creator_path {
        if !ctx.is_neutral(&edge.from)? {
            creator_funders.insert(edge.from.clone());
        }
    }
    let buyers: BTreeSet<String> = early_buys.iter().map(|b| b.wallet.clone()).collect();
    let mut linked_wallets = vec![LinkedWallet { wallet: creator.clone(), funding_path: vec![] }];
    for buyer in buyers.iter().filter(|b| **b != creator) {
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
    let mut prior = BTreeSet::new();
    for s in &creator_sigs {
        let slot = s["slot"].as_u64().unwrap_or(u64::MAX);
        let Some(sig) = s["signature"].as_str() else { continue };
        if slot >= creation_slot || !s["err"].is_null() {
            continue;
        }
        let tx = ctx.transaction(sig)?;
        for ix in all_instructions(&tx) {
            if let Some((m, user)) = ctx.pump_create(ix) {
                if user == creator && m != mint {
                    prior.insert(m);
                }
            }
        }
    }
    if prior.len() > MAX_PRIOR_CHECK {
        ctx.partial.insert(format!("only {MAX_PRIOR_CHECK} earlier launches checked for activity"));
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let mut dead = Vec::new();
    for m in prior.iter().take(MAX_PRIOR_CHECK) {
        let last = ctx.signatures(m, 1, None)?;
        let last_time = last.first().and_then(|s| s["blockTime"].as_i64()).unwrap_or(0);
        if now - last_time > DEAD_AFTER_SECS {
            dead.push(m.clone());
        }
    }
    let creator_prior_launches: Vec<String> = prior.into_iter().collect();

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
        linked_initial_bps: c.linked_initial_bps,
        linked_now_bps: c.linked_now_bps,
        creator_prior: clamp(c.creator_prior_launches.len()),
        creator_dead: clamp(c.creator_dead_launches.len()),
        flags: f,
        issued_at,
        evidence_hash,
    })
}
