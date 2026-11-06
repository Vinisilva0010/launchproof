//! LaunchProof MCP server over stdio (JSON-RPC 2.0, one message per line).
//!
//! Tools: investigate_token, get_attestation, build_guarded_buy and, when an
//! agent keypair is configured, guarded_buy (devnet only, capped per call).
//! Logs go to stderr; stdout carries protocol messages only.
//!
//! Environment:
//!   LP_API_URL         LaunchProof API (default http://localhost:8080)
//!   LP_AGENT_KEYPAIR   optional agent wallet keypair file (enables guarded_buy)
//!   LP_RPC_URL         devnet RPC used to send agent purchases
//!   LP_AGENT_MAX_SOL   largest purchase the agent may make (default 0.1)

use std::io::{self, BufRead, Write};
use std::thread::sleep;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use base64::Engine;
use serde_json::{json, Value};
use solana_commitment_config::CommitmentConfig;
use solana_keypair::{read_keypair_file, Keypair};
use solana_rpc_client::rpc_client::RpcClient;
use solana_rpc_client_api::config::RpcSendTransactionConfig;
use solana_signer::Signer;
use solana_transaction::Transaction;

const DEFAULT_API: &str = "http://localhost:8080";
const DEFAULT_RPC: &str = "https://api.devnet.solana.com";
const DEFAULT_AGENT_MAX_SOL: f64 = 0.1;
const FLAG_MINT: u64 = 1;
const FLAG_FREEZE: u64 = 2;
const FLAG_PARTIAL: u64 = 4;
const MAX_PROOFS_PER_FINDING: usize = 3;

struct Agent {
    keypair: Keypair,
    rpc: RpcClient,
    max_sol: f64,
}

struct Server {
    api: String,
    http: reqwest::blocking::Client,
    agent: Option<Agent>,
}

/// Buyer limits, with the same defaults as the web client.
struct Limits {
    max_linked_initial_bps: u64,
    max_linked_now_bps: u64,
    max_creator_dead: u64,
    deny_flags: u64,
}

impl Limits {
    fn from_args(args: &Value) -> Self {
        let pct = |key: &str, default: f64| (args[key].as_f64().unwrap_or(default) * 100.0).round().clamp(0.0, 10_000.0) as u64;
        let flag = |key: &str, default: bool, bit: u64| if args[key].as_bool().unwrap_or(default) { bit } else { 0 };
        Self {
            max_linked_initial_bps: pct("max_linked_initial_pct", 10.0),
            max_linked_now_bps: pct("max_linked_now_pct", 10.0),
            max_creator_dead: args["max_creator_dead"].as_u64().unwrap_or(1),
            deny_flags: flag("refuse_mint_authority", true, FLAG_MINT)
                | flag("refuse_freeze_authority", true, FLAG_FREEZE)
                | flag("refuse_partial_analysis", false, FLAG_PARTIAL),
        }
    }

    fn policy_json(&self) -> Value {
        json!({
            "max_linked_initial_bps": self.max_linked_initial_bps,
            "max_linked_now_bps": self.max_linked_now_bps,
            "max_creator_dead": self.max_creator_dead,
            "deny_flags": self.deny_flags,
            "max_age_secs": 600,
        })
    }

    /// Same rules as the on-chain program; empty means the guard passes.
    fn violations(&self, report: &Value) -> Vec<String> {
        let num = |key: &str| report[key].as_u64().unwrap_or(0);
        let count = |key: &str| report[key].as_array().map(|a| a.len() as u64).unwrap_or(0);
        let mut flags = 0;
        if report["mint_authority_active"].as_bool().unwrap_or(false) {
            flags |= FLAG_MINT;
        }
        if report["freeze_authority_active"].as_bool().unwrap_or(false) {
            flags |= FLAG_FREEZE;
        }
        if count("partial_reasons") > 0 {
            flags |= FLAG_PARTIAL;
        }
        let mut out = Vec::new();
        if num("linked_initial_bps") > self.max_linked_initial_bps {
            out.push(format!("bought at launch {} is above the limit {}", pct(num("linked_initial_bps")), pct(self.max_linked_initial_bps)));
        }
        if num("linked_now_bps") > self.max_linked_now_bps {
            out.push(format!("still held {} is above the limit {}", pct(num("linked_now_bps")), pct(self.max_linked_now_bps)));
        }
        if count("creator_dead_launches") > self.max_creator_dead {
            out.push(format!("{} dead earlier launches is above the limit {}", count("creator_dead_launches"), self.max_creator_dead));
        }
        if flags & self.deny_flags != 0 {
            out.push("the token has a property the buyer refuses (active authority or partial analysis)".to_string());
        }
        out
    }
}

fn pct(bps: u64) -> String {
    format!("{:.2}%", bps as f64 / 100.0)
}

fn explorer(kind: &str, id: &str, network: &str) -> String {
    let cluster = if network == "devnet" { "?cluster=devnet" } else { "" };
    format!("https://explorer.solana.com/{kind}/{id}{cluster}")
}

fn str_arg<'a>(args: &'a Value, key: &str) -> Result<&'a str> {
    args[key].as_str().filter(|s| !s.is_empty()).ok_or_else(|| anyhow!("argument '{key}' is required"))
}

fn summary(report: &Value, network: &str) -> String {
    let num = |key: &str| report[key].as_u64().unwrap_or(0);
    let count = |key: &str| report[key].as_array().map(|a| a.len()).unwrap_or(0);
    let mut lines = vec![
        format!("Mint: {} ({network})", report["mint"].as_str().unwrap_or("?")),
        format!("Bought at launch by the creator and linked wallets: {}", pct(num("linked_initial_bps"))),
        format!("Still held by them now: {}", pct(num("linked_now_bps"))),
        format!("Earlier launches by the creator: {} ({} with no activity for 24 hours)", count("creator_prior_launches"), count("creator_dead_launches")),
        format!("Mint authority active: {}", report["mint_authority_active"].as_bool().unwrap_or(false)),
        format!("Freeze authority active: {}", report["freeze_authority_active"].as_bool().unwrap_or(false)),
        "Findings:".to_string(),
    ];
    for f in report["findings"].as_array().into_iter().flatten() {
        let proofs: Vec<String> = f["transactions"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|s| s.as_str())
            .take(MAX_PROOFS_PER_FINDING)
            .map(|s| explorer("tx", s, network))
            .collect();
        let proof_text = if proofs.is_empty() { String::new() } else { format!(" Proof: {}", proofs.join(" ")) };
        lines.push(format!("- [{}] {}{}", f["level"].as_str().unwrap_or("info"), f["text"].as_str().unwrap_or(""), proof_text));
    }
    lines.push(format!("Evidence hash: {}", report["evidence_hash"].as_str().unwrap_or("")));
    lines.join("\n")
}

fn expectation(violations: &[String]) -> String {
    if violations.is_empty() {
        "Expected result: the LaunchProof guard passes and the purchase goes through.".to_string()
    } else {
        format!("Expected result: the LaunchProof guard cancels the purchase because {}.", violations.join("; "))
    }
}

impl Server {
    fn get(&self, path: &str) -> Result<Value> {
        let res = self.http.get(format!("{}{path}", self.api)).send()?;
        let status = res.status();
        let body: Value = res.json()?;
        if !status.is_success() {
            bail!("API error {status}: {}", body["error"].as_str().unwrap_or("unknown"));
        }
        Ok(body)
    }

    fn post(&self, path: &str, payload: &Value) -> Result<Value> {
        let res = self.http.post(format!("{}{path}", self.api)).json(payload).send()?;
        let status = res.status();
        let body: Value = res.json()?;
        if !status.is_success() {
            bail!("API error {status}: {}", body["error"].as_str().unwrap_or("unknown"));
        }
        Ok(body)
    }

    fn tools(&self) -> Value {
        let limits = json!({
            "max_linked_initial_pct": { "type": "number", "description": "Largest share (%) the creator and wallets it funded may have bought at launch. Default 10." },
            "max_linked_now_pct": { "type": "number", "description": "Largest share (%) they may still hold. Default 10." },
            "max_creator_dead": { "type": "integer", "description": "Largest number of the creator's earlier launches that died. Default 1." },
            "refuse_mint_authority": { "type": "boolean", "description": "Refuse tokens whose mint authority is active. Default true." },
            "refuse_freeze_authority": { "type": "boolean", "description": "Refuse tokens whose freeze authority is active. Default true." },
            "refuse_partial_analysis": { "type": "boolean", "description": "Refuse when the investigation hit a search limit. Default false." }
        });
        let with = |base: Value| {
            let mut props = base;
            for (k, v) in limits.as_object().expect("object") {
                props[k] = v.clone();
            }
            props
        };
        let mut tools = vec![
            json!({
                "name": "investigate_token",
                "description": "Investigate a Pump.fun token: creator, wallets that bought in the first minute, where their SOL came from, the creator's earlier launches, and findings with on-chain proof links.",
                "inputSchema": { "type": "object", "properties": {
                    "mint": { "type": "string", "description": "Token mint address" },
                    "network": { "type": "string", "enum": ["mainnet", "devnet"], "description": "Default mainnet" }
                }, "required": ["mint"] }
            }),
            json!({
                "name": "get_attestation",
                "description": "Get the LaunchProof attestation for a devnet token: the 97-byte message and its Ed25519 signature that the on-chain program verifies.",
                "inputSchema": { "type": "object", "properties": { "mint": { "type": "string" } }, "required": ["mint"] }
            }),
            json!({
                "name": "build_guarded_buy",
                "description": "Build an unsigned devnet purchase transaction protected by the LaunchProof guard. The buyer's wallet signs and sends it. If the token is outside the limits, Solana cancels the whole purchase.",
                "inputSchema": { "type": "object", "properties": with(json!({
                    "mint": { "type": "string" },
                    "buyer": { "type": "string", "description": "Buyer wallet address (fee payer and signer)" },
                    "sol": { "type": "number", "description": "SOL to spend, at most 5" }
                })), "required": ["mint", "buyer", "sol"] }
            }),
        ];
        if let Some(agent) = &self.agent {
            tools.push(json!({
                "name": "guarded_buy",
                "description": format!(
                    "Buy a devnet Pump.fun token with this agent's own wallet ({}), protected by the LaunchProof guard. At most {} SOL per call. The transaction is sent even when the guard is expected to cancel it, so the refusal is recorded on-chain; a cancelled purchase spends only the network fee.",
                    agent.keypair.pubkey(), agent.max_sol
                ),
                "inputSchema": { "type": "object", "properties": with(json!({
                    "mint": { "type": "string" },
                    "sol": { "type": "number" }
                })), "required": ["mint", "sol"] }
            }));
        }
        json!({ "tools": tools })
    }

    fn investigate(&self, args: &Value) -> Result<String> {
        let mint = str_arg(args, "mint")?;
        let network = args["network"].as_str().unwrap_or("mainnet");
        let report = self.get(&format!("/v1/investigate/{network}/{mint}"))?;
        Ok(summary(&report, network))
    }

    fn attestation(&self, args: &Value) -> Result<String> {
        let mint = str_arg(args, "mint")?;
        let body = self.get(&format!("/v1/attestation/{mint}"))?;
        Ok(format!(
            "Attester: {}\nMessage (hex): {}\nSignature (hex): {}\nThe launchproof program verifies this signature with the native Ed25519 program in the same transaction as the purchase.",
            body["attester"].as_str().unwrap_or(""),
            body["message_hex"].as_str().unwrap_or(""),
            body["signature_hex"].as_str().unwrap_or("")
        ))
    }

    fn build(&self, mint: &str, buyer: &str, sol: f64, limits: &Limits) -> Result<(String, String)> {
        let report = self.get(&format!("/v1/investigate/devnet/{mint}"))?;
        let expected = expectation(&limits.violations(&report));
        let body = self.post("/v1/guarded-buy", &json!({ "mint": mint, "buyer": buyer, "sol": sol, "policy": limits.policy_json() }))?;
        let tx = body["transaction_base64"].as_str().ok_or_else(|| anyhow!("API returned no transaction"))?.to_string();
        Ok((expected, tx))
    }

    fn build_guarded_buy(&self, args: &Value) -> Result<String> {
        let (mint, buyer) = (str_arg(args, "mint")?, str_arg(args, "buyer")?);
        let sol = args["sol"].as_f64().ok_or_else(|| anyhow!("argument 'sol' is required"))?;
        let (expected, tx) = self.build(mint, buyer, sol, &Limits::from_args(args))?;
        Ok(format!("{expected}\nUnsigned transaction (base64, legacy format, devnet). The buyer wallet must sign and send it:\n{tx}"))
    }

    fn guarded_buy(&self, args: &Value) -> Result<String> {
        let agent = self.agent.as_ref().ok_or_else(|| anyhow!("no agent wallet configured"))?;
        let mint = str_arg(args, "mint")?;
        let sol = args["sol"].as_f64().ok_or_else(|| anyhow!("argument 'sol' is required"))?;
        if !(sol > 0.0 && sol <= agent.max_sol) {
            bail!("sol must be greater than 0 and at most {} for this agent", agent.max_sol);
        }
        let (expected, tx_b64) = self.build(mint, &agent.keypair.pubkey().to_string(), sol, &Limits::from_args(args))?;
        let bytes = base64::engine::general_purpose::STANDARD.decode(tx_b64)?;
        let mut tx: Transaction = bincode::deserialize(&bytes)?;
        let blockhash = tx.message.recent_blockhash;
        tx.try_sign(&[&agent.keypair], blockhash)?;
        let config = RpcSendTransactionConfig { skip_preflight: true, ..Default::default() };
        let sig = agent.rpc.send_transaction_with_config(&tx, config)?;
        let link = explorer("tx", &sig.to_string(), "devnet");
        for _ in 0..60 {
            if let Some(status) = agent.rpc.get_signature_status(&sig)? {
                return Ok(match status {
                    Ok(()) => format!("{expected}\nResult: purchase executed, the guard passed.\nTransaction: {link}"),
                    Err(e) => format!("{expected}\nResult: purchase cancelled on-chain by the guard ({e:?}). Only the network fee was spent.\nTransaction: {link}"),
                });
            }
            sleep(Duration::from_millis(500));
        }
        bail!("transaction not confirmed in time: {link}")
    }

    fn call_tool(&self, params: &Value) -> Value {
        let args = &params["arguments"];
        let result = match params["name"].as_str().unwrap_or("") {
            "investigate_token" => self.investigate(args),
            "get_attestation" => self.attestation(args),
            "build_guarded_buy" => self.build_guarded_buy(args),
            "guarded_buy" => self.guarded_buy(args),
            other => Err(anyhow!("unknown tool '{other}'")),
        };
        match result {
            Ok(text) => json!({ "content": [{ "type": "text", "text": text }], "isError": false }),
            Err(e) => json!({ "content": [{ "type": "text", "text": format!("Error: {e:#}") }], "isError": true }),
        }
    }

    /// Returns the response for requests; None for notifications.
    fn handle(&self, msg: &Value) -> Option<Value> {
        let id = msg.get("id")?.clone();
        let method = msg["method"].as_str().unwrap_or("");
        let result = match method {
            "initialize" => json!({
                "protocolVersion": msg["params"]["protocolVersion"].as_str().unwrap_or("2025-06-18"),
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "launchproof", "version": env!("CARGO_PKG_VERSION") },
                "instructions": "Use investigate_token before any purchase. Purchases go through the LaunchProof guard: if the token exceeds the limits, Solana cancels the whole purchase."
            }),
            "ping" => json!({}),
            "tools/list" => self.tools(),
            "tools/call" => self.call_tool(&msg["params"]),
            _ => return Some(json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32601, "message": format!("method not found: {method}") } })),
        };
        Some(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
    }
}

fn load_agent() -> Result<Option<Agent>> {
    let Ok(path) = std::env::var("LP_AGENT_KEYPAIR") else { return Ok(None) };
    let keypair = read_keypair_file(&path).map_err(|e| anyhow!("cannot read {path}: {e}"))?;
    let rpc_url = std::env::var("LP_RPC_URL").unwrap_or_else(|_| DEFAULT_RPC.to_string());
    let max_sol = std::env::var("LP_AGENT_MAX_SOL").ok().and_then(|v| v.parse().ok()).unwrap_or(DEFAULT_AGENT_MAX_SOL);
    Ok(Some(Agent { keypair, rpc: RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed()), max_sol }))
}

fn main() -> Result<()> {
    let server = Server {
        api: std::env::var("LP_API_URL").unwrap_or_else(|_| DEFAULT_API.to_string()),
        http: reqwest::blocking::Client::builder().timeout(Duration::from_secs(120)).build()?,
        agent: load_agent()?,
    };
    eprintln!(
        "launchproof mcp: api {}, agent wallet {}",
        server.api,
        server.agent.as_ref().map(|a| a.keypair.pubkey().to_string()).unwrap_or_else(|| "not configured".to_string())
    );
    let mut stdout = io::stdout();
    for line in io::stdin().lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Value>(&line) {
            Ok(msg) => server.handle(&msg),
            Err(_) => Some(json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": "parse error" } })),
        };
        if let Some(response) = response {
            writeln!(stdout, "{response}")?;
            stdout.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server() -> Server {
        Server { api: DEFAULT_API.to_string(), http: reqwest::blocking::Client::new(), agent: None }
    }

    #[test]
    fn initialize_and_list_tools_without_agent() {
        let s = server();
        let init = s.handle(&json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2025-06-18" } })).unwrap();
        assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
        assert!(s.handle(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })).is_none());
        let list = s.handle(&json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" })).unwrap();
        let names: Vec<&str> = list["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["investigate_token", "get_attestation", "build_guarded_buy"]);
        let unknown = s.handle(&json!({ "jsonrpc": "2.0", "id": 3, "method": "nope" })).unwrap();
        assert_eq!(unknown["error"]["code"], -32601);
    }

    #[test]
    fn limits_match_onchain_rules() {
        let limits = Limits::from_args(&json!({}));
        let bundled = json!({ "linked_initial_bps": 7867, "linked_now_bps": 7867, "creator_dead_launches": [], "partial_reasons": ["x"], "mint_authority_active": false, "freeze_authority_active": false });
        assert_eq!(limits.violations(&bundled).len(), 2);
        let clean = json!({ "linked_initial_bps": 336, "linked_now_bps": 336, "creator_dead_launches": [], "partial_reasons": ["x"], "mint_authority_active": false, "freeze_authority_active": false });
        assert!(limits.violations(&clean).is_empty());
        let strict = Limits::from_args(&json!({ "refuse_partial_analysis": true }));
        assert_eq!(strict.violations(&clean).len(), 1);
    }
}
