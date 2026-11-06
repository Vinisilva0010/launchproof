//! LaunchProof HTTP API.
//!
//! GET  /health
//! GET  /v1/investigate/{devnet|mainnet}/{mint}  risk report with evidence
//! GET  /v1/attestation/{mint}                   signed attestation (devnet)
//! POST /v1/guarded-buy                          unsigned guarded purchase transaction (devnet)

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anchor_lang::prelude::Pubkey;
use anyhow::{anyhow, Context, Result};
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use launchproof::PolicyArgs;
use lp_attest::{network, MAX_BPS};
use serde::Deserialize;
use serde_json::{json, Value};
use solana_commitment_config::CommitmentConfig;
use solana_keypair::{read_keypair, read_keypair_file, Keypair};
use solana_rpc_client::rpc_client::RpcClient;
use solana_signer::Signer;
use solana_transaction::Transaction;
use sqlx::postgres::{PgPool, PgPoolOptions};
use tower_http::cors::CorsLayer;

/// Reports younger than this are served from the database.
const CACHE_SECS: f64 = 120.0;
/// Largest purchase the API will build.
const MAX_SOL: f64 = 5.0;
const LIMIT_INVESTIGATE: u32 = 20;
const LIMIT_ATTEST: u32 = 20;
const LIMIT_BUY: u32 = 10;

struct AppState {
    devnet: Arc<RpcClient>,
    mainnet: Arc<RpcClient>,
    attester: Arc<Keypair>,
    db: PgPool,
    limiter: RateLimiter,
}

/// Fixed one-minute window per client IP and route.
struct RateLimiter {
    hits: Mutex<HashMap<(IpAddr, &'static str), (Instant, u32)>>,
}

impl RateLimiter {
    fn new() -> Self {
        Self { hits: Mutex::new(HashMap::new()) }
    }

    fn allow(&self, ip: IpAddr, route: &'static str, limit: u32) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(60);
        let mut hits = self.hits.lock().expect("rate limiter lock");
        if hits.len() > 10_000 {
            hits.retain(|_, (start, _)| now.duration_since(*start) < window);
        }
        let entry = hits.entry((ip, route)).or_insert((now, 0));
        if now.duration_since(entry.0) >= window {
            *entry = (now, 0);
        }
        if entry.1 >= limit {
            return false;
        }
        entry.1 += 1;
        true
    }
}

struct ApiError(StatusCode, String);

impl ApiError {
    fn bad_request(msg: impl Into<String>) -> Self {
        Self(StatusCode::BAD_REQUEST, msg.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        // Details go to the server log only.
        eprintln!("internal error: {e:#}");
        Self(StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string())
    }
}

/// The proxy in front of the service appends the real client address last.
fn client_ip(headers: &HeaderMap, peer: SocketAddr) -> IpAddr {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.rsplit(',').next())
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(peer.ip())
}

fn check_limit(state: &AppState, headers: &HeaderMap, peer: SocketAddr, route: &'static str, limit: u32) -> Result<(), ApiError> {
    if state.limiter.allow(client_ip(headers, peer), route, limit) {
        Ok(())
    } else {
        Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "too many requests, try again in a minute".to_string()))
    }
}

fn parse_pubkey(value: &str, field: &str) -> Result<Pubkey, ApiError> {
    Pubkey::from_str(value).map_err(|_| ApiError::bad_request(format!("{field} is not a valid address")))
}

fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Cached report for a mint, investigating on a cache miss.
async fn report_json(state: &AppState, network_name: &str, rpc: Arc<RpcClient>, mint: Pubkey) -> Result<Value> {
    let key = mint.to_string();
    let cached: Option<(String,)> = sqlx::query_as(
        "SELECT report FROM reports WHERE network = $1 AND mint = $2 AND created_at > now() - make_interval(secs => $3)",
    )
    .bind(network_name)
    .bind(&key)
    .bind(CACHE_SECS)
    .fetch_optional(&state.db)
    .await?;
    if let Some((text,)) = cached {
        return Ok(serde_json::from_str(&text)?);
    }

    let curve = lp_tx::bonding_curve(&mint).to_string();
    let mint_str = key.clone();
    let report = tokio::task::spawn_blocking(move || lp_investigate::investigate(&rpc, &mint_str, &curve)).await??;
    let value = serde_json::to_value(&report)?;
    sqlx::query(
        "INSERT INTO reports (network, mint, report, created_at) VALUES ($1, $2, $3, now()) \
         ON CONFLICT (network, mint) DO UPDATE SET report = EXCLUDED.report, created_at = now()",
    )
    .bind(network_name)
    .bind(&key)
    .bind(value.to_string())
    .execute(&state.db)
    .await?;
    Ok(value)
}

async fn health() -> &'static str {
    "ok"
}

async fn investigate(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((network_name, mint)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    check_limit(&state, &headers, peer, "investigate", LIMIT_INVESTIGATE)?;
    let rpc = match network_name.as_str() {
        "devnet" => state.devnet.clone(),
        "mainnet" => state.mainnet.clone(),
        _ => return Err(ApiError::bad_request("network must be devnet or mainnet")),
    };
    let mint = parse_pubkey(&mint, "mint")?;
    let mut value = report_json(&state, &network_name, rpc, mint).await?;
    let report: lp_investigate::Report = serde_json::from_value(value.clone()).map_err(anyhow::Error::from)?;
    value["findings"] = serde_json::to_value(report.explain()).map_err(anyhow::Error::from)?;
    Ok(Json(value))
}

async fn attestation(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(mint): Path<String>,
) -> Result<Json<Value>, ApiError> {
    check_limit(&state, &headers, peer, "attestation", LIMIT_ATTEST)?;
    let mint = parse_pubkey(&mint, "mint")?;
    let report = report_json(&state, "devnet", state.devnet.clone(), mint).await?;
    let att = lp_investigate::attestation_from_report_json(&report, network::DEVNET, now_secs())?;
    let message = att.encode().map_err(|e| anyhow!("encode attestation: {e:?}"))?;
    let signature = state.attester.sign_message(&message);
    Ok(Json(json!({
        "attester": state.attester.pubkey().to_string(),
        "message_hex": hex(&message),
        "signature_hex": hex(signature.as_ref()),
        "report": report,
    })))
}

#[derive(Deserialize)]
struct PolicyInput {
    max_linked_initial_bps: u16,
    max_linked_now_bps: u16,
    max_creator_dead: u16,
    deny_flags: u32,
    max_age_secs: u32,
}

#[derive(Deserialize)]
struct GuardedBuyRequest {
    mint: String,
    buyer: String,
    sol: f64,
    policy: Option<PolicyInput>,
}

fn validate_policy(p: Option<PolicyInput>) -> Result<PolicyArgs, ApiError> {
    let p = p.unwrap_or(PolicyInput {
        max_linked_initial_bps: 3_000,
        max_linked_now_bps: 3_000,
        max_creator_dead: 2,
        deny_flags: 0,
        max_age_secs: 600,
    });
    if p.max_linked_initial_bps > MAX_BPS || p.max_linked_now_bps > MAX_BPS {
        return Err(ApiError::bad_request("limits in basis points must be at most 10000"));
    }
    if !(30..=3_600).contains(&p.max_age_secs) {
        return Err(ApiError::bad_request("max_age_secs must be between 30 and 3600"));
    }
    Ok(PolicyArgs {
        max_linked_initial_bps: p.max_linked_initial_bps,
        max_linked_now_bps: p.max_linked_now_bps,
        max_creator_dead: p.max_creator_dead,
        deny_flags: p.deny_flags,
        max_age_secs: p.max_age_secs,
    })
}

async fn guarded_buy(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<GuardedBuyRequest>,
) -> Result<Json<Value>, ApiError> {
    check_limit(&state, &headers, peer, "guarded-buy", LIMIT_BUY)?;
    let mint = parse_pubkey(&req.mint, "mint")?;
    let buyer = parse_pubkey(&req.buyer, "buyer")?;
    if !(req.sol > 0.0 && req.sol <= MAX_SOL) {
        return Err(ApiError::bad_request(format!("sol must be greater than 0 and at most {MAX_SOL}")));
    }
    let policy = validate_policy(req.policy)?;

    let report = report_json(&state, "devnet", state.devnet.clone(), mint).await?;
    let att = lp_investigate::attestation_from_report_json(&report, network::DEVNET, now_secs())?;
    let (rpc, attester, sol_in) = (state.devnet.clone(), state.attester.clone(), lp_tx::lamports(req.sol));
    let tx_bytes = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
        let ixs = lp_tx::guarded_buy_ixs(&rpc, &attester, &buyer, sol_in, &att, policy)?;
        let mut tx = Transaction::new_with_payer(&ixs, Some(&buyer));
        tx.message.recent_blockhash = rpc.get_latest_blockhash()?;
        Ok(bincode::serialize(&tx)?)
    })
    .await
    .map_err(|e| anyhow!(e))??;

    Ok(Json(json!({
        "transaction_base64": base64::engine::general_purpose::STANDARD.encode(tx_bytes),
        "linked_initial_bps": report["linked_initial_bps"],
        "linked_now_bps": report["linked_now_bps"],
        "creator_prior_launches": report["creator_prior_launches"].as_array().map(|a| a.len()).unwrap_or(0),
        "creator_dead_launches": report["creator_dead_launches"].as_array().map(|a| a.len()).unwrap_or(0),
        "partial_reasons": report["partial_reasons"],
        "evidence_hash": report["evidence_hash"],
    })))
}

/// ATTESTER_KEYPAIR_JSON (hosting) takes precedence over ATTESTER_KEYPAIR_PATH (local).
fn load_attester() -> Result<Keypair> {
    if let Ok(json) = std::env::var("ATTESTER_KEYPAIR_JSON") {
        return read_keypair(&mut std::io::Cursor::new(json.into_bytes())).map_err(|e| anyhow!("ATTESTER_KEYPAIR_JSON: {e}"));
    }
    let path = std::env::var("ATTESTER_KEYPAIR_PATH").context("set ATTESTER_KEYPAIR_JSON or ATTESTER_KEYPAIR_PATH")?;
    read_keypair_file(&path).map_err(|e| anyhow!("cannot read {path}: {e}"))
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = dotenvy::dotenv();
    let helius = std::env::var("HELIUS_API_KEY").context("HELIUS_API_KEY is required")?;
    let db_url = std::env::var("DATABASE_URL").context("DATABASE_URL is required")?;
    let attester = load_attester()?;
    println!("attester: {}", attester.pubkey());

    let (devnet, mainnet) = tokio::task::spawn_blocking(move || {
        let make = |cluster: &str| {
            RpcClient::new_with_commitment(format!("https://{cluster}.helius-rpc.com/?api-key={helius}"), CommitmentConfig::confirmed())
        };
        (make("devnet"), make("mainnet"))
    })
    .await?;

    let db = PgPoolOptions::new().max_connections(5).acquire_timeout(Duration::from_secs(10)).connect(&db_url).await?;
    sqlx::migrate!("./migrations").run(&db).await?;

    let state = Arc::new(AppState {
        devnet: Arc::new(devnet),
        mainnet: Arc::new(mainnet),
        attester: Arc::new(attester),
        db,
        limiter: RateLimiter::new(),
    });
    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/investigate/{network}/{mint}", get(investigate))
        .route("/v1/attestation/{mint}", get(attestation))
        .route("/v1/guarded-buy", post(guarded_buy))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let port: u16 = std::env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8080);
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;
    println!("listening on port {port}");
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_blocks_after_limit_per_route() {
        let limiter = RateLimiter::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(limiter.allow(ip, "a", 2));
        assert!(limiter.allow(ip, "a", 2));
        assert!(!limiter.allow(ip, "a", 2));
        assert!(limiter.allow(ip, "b", 2));
    }

    #[test]
    fn client_ip_uses_last_forwarded_address() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "9.9.9.9, 5.6.7.8".parse().unwrap());
        let peer: SocketAddr = "127.0.0.1:1".parse().unwrap();
        assert_eq!(client_ip(&headers, peer), "5.6.7.8".parse::<IpAddr>().unwrap());
        assert_eq!(client_ip(&HeaderMap::new(), peer), peer.ip());
    }
}
