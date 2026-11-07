// LaunchProof web client. All heavy work runs in the Rust API; this file only
// renders results and asks the wallet to sign. API data is inserted as text,
// never as HTML.
import { getWallets } from "@wallet-standard/app";

declare const __API_URL__: string;
declare const __DEMO_CLEAN__: string;
declare const __DEMO_BUNDLED__: string;

const API = __API_URL__;
const FLAG_MINT = 1;
const FLAG_FREEZE = 2;
const FLAG_PARTIAL = 4;

const byId = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
let report: any = null;
let network = "mainnet";
let wallet: any = null;
let account: any = null;

function make(tag: string, className?: string, text?: string): HTMLElement {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function setStatus(id: string, text: string, isError = false) {
  const node = byId(id);
  node.textContent = text;
  node.className = isError ? "error" : "";
}

function explorer(kind: "tx" | "address", id: string): string {
  const cluster = network === "devnet" ? "?cluster=devnet" : "";
  return `https://explorer.solana.com/${kind}/${id}${cluster}`;
}

function short(id: string): string {
  return id.length > 12 ? `${id.slice(0, 4)}...${id.slice(-4)}` : id;
}

function pct(bps: number): string {
  return `${(bps / 100).toFixed(2)}%`;
}

const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58(bytes: Uint8Array): string {
  let n = 0n;
  for (const b of bytes) n = n * 256n + BigInt(b);
  let out = "";
  while (n > 0n) {
    out = BASE58[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b !== 0) break;
    out = "1" + out;
  }
  return out;
}

function link(kind: "tx" | "address", id: string, label: string): HTMLAnchorElement {
  const a = make("a", undefined, label) as HTMLAnchorElement;
  a.href = explorer(kind, id);
  a.target = "_blank";
  a.rel = "noopener noreferrer";
  return a;
}

function stat(value: string, label: string): HTMLElement {
  const box = make("div", "stat");
  box.append(make("span", "value", value), make("span", "label", label));
  return box;
}

function render() {
  const stats = byId("stats");
  stats.replaceChildren(
    stat(pct(report.linked_initial_bps), "bought at launch by the creator and linked wallets"),
    stat(pct(report.linked_now_bps), "still held by them now"),
    stat(String(report.creator_prior_launches.length), "earlier launches by the creator"),
    stat(String(report.creator_dead_launches.length), "of those never completed their bonding curve"),
  );
  const list = byId("findings");
  list.replaceChildren();
  for (const f of report.findings ?? []) {
    const item = make("li");
    item.append(make("span", `badge ${f.level}`, f.level), make("span", undefined, f.text));
    const proofs = make("div", "proofs");
    f.transactions.forEach((sig: string, i: number) => proofs.append(link("tx", sig, `transaction ${i + 1}`)));
    f.accounts.slice(0, 8).forEach((acc: string) => proofs.append(link("address", acc, short(acc))));
    if (proofs.childElementCount > 0) item.append(proofs);
    list.append(item);
  }
  byId("result").classList.remove("hidden");
  byId("buy").classList.toggle("hidden", network !== "devnet");
  updateExpected();
}

async function investigate(mint: string, net: string) {
  network = net;
  report = null;
  byId("result").classList.add("hidden");
  byId("buy").classList.add("hidden");
  setStatus("status", "Investigating. This reads the token's on-chain history and can take up to a minute.");
  const button = byId<HTMLButtonElement>("investigate-form").querySelector("button[type=submit]") as HTMLButtonElement;
  button.disabled = true;
  try {
    const res = await fetch(`${API}/v1/investigate/${net}/${encodeURIComponent(mint)}`);
    const body = await res.json();
    if (!res.ok) throw new Error(body.error ?? `HTTP ${res.status}`);
    report = body;
    setStatus("status", "");
    render();
  } catch (e: any) {
    setStatus("status", `Error: ${e.message}`, true);
  } finally {
    button.disabled = false;
  }
}

function numberInput(id: string): number {
  return Number(byId<HTMLInputElement>(id).value);
}

function percentToBps(id: string): number {
  return Math.min(10000, Math.max(0, Math.round(numberInput(id) * 100)));
}

function policy() {
  let deny = 0;
  if (byId<HTMLInputElement>("deny-mint").checked) deny |= FLAG_MINT;
  if (byId<HTMLInputElement>("deny-freeze").checked) deny |= FLAG_FREEZE;
  if (byId<HTMLInputElement>("deny-partial").checked) deny |= FLAG_PARTIAL;
  return {
    max_linked_initial_bps: percentToBps("max-initial"),
    max_linked_now_bps: percentToBps("max-now"),
    max_creator_dead: Math.max(0, Math.round(numberInput("max-dead"))),
    deny_flags: deny,
    max_age_secs: 600,
  };
}

function reportFlags(): number {
  let f = 0;
  if (report.mint_authority_active) f |= FLAG_MINT;
  if (report.freeze_authority_active) f |= FLAG_FREEZE;
  if (report.partial_reasons.length > 0) f |= FLAG_PARTIAL;
  return f;
}

/** Same rules as the on-chain program, so the user knows the outcome before signing. */
function updateExpected() {
  if (!report) return;
  const p = policy();
  const reasons: string[] = [];
  if (report.linked_initial_bps > p.max_linked_initial_bps) reasons.push(`bought at launch ${pct(report.linked_initial_bps)} is above ${pct(p.max_linked_initial_bps)}`);
  if (report.linked_now_bps > p.max_linked_now_bps) reasons.push(`still held ${pct(report.linked_now_bps)} is above ${pct(p.max_linked_now_bps)}`);
  if (report.creator_dead_launches.length > p.max_creator_dead) reasons.push(`${report.creator_dead_launches.length} dead earlier launches is above ${p.max_creator_dead}`);
  if (reportFlags() & p.deny_flags) reasons.push("the token has a property you refused");
  const node = byId("expected");
  if (reasons.length === 0) {
    node.textContent = "Expected result: the guard passes and the purchase goes through.";
    node.className = "expected pass";
  } else {
    node.textContent = `Expected result: the guard cancels the purchase because ${reasons.join("; ")}.`;
    node.className = "expected fail";
  }
}

function solanaWallets(): any[] {
  return getWallets()
    .get()
    .filter((w: any) => "standard:connect" in w.features && "solana:signAndSendTransaction" in w.features);
}

async function connect() {
  const list = solanaWallets();
  if (list.length === 0) {
    setStatus("buy-status", "No Solana wallet found. Install Phantom or Solflare and switch it to devnet.", true);
    return;
  }
  wallet = list[0];
  try {
    const out = await wallet.features["standard:connect"].connect();
    account = out.accounts[0];
    byId("wallet").textContent = `Connected: ${wallet.name} ${short(account.address)}`;
    setStatus("buy-status", "");
  } catch (e: any) {
    setStatus("buy-status", `Wallet connection failed: ${e.message}`, true);
  }
}

async function buy() {
  if (!report) return;
  if (!account) {
    setStatus("buy-status", "Connect a wallet first.", true);
    return;
  }
  const sol = numberInput("sol");
  if (!(sol > 0 && sol <= 5)) {
    setStatus("buy-status", "Amount must be greater than 0 and at most 5 SOL.", true);
    return;
  }
  const button = byId<HTMLButtonElement>("buy-button");
  button.disabled = true;
  setStatus("buy-status", "Building the guarded transaction...");
  try {
    const res = await fetch(`${API}/v1/guarded-buy`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ mint: report.mint, buyer: account.address, sol, policy: policy() }),
    });
    const body = await res.json();
    if (!res.ok) throw new Error(body.error ?? `HTTP ${res.status}`);
    const bytes = Uint8Array.from(atob(body.transaction_base64), (c) => c.charCodeAt(0));
    setStatus("buy-status", "Approve the transaction in your wallet.");
    const [out] = await wallet.features["solana:signAndSendTransaction"].signAndSendTransaction({
      account,
      transaction: bytes,
      chain: "solana:devnet",
    });
    const signature = base58(out.signature);
    const status = byId("buy-status");
    status.className = "";
    status.replaceChildren(make("span", undefined, "Sent. Check the result on the explorer: "), link("tx", signature, short(signature)));
  } catch (e: any) {
    const blocked = byId("expected").classList.contains("fail");
    setStatus(
      "buy-status",
      blocked
        ? "Not purchased. Your wallet simulated the transaction, saw that the LaunchProof guard cancels it, and refused to send it. No SOL was spent."
        : `Purchase not sent: ${e.message}`,
      true,
    );
  } finally {
    button.disabled = false;
  }
}

byId<HTMLFormElement>("investigate-form").addEventListener("submit", (event) => {
  event.preventDefault();
  investigate(byId<HTMLInputElement>("mint").value.trim(), byId<HTMLSelectElement>("network").value);
});
for (const [id, mint] of [["demo-clean", __DEMO_CLEAN__], ["demo-bundled", __DEMO_BUNDLED__]]) {
  byId(id).addEventListener("click", () => {
    byId<HTMLInputElement>("mint").value = mint;
    byId<HTMLSelectElement>("network").value = "devnet";
    investigate(mint, "devnet");
  });
}
byId("connect").addEventListener("click", connect);
byId("buy-button").addEventListener("click", buy);
for (const id of ["max-initial", "max-now", "max-dead", "deny-mint", "deny-freeze", "deny-partial"]) {
  byId(id).addEventListener("input", updateExpected);
}
