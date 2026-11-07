// LaunchProof web client. Heavy work runs in the Rust API; this file renders
// results, runs light animations and asks the wallet to sign. API data is
// inserted as text, never as HTML.
import { getWallets } from "@wallet-standard/app";

declare const __API_URL__: string;
declare const __DEMO_CLEAN__: string;
declare const __DEMO_BUNDLED__: string;

const API = __API_URL__;
const FLAG_MINT = 1;
const FLAG_FREEZE = 2;
const FLAG_PARTIAL = 4;
const MASCOT = "assets/mascot/";
const REDUCED = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

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

// Missing mascot images hide themselves so the page still works.
document.querySelectorAll<HTMLImageElement>(".mascot img").forEach((img) => {
  img.addEventListener("error", () => ((img.closest(".mascot") as HTMLElement).style.display = "none"));
  img.addEventListener("load", () => ((img.closest(".mascot") as HTMLElement).style.display = ""));
});

// Scroll reveal.
const observer = new IntersectionObserver(
  (entries) => entries.forEach((e) => e.isIntersecting && (e.target.classList.add("in"), observer.unobserve(e.target))),
  { threshold: 0.15 },
);
document.querySelectorAll(".reveal").forEach((el) => observer.observe(el));

// API status in the navigation bar.
async function pingApi() {
  const node = byId("api-status");
  try {
    const res = await fetch(`${API}/health`, { cache: "no-store" });
    node.classList.toggle("online", res.ok);
    node.lastElementChild!.textContent = res.ok ? "API online" : "API offline";
  } catch {
    node.classList.remove("online");
    node.lastElementChild!.textContent = "API waking up";
  }
}
pingApi();
setInterval(pingApi, 30_000);

function explorer(kind: "tx" | "address", id: string): string {
  return `https://explorer.solana.com/${kind}/${id}${network === "devnet" ? "?cluster=devnet" : ""}`;
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

/** Counts a number up from zero; `format` turns the current value into text. */
function countUp(node: HTMLElement, target: number, format: (v: number) => string) {
  if (REDUCED) {
    node.textContent = format(target);
    return;
  }
  const start = performance.now();
  const duration = 1000;
  const step = (now: number) => {
    const t = Math.min(1, (now - start) / duration);
    node.textContent = format(target * (1 - Math.pow(1 - t, 3)));
    if (t < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

function stat(target: number, format: (v: number) => string, label: string, barPercent: number | null, delay: number): HTMLElement {
  const box = make("div", "stat");
  box.style.animationDelay = `${delay}ms`;
  const value = make("span", "value", format(0));
  box.append(value, make("span", "label", label));
  if (barPercent !== null) {
    const bar = make("div", "bar");
    const fill = make("span");
    bar.append(fill);
    box.append(bar);
    setTimeout(() => (fill.style.width = `${Math.min(100, barPercent)}%`), 80 + delay);
  }
  setTimeout(() => countUp(value, target, format), delay);
  return box;
}

function setVerdict() {
  const levels = (report.findings ?? []).map((f: any) => f.level);
  const kind = levels.includes("danger") ? "danger" : levels.includes("warning") ? "warning" : "clean";
  const verdict = byId("verdict");
  verdict.className = `verdict card ${kind}`;
  const linked = pct(report.linked_initial_bps);
  const copy = {
    danger: ["High risk", `Red flags found. The creator's network bought ${linked} of the supply at launch.`, "04-doubtful.png"],
    warning: ["Be careful", `Some warnings. The creator's network bought ${linked} of the supply at launch.`, "06-raising-hand.png"],
    clean: ["No red flags found", `The creator's network bought ${linked} at launch, and no launch buyer was funded by the creator.`, "01-hello.png"],
  }[kind] as string[];
  byId("verdict-label").textContent = copy[0];
  byId("verdict-text").textContent = copy[1];
  const img = byId<HTMLImageElement>("verdict-img");
  img.src = MASCOT + copy[2];
  // Restart the pop animation on every new result.
  img.style.animation = "none";
  void img.offsetWidth;
  img.style.animation = "";
}

function render() {
  setVerdict();
  const dead = report.creator_dead_launches.length;
  const prior = report.creator_prior_launches.length;
  byId("stats").replaceChildren(
    stat(report.linked_initial_bps, (v) => pct(v), "bought at launch by the creator and linked wallets", report.linked_initial_bps / 100, 0),
    stat(report.linked_now_bps, (v) => pct(v), "still held by them now", report.linked_now_bps / 100, 120),
    stat(prior, (v) => String(Math.round(v)), "earlier launches by the creator", null, 240),
    stat(dead, (v) => String(Math.round(v)), "of those never completed their bonding curve", null, 360),
  );
  const list = byId("findings");
  list.replaceChildren();
  (report.findings ?? []).forEach((f: any, i: number) => {
    const item = make("li", `finding ${f.level}`);
    item.style.animationDelay = `${400 + i * 90}ms`;
    item.append(make("span", `badge ${f.level}`, f.level), make("span", undefined, f.text));
    const proofs = make("div", "proofs");
    f.transactions.forEach((sig: string, n: number) => proofs.append(link("tx", sig, `proof ${n + 1}`)));
    f.accounts.slice(0, 8).forEach((acc: string) => proofs.append(link("address", acc, short(acc))));
    if (proofs.childElementCount > 0) item.append(proofs);
    list.append(item);
  });
  byId("result").classList.remove("hidden");
  byId("buy").classList.toggle("hidden", network !== "devnet");
  updateExpected();
  byId("result").scrollIntoView({ behavior: REDUCED ? "auto" : "smooth", block: "start" });
}

function showError(message: string) {
  byId("error-text").textContent = message;
  byId("error-box").classList.remove("hidden");
}

async function investigate(mint: string, net: string) {
  network = net;
  report = null;
  for (const id of ["result", "buy", "error-box"]) byId(id).classList.add("hidden");
  byId("loading").classList.remove("hidden");
  const button = byId<HTMLFormElement>("investigate-form").querySelector("button[type=submit]") as HTMLButtonElement;
  button.disabled = true;
  try {
    const res = await fetch(`${API}/v1/investigate/${net}/${encodeURIComponent(mint)}`);
    const body = await res.json();
    if (!res.ok) throw new Error(body.error ?? `HTTP ${res.status}`);
    report = body;
    byId("loading").classList.add("hidden");
    render();
  } catch (e: any) {
    byId("loading").classList.add("hidden");
    showError(e.message === "Failed to fetch" ? "The API did not answer. It may be waking up; try again in a minute." : e.message);
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
  const img = byId<HTMLImageElement>("buy-img");
  if (reasons.length === 0) {
    node.textContent = "Expected result: the guard passes and the purchase goes through.";
    node.className = "expected pass";
    img.src = MASCOT + "01-hello.png";
  } else {
    node.textContent = `Expected result: the guard cancels the purchase because ${reasons.join("; ")}.`;
    node.className = "expected fail";
    img.src = MASCOT + "06-raising-hand.png";
  }
}

function setBuyStatus(text: string, busy = false, isError = false) {
  const node = byId("buy-status");
  node.textContent = text;
  node.className = `buy-status${busy ? " busy" : ""}${isError ? " error" : ""}`;
}

function solanaWallets(): any[] {
  return getWallets()
    .get()
    .filter((w: any) => "standard:connect" in w.features && "solana:signAndSendTransaction" in w.features);
}

async function connect() {
  const list = solanaWallets();
  if (list.length === 0) {
    setBuyStatus("No Solana wallet found. Install Phantom or Solflare and switch it to devnet.", false, true);
    return;
  }
  wallet = list[0];
  try {
    setBuyStatus("Waiting for the wallet...", true);
    const out = await wallet.features["standard:connect"].connect();
    account = out.accounts[0];
    byId("wallet").textContent = `Connected: ${wallet.name} ${short(account.address)}`;
    setBuyStatus("");
  } catch (e: any) {
    setBuyStatus(`Wallet connection failed: ${e.message}`, false, true);
  }
}

async function buy() {
  if (!report) return;
  if (!account) {
    setBuyStatus("Connect a wallet first.", false, true);
    return;
  }
  const sol = numberInput("sol");
  if (!(sol > 0 && sol <= 5)) {
    setBuyStatus("Amount must be greater than 0 and at most 5 SOL.", false, true);
    return;
  }
  const button = byId<HTMLButtonElement>("buy-button");
  button.disabled = true;
  setBuyStatus("Building the guarded transaction", true);
  try {
    const res = await fetch(`${API}/v1/guarded-buy`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ mint: report.mint, buyer: account.address, sol, policy: policy() }),
    });
    const body = await res.json();
    if (!res.ok) throw new Error(body.error ?? `HTTP ${res.status}`);
    const bytes = Uint8Array.from(atob(body.transaction_base64), (c) => c.charCodeAt(0));
    setBuyStatus("Approve the transaction in your wallet", true);
    const [out] = await wallet.features["solana:signAndSendTransaction"].signAndSendTransaction({
      account,
      transaction: bytes,
      chain: "solana:devnet",
    });
    const signature = base58(out.signature);
    const status = byId("buy-status");
    status.className = "buy-status";
    status.replaceChildren(make("span", undefined, "Sent. Check the result on the explorer: "), link("tx", signature, short(signature)));
  } catch (e: any) {
    const blocked = byId("expected").classList.contains("fail");
    setBuyStatus(
      blocked
        ? "Not purchased. Your wallet simulated the transaction, saw that the LaunchProof guard cancels it, and refused to send it. No SOL was spent."
        : `Purchase not sent: ${e.message}`,
      false,
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
