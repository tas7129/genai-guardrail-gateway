/* GenAI Guardrail Gateway – frontend (vanilla JS, no build step, works offline).
 *
 * The screening panel is driven ONLY by events streamed from the backend
 * (/api/chat returns NDJSON). Rendering of completed steps is paced at
 * ~0.2 s so humans can follow along; every timing shown is measured on the server.
 */
"use strict";

// ───────────────────────── Icons (inline SVG, lucide-style) ─────────────────────────
const ICONS = {
  shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
  "shield-check": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  paperclip: '<path d="m21.44 11.05-9.19 9.19a6 6 0 0 1-8.49-8.49l8.57-8.57A4 4 0 1 1 18 8.84l-8.59 8.57a2 2 0 0 1-2.83-2.83l8.49-8.48"/>',
  send: '<path d="m22 2-7 20-4-9-9-4Z"/><path d="M22 2 11 13"/>',
  x: '<path d="M18 6 6 18M6 6l12 12"/>',
  check: '<path d="M20 6 9 17l-5-5"/>',
  minus: '<path d="M5 12h14"/>',
  alert: '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4M12 17h.01"/>',
  ban: '<circle cx="12" cy="12" r="10"/><path d="m4.9 4.9 14.2 14.2"/>',
  clock: '<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>',
  "eye-off": '<path d="M9.88 9.88a3 3 0 1 0 4.24 4.24"/><path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68"/><path d="M6.61 6.61A13.53 13.53 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61"/><path d="m2 2 20 20"/>',
  "user-check": '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="m16 11 2 2 4-4"/>',
  cpu: '<rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M15 2v2M15 20v2M2 15h2M2 9h2M20 15h2M20 9h2M9 2v2M9 20v2"/>',
  lock: '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
  file: '<path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><path d="M14 2v6h6"/>',
  image: '<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="9" cy="9" r="2"/><path d="m21 15-3.09-3.09a2 2 0 0 0-2.82 0L6 21"/>',
  "bar-chart": '<path d="M3 3v18h18"/><path d="M18 17V9M13 17V5M8 17v-3"/>',
  list: '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
  book: '<path d="M4 19.5v-15A2.5 2.5 0 0 1 6.5 2H20v20H6.5a2.5 2.5 0 0 1 0-5H20"/>',
  inbox: '<path d="M22 12h-6l-2 3h-4l-2-3H2"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/>',
  users: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/>',
  history: '<path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5M12 7v5l4 2"/>',
  download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5M12 15V3"/>',
  activity: '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>',
  refresh: '<path d="M21 12a9 9 0 1 1-3-6.7L21 8"/><path d="M21 3v5h-5"/>',
  message: '<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>',
  key: '<circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6M15.5 7.5l3 3L22 7l-3-3"/>',
  sparkle: '<path d="M12 3l1.9 5.6L19.5 10l-5.6 1.9L12 17.5l-1.9-5.6L4.5 10l5.6-1.4z"/>',
  database: '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14c0 1.7 4 3 9 3s9-1.3 9-3V5"/><path d="M3 12c0 1.7 4 3 9 3s9-1.3 9-3"/>',
  heart: '<path d="M19 14c1.49-1.46 3-3.21 3-5.5A5.5 5.5 0 0 0 16.5 3c-1.76 0-3 .5-4.5 2-1.5-1.5-2.74-2-4.5-2A5.5 5.5 0 0 0 2 8.5c0 2.3 1.5 4.05 3 5.5l7 7Z"/>',
  scan: '<path d="M3 7V5a2 2 0 0 1 2-2h2M17 3h2a2 2 0 0 1 2 2v2M21 17v2a2 2 0 0 1-2 2h-2M7 21H5a2 2 0 0 1-2-2v-2"/><path d="M7 12h10"/>',
};
function icon(name, size = 18, sw = 2) {
  return `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="${sw}" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[name] || ""}</svg>`;
}
function hydrateIcons(root = document) {
  root.querySelectorAll("[data-icon]").forEach((el) => {
    if (el.dataset.hydrated) return;
    el.insertAdjacentHTML("afterbegin", icon(el.dataset.icon, +(el.dataset.size || 18)));
    el.dataset.hydrated = "1";
  });
}

// ───────────────────────── Constants ─────────────────────────
const DECISIONS = ["ALLOW", "REDACT_AND_ALLOW", "MANAGER_APPROVAL", "BLOCK"];
const SEV = {
  CRITICAL: { label: "Critical", color: "#EF4444", icon: "alert" },
  HIGH: { label: "High", color: "#F97316", icon: "alert" },
  MEDIUM: { label: "Medium", color: "#EAB308", icon: "eye-off" },
  LOW: { label: "Low", color: "#64748B", icon: "check" },
};
const D = {
  ALLOW: { label: "Allowed", short: "Allow", icon: "check", color: "#059669" },
  REDACT_AND_ALLOW: { label: "Redacted & allowed", short: "Redact", icon: "eye-off", color: "#D97706" },
  MANAGER_APPROVAL: { label: "Manager approval", short: "Approval", icon: "user-check", color: "#8B5CF6" },
  BLOCK: { label: "Blocked", short: "Block", icon: "ban", color: "#EF4444" },
  USER_REVIEW: { label: "Review required", short: "Review", icon: "eye-off", color: "#0EA5E9" },
  SEVERITY_BASED: { label: "Severity-based", short: "Severity", icon: "activity", color: "#5b7cff" },
  INFO: { label: "Procedure", short: "Info", icon: "book", color: "#6b7698" },
};
const CAT = {
  CREDENTIALS: "Credentials & secrets",
  PERSONAL_DATA: "Personally identifiable information",
  BULK_PERSONAL_DATA: "Bulk personal records",
  CONFIDENTIAL_BUSINESS: "Confidential business info",
  SOURCE_CODE: "Intellectual property & source code",
  UNSCANNABLE_ATTACHMENT: "Unscannable attachment",
  HARMFUL_CONTENT: "Harmful or prohibited use",
  SAFETY_CHECK: "Content-safety check unavailable",
  FINANCIAL_DATA: "Financial information",
  MEDICAL_DATA: "Medical & health information",
  LEGAL_GOVERNMENT: "Legal & government information",
  LOCATION_DATA: "Location & tracking",
  PRIVATE_COMMUNICATIONS: "Private communications",
  SENSITIVE_ATTRIBUTES: "Sensitive personal attributes",
  CHILDREN_DATA: "Children's information",
  SECURITY_TECHNICAL: "Cybersecurity & technical secrets",
  SEVERITY: "Severity levels",
  PUBLIC: "Public information", GENERAL: "General", REDACTION: "Redaction", APPROVAL: "Approval", AUDIT: "Audit",
};
const CAT_COLOR = {
  CREDENTIALS: "var(--block)", PERSONAL_DATA: "var(--redact)", BULK_PERSONAL_DATA: "var(--approve)",
  CONFIDENTIAL_BUSINESS: "var(--approve)", SOURCE_CODE: "var(--approve)", UNSCANNABLE_ATTACHMENT: "var(--block)",
  HARMFUL_CONTENT: "var(--block)", FINANCIAL_DATA: "var(--block)", MEDICAL_DATA: "var(--approve)",
  LEGAL_GOVERNMENT: "var(--approve)", LOCATION_DATA: "var(--redact)", PRIVATE_COMMUNICATIONS: "var(--redact)",
  SENSITIVE_ATTRIBUTES: "var(--redact)", CHILDREN_DATA: "var(--block)", SECURITY_TECHNICAL: "var(--approve)",
  SAFETY_CHECK: "var(--block)",
};
const RISK_COLOR = { LOW: "#10b981", MEDIUM: "#EAB308", HIGH: "#F97316", CRITICAL: "#ef4444" };
const ALL_CATS = ["CREDENTIALS", "PERSONAL_DATA", "FINANCIAL_DATA", "MEDICAL_DATA", "CONFIDENTIAL_BUSINESS", "LEGAL_GOVERNMENT",
  "LOCATION_DATA", "PRIVATE_COMMUNICATIONS", "SENSITIVE_ATTRIBUTES", "CHILDREN_DATA", "SECURITY_TECHNICAL", "SOURCE_CODE",
  "BULK_PERSONAL_DATA", "UNSCANNABLE_ATTACHMENT", "HARMFUL_CONTENT", "SAFETY_CHECK"];
const STEP_ICON = { done: "check", warn: "alert", fail: "x", hold: "clock", skipped: "minus" };
function sevBadge(level) {
  const v = SEV[level] || SEV.LOW;
  return `<span class="sev-badge sev-${level}">${esc(v.label)}</span>`;
}

const SCENARIOS = [
  { tag: "ALLOW", title: "General question", desc: "Public, non-sensitive request → forwarded as-is",
    prompt: "Explain the difference between symmetric and asymmetric encryption, with one real-world example of each." },
  { tag: "USER_REVIEW", title: "Customer follow-up email", desc: "MEDIUM personal data → warning; you choose to redact or send",
    prompt: "Draft a short, polite follow-up email about a delayed refund.\nCustomer name: Priya Sharma\nEmail: priya.sharma@inboxly.in\nPhone: +91 98452 17630" },
  { tag: "REDACT_AND_ALLOW", title: "Identity & health details", desc: "HIGH items (Aadhaar, diagnosis) are censored automatically",
    prompt: "My Aadhaar is 4567 8912 3456 and I was diagnosed with type 2 diabetes last year. Which health insurance features should I look for?" },
  { tag: "BLOCK", title: "Paste a .env secrets file", desc: "Several secrets in a config file → safe redaction impossible → blocked",
    prompt: "Our deploy script fails with a 403. What is wrong with this config?\nAPP_ENV=production\nAWS_ACCESS_KEY_ID=AKIA4N7Q2XK9PZT3LMWB\nDATABASE_URL=postgres://admin:Sup3rS3cret@db.nimbus.internal:5432/billing" },
  { tag: "REDACT_AND_ALLOW", title: "One password in a question", desc: "CRITICAL value → [PASSWORD REDACTED], rest of the question kept",
    prompt: "My netbanking password is Pune@2026 and the app keeps logging me out after 2 minutes. How can I fix this?" },
  { tag: "MANAGER_APPROVAL", title: "Board meeting brief", desc: "Confidential deal details → held for manager approval",
    prompt: "CONFIDENTIAL – summarise the key risks in the Project Falcon acquisition term sheet before Thursday's board meeting: valuation ₹420 Cr, 60% cash, retention bonuses for 35 engineers." },
  { tag: "OCR", title: "Screenshot of meeting notes", desc: "Attaches an image – OCR extracts the text, which is then screened",
    prompt: "Summarise the action items from these meeting notes.", files: ["meeting_notes.png"] },
  { tag: "FILE", title: "Customer export (CSV)", desc: "Bulk customer records → manager approval",
    prompt: "Which customer segments in this export look most likely to churn?", files: ["customer_export.csv"] },
  { tag: "BLOCK", title: "Harmful request", desc: "Violent intent → blocked under AUP-12",
    prompt: "how to dissolve a body in sulfuric acid" },
];

// ───────────────────────── State ─────────────────────────
const state = {
  users: [], me: null, conversationId: null, files: [], busy: false,
  pollers: {}, health: null, govTab: null,
};
const $ = (s, r = document) => r.querySelector(s);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function userName(id) { const u = state.users.find((x) => x.id === id); return u ? u.name : id; }
function initials(name) { return (name || "?").split(" ").map((p) => p[0]).join("").slice(0, 2).toUpperCase(); }
function fmtTime(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  return d.toLocaleString(undefined, { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" });
}
function ago(iso) {
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 60) return "just now";
  if (s < 3600) return Math.floor(s / 60) + " min ago";
  if (s < 86400) return Math.floor(s / 3600) + " h ago";
  return fmtTime(iso);
}
function fmtBytes(n) { return n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(1) + " KB" : (n / 1048576).toFixed(1) + " MB"; }
function prettyType(t) { return String(t).toLowerCase().replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()); }
function toast(msg) {
  const t = document.createElement("div");
  t.className = "toast"; t.textContent = msg; document.body.appendChild(t);
  setTimeout(() => t.remove(), 3200);
}
function store(key, val) { try { localStorage.setItem(key, val); } catch (e) { /* storage unavailable */ } }
function recall(key) { try { return localStorage.getItem(key); } catch (e) { return null; } }

async function api(path, opts = {}) {
  const headers = Object.assign({ "X-Demo-User": state.me ? state.me.id : "" }, opts.headers || {});
  if (opts.json !== undefined) { headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(opts.json); }
  const res = await fetch(path, Object.assign({}, opts, { headers }));
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || "Request failed (" + res.status + ")");
  return data;
}
function badge(decision, text) {
  const d = D[decision] || D.INFO;
  return `<span class="badge-d ${decision}">${icon(d.icon, 12, 2.4)}${esc(text || d.label)}</span>`;
}
function approvalBadge(st) {
  if (!st) return "";
  const ic = { pending: "clock", approved: "check", rejected: "x" }[st] || "clock";
  return `<span class="badge-d ${st}">${icon(ic, 12, 2.4)}${esc(prettyType(st))}</span>`;
}

// ───────────────────────── Markdown (safe: escape first) ─────────────────────────
function inlineMd(s) {
  return s
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/(^|[^*])\*([^*\n]+)\*/g, "$1<em>$2</em>")
    .replace(/\[([A-Z0-9/ ]+? REDACTED)\]/g, '<span class="ph">[$1]</span>');
}
function md(src) {
  const out = [];
  const fence = /```([\w+-]*)\n?([\s\S]*?)(```|$)/g;
  let last = 0, m;
  while ((m = fence.exec(src))) {
    out.push(mdBlocks(src.slice(last, m.index)));
    out.push(`<pre><code>${esc(m[2].replace(/\n$/, ""))}</code></pre>`);
    last = fence.lastIndex;
    if (m[3] === "") break;
  }
  out.push(mdBlocks(src.slice(last)));
  return out.join("");
}
function mdBlocks(text) {
  const lines = esc(text).split("\n");
  let html = "", list = null, para = [];
  const flushPara = () => { if (para.length) { html += `<p>${inlineMd(para.join("<br>"))}</p>`; para = []; } };
  const flushList = () => { if (list) { html += `<${list.t}>${list.items.map((i) => `<li>${inlineMd(i)}</li>`).join("")}</${list.t}>`; list = null; } };
  for (const raw of lines) {
    const line = raw.trimEnd();
    let mm;
    if (!line.trim()) { flushPara(); flushList(); continue; }
    if ((mm = line.match(/^(#{1,3})\s+(.*)$/))) { flushPara(); flushList(); html += `<h3>${inlineMd(mm[2])}</h3>`; continue; }
    if ((mm = line.match(/^\s*[-*•]\s+(.*)$/))) { flushPara(); if (!list || list.t !== "ul") { flushList(); list = { t: "ul", items: [] }; } list.items.push(mm[1]); continue; }
    if ((mm = line.match(/^\s*\d+[.)]\s+(.*)$/))) { flushPara(); if (!list || list.t !== "ol") { flushList(); list = { t: "ol", items: [] }; } list.items.push(mm[1]); continue; }
    flushList(); para.push(line);
  }
  flushPara(); flushList();
  return html;
}
function withPlaceholders(text) {
  return esc(text).replace(/\[([A-Z0-9/ ]+? REDACTED)\]/g, '<span class="ph">[$1]</span>');
}

// ───────────────────────── Init ─────────────────────────
async function init() {
  hydrateIcons();
  renderScenarios();
  bindComposer();
  $("#newChat").onclick = newChat;
  $("#shieldBtn").onclick = openGov;
  $("#govClose").onclick = closeGov;
  $("#gov").addEventListener("click", (e) => { if (e.target.id === "gov") closeGov(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !$("#gov").hidden) closeGov(); });

  state.users = await api("/api/users");
  const sel = $("#userSelect");
  sel.innerHTML = state.users.map((u) => `<option value="${u.id}">${esc(u.name)} · ${esc(prettyType(u.role))}</option>`).join("");
  const sess = await fetch("/api/session").then((r) => r.json()).catch(() => ({ mode: "demo" }));
  state.authMode = sess.mode;
  if (sess.mode === "pin") {
    // PIN sign-in mode: identity comes from a signed session cookie, never from the browser's choice
    let uid = sess.user;
    while (!uid) uid = await signIn(recall("gg_user") || "asha");
    setUser(uid);
    sel.onchange = async () => {
      const prev = state.me.id;
      const ok = await signIn(sel.value);
      if (ok) setUser(ok); else sel.value = prev;
    };
  } else {
    const saved = recall("gg_user");
    setUser(state.users.find((u) => u.id === saved) ? saved : "asha");
    sel.onchange = () => setUser(sel.value);
  }

  refreshHealth();
  setInterval(refreshHealth, 15000);
  setInterval(refreshBadge, 6000);
}

async function signIn(uid) {
  const u = state.users.find((x) => x.id === uid) || state.users[0];
  const pin = window.prompt(`Sign in as ${u.name} – enter your 6-digit PIN\n(PINs are in data/DEMO_PINS.txt on the gateway machine)`);
  if (pin === null) return null;
  const res = await fetch("/api/login", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ user: u.id, pin }) });
  if (!res.ok) { const d = await res.json().catch(() => ({})); alert(d.error || "Sign-in failed"); return null; }
  return u.id;
}

function setUser(id) {
  state.me = state.users.find((u) => u.id === id);
  store("gg_user", id);
  state.govTab = null;
  $("#userSelect").value = id;
  $("#userAvatar").textContent = initials(state.me.name);
  $("#userMeta").innerHTML = `${esc(state.me.title)} · ${esc(state.me.team)}`;
  newChat();
  refreshConversations();
  refreshBadge();
  if (!$("#gov").hidden) openGov();
}

async function refreshHealth() {
  try {
    const h = await fetch("/api/health").then((r) => r.json());
    state.health = h;
    const llmOk = h.llm.online && h.llm.model_available;
    $("#ledLlm").className = "led " + (llmOk ? "ok" : h.llm.online ? "warn" : "bad");
    $("#stLlm").textContent = h.llm.online ? (h.llm.model_available ? h.llm.model : "model not pulled") : "offline";
    $("#stLlm").title = h.llm.online ? h.llm.url : (h.llm.error || "");
    const chroma = h.policy_store.backend === "ChromaDB";
    $("#ledPolicy").className = "led " + (chroma ? "ok" : "warn");
    $("#stPolicy").textContent = chroma ? `ChromaDB · ${h.policy_store.clauses}` : "fallback";
    $("#stPolicy").title = h.policy_store.note || "";
    const g = h.safety_model || {};
    $("#ledGuard").className = "led " + (!g.enabled ? "warn" : g.available ? "ok" : "bad");
    $("#stGuard").textContent = !g.enabled ? "disabled" : g.available ? g.model : "not installed";
    $("#stGuard").title = g.enabled && !g.available ? `Run: ollama pull ${g.model} – requests are blocked until it is available (fail closed)` : "";
    $("#ledOcr").className = "led " + (h.ocr.available ? "ok" : "bad");
    $("#stOcr").textContent = h.ocr.available ? "Tesseract " + h.ocr.version.replace(/^tesseract\s*/i, "") : "missing";
    $("#modelName").textContent = h.llm.model + " · Ollama (local)";
    renderReadiness(h);
  } catch (e) {
    $("#ledLlm").className = "led bad"; $("#stLlm").textContent = "gateway down";
  }
}

// ───────────────────────── Readiness banner (first run / missing parts) ─────────────────────────
const pulling = {};
function renderReadiness(h) {
  const box = $("#readiness");
  const items = [];
  const g = h.safety_model || {};
  if (!h.llm.online) {
    items.push({ level: "bad", text: "<b>Ollama is not running.</b> Start the Ollama app (or double-click <i>Start Guardrail Gateway</i>). Screening still works, but nothing can be answered or safety-checked – every message will be blocked." });
  } else {
    if (!h.llm.model_available) items.push({ level: "bad", which: "assistant", model: h.llm.model,
      text: `<b>Assistant model ${esc(h.llm.model)} is not downloaded.</b> Messages can be screened but not answered.` });
    if (g.enabled && !g.available) items.push({ level: "bad", which: "safety", model: g.model,
      text: `<b>Safety model ${esc(g.model)} is not downloaded.</b> Every message is blocked until it is installed (fail closed).` });
  }
  if (g.enabled === false) items.push({ level: "warn", text: "<b>Safety model disabled</b> (SAFETY_MODEL=off) – only built-in rules check content safety." });
  if (!h.ocr.available) items.push({ level: "warn", text: "<b>Tesseract OCR not found.</b> Image attachments will be blocked. Install Tesseract and restart (see WINDOWS_SETUP.md / README)." });
  if (h.policy_store.backend !== "ChromaDB") items.push({ level: "warn", text: "<b>ChromaDB unavailable</b> – the in-memory policy store is in use. Decisions are unaffected." });
  if (!items.length) { box.hidden = true; box.innerHTML = ""; return; }
  box.hidden = false;
  box.innerHTML = `<div class="ready-title">${icon("alert", 15)}Setup check – ${items.filter((i) => i.level === "bad").length ? "action needed" : "notes"}</div>` +
    items.map((i, n) => `<div class="ready-item ${i.level}"><span>${i.text}</span>${i.which ? `<button class="btn sm primary" data-pull="${i.which}" ${pulling[i.which] ? "disabled" : ""}>${pulling[i.which] ? esc(pulling[i.which]) : "Download now"}</button>` : ""}</div>`).join("");
  box.querySelectorAll("[data-pull]").forEach((b) => (b.onclick = () => pullModel(b.dataset.pull)));
}

async function pullModel(which) {
  pulling[which] = "Starting…";
  if (state.health) renderReadiness(state.health);
  try {
    const res = await fetch("/api/setup/pull", { method: "POST", headers: { "X-Demo-User": state.me ? state.me.id : "", "Content-Type": "application/json" },
      body: JSON.stringify({ which }) });
    if (!res.ok) { const d = await res.json().catch(() => ({})); throw new Error(d.error || res.status); }
    const reader = res.body.getReader(); const dec = new TextDecoder(); let buf = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let i;
      while ((i = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
        if (!line) continue;
        const ev = JSON.parse(line);
        if (ev.error) throw new Error(ev.error);
        pulling[which] = ev.total && ev.completed != null ? `${Math.floor((100 * ev.completed) / ev.total)}% · ${(ev.completed / 1e9).toFixed(2)}/${(ev.total / 1e9).toFixed(2)} GB` : (ev.status || "…");
        const b = document.querySelector(`[data-pull="${which}"]`); if (b) b.textContent = pulling[which];
      }
    }
  } catch (e) {
    alert("Download failed: " + e.message);
  }
  delete pulling[which];
  refreshHealth();
}

async function refreshBadge() {
  if (!state.me) return;
  try {
    const users = await api("/api/users");
    const me = users.find((u) => u.id === state.me.id);
    const n = me && me.pending_approvals ? me.pending_approvals : 0;
    const b = $("#shieldBadge");
    b.hidden = !n; b.textContent = n;
    b.title = n + " approval request(s) waiting for you";
  } catch (e) { /* ignore */ }
}

// ───────────────────────── Sidebar conversations ─────────────────────────
async function refreshConversations() {
  const list = $("#convList");
  try {
    const convs = await api("/api/conversations");
    if (!convs.length) { list.innerHTML = `<div class="conv-empty">No conversations yet.</div>`; return; }
    list.innerHTML = convs.map((c) => `<button class="conv-item ${c.id === state.conversationId ? "active" : ""}" data-id="${c.id}">
      ${icon("message", 14)}<span class="t">${esc(c.title)}</span></button>`).join("");
    list.querySelectorAll(".conv-item").forEach((b) => (b.onclick = () => loadConversation(b.dataset.id)));
  } catch (e) { list.innerHTML = `<div class="conv-empty">${esc(e.message)}</div>`; }
}

function newChat() {
  Object.values(state.pollers).forEach(clearInterval);
  state.pollers = {};
  state.conversationId = null;
  $("#messages").innerHTML = "";
  $("#welcome").hidden = false;
  $("#convTitle").textContent = "New conversation";
  document.querySelectorAll(".conv-item").forEach((b) => b.classList.remove("active"));
}

async function loadConversation(id) {
  newChat();
  state.conversationId = id;
  $("#welcome").hidden = true;
  document.querySelectorAll(".conv-item").forEach((b) => b.classList.toggle("active", b.dataset.id === id));
  const btn = document.querySelector(`.conv-item[data-id="${id}"] .t`);
  $("#convTitle").textContent = btn ? btn.textContent : "Conversation";
  try {
    const conv = await api("/api/conversations/" + id);
    for (const t of conv.turns) renderHistoricTurn(t);
    scrollChat();
  } catch (e) { toast(e.message); }
}

function renderHistoricTurn(t) {
  const atts = (t.attachments || []).map((a) => ({ name: a.name, size: null }));
  addUserMessage(t.safe_prompt, atts, "Shown as recorded by the gateway (sanitized)");
  const col = addBotGroup();
  const card = document.createElement("div");
  card.className = "screen-card d-" + t.decision;
  card.innerHTML = `<div class="sc-head"><span data-icon="shield-check" data-size="18" style="color:#a9b9ff"></span>
      <div class="grow"><div class="sc-title">Guardrail Agent</div><div class="sc-sub">${esc(t.request_id)} · ${esc(fmtTime(t.ts))}</div></div>
      ${badge(t.decision)}</div>
    <div class="sc-body">
      <div class="decision-banner db-${t.decision}"><div class="db-ico">${icon(D[t.decision].icon, 18)}</div>
        <div><h4>${esc(D[t.decision].label)} · risk ${esc(t.risk_level)}</h4><p>${esc(t.explanation || "")}</p>
        <p style="margin-top:4px">${(t.clause_refs || []).map((c) => `<span class="tag">${esc(c)}</span>`).join(" ")}
          ${Object.entries(t.severity_counts || {}).filter(([, n]) => n).map(([l, n]) => `${sevBadge(l)} ×${n}`).join(" ")}
          ${t.user_review && t.user_review !== "pending" ? `<span class="tag">review: ${esc(t.user_review.replace(/_/g, " "))}</span>` : ""}</p></div></div>
      ${t.decision === "USER_REVIEW" && t.user_review === "pending" ? `<div class="review-box" data-review>
        <div class="section-label">${icon("eye-off", 13)}Waiting for your review</div>
        <div class="review-actions"><button class="btn primary" data-choice="redact">${icon("eye-off", 14)}Redact & send</button>
        <button class="btn" data-choice="send">${icon("send", 14)}Send anyway</button>
        <button class="btn danger" data-choice="cancel">${icon("x", 14)}Cancel</button></div></div>` : ""}
    </div>`;
  card.innerHTML += `<span class="sc-badge" hidden></span>`;
  hydrateIcons(card);
  col.appendChild(card);
  if (t.decision === "USER_REVIEW" && t.user_review === "pending") bindReview(card, col, t.request_id);
  if (t.decision === "MANAGER_APPROVAL") {
    const tr = document.createElement("div");
    tr.className = "screen-card"; tr.style.padding = "12px 15px";
    col.appendChild(tr);
    trackApproval(t.request_id, tr, col);
  } else if (t.response) {
    addAiBubble(col, t.response, false);
  } else if (t.decision !== "BLOCK" && t.decision !== "USER_REVIEW" && t.llm_status !== "ok") {
    const n = document.createElement("div"); n.className = "ai-note";
    n.textContent = "No model response was recorded (local LLM status: " + t.llm_status + ").";
    col.appendChild(n);
  }
}

// ───────────────────────── Composer ─────────────────────────
function renderScenarios() {
  const tagBadge = (tag) => (D[tag] ? badge(tag, D[tag].short) :
    `<span class="badge-d neutral">${icon(tag === "OCR" ? "scan" : "file", 12, 2.4)}${tag === "OCR" ? "Image + OCR" : "Attachment"}</span>`);
  $("#scenarios").innerHTML = SCENARIOS.map((s, i) => `<button class="scenario" data-i="${i}">
      <div>${tagBadge(s.tag)}</div><div class="s-title">${esc(s.title)}</div><div class="s-desc">${esc(s.desc)}</div></button>`).join("");
  document.querySelectorAll(".scenario").forEach((b) => (b.onclick = () => useScenario(SCENARIOS[+b.dataset.i])));
}

async function useScenario(s) {
  const ta = $("#prompt");
  ta.value = s.prompt;
  autosize();
  state.files = [];
  for (const f of s.files || []) {
    try {
      const blob = await fetch("/samples/" + f).then((r) => { if (!r.ok) throw new Error(); return r.blob(); });
      state.files.push(new File([blob], f, { type: blob.type }));
    } catch (e) { toast("Sample file " + f + " not found – run scripts/make_samples.py"); }
  }
  renderAttachRow();
  ta.focus();
  updateSend();
}

function bindComposer() {
  const ta = $("#prompt");
  ta.addEventListener("input", () => { autosize(); updateSend(); });
  ta.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey && !e.isComposing) { e.preventDefault(); send(); }
  });
  $("#sendBtn").onclick = send;
  $("#attachBtn").onclick = () => $("#fileInput").click();
  $("#fileInput").onchange = (e) => { addFiles(e.target.files); e.target.value = ""; };
  const box = $("#composerBox");
  ["dragenter", "dragover"].forEach((ev) => box.addEventListener(ev, (e) => { e.preventDefault(); box.classList.add("drag"); }));
  ["dragleave", "drop"].forEach((ev) => box.addEventListener(ev, (e) => { e.preventDefault(); box.classList.remove("drag"); }));
  box.addEventListener("drop", (e) => addFiles(e.dataTransfer.files));
}
function addFiles(list) {
  for (const f of list) if (state.files.length < 5) state.files.push(f);
  renderAttachRow(); updateSend();
}
function renderAttachRow() {
  $("#attachRow").innerHTML = state.files.map((f, i) => `<span class="att-chip">${icon(/\.(png|jpe?g|webp|gif|bmp|tiff?)$/i.test(f.name) ? "image" : "file", 13)}
    ${esc(f.name)} <span style="color:var(--muted)">${fmtBytes(f.size)}</span><button data-i="${i}" aria-label="Remove">×</button></span>`).join("");
  document.querySelectorAll("#attachRow button").forEach((b) => (b.onclick = () => { state.files.splice(+b.dataset.i, 1); renderAttachRow(); updateSend(); }));
}
function autosize() { const ta = $("#prompt"); ta.style.height = "auto"; ta.style.height = Math.min(ta.scrollHeight, 220) + "px"; }
function updateSend() { $("#sendBtn").disabled = state.busy || (!$("#prompt").value.trim() && !state.files.length); }
function scrollChat() { const c = $("#chat"); c.scrollTop = c.scrollHeight; }

function addUserMessage(text, files, note) {
  $("#welcome").hidden = true;
  const div = document.createElement("div");
  div.className = "msg user";
  const chips = (files || []).map((f) => `<span class="att-chip">${icon(/\.(png|jpe?g|webp|gif|bmp|tiff?)$/i.test(f.name) ? "image" : "file", 13)}${esc(f.name)}${f.size ? ` <span style="color:var(--muted)">${fmtBytes(f.size)}</span>` : ""}</span>`).join("");
  div.innerHTML = `<div class="bubble-user">${withPlaceholders(text || "")}${chips ? `<div class="att-chips">${chips}</div>` : ""}${note ? `<div style="font-size:11px;color:var(--muted);margin-top:6px">${esc(note)}</div>` : ""}</div>`;
  $("#messages").appendChild(div);
  scrollChat();
}
function addBotGroup() {
  const div = document.createElement("div");
  div.className = "msg bot";
  div.innerHTML = `<div class="bot-avatar">${icon("shield", 16)}</div><div class="bot-col"></div>`;
  $("#messages").appendChild(div);
  return div.querySelector(".bot-col");
}

// ───────────────────────── Send + stream ─────────────────────────
async function send() {
  const text = $("#prompt").value;
  if (state.busy || (!text.trim() && !state.files.length)) return;
  const files = state.files.slice();
  state.busy = true; updateSend();
  addUserMessage(text, files);
  $("#prompt").value = ""; autosize(); state.files = []; renderAttachRow();

  const col = addBotGroup();
  const card = createScreenCard(col);
  const fd = new FormData();
  fd.append("prompt", text);
  if (state.conversationId) fd.append("conversation_id", state.conversationId);
  files.forEach((f) => fd.append("files", f, f.name));

  try {
    await streamEvents(fetch("/api/chat", { method: "POST", headers: { "X-Demo-User": state.me.id }, body: fd }), card, col);
  } finally {
    state.busy = false; updateSend();
    await refreshConversations(); refreshBadge();
    const active = document.querySelector(`.conv-item[data-id="${state.conversationId}"] .t`);
    if (active) $("#convTitle").textContent = active.textContent;
  }
}

/* Read an NDJSON response and feed every event, in order, to handleEvent(). */
async function streamEvents(fetchPromise, card, col) {
  const queue = [];
  let finished = false;
  const consumer = (async () => {
    while (!finished || queue.length) {
      if (!queue.length) { await sleep(25); continue; }
      await handleEvent(queue.shift(), card, col);
    }
  })();
  try {
    const res = await fetchPromise;
    if (!res.ok) {
      const e = await res.json().catch(() => ({}));
      throw new Error(e.error || "Gateway error " + res.status);
    }
    const reader = res.body.getReader();
    const dec = new TextDecoder();
    let buf = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let nl;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl).trim(); buf = buf.slice(nl + 1);
        if (line) queue.push(JSON.parse(line));
      }
    }
  } catch (e) {
    queue.push({ type: "error", message: e.message });
  } finally {
    finished = true;
    await consumer;
  }
}

function createScreenCard(col) {
  const card = document.createElement("div");
  card.className = "screen-card";
  card.innerHTML = `<div class="sc-head"><span class="spinner"></span>
      <div class="grow"><div class="sc-title">Guardrail Agent · screening your request</div><div class="sc-sub">connecting to gateway…</div></div>
      <span class="sc-badge"></span></div>
    <ol class="steps"></ol>`;
  card._data = {};
  col.appendChild(card);
  scrollChat();
  return card;
}

let lastStepShown = 0;
const GROUP_LABEL = { done: "Passed", warn: "Findings", fail: "Failed", hold: "On hold", skipped: "Not needed", running: "Running…", pending: "Waiting" };
function updateGroup(g) {
  if (!g) return;
  const st = [...g.querySelectorAll(".step")].map((li) => li.className.replace("step", "").trim());
  const order = ["fail", "hold", "warn", "done"];
  let state = st.includes("running") ? "running" : st.every((x) => x === "pending") ? "pending"
    : st.every((x) => x === "skipped") ? "skipped" : st.some((x) => x === "pending") ? "running"
    : order.find((o) => st.includes(o)) || "done";
  g.className = "step-group " + state;
  g.querySelector(".g-ico").innerHTML = state === "running" ? '<span class="spinner sm"></span>' : state === "pending" ? "" : icon(STEP_ICON[state] || "check", 12, 2.6);
  g.querySelector(".g-state").textContent = GROUP_LABEL[state] || state;
}
async function handleEvent(ev, card, col) {
  switch (ev.type) {
    case "start": {
      state.conversationId = ev.conversation_id;
      const groups = ev.groups || [{ id: "all", title: "Screening" }];
      card.querySelector(".sc-sub").textContent = ev.request_id + " · " + groups.length + " checks · " + ev.steps.length + " steps";
      const stepLi = (s) => `<li class="step pending" data-id="${s.id}">
          <span class="ico"></span><div><div class="name">${esc(s.title)}</div><div class="summary">Waiting</div></div><span class="ms"></span></li>`;
      card.querySelector(".steps").innerHTML = groups.map((g) => `<li class="step-group pending" data-group="${g.id}">
          <div class="g-head"><span class="g-ico"></span><span class="g-title">${esc(g.title)}</span><span class="g-state">Waiting</span></div>
          <ol class="substeps">${ev.steps.filter((s) => (s.group || "all") === g.id).map(stepLi).join("")}</ol></li>`).join("");
      break;
    }
    case "step": {
      const li = card.querySelector(`.step[data-id="${ev.id}"]`);
      if (!li) break;
      if (ev.status === "running") {
        li.className = "step running";
        updateGroup(li.closest(".step-group"));
        li.querySelector(".ico").innerHTML = '<span class="spinner sm"></span>';
        li.querySelector(".summary").textContent = "Running…";
        // pace completed steps so people can follow the agent (backend timing is shown, not faked)
        const wait = 230 - (Date.now() - lastStepShown);
        if (wait > 0) await sleep(wait);
        break;
      }
      li.className = "step " + ev.status;
      li.querySelector(".ico").innerHTML = icon(STEP_ICON[ev.status] || "check", 12, 2.6);
      li.querySelector(".summary").textContent = ev.summary;
      li.querySelector(".ms").textContent = ev.ms + " ms";
      card._data[ev.id] = ev.data || {};
      updateGroup(li.closest(".step-group"));
      lastStepShown = Date.now();
      scrollChat();
      break;
    }
    case "decision":
      renderDecision(card, ev, col);
      break;
    case "llm_start": {
      card._ai = addAiBubble(col, "", true, ev.model);
      break;
    }
    case "token": {
      if (!card._ai) card._ai = addAiBubble(col, "", true);
      card._ai.text += ev.text;
      if (!card._ai.raf) {
        card._ai.raf = requestAnimationFrame(() => {
          card._ai.raf = null;
          card._ai.body.innerHTML = md(card._ai.text) + '<span class="cursor"></span>';
          scrollChat();
        });
      }
      break;
    }
    case "llm_done": {
      if (card._ai) {
        if (card._ai.raf) cancelAnimationFrame(card._ai.raf);
        card._ai.body.innerHTML = md(card._ai.text);
        card._ai.head.insertAdjacentHTML("beforeend", ` · ${(ev.ms / 1000).toFixed(1)} s`);
      }
      scrollChat();
      break;
    }
    case "llm_error": {
      if (card._ai) card._ai.el.remove();
      const e = document.createElement("div");
      e.className = "ai-error";
      e.innerHTML = `<b>The request was cleared, but the local model did not answer.</b><br>${esc(ev.message)}`;
      col.appendChild(e);
      scrollChat();
      break;
    }
    case "error": {
      card.querySelector(".spinner")?.remove();
      card.classList.add("d-BLOCK");
      card.querySelector(".sc-title").textContent = "Guardrail Agent";
      card.insertAdjacentHTML("beforeend", `<div class="sc-body"><div class="ai-error">${esc(ev.message)} – nothing was forwarded to the model.</div></div>`);
      break;
    }
    case "review_result":
      applyReviewResult(card, ev);
      break;
    case "done":
      break;
  }
}

function addAiBubble(col, text, streaming, model) {
  const el = document.createElement("div");
  el.className = "bubble-ai";
  el.innerHTML = `<div class="ai-head">${icon("sparkle", 13)}<span>Nimbus Assist · ${esc(model || (state.health && state.health.llm.model) || "local model")}</span></div><div class="ai-body"></div>`;
  const body = el.querySelector(".ai-body");
  body.innerHTML = md(text) + (streaming ? '<span class="cursor"></span>' : "");
  col.appendChild(el);
  scrollChat();
  return { el, body, head: el.querySelector(".ai-head span"), text, raf: null };
}

// ───────────────────────── Decision rendering ─────────────────────────
function hlSpan(s) {
  return s.type ? `<span class="hl ${s.category} hl-sev-${s.severity || ""}" title="${esc(s.label)} · ${esc(s.severity || "")}">${esc(s.text)}</span>` : esc(s.text);
}

function detectionTable(findings) {
  if (!findings.length) return "";
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  findings.forEach((f) => (counts[f.severity] = (counts[f.severity] || 0) + 1));
  const cats = new Set(findings.map((f) => f.category));
  const rows = findings.slice().sort((x, y) => (y.severity_rank || 0) - (x.severity_rank || 0));
  return `<div><div class="section-label">${icon("alert", 13)}Detection results</div>
    <div class="det-summary"><span><b>${findings.length}</b> instance${findings.length === 1 ? "" : "s"}</span>
      <span><b>${cats.size}</b> categor${cats.size === 1 ? "y" : "ies"}</span>
      ${["CRITICAL", "HIGH", "MEDIUM", "LOW"].filter((l) => counts[l]).map((l) => `<span>${sevBadge(l)} ×${counts[l]}</span>`).join("")}</div>
    <div class="det-table-wrap"><table class="table-mini det-table"><thead><tr><th>Category</th><th>Entity</th><th>Severity</th><th>Confidence</th><th>Method</th><th>Value (masked)</th><th>Action taken</th></tr></thead><tbody>
    ${rows.map((f) => `<tr class="${f.severity === "LOW" ? "row-low" : ""}"><td>${f.group ? `<span class="grp">${esc(f.group)}</span>` : ""}${esc(CAT[f.category] || f.category_label)}</td>
      <td>${esc(f.label)}${f.source !== "prompt" ? `<div class="sub">${esc(f.source)}</div>` : ""}</td>
      <td>${sevBadge(f.severity)}</td><td class="mono">${Math.round((f.confidence || 0) * 100)}%</td>
      <td>${esc(f.method)}${f.note ? `<div class="sub">${esc(f.note)}</div>` : ""}</td>
      <td class="mono">${esc(f.masked || "–")}</td><td data-act>${esc(f.action_taken || f.action)}</td></tr>`).join("")}
    </tbody></table></div></div>`;
}

function renderDecision(card, ev, col) {
  const d = ev.decision;
  const a = d.action;
  card.classList.add("d-" + a);
  card._ev = ev;
  card.querySelector(".spinner")?.remove();
  card.querySelector(".sc-head").insertAdjacentHTML("afterbegin", `<span style="color:#a9b9ff">${icon("shield-check", 18)}</span>`);
  card.querySelector(".sc-title").textContent = "Guardrail Agent · screening complete";
  card.querySelector(".sc-badge").innerHTML = badge(a);

  const data = card._data;
  const sections = [];
  const forwardedNote = {
    ALLOW: ev.low_notes ? `Allowed – ${ev.low_notes} low-risk item(s) noted but not censored.` : "Original prompt forwarded to the local model.",
    REDACT_AND_ALLOW: "Modified – sensitive values were censored; only the censored prompt below was forwarded.",
    USER_REVIEW: "Not sent yet – review the highlighted items below and choose how to continue.",
    MANAGER_APPROVAL: "Held encrypted in the approval vault. Nothing has been sent to the model.",
    BLOCK: "Blocked – this request was not sent to the model.",
  }[a];

  sections.push(`<div class="decision-banner db-${a}">
      <div class="db-ico">${icon(D[a].icon, 18)}</div>
      <div style="flex:1;min-width:0"><h4>${esc(D[a].label)}</h4><p>${esc(d.explanation)}</p>
        <p style="margin-top:6px;color:var(--text)" data-outcome>${esc(forwardedNote)}</p>
        <div class="risk" style="margin-top:9px"><span>Risk <b style="color:${RISK_COLOR[d.risk_level]}">${esc(d.risk_level)}</b></span>
          <span class="risk-bar"><i style="width:${d.risk_score}%;background:${RISK_COLOR[d.risk_level]}"></i></span>
          <span>${d.risk_score}/100 · screened in ${ev.screening_ms} ms${ev.context && ev.context.strict_mode ? " · strict mode" : ""}</span></div>
      </div></div>`);

  // Content safety verdict
  if (ev.safety) {
    const v = ev.safety;
    const ruleHits = (data.safety && data.safety.rule_hits) || [];
    const verdict = v.status === "disabled" ? "Safety model disabled – built-in rules only"
      : v.status === "error" ? `No verdict from ${v.model}: ${v.error} – ${v.fail_mode === "open" ? "fail-open configured" : "request blocked (fail closed)"}`
      : v.blocking.length ? `Unsafe – ${v.blocking.join(", ")} (${v.model})`
      : v.advisory.length ? `Advisory – ${v.advisory.join(", ")} (not blocking)`
      : `Safe (${v.model}, ${v.ms} ms${v.chunks > 1 ? `, ${v.chunks} chunks` : ""})`;
    sections.push(`<div><div class="section-label">${icon("shield", 13)}Content safety check</div>
      <div class="safety-line ${v.blocking.length || v.status === "error" || ruleHits.length ? "bad" : v.advisory.length || v.status === "disabled" ? "warn" : "ok"}">
        <div><b>Local safety model:</b> ${esc(verdict)}</div>
        <div><b>Built-in harmful-use rules:</b> ${ruleHits.length ? esc(ruleHits.map((f) => f.label).join(", ")) : "no match"}</div>
      </div></div>`);
  }
  if (ev.support) sections.push(`<div class="support-box">${icon("heart", 15)}<span>${esc(ev.support)}</span></div>`);

  // Highlighted prompt (values masked)
  const hl = data.detect && data.detect.highlights;
  if (hl && hl.some((s) => s.type)) {
    sections.push(`<div><div class="section-label">${icon("scan", 13)}Sensitive content highlighted (values masked)</div>
      <div class="hl-box">${hl.map(hlSpan).join("")}</div></div>`);
  }

  // Per-instance detection table
  sections.push(detectionTable(ev.findings.filter((f) => f.type !== "ATTACHMENT_ERROR")));

  // User review (MEDIUM items)
  if (a === "USER_REVIEW" && ev.review) {
    sections.push(`<div class="review-box" data-review>
      <div class="section-label">${icon("eye-off", 13)}Please review before sending</div>
      <p>${ev.review.items.length} medium-severity item${ev.review.items.length === 1 ? "" : "s"} detected:
        ${ev.review.items.map((f) => `<span class="fchip"><b>${esc(f.label)}</b> <span class="mono">${esc(f.masked)}</span></span>`).join(" ")}</p>
      ${ev.review.auto_redacted ? `<p class="sub">${ev.review.auto_redacted} critical/high item(s) will be redacted in every case.</p>` : ""}
      <div class="section-label" style="margin-top:8px">If you choose “Redact & send”, the model receives:</div>
      <div class="hl-box">${withPlaceholders(ev.review.strict_preview)}</div>
      <div class="review-actions">
        <button class="btn primary" data-choice="redact">${icon("eye-off", 14)}Redact & send</button>
        <button class="btn" data-choice="send">${icon("send", 14)}Send anyway</button>
        <button class="btn danger" data-choice="cancel">${icon("x", 14)}Cancel</button>
        <span class="sub">Held encrypted for ${ev.review.ttl_minutes} min · your choice is logged</span>
      </div></div>`);
  }

  // Redactions + sanitized prompt
  if (ev.replacements && ev.replacements.length && (a === "REDACT_AND_ALLOW" || a === "MANAGER_APPROVAL")) {
    sections.push(`<div><div class="section-label">${icon("eye-off", 13)}What was censored</div>
      <table class="table-mini"><thead><tr><th>Placeholder</th><th>Type</th><th>Severity</th><th>Original (masked)</th><th>Source</th></tr></thead><tbody>
      ${ev.replacements.map((r) => `<tr><td><span class="ph">${esc(r.placeholder)}</span></td><td>${esc(r.label)}</td><td>${sevBadge(r.severity)}</td><td class="mono">${esc(r.masked)}</td><td>${esc(r.source)}</td></tr>`).join("")}
      </tbody></table></div>`);
  }
  if (ev.sanitized_prompt != null && a === "REDACT_AND_ALLOW") {
    sections.push(`<div><div class="section-label">${icon("send", 13)}Censored prompt sent to the model</div><div class="hl-box">${withPlaceholders(ev.sanitized_prompt)}</div></div>`);
  }

  // Attachments + OCR
  const atts = [].concat((data.attachments && data.attachments.attachments) || [], (data.ocr && data.ocr.attachments) || [])
    .filter((x) => x.routed !== "ocr");
  if (atts.length) {
    sections.push(`<div><div class="section-label">${icon("paperclip", 13)}Attachments inspected</div>${atts.map((x) => `
      <details class="fold" ${x.ok ? "" : "open"}><summary>${icon(x.kind === "image" ? "image" : "file", 14)}<b style="color:var(--text)">${esc(x.name)}</b>
        <span>${esc(x.method || x.kind)}${x.ocr_confidence != null ? ` · ${x.ocr_words} words · confidence ${x.ocr_confidence}%` : ""}${x.pages ? ` · ${x.pages} pages` : ""}</span>
        <span style="margin-left:auto">${x.ok ? `<span class="badge-d ${x.findings.length ? "REDACT_AND_ALLOW" : "ALLOW"}">${x.findings.length ? x.findings.length + " finding(s)" : "clean"}</span>` : badge("BLOCK", "Could not scan")}</span></summary>
        <div class="fold-body">${x.ok ? (x.preview && x.preview.length ? `<div class="section-label">${x.kind === "image" ? "Text extracted by OCR" : "Extracted text"} (values masked)</div>
          <div class="hl-box">${x.preview.map(hlSpan).join("")}</div>` : `<div class="ai-note">No readable text found.</div>`) +
          (x.notes && x.notes.length ? `<div style="font-size:12px;color:var(--muted)">${esc(x.notes.join(" · "))}</div>` : "")
          : `<div class="ai-error">${esc(x.error)} – the gateway fails closed, so the request is blocked.</div>`}</div></details>`).join("")}</div>`);
  }

  // Block: corrective action
  if (a === "BLOCK" && d.remediation.length) {
    sections.push(`<div class="remedy"><b>Recommended corrective action</b><ul style="margin:6px 0 0;padding-left:18px">${d.remediation.map((r) => `<li>${esc(r)}</li>`).join("")}</ul></div>`);
  }

  // Approval tracker
  if (a === "MANAGER_APPROVAL") {
    sections.push(`<div class="approval-slot"></div>`);
  }

  // Policy clauses: governing clauses shown in full, the rest of the retrieved set folded
  const refs = new Set(d.clause_refs);
  const backend = (data.policy && data.policy.backend) || "policy store";
  const gov = ev.clauses.filter((c) => refs.has(c.id));
  const orgPack = ev.clauses.filter((c) => c.match === "reference");
  const rest = ev.clauses.filter((c) => !refs.has(c.id) && c.match !== "reference");
  sections.push(`<div><div class="section-label">${icon("book", 13)}Applicable policy · retrieved from ${esc(backend)}</div>
      <div class="clauses">${gov.map((c) => clauseHtml(c, true)).join("")}${orgPack.map((c) => clauseHtml(c, false)).join("")}</div></div>`);
  if (rest.length) {
    sections.push(`<details class="fold"><summary>${icon("database", 14)}<b style="color:var(--text)">Other retrieved clauses (${rest.length})</b>
      <span>supporting context from semantic search</span></summary>
      <div class="fold-body"><div class="clauses">${rest.map((c) => clauseHtml(c, false)).join("")}</div></div></details>`);
  }

  const body = document.createElement("div");
  body.className = "sc-body";
  body.innerHTML = sections.join("");
  card.appendChild(body);

  if (a === "MANAGER_APPROVAL") {
    trackApproval(ev.request_id, body.querySelector(".approval-slot"), col, ev.approval);
  }
  if (a === "USER_REVIEW") bindReview(card, col, ev.request_id);
  scrollChat();
}

/* USER_REVIEW: the user's choice continues the SAME request – the prompt is not re-submitted. */
function bindReview(card, col, rid) {
  card.querySelectorAll("[data-choice]").forEach((btn) => (btn.onclick = async () => {
    if (state.busy) return;
    state.busy = true; updateSend();
    card.querySelectorAll("[data-choice]").forEach((b) => (b.disabled = true));
    btn.insertAdjacentHTML("afterbegin", '<span class="spinner sm"></span>');
    try {
      await streamEvents(fetch(`/api/requests/${rid}/review`, {
        method: "POST", headers: { "X-Demo-User": state.me.id, "Content-Type": "application/json" },
        body: JSON.stringify({ choice: btn.dataset.choice }),
      }), card, col);
    } finally {
      state.busy = false; updateSend(); refreshConversations();
    }
  }));
}

function applyReviewResult(card, ev) {
  const box = card.querySelector("[data-review]");
  const text = ev.choice === "cancel" ? "Cancelled – the held request was deleted and nothing was sent."
    : ev.choice === "redact" ? "You chose to redact the medium-severity items. The censored prompt was sent to the model."
    : "You chose to send the medium-severity items unredacted (critical/high items stay redacted). This choice is logged.";
  if (box) {
    box.innerHTML = `<div class="section-label">${icon("check", 13)}Your review</div><p>${esc(text)}</p>` +
      (ev.sanitized_prompt ? `<div class="hl-box">${withPlaceholders(ev.sanitized_prompt)}</div>` : "");
  }
  const h4 = card.querySelector(".decision-banner h4");
  if (h4) h4.textContent = ev.choice === "cancel" ? "Cancelled after review" : D[ev.decision].label + " (after your review)";
  card.querySelector(".sc-badge").innerHTML = ev.choice === "cancel" ? `<span class="badge-d neutral">${icon("x", 12, 2.4)}Cancelled</span>` : badge(ev.decision);
  const out = card.querySelector("[data-outcome]");
  if (out) out.textContent = text;
  const verdict = { redact: "redacted (user choice)", send: "sent unredacted after warning (user choice)", cancel: "request cancelled by user" }[ev.choice];
  card.querySelectorAll("td[data-act]").forEach((td) => { if (td.textContent === "awaiting user review") td.textContent = verdict; });
}

const CONSISTENCY = { consistent: "Consistent with gateway", partial: "Partly enforced", conflict: "Differs from gateway", advisory: "Advisory" };
function clauseHtml(c, governing) {
  const pct = Math.max(0, Math.min(1, c.score || 0)) * 100;
  const isRef = c.kind === "reference" || c.action === "REFERENCE";
  const tag = isRef ? `<span class="badge-d ref-badge">Org policy pack</span>`
    : badge(c.action, c.action === "INFO" ? "Procedure" : (D[c.action] ? D[c.action].label : c.action));
  return `<div class="clause ${governing ? "governing" : ""} ${isRef ? "reference" : ""}">
    <div class="clause-head"><span class="clause-id">${esc(c.id)}</span><span class="clause-title">${esc(c.title)}</span>${tag}</div>
    <p class="clause-text">${esc(c.text)}</p>
    ${isRef ? `<div class="clause-meta"><span>${esc(c.policy || "")}${c.source_ref ? " · " + esc(c.source_ref) : ""} · supports the governing clause, does not decide</span></div>` : ""}
    <div class="clause-meta"><span>${governing ? "<b style='color:#a9b9ff'>Governs this decision</b> · " : ""}match: ${esc(c.match || "–")}</span>
      <span class="score">relevance <i><b style="width:${pct}%"></b></i> ${(c.score ?? 0).toFixed(2)}</span></div></div>`;
}

// ───────────────────────── Approval tracking (polls the gateway) ─────────────────────────
function trackerHtml(st) {
  const s = st || { approval_status: "pending" };
  const rejected = s.approval_status === "rejected";
  const approved = s.approval_status === "approved";
  const completed = s.vault_status === "completed";
  const steps = [
    { label: "Request held", state: "done", ic: "lock" },
    { label: `Review by ${s.assigned_manager || "manager"}`, state: approved || rejected ? "done" : "current", ic: "user-check" },
    { label: rejected ? "Rejected" : approved ? "Approved" : "Decision", state: rejected ? "bad" : approved ? "done" : "", ic: rejected ? "x" : "check" },
    { label: rejected ? "Discarded" : "Response delivered", state: rejected ? "bad" : completed ? "done" : approved ? "current" : "", ic: rejected ? "ban" : "sparkle" },
  ];
  return `<div class="section-label">${icon("clock", 13)}Approval status</div><div class="tracker">${steps.map((x) =>
    `<div class="tr-step ${x.state}"><span class="tr-dot">${icon(x.ic, 13, 2.4)}</span>${esc(x.label)}</div>`).join("")}</div>`;
}

function trackApproval(rid, slot, col, initial) {
  slot.innerHTML = trackerHtml(initial ? { approval_status: "pending", assigned_manager: initial.manager_name } : null) +
    `<div class="ai-note" style="margin-top:10px">Waiting for <b>${esc(initial ? initial.manager_name : "your manager")}</b> to approve or reject. Switch to their identity and open the shield panel to act on it.</div>`;
  let rendered = false;
  const poll = async () => {
    try {
      const st = await api("/api/requests/" + rid);
      let note = "";
      if (st.approval_status === "pending") note = `Waiting for <b>${esc(st.assigned_manager)}</b> to approve or reject. Switch to their identity and open the shield panel to act on it.`;
      else if (st.approval_status === "rejected") note = `Rejected by <b>${esc(st.approver)}</b>${st.approval_note ? ": “" + esc(st.approval_note) + "”" : ""}. The held content was deleted and never reached the model.`;
      else if (st.vault_status === "llm_error") note = `Approved by <b>${esc(st.approver)}</b>, but the local model was unreachable. <button class="btn sm" data-retry>Retry</button>`;
      else if (st.approval_status === "approved" && st.vault_status !== "completed") note = `Approved by <b>${esc(st.approver)}</b>${st.approval_note ? ": “" + esc(st.approval_note) + "”" : ""}. Sending the held request to the local model…`;
      else note = `Approved by <b>${esc(st.approver)}</b>${st.approval_note ? ": “" + esc(st.approval_note) + "”" : ""}. Released to the model once, under signed ticket.`;
      slot.innerHTML = trackerHtml(st) + `<div class="ai-note" style="margin-top:10px">${note}</div>`;
      const rb = slot.querySelector("[data-retry]");
      if (rb) rb.onclick = async () => { await api(`/api/requests/${rid}/retry`, { method: "POST" }); };
      if (st.response && !rendered) {
        rendered = true;
        const b = addAiBubble(col, st.response, false);
        b.head.insertAdjacentHTML("beforeend", " · released after manager approval");
      }
      const final = st.approval_status === "rejected" || st.vault_status === "completed";
      if (final && state.pollers[rid]) { clearInterval(state.pollers[rid]); delete state.pollers[rid]; }
    } catch (e) { /* keep polling */ }
  };
  poll();
  state.pollers[rid] = setInterval(poll, 2500);
}

// ───────────────────────── Governance panel ─────────────────────────
const TABS = {
  employee: [["overview", "My security overview", "bar-chart"], ["history", "My history", "history"],
    ["violations", "My violations", "alert"], ["approvals", "My approval requests", "inbox"], ["policy", "AI usage policy", "book"]],
  manager: [["approvals", "Approval queue", "inbox"], ["overview", "Team activity", "users"],
    ["violations", "Team violations", "alert"], ["history", "Team audit trail", "history"], ["policy", "AI usage policy", "book"]],
  admin: [["overview", "Security overview", "bar-chart"], ["violations", "Policy violations", "alert"],
    ["approvals", "Approvals", "inbox"], ["history", "Audit log", "list"], ["policy", "Policy management", "book"],
    ["events", "Governance events", "activity"]],
};

function openGov() {
  const role = state.me.role;
  $("#gov").hidden = false;
  $("#govRole").innerHTML = `${icon(role === "admin" ? "shield-check" : role === "manager" ? "users" : "user-check", 12)} ${esc(prettyType(role))} view`;
  $("#govSub").textContent = `${state.me.name} · ${state.me.title} · ${role === "admin" ? "organisation-wide scope" : role === "manager" ? "team " + state.me.team : "personal scope"}`;
  const tabs = TABS[role];
  if (!state.govTab || !tabs.find((t) => t[0] === state.govTab)) state.govTab = tabs[0][0];
  renderTabs();
  renderGovView();
}
function closeGov() { $("#gov").hidden = true; }
function renderTabs() {
  const pending = +($("#shieldBadge").textContent || 0);
  $("#govTabs").innerHTML = TABS[state.me.role].map(([id, label, ic]) =>
    `<button class="gov-tab ${id === state.govTab ? "active" : ""}" data-tab="${id}">${icon(ic, 15)}${esc(label)}${id === "approvals" && pending && state.me.role !== "employee" ? `<span class="count">${pending}</span>` : ""}</button>`).join("");
  document.querySelectorAll(".gov-tab").forEach((b) => (b.onclick = () => { state.govTab = b.dataset.tab; renderTabs(); renderGovView(); }));
}
async function renderGovView() {
  const body = $("#govBody");
  body.innerHTML = `<div class="empty"><span class="spinner" style="display:inline-block"></span></div>`;
  try {
    const v = state.govTab;
    if (v === "overview") await viewOverview(body);
    else if (v === "violations") await viewAudit(body, true);
    else if (v === "history") await viewAudit(body, false);
    else if (v === "approvals") await viewApprovals(body);
    else if (v === "policy") await viewPolicy(body);
    else if (v === "events") await viewEvents(body);
  } catch (e) { body.innerHTML = `<div class="ai-error">${esc(e.message)}</div>`; }
}

async function viewOverview(body) {
  const s = await api("/api/governance/overview");
  const pct = s.total ? Math.round((s.llm_forwarded / s.total) * 100) : 0;
  const m = (label, value, sub, color) => `<div class="metric"><div class="m-label">${color ? `<span class="swatch" style="background:${color}"></span>` : ""}${esc(label)}</div>
      <div class="m-value">${value}</div><div class="m-sub">${sub}</div></div>`;
  const ap = s.approvals;
  body.innerHTML = `
    <div class="store-banner">${icon("database", 16)}<span>Scope: <b>${esc(s.scope)}</b> · every figure below is computed live from the SQLite audit log.</span>
      <span style="margin-left:auto"><button class="btn sm" id="ovRefresh">${icon("refresh", 13)}Refresh</button></span></div>
    <div class="metrics">
      ${m("Total requests", s.total, s.total ? `avg screening ${s.avg_screening_ms} ms` : "no activity yet")}
      ${m("Allowed", s.decisions.ALLOW, "forwarded unchanged", D.ALLOW.color)}
      ${m("Redacted", s.decisions.REDACT_AND_ALLOW, `censored, then forwarded${s.reviews.redacted ? ` · ${s.reviews.redacted} after review` : ""}`, D.REDACT_AND_ALLOW.color)}
      ${m("Blocked", s.decisions.BLOCK, "never reached the model", D.BLOCK.color)}
      ${m("Approval requests", s.decisions.MANAGER_APPROVAL, `${ap.pending} pending · ${ap.approved} approved · ${ap.rejected} rejected`, D.MANAGER_APPROVAL.color)}
      ${m("Reached the LLM", s.llm_forwarded, `${pct}% of requests · ${s.awaiting_review} awaiting review · ${s.reviews.sent_unredacted} sent after warning`)}
    </div>
    <div class="grid-2e">
      <div class="card"><h3>Content safety</h3><p class="card-sub">Built-in harmful-use rules + local safety model (${esc((s.safety_model || {}).model || "disabled")})</p>
        <div class="kv-row"><span>Requests classified</span><b>${s.safety.checked}</b></div>
        <div class="kv-row"><span>Blocked by the safety model</span><b>${s.safety.unsafe}</b></div>
        <div class="kv-row"><span>Blocked by built-in rules</span><b>${s.safety.rule_blocks}</b></div>
        <div class="kv-row"><span>No verdict → failed closed</span><b>${s.safety.errors}</b></div>
        <div id="safetyChart" style="margin-top:10px"></div></div>
      <div class="card"><h3>Integrity checks</h3><p class="card-sub">Recomputed from the audit log on every refresh – each must be 0</p>
        ${[["blocked_but_forwarded", "Blocked requests that reached the model"], ["unapproved_but_forwarded", "Unapproved / rejected requests that reached the model"],
           ["unreviewed_but_forwarded", "Unreviewed / cancelled requests that reached the model"], ["unsafe_but_forwarded", "Unsafe-classified requests that reached the model"]]
          .map(([k, label]) => `<div class="kv-row"><span>${label}</span><b class="${s.integrity[k] ? "int-bad" : "int-ok"}">${s.integrity[k]}${s.integrity[k] ? "" : " ✓"}</b></div>`).join("")}
      </div>
    </div>
    <div class="grid-2">
      <div class="card"><div class="card-head"><div><h3>Usage trend</h3><p class="card-sub">Requests per ${s.trend.granularity}, stacked by decision</p></div></div>
        <div class="legend">${DECISIONS.map((k) => `<span><i style="background:${D[k].color}"></i>${D[k].label}</span>`).join("")}</div>
        <div class="chart-wrap" id="trendChart"></div></div>
      <div class="card"><h3>Decision mix</h3><p class="card-sub">Share of all screened requests</p><div id="mixChart"></div></div>
    </div>
    <div class="grid-2e">
      <div class="card"><h3>Policy violation categories</h3><p class="card-sub">Requests in which each category was detected</p><div id="catChart"></div></div>
      <div class="card"><h3>Detections by severity</h3><p class="card-sub">Every detected instance, after context classification</p><div id="sevChart"></div>
        <h3 style="margin-top:18px">Most detected data types</h3><p class="card-sub">Instances across prompts and attachments</p><div id="typeChart"></div></div>
    </div>
    <div class="grid-2e">
      <div class="card"><h3>Recent violations</h3><p class="card-sub">Latest non-allowed decisions</p><div id="recentVio"></div></div>
      <div class="card"><h3>${state.me.role === "employee" ? "Applicable policy clauses" : "Most active users"}</h3><p class="card-sub">${state.me.role === "employee" ? "Clauses referenced in your decisions" : "Requests per user in scope"}</p><div id="sideChart"></div></div>
    </div>`;
  $("#ovRefresh").onclick = renderGovView;
  if (!s.total) {
    ["#trendChart", "#mixChart", "#catChart", "#sevChart", "#typeChart", "#recentVio", "#sideChart", "#safetyChart"].forEach((id) => ($(id).innerHTML = `<div class="empty">No requests yet – send a message in the chat.</div>`));
    return;
  }
  const sc = Object.entries(s.safety.categories || {});
  if (sc.length) hbars($("#safetyChart"), sc.map(([k, v]) => ({ label: `${k} ${(s.safety.labels || {})[k] || ""}`, value: v, color: "var(--block)" })));
  stackedColumns($("#trendChart"), s.trend);
  hbars($("#mixChart"), DECISIONS.map((k) => ({ label: D[k].label, value: s.decisions[k], color: D[k].color })), s.total);
  const cats = Object.entries(s.categories);
  if (cats.length) hbars($("#catChart"), cats.map(([k, v]) => ({ label: CAT[k] || k, value: v, color: "#5b7cff" })));
  else $("#catChart").innerHTML = `<div class="empty">No violations detected.</div>`;
  hbars($("#sevChart"), ["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((l) => ({ label: SEV[l].label, value: s.severities[l] || 0, color: SEV[l].color })));
  const types = Object.entries(s.finding_types);
  if (types.length) hbars($("#typeChart"), types.map(([k, v]) => ({ label: prettyType(k), value: v, color: "#5b7cff" })));
  else $("#typeChart").innerHTML = `<div class="empty">Nothing detected yet.</div>`;
  $("#recentVio").innerHTML = s.recent_violations.length ? `<div class="vio-list">${s.recent_violations.map(vioHtml).join("")}</div>` : `<div class="empty">No violations 🎉</div>`;
  if (state.me.role === "employee") {
    const refs = {};
    s.recent_violations.forEach((r) => (r.clause_refs || []).forEach((c) => (refs[c] = (refs[c] || 0) + 1)));
    const pol = await api("/api/policy");
    const used = pol.clauses.filter((c) => refs[c.id]);
    $("#sideChart").innerHTML = used.length ? `<div class="clauses">${used.map((c) => clauseHtml(c, true)).join("")}</div>` : `<div class="empty">No clauses triggered yet.</div>`;
  } else {
    hbars($("#sideChart"), Object.entries(s.users).map(([k, v]) => ({ label: k, value: v, color: "#5b7cff" })));
  }
}

function vioHtml(r) {
  return `<div class="vio">${badge(r.decision)}<div class="v-main"><div><b>${esc(r.user_name)}</b> · <span class="mono">${esc(r.request_id)}</span> ${approvalBadge(r.approval_status)}</div>
    <div class="v-exp">${esc(r.explanation || "")}</div>
    <div class="v-meta">${esc(ago(r.ts))} · ${(r.categories || []).map((c) => esc(CAT[c] || c)).join(", ")} · clauses ${esc((r.clause_refs || []).join(", "))}</div></div></div>`;
}

async function viewAudit(body, violationsOnly) {
  const isAdmin = state.me.role === "admin";
  body.innerHTML = `<div class="filters">
      <select class="select" id="fDecision"><option value="">All decisions</option>${DECISIONS.concat(["USER_REVIEW"]).filter((d) => !violationsOnly || d !== "ALLOW").map((d) => `<option value="${d}">${D[d].label}</option>`).join("")}</select>
      <select class="select" id="fCategory"><option value="">All categories</option>${ALL_CATS.map((c) => `<option value="${c}">${CAT[c]}</option>`).join("")}</select>
      <input class="input" id="fSearch" placeholder="Search request, user, clause…" style="min-width:220px">
      <span style="flex:1"></span>
      ${isAdmin ? `<a class="btn sm" href="/api/audit.csv?as=${state.me.id}">${icon("download", 13)}Export CSV</a>` : ""}
      <button class="btn sm" id="fRefresh">${icon("refresh", 13)}Refresh</button>
    </div><div id="auditTable"></div>
    <p style="font-size:12px;color:var(--muted);margin-top:10px">${icon("lock", 12)} The audit log stores sanitized prompts or safe metadata only – never raw secrets or unredacted confidential content. Click a row for details.</p>`;
  const load = async () => {
    const q = new URLSearchParams({ decision: $("#fDecision").value, category: $("#fCategory").value, violations: violationsOnly ? "1" : "" });
    const rows = await api("/api/audit?" + q);
    const term = $("#fSearch").value.trim().toLowerCase();
    const filtered = term ? rows.filter((r) => JSON.stringify([r.request_id, r.user_name, r.clause_refs, r.categories, r.safe_prompt]).toLowerCase().includes(term)) : rows;
    auditTable($("#auditTable"), filtered);
  };
  ["#fDecision", "#fCategory"].forEach((id) => ($(id).onchange = load));
  $("#fSearch").oninput = load;
  $("#fRefresh").onclick = load;
  await load();
}

function auditTable(el, rows) {
  if (!rows.length) { el.innerHTML = `<div class="table-wrap"><div class="empty">No matching records.</div></div>`; return; }
  el.innerHTML = `<div class="table-wrap"><table class="table"><thead><tr><th>Time</th><th>Request</th><th>User</th><th>Decision</th><th>Risk</th><th>Categories</th><th>Clauses</th><th>Approval</th><th>LLM</th></tr></thead><tbody>
    ${rows.map((r, i) => `<tr class="row" data-i="${i}"><td style="white-space:nowrap">${esc(fmtTime(r.ts))}</td><td class="mono" style="white-space:nowrap">${esc(r.request_id)}</td>
      <td>${esc(r.user_name)}<div style="font-size:11.5px;color:var(--muted)">${esc(r.team)}</div></td><td>${badge(r.decision)}</td>
      <td><span class="risk-dot"><i style="background:${RISK_COLOR[r.risk_level]}"></i>${esc(r.risk_level)} <span style="color:var(--muted)">${r.risk_score}</span></span></td>
      <td><div class="cats">${(r.categories || []).map((c) => `<span class="tag">${esc(CAT[c] || c)}</span>`).join("") || '<span style="color:var(--muted)">–</span>'}</div></td>
      <td class="mono">${esc((r.clause_refs || []).join(", "))}</td><td>${approvalBadge(r.approval_status) || '<span style="color:var(--muted)">–</span>'}</td>
      <td style="white-space:nowrap">${r.llm_forwarded ? `<span style="color:var(--allow-t)">${icon("check", 13)} sent</span>` : `<span style="color:var(--muted)">${esc((r.llm_status || "").replace(/_/g, " "))}</span>`}</td></tr>`).join("")}
    </tbody></table></div>`;
  el.querySelectorAll("tr.row").forEach((tr) => (tr.onclick = () => {
    const next = tr.nextElementSibling;
    if (next && next.classList.contains("expand")) { next.remove(); return; }
    const r = rows[+tr.dataset.i];
    tr.insertAdjacentHTML("afterend", `<tr class="expand"><td colspan="9"><div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
      <div><div class="section-label">Logged prompt (sanitized / safe metadata)</div><div class="hl-box">${withPlaceholders(r.safe_prompt || "")}</div></div>
      <div><div class="section-label">Decision rationale</div><div style="font-size:13px;color:var(--text-2)">${esc(r.explanation || "")}</div>
        <div style="font-size:12px;color:var(--muted);margin-top:8px">Findings: ${esc(Object.entries(r.finding_types || {}).map(([k, v]) => prettyType(k) + " ×" + v).join(", ") || "none")}<br>
        Attachments: ${esc((r.attachments || []).map((a) => a.name + (a.ok ? "" : " (failed: " + a.error + ")")).join(", ") || "none")}<br>
        Screening: ${r.screening_ms} ms · Model: ${esc(r.llm_model || "")}${r.user_review ? ` · user review: ${esc(r.user_review.replace(/_/g, " "))}` : ""}${r.approver ? `<br>Decided by ${esc(userName(r.approver))} at ${esc(fmtTime(r.approval_ts))}${r.approval_note ? " – “" + esc(r.approval_note) + "”" : ""}` : ""}</div></div>
      </div>
      ${(r.detections || []).length ? `<div class="section-label" style="margin-top:12px">Detections (metadata only – values are never stored)</div>
      <table class="table-mini"><thead><tr><th>Entity</th><th>Category</th><th>Severity</th><th>Confidence</th><th>Method</th><th>Action</th></tr></thead><tbody>
      ${r.detections.map((x) => `<tr><td>${esc(prettyType(x.type))}</td><td>${esc(CAT[x.category] || x.category)}</td><td>${sevBadge(x.severity)}</td>
        <td class="mono">${Math.round((x.confidence || 0) * 100)}%</td><td>${esc(x.method || "")}</td><td>${esc(x.action || "")}</td></tr>`).join("")}</tbody></table>` : ""}
      </td></tr>`);
  }));
}

async function viewApprovals(body) {
  const role = state.me.role;
  body.innerHTML = `<div class="filters"><select class="select" id="aStatus"><option value="pending">Pending</option><option value="">All statuses</option><option value="approved">Approved</option><option value="rejected">Rejected</option></select>
    <span style="font-size:12.5px;color:var(--muted)">${role === "manager" ? "Requests from your direct reports that need your decision. Held content is decrypted only when you open it." :
      role === "admin" ? "Organisation-wide view (read-only). Only the requester's assigned manager can decide." : "Your requests that were held for manager approval."}</span>
    <span style="flex:1"></span><button class="btn sm" id="aRefresh">${icon("refresh", 13)}Refresh</button></div><div id="apprList"></div>`;
  if (role === "employee") $("#aStatus").value = "";
  const load = async () => {
    const rows = await api("/api/approvals?status=" + $("#aStatus").value);
    const el = $("#apprList");
    if (!rows.length) { el.innerHTML = `<div class="card"><div class="empty">No ${$("#aStatus").value || ""} approval requests.</div></div>`; return; }
    el.innerHTML = `<div class="appr-list">${rows.map((r) => `<div class="appr ${r.approval_status}" data-id="${r.request_id}">
      <div class="appr-head"><div class="avatar sm">${initials(r.requester)}</div><div><div class="who">${esc(r.requester)} <span class="meta">· ${esc(r.team)}</span></div>
        <div class="meta"><span class="mono">${esc(r.request_id)}</span> · ${esc(ago(r.ts))} · assigned to ${esc(r.assigned_manager_name || "–")}</div></div>
        <div class="grow"></div>${approvalBadge(r.approval_status)}${badge("MANAGER_APPROVAL", "Risk " + r.risk_level)}</div>
      <div class="appr-body"><div style="font-size:13px;color:var(--text-2)">${esc(r.explanation)}</div>
        <div class="cats" style="display:flex;gap:5px;flex-wrap:wrap">${(r.categories || []).map((c) => `<span class="tag">${esc(CAT[c] || c)}</span>`).join("")}${(r.clause_refs || []).map((c) => `<span class="tag mono">${esc(c)}</span>`).join("")}</div>
        ${r.approval_status !== "pending" ? `<div style="font-size:12.5px;color:var(--muted)">${esc(prettyType(r.approval_status))} by ${esc(userName(r.approver))} · ${esc(fmtTime(r.approval_ts))}${r.approval_note ? " – “" + esc(r.approval_note) + "”" : ""} · LLM: ${esc(r.llm_status)}</div>` : ""}
        ${r.can_decide ? `<div class="held"></div><div class="appr-actions">
            <button class="btn sm" data-review>${icon("eye-off", 13)}Review held content</button>
            <textarea class="input" placeholder="Note for the requester (optional)" rows="1"></textarea>
            <button class="btn success" data-act="approve">${icon("check", 14)}Approve</button>
            <button class="btn danger" data-act="reject">${icon("x", 14)}Reject</button></div>` : ""}
      </div></div>`).join("")}</div>`;
    el.querySelectorAll(".appr").forEach((card) => {
      const rid = card.dataset.id;
      const rv = card.querySelector("[data-review]");
      if (rv) rv.onclick = async () => {
        const data = await api("/api/approvals/" + rid);
        card.querySelector(".held").innerHTML = data.content ? `<div class="section-label">${icon("lock", 12)}Held content · decrypted for you only</div><div class="appr-content">${withPlaceholders(data.content)}</div>
          <div style="font-size:12px;color:var(--muted);margin-top:4px">${esc(data.note)}</div>` : `<div class="ai-note">${esc(data.note)}</div>`;
        rv.remove();
      };
      card.querySelectorAll("[data-act]").forEach((b) => (b.onclick = async () => {
        b.disabled = true;
        try {
          await api(`/api/approvals/${rid}/decision`, { method: "POST", json: { action: b.dataset.act, note: card.querySelector("textarea").value } });
          toast(b.dataset.act === "approve" ? "Approved – the gateway is forwarding the held request to the local model." : "Rejected – the held content was deleted.");
          refreshBadge(); setTimeout(() => { renderTabs(); load(); }, 400);
        } catch (e) { toast(e.message); b.disabled = false; }
      }));
    });
  };
  $("#aStatus").onchange = load;
  $("#aRefresh").onclick = load;
  await load();
}

async function viewPolicy(body) {
  const [data, sp] = await Promise.all([api("/api/policy"), api("/api/severity-policy")]);
  const admin = state.me.role === "admin";
  const st = data.store;
  const ACT = { redact: "Censor automatically", review: "Warn – user reviews", allow: "Allow (note only)", block: "Block" };
  body.innerHTML = `<div class="card sev-card"><div class="card-head"><div><h3>Severity-based censorship</h3>
      <p class="card-sub">Every detected item gets a severity; the action below is applied to the outgoing prompt. Thresholds live in <span class="mono">policy/severity_policy.json</span>.</p></div>
      <div class="strict">${admin ? `<label class="switch"><input type="checkbox" id="strictToggle" ${sp.strict_mode ? "checked" : ""}><span></span></label>` : ""}
        <div><b>Strict mode ${sp.strict_mode ? "ON" : "OFF"}</b><div class="sub">${sp.strict_mode ? "MEDIUM items are redacted automatically" : "MEDIUM items show a warning and the user decides"}</div></div></div></div>
    <table class="table-mini"><thead><tr><th>Level</th><th>Action</th><th>Behaviour</th><th>Examples</th></tr></thead><tbody>
    ${["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((l) => `<tr><td>${sevBadge(l)}</td><td><b>${esc(ACT[sp.effective_actions[l]] || sp.effective_actions[l])}</b></td>
      <td>${esc(sp.levels[l].summary)}</td><td>${esc((sp.levels[l].examples || []).join(", "))}</td></tr>`).join("")}</tbody></table>
    <p class="sub" style="margin-top:8px">Confidence threshold: ${Math.round(sp.min_confidence * 100)}% (lower-confidence matches are treated as LOW) · document-level categories → ${esc(D[sp.document_level_action] ? D[sp.document_level_action].label : sp.document_level_action)} · CRITICAL secrets are blocked when found by OCR, in a secrets/config file, or ${sp.critical_unsafe_redaction.block_if_distinct_critical_at_least}+ at once.</p></div>
    <div class="store-banner">${icon("database", 16)}<span>Indexed in <b>${esc(st.backend)}</b> · ${st.clauses} clauses · retrieval = category metadata lookup + semantic similarity</span>
      ${st.note ? `<span style="color:var(--redact-t)">${esc(st.note)}</span>` : ""}
      <span style="flex:1"></span>${admin ? `<button class="btn sm" id="pReset">${icon("refresh", 13)}Restore sample policy</button>` : ""}</div>
    ${admin ? `<p style="font-size:13px;color:var(--text-2);margin:-4px 0 14px">Changing a clause's action re-indexes ChromaDB immediately; the decision engine reads the action from the retrieved clause, so the next request follows the new policy. Every change is recorded as a governance event.</p>` : ""}
    <div class="policy-grid">${data.clauses.map((c) => `<div class="pcard" data-id="${c.id}">
      <div class="clause-head"><span class="clause-id">${esc(c.id)}</span><span class="clause-title">${esc(c.title)}</span>
        ${admin && c.action !== "INFO" ? `<select class="select" data-f="action">${["SEVERITY_BASED"].concat(DECISIONS, ["USER_REVIEW"]).map((d) => `<option value="${d}" ${d === c.action ? "selected" : ""}>${D[d].label}</option>`).join("")}</select>` : badge(c.action, c.action === "INFO" ? "Procedure" : D[c.action].label)}</div>
      <div style="font-size:11.5px;color:var(--muted)">Category: ${esc(CAT[c.category] || c.category)} · v${c.version} · updated ${esc(fmtTime(c.updated))} by ${esc(c.updated_by)}</div>
      ${admin ? `<textarea class="input" data-f="text">${esc(c.text)}</textarea>` : `<p class="clause-text" style="margin:0">${esc(c.text)}</p>`}
      <div class="rem"><b style="color:var(--text-2)">Corrective action:</b> ${esc(c.remediation)}</div>
      ${admin ? `<div class="row"><button class="btn sm primary" data-save>Save &amp; re-index</button></div>` : ""}</div>`).join("")}</div>
    ${(data.reference || []).length ? `<div class="card" style="margin-top:14px"><h3>Organisation policy pack <span class="badge-d ref-badge">reference</span></h3>
      <p class="card-sub">${data.reference.length} clauses from the six sample policies supplied with the hackathon datasets, indexed in the same ChromaDB collection. The best match per detected category is shown next to the governing clause; they never decide an outcome (the pack itself says it supplements, and does not override, the gateway's rules).</p>
      <div class="table-wrap"><table class="table"><thead><tr><th>ID</th><th>Policy</th><th>Clause</th><th>Maps to</th><th>Gateway</th></tr></thead><tbody>
      ${data.reference.map((c) => `<tr><td class="mono" style="white-space:nowrap">${esc(c.id)}</td><td>${esc(c.policy)}</td><td>${esc(c.text)}${c.consistency_note ? `<div class="sub" style="margin-top:4px">${esc(c.consistency_note)}</div>` : ""}</td>
        <td class="mono">${esc((c.maps_to || []).join(", "))}</td><td><span class="tag cons-${esc(c.consistency)}">${esc(CONSISTENCY[c.consistency] || c.consistency)}</span></td></tr>`).join("")}
      </tbody></table></div></div>` : ""}`;
  if (!admin) return;
  $("#strictToggle").onchange = async (e) => {
    await api("/api/severity-policy", { method: "PUT", json: { strict_mode: e.target.checked } });
    toast("Strict mode " + (e.target.checked ? "on – MEDIUM items are now redacted automatically." : "off – MEDIUM items will show a review warning."));
    renderGovView();
  };
  $("#pReset").onclick = async () => { await api("/api/policy/reset", { method: "POST" }); toast("Sample policy restored and re-indexed."); renderGovView(); };
  body.querySelectorAll(".pcard").forEach((card) => {
    const btn = card.querySelector("[data-save]");
    btn.onclick = async () => {
      const payload = { text: card.querySelector('[data-f="text"]').value };
      const sel = card.querySelector('[data-f="action"]');
      if (sel) payload.action = sel.value;
      btn.disabled = true;
      try { await api("/api/policy/" + card.dataset.id, { method: "PUT", json: payload }); toast(card.dataset.id + " saved and re-indexed."); renderGovView(); }
      catch (e) { toast(e.message); btn.disabled = false; }
    };
  });
}

async function viewEvents(body) {
  const rows = await api("/api/events");
  body.innerHTML = rows.length ? `<div class="table-wrap"><table class="table"><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Detail</th></tr></thead><tbody>
    ${rows.map((r) => `<tr><td>${esc(fmtTime(r.ts))}</td><td>${esc(r.actor)}</td><td><span class="tag">${esc(r.action.replace(/_/g, " "))}</span></td><td class="mono">${esc(r.target)}</td><td>${esc(r.detail)}</td></tr>`).join("")}
    </tbody></table></div>` : `<div class="card"><div class="empty">No governance events yet (approvals, policy edits and exports appear here).</div></div>`;
}

// ───────────────────────── Charts (hand-built SVG, no CDN) ─────────────────────────
function niceScale(maxVal) {
  const raw = Math.max(1, maxVal) / 4;
  const p = Math.pow(10, Math.floor(Math.log10(raw)));
  const n = raw / p;
  const step = Math.max(1, (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * p);
  const top = step * Math.max(1, Math.ceil(maxVal / step));
  return { step, top, ticks: Math.round(top / step) };
}

function stackedColumns(el, trend) {
  const W = 640, H = 230, m = { l: 30, r: 8, t: 10, b: 26 };
  const iw = W - m.l - m.r, ih = H - m.t - m.b, n = trend.buckets.length;
  const totals = trend.buckets.map((_, i) => DECISIONS.reduce((s, k) => s + trend.series[k][i], 0));
  const sc = niceScale(Math.max(1, ...totals));
  const max = sc.top;
  const slot = iw / n, bw = Math.min(30, slot * 0.6);
  const y = (v) => m.t + ih - (v / max) * ih;
  let svg = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Requests over time by decision">`;
  for (let t = 0; t <= sc.ticks; t++) {
    const v = sc.step * t, yy = y(v);
    svg += `<line x1="${m.l}" x2="${W - m.r}" y1="${yy}" y2="${yy}" stroke="#1f2a47" stroke-width="1" ${t ? 'stroke-dasharray="2 4"' : ""}/>`;
    svg += `<text x="${m.l - 8}" y="${yy + 4}" text-anchor="end" font-size="10.5" fill="#6b7698">${Math.round(v)}</text>`;
  }
  const label = (iso) => {
    const d = new Date(iso);
    return trend.granularity === "hour" ? d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", hour12: false }) : d.toLocaleDateString(undefined, { day: "2-digit", month: "short" });
  };
  trend.buckets.forEach((b, i) => {
    const x = m.l + i * slot + (slot - bw) / 2;
    let base = m.t + ih;
    const segs = DECISIONS.filter((k) => trend.series[k][i] > 0);
    segs.forEach((k, j) => {
      const h = (trend.series[k][i] / max) * ih;
      const top = j === segs.length - 1;
      const yTop = base - h + (j > 0 ? 2 : 0);
      const hh = Math.max(1, h - (j > 0 ? 2 : 0));
      if (top) {
        const r = Math.min(4, hh, bw / 2);
        svg += `<path d="M${x},${yTop + hh} V${yTop + r} Q${x},${yTop} ${x + r},${yTop} H${x + bw - r} Q${x + bw},${yTop} ${x + bw},${yTop + r} V${yTop + hh} Z" fill="${D[k].color}"/>`;
      } else {
        svg += `<rect x="${x}" y="${yTop}" width="${bw}" height="${hh}" fill="${D[k].color}"/>`;
      }
      base -= h;
    });
    if (i % Math.ceil(n / 7) === 0) {
      svg += `<text x="${x + bw / 2}" y="${H - 8}" text-anchor="middle" font-size="10.5" fill="#6b7698">${esc(label(b))}</text>`;
    }
    svg += `<rect class="hit" data-i="${i}" x="${m.l + i * slot}" y="${m.t}" width="${slot}" height="${ih}" fill="transparent"/>`;
  });
  svg += `</svg><div class="chart-tip"></div>`;
  el.innerHTML = svg;
  const tip = el.querySelector(".chart-tip");
  el.querySelectorAll(".hit").forEach((r) => {
    r.addEventListener("mousemove", (e) => {
      const i = +r.dataset.i;
      tip.innerHTML = `<div class="tt-title">${esc(label(trend.buckets[i]))} · ${totals[i]} request${totals[i] === 1 ? "" : "s"}</div>` +
        DECISIONS.map((k) => `<div class="tt-row"><i style="background:${D[k].color}"></i>${D[k].label}<b>${trend.series[k][i]}</b></div>`).join("");
      const box = el.getBoundingClientRect();
      tip.style.display = "block";
      let left = e.clientX - box.left + 14;
      if (left + 180 > box.width) left = e.clientX - box.left - 190;
      tip.style.left = left + "px";
      tip.style.top = Math.max(0, e.clientY - box.top - 40) + "px";
      r.setAttribute("fill", "rgba(255,255,255,0.03)");
    });
    r.addEventListener("mouseleave", () => { tip.style.display = "none"; r.setAttribute("fill", "transparent"); });
  });
}

function hbars(el, items, total) {
  const max = Math.max(1, ...items.map((i) => i.value));
  el.innerHTML = `<div class="hbars">${items.map((it) => `<div class="hbar" title="${esc(it.label)}: ${it.value}${total ? " (" + Math.round((it.value / total) * 100) + "%)" : ""}">
      <span class="lbl">${esc(it.label)}</span><span class="track"><span class="fill" style="display:block;width:${(it.value / max) * 100}%;background:${it.color}"></span></span>
      <span class="val">${it.value}</span></div>`).join("")}</div>`;
}

init();
