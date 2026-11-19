# 🛡️ GenAI Guardrail Gateway — AI Usage Governance Agent

**Agent Forge: Agentic AI Hackathon · PS16 · Theme: Data Privacy, Security & Governance**

An AI chat assistant with a built-in security gateway. Employees chat with a **local LLM (Ollama + Qwen)** as usual. Every prompt and attachment is intercepted first, screened by a **Guardrail Agent** (sensitive-data detection, OCR for images, a content-safety check by a second local model, **Llama Guard 3**, and policy retrieval from **ChromaDB**), and ends with one of four outcomes: **ALLOW**, **REDACT & ALLOW**, **BLOCK** or **REQUEST MANAGER APPROVAL**. Censorship is **severity-based** (CRITICAL / HIGH / MEDIUM / LOW): secrets and IDs are replaced with descriptive placeholders such as `[API KEY REDACTED]`, and MEDIUM personal details trigger a warning the user reviews before anything is sent. The gateway logs every decision. A shield icon opens a role-based governance dashboard built from the real audit data.

---

Everything runs on your own machine: no cloud APIs, no API keys, no paid services.

## Quick start (one click, for reviewers)

0. Get the code: `git clone https://github.com/tas7129/genai-guardrail-gateway.git`, or on GitHub click **Code → Download ZIP** and unzip it.
1. Install **Python 3.10+** if the machine does not have it (the Windows starter offers to install it for you).
2. Double-click the starter in the project folder:
   * **Windows:** `Start Guardrail Gateway.bat`
   * **macOS:** `Start Guardrail Gateway.command` (first time only: right-click → **Open** → **Open**, because macOS asks about downloaded scripts)
   * **Linux / any terminal:** `python3 launcher.py`
3. Leave the window that opens running. The launcher does every setup step that is still missing, then opens **http://127.0.0.1:8000** in your browser:

| Step | What the launcher does | Asks first? |
|---|---|---|
| 1 | Creates `.venv` and installs `requirements.txt` (first run, or when requirements change) | no |
| 2 | Starts Ollama if it is installed but stopped; offers to install it (winget / Homebrew) if missing | yes |
| 3 | Downloads the two local models if missing – `qwen2.5:3b` (assistant) and `llama-guard3:1b` (safety classifier), about 3.5 GB once, with progress | no |
| 4 | Checks Tesseract OCR (offers to install it) and ChromaDB (falls back to the built-in policy store if it cannot load) | yes, for installs |
| 5 | Starts the gateway; if it is already running, just opens the browser | no |

Close the window (or press `Ctrl+C`) to stop. `launcher.py --check` runs the checks without starting anything.

If something is still missing once the app is open, a **Setup check** banner at the top of the chat says what and why, and offers a **Download now** button for a missing model. The sidebar lights show the same status.

The manual, step-by-step route is still documented in [Installation](#6-installation) and [WINDOWS_SETUP.md](WINDOWS_SETUP.md).

---

## Screenshots

| Redact & allow | Block |
|---|---|
| ![Screening panel: an Aadhaar number and a diagnosis are censored before the prompt is forwarded](docs/screenshots/02_redact_and_allow.png) | ![Screening panel: a pasted config file with an AWS key and a database URL is blocked](docs/screenshots/03_block.png) |
| **Attachment + OCR** | **Request manager approval** |
| ![An attached screenshot is read with OCR and the personal data inside it is redacted](docs/screenshots/04_ocr_attachment.png) | ![Confidential deal details are encrypted and held for the assigned manager](docs/screenshots/05_manager_approval_request.png) |

| Manager approval queue | Admin governance dashboard |
|---|---|
| ![The engineering manager sees the held request with Review, Approve and Reject](docs/screenshots/06_manager_approval_queue.png) | ![Organisation-wide totals, content-safety statistics, integrity checks and charts from the audit log](docs/screenshots/07_admin_dashboard.png) |

*All data shown is synthetic. These were captured by an automated browser run that used the test stand-in for Ollama and the built-in in-memory policy store. On a fully set-up machine the panel reads "retrieved from ChromaDB" and shows the real model timings.*

---

## 1. Problem statement (PS16)

Employees use generative AI tools every day, and some paste source code, customer records or confidential plans into them. Banning AI isn't practical. Uncontrolled use, though, creates data-protection and intellectual-property risk, and governance teams can't see how AI is actually being used.

**What to build:** a chat front end that sits between users and a local LLM. Before forwarding any prompt or attachment, the agent must (1) check the prompt for sensitive data, (2) inspect attachments, including OCR of images, (3) retrieve relevant AI-usage-policy clauses from ChromaDB, (4) decide ALLOW / REDACT & ALLOW / BLOCK / REQUEST MANAGER APPROVAL, and (5) log every decision. **Expected output:** governed AI responses plus a dashboard of usage trends and policy violations.

## 2. Proposed solution

```
 Employee ──► Chat UI ──► Guardrail Gateway (Python) ──────────────► Ollama: Qwen 2.5 (assistant)
                              │ ① Sensitive Information Detection    ▲ only with a signed forward ticket,
                              │ ② Attachment and OCR Inspection       │ only after every check passed
                              │ ③ Content Safety Check ─────────────► Ollama: Llama Guard 3 (classifier only)
                              │ ④ Policy Retrieval ◄── ChromaDB (AI usage policy)
                              │ ⑤ Final Security Decision ──► SQLite audit log · encrypted approval vault
                              ▼
                   Governance panel (shield icon): employee / manager / admin views
```

Screening happens **before** the assistant model, so it never receives secrets, raw personal data, unsafe requests, or confidential content that hasn't been approved. Two local models run in Ollama with strictly separate roles: **Qwen** answers users; **Llama Guard** only classifies ("safe" / "unsafe" + hazard category) and never answers. The safety model sees exactly the text that could be forwarded, plus the recent conversation, and if it is missing or gives no verdict the request is blocked (**fail closed**). The rest of the decision is deterministic rules and policy, so a prompt-injection attack can't talk the gateway into allowing something.

### Architecture decision: Approach A vs Approach B

| Criterion | A – Separate security chatbot | B – Integrated guardrail agent | Our build |
|---|---|---|---|
| 1. Development time | ✅ Fastest | ⚠️ Slightly more integration | Same effort as A: one app, one backend |
| 2. Technical complexity | Low | Medium (interception, streaming) | Medium, isolated in `pipeline.py` |
| 3. Reliability | High | High if enforcement is server-side | Enforcement is 100% server-side |
| 4. Demonstrating all four decisions | Easy | Easy | One-click demo scenarios |
| 5. Image / attachment processing | Same | Same | Shared OCR + extraction module |
| 6. Local LLM integration | Simple | Simple via backend | Gateway is the *only* Ollama client |
| 7. Security & interception | Users can skip the checkpoint | Gateway in the path; Ollama must not be reachable directly | Ollama on 127.0.0.1 + signed forward tickets |
| 8. User experience | ❌ Two steps, two apps | ✅ Type once, click Send | ✅ |
| 9. Visual appeal | Basic | Live screening panel in the chat | ✅ |
| 10. Fit for a 3-person beginner team | ✅ | ⚠️ Fine *without* a browser extension | No extension, no build tools |

**Selected: Approach B, built as a custom integrated chat front end plus a Python middleware gateway** (no browser extension). It needs about the same effort as A, since it's still one app we fully control, but the user types once, sees screening live and gets the answer in the same window. That's what PS16 describes: a front end that *sits between* users and the LLM.

## 3. Features (all implemented)

| Area | What it does |
|---|---|
| **Chat interface** | ChatGPT-style UI, chat history, file/image upload (button or drag-and-drop), streaming responses, live status for LLM / policy store / OCR |
| **Live security screening** | Five checks – Sensitive Information Detection, Attachment and OCR Inspection, Content Safety Check, Policy Retrieval, Final Security Decision – made of eight real backend steps streamed as they finish, with measured timings, highlighted sensitive spans (values masked), the safety verdict and the governing policy clause |
| **Content safety** | Built-in harmful-use rules **plus a local safety classifier, Llama Guard 3 (`llama-guard3:1b`) via Ollama**. Hazard categories (violent and non-violent crimes, sexual content, child exploitation, weapons, hate, self-harm, …) block per `policy/safety_policy.json`; privacy and IP are advisory because the gateway's own detectors handle them. Missing model, timeout or unreadable verdict → **BLOCK** (fail closed). Attachments, OCR text and the conversation context are classified too, so split-up or hidden requests are seen |
| **Detection (12 categories, A–L)** | Personal identifiers, financial data, credentials, medical/health, confidential business, legal & government, location & tracking, private communications, sensitive personal attributes, children's information, cybersecurity secrets and intellectual property – 89 entity types – plus harmful or prohibited use and hidden zero-width characters. See **§3a**. |
| **Severity-based censorship** | Each instance gets a severity, confidence score and detection method. CRITICAL and HIGH values are replaced automatically; MEDIUM items show a warning with *Redact & send / Send anyway / Cancel* (or are redacted automatically in **strict mode**); LOW items are noted only. Context rules handle documented example values, public business contacts and children's data. Thresholds are configurable. |
| **Attachments** | txt / md / csv / json / code / PDF (text layer) / DOCX; images via **Tesseract OCR** with automatic rotation (90°/180°/270°), upscaling for small or blurry text and contrast enhancement for faint text. Unsupported, corrupt, encrypted, oversized or unreliably-read files → **fail closed (BLOCK)**. Image pixels are never forwarded, only the screened text |
| **Policy knowledge base** | 22-clause sample AI Usage Policy stored in **ChromaDB**; each request retrieves the governing clause per detected category (metadata query) plus semantically similar clauses |
| **Decision engine** | Reads the `action` of the retrieved clauses; most restrictive wins (BLOCK > APPROVAL > REVIEW > REDACT > ALLOW); a missing clause fails closed. **Mandatory controls** (harmful content, content-safety check, unscannable attachments) are always BLOCK: admins cannot weaken them and the engine enforces the minimum even if a stored clause were altered |
| **Manager approval** | Request held **encrypted** (Fernet) in a vault; only the assigned line manager can review/approve/reject; on approval the held text is **screened again** (detectors + safety model) before it is released once; rejection deletes it; a tampered vault entry releases nothing |
| **Audit log** | SQLite: request ID, timestamp, user/role/team, decision, risk, categories, finding counts, clause refs, approval status, sanitized prompt or safe metadata. Never raw secrets |
| **Governance panel** | Shield icon → role-based views. Employee: personal overview, history, violations, policy. Manager: approval queue, team activity, team violations. Admin: org-wide analytics, **content-safety statistics**, **integrity checks** (blocked / unapproved / unreviewed / unsafe requests that reached the model – must all be 0), violations, approvals, audit log + CSV export, **policy management** (edit and re-index live), governance events |
| **Identity** | `demo` mode (default, for presentations): pick any demo user. `pin` mode (`GG_AUTH_MODE=pin`): per-user PIN sign-in, HttpOnly signed session cookie, spoofed headers ignored, lock-out after 5 wrong PINs |

## 3a. Sensitive-information detection and censorship

**Pipeline.** `detectors.py` finds candidate values (regex + checksums + labelled fields + context lexicons) → `classifier.py` applies context rules and the severity policy → `decision.py` combines the result with the clause retrieved from ChromaDB → `redactor.py` censors **the actual outgoing prompt** (not just the display) → only then does `llm.py` forward it with a signed ticket.

| Level | Default action | Examples |
|---|---|---|
| **CRITICAL** | Censored automatically with a descriptive placeholder (`[PASSWORD REDACTED]`). **Blocked** when safe redaction can't be guaranteed: a pasted secrets/config file, 4+ separate secrets, or a secret read by OCR | Passwords, API keys, access/refresh tokens, OAuth secrets, SSH/encryption keys, DB & cloud credentials, session cookies, OTPs, recovery codes, JWTs, CVV/PIN, bank logins, crypto keys & seed phrases |
| **HIGH** | Redacted automatically with a category-specific placeholder; the rest of the prompt is preserved and the user is notified | Aadhaar, PAN, passport, driving licence, voter ID, SSN, biometrics, bank account & card numbers, medical diagnoses/prescriptions/records, children's personal data, live GPS/location, court & FIR numbers, visa details, internal hosts & IPs |
| **MEDIUM** | Warning + review: *Redact & send*, *Send anyway* (CRITICAL/HIGH stay redacted) or *Cancel*. **Strict mode** (admin toggle) redacts automatically | Personal phone/email, residential address, DOB, IP address, employee ID, UPI ID, salary, tax/insurance/transaction records, booking refs, vehicle numbers, chat participants & email correspondents, religion, caste, political affiliation, ethnicity, sexual orientation, gender identity, union membership |
| **LOW** | Not censored; shown as a note | Documented example values (`AKIAIOSFODNN7EXAMPLE`, `…@example.com`, `<API_KEY>`, sequential digits), public business contacts (`support@…`, toll-free numbers, office addresses), generic network addresses (`192.168.1.1`), matches below the confidence threshold |

Document-level categories (confidential business information, unpublished IP and source code, privileged/classified legal material, undisclosed vulnerabilities and security documents) have no single value to cut out, so they keep the **manager-approval** gate; any values inside are still redacted.

**Context rules (fewer false positives, no easy bypass).** Medical conditions and personal attributes are flagged only when tied to a person (*"I was diagnosed with …"*, not *"symptoms of diabetes"*). A name on its own is not flagged. Calling a value an *example* only lowers its severity when the value **also fails validation** (e.g. an Aadhaar that fails the Verhoeff checksum); a real-looking value is treated as real whatever the user claims. Requests about a minor raise personal data to *children's information* (HIGH). An address next to *"currently at"* becomes live location (HIGH).

**Censorship rules.** Only the sensitive span is replaced. Placeholders are descriptive (`[EMAIL REDACTED]`, `[AADHAAR NUMBER REDACTED]`, `[MEDICAL INFORMATION REDACTED]`). Several different values of one kind are numbered (`[EMAIL 1 REDACTED]`, `[EMAIL 2 REDACTED]`), and repeats get the same placeholder. Overlapping detections are **merged** so no fragment of a value survives. Original values never appear in the UI (always masked), the audit log (metadata only), logs, error messages or stored chat history (model replies are re-screened before storage).

**Per-instance output.** For every detection the gateway records the category (A–L), entity type, severity, confidence, detection method, censorship action taken and the censored prompt. The chat shows a detection table, and the audit log keeps the same metadata without values.

**Configuration.** `policy/severity_policy.json` holds the actions per level, `strict_mode`, `min_confidence`, the unsafe-redaction rules for CRITICAL items, the minimum severity for children's data and per-entity severity overrides. Admins can toggle strict mode in **Shield → Policy management**. Clause actions can also be overridden per category: `SEVERITY_BASED` follows the table above, and an explicit action such as `BLOCK` applies to the whole category.

## 4. Technology stack

| Component | Technology | Notes |
|---|---|---|
| Frontend | HTML + CSS + vanilla JS | No build step, no CDN; charts hand-built in SVG (works offline) |
| Backend | Python, **Starlette** + Uvicorn | Starlette is the ASGI toolkit FastAPI is built on; used for streaming responses |
| Local LLM | **Ollama + Qwen 2.5** (`qwen2.5:3b`) | `qwen2.5:1.5b` for 8 GB laptops |
| Content-safety classifier | **Ollama + Llama Guard 3** (`llama-guard3:1b`) | Classifier only; `llama-guard3:8b` is more accurate if RAM allows |
| Policy retrieval | **ChromaDB** | Offline feature-hashing embeddings, so no model download is needed |
| OCR | **Tesseract** via pytesseract | Grayscale + upscaling pre-processing |
| Sensitive-data detection | Regex + validators + lexicons | Deterministic and explainable; Presidio listed as future work |
| Database | **SQLite** | Audit log, vault, policy source of truth, events |
| Crypto | `cryptography` (Fernet, HMAC-SHA256) | Approval vault + forward tickets |

**Deviations from the suggested stack, stated openly:** Starlette instead of Streamlit, because Streamlit can't stream a real step-by-step backend trace into a chat bubble or render a shield-triggered role panel cleanly. Regex/validators instead of Presidio, because Presidio needs spaCy model downloads. All core PS16 requirements are kept: local LLM, ChromaDB, OCR, four decisions, logging and dashboard.

## 5. Project structure

```
genai-guardrail-gateway/
├── Start Guardrail Gateway.command   # macOS: double-click to set up and start
├── Start Guardrail Gateway.bat       # Windows: double-click to set up and start
├── launcher.py                 # one-click launcher (stdlib only): setup checks, model download, start
├── run.py                      # start the gateway directly  →  http://127.0.0.1:8000
├── requirements.txt · .env.example · .gitignore · .gitattributes
├── WINDOWS_SETUP.md            # step-by-step setup on a fresh Windows PC
├── backend/
│   ├── main.py                 # HTTP API + static frontend (Starlette)
│   ├── pipeline.py             # ★ Guardrail Agent: 5 checks / 8 screening steps
│   ├── safety_guard.py         # local safety classifier client (Llama Guard via Ollama, fail closed)
│   ├── sessions.py             # optional PIN sign-in + signed session cookies
│   ├── decision.py             # decision engine (detections + retrieved clauses)
│   ├── approvals.py            # manager-approval gate
│   ├── llm.py                  # Ollama client (requires a forward ticket)
│   ├── vault.py                # encryption + signed forward tickets
│   ├── db.py                   # SQLite: audit, vault, policy, events, history
│   ├── auth.py                 # demo identities & role scoping
│   ├── config.py
│   ├── scanner/
│   │   ├── entities.py         # entity types: category, severity, placeholder
│   │   ├── detectors.py        # sensitive-data detection (patterns, checksums, context)
│   │   ├── classifier.py       # context rules + severity policy → censorship action
│   │   ├── redactor.py         # descriptive placeholders + UI highlighting
│   │   ├── attachments.py      # file inspection (fail closed)
│   │   └── ocr.py              # Tesseract OCR (multi-pass: rotation, upscaling, contrast)
│   └── policy/
│       ├── store.py            # ChromaDB policy store + retrieval
│       └── embeddings.py       # offline embeddings
├── frontend/                   # index.html · styles.css · app.js
├── policy/ai_usage_policy.json # sample AI usage policy (22 governing clauses)
├── policy/safety_policy.json   # what each safety-model hazard category does (BLOCK / WARN)
├── policy/reference_policies.json # organisation policy pack from the datasets (27 reference clauses)
├── policy/severity_policy.json # severity levels, actions, thresholds (configurable)
├── samples/                    # synthetic demo files (image, CSV, code, broken files)
├── scripts/
│   ├── smoke_test.py           # end-to-end check against the running app
│   ├── run_audit.py            # full test suite → audit_report/AUDIT_REPORT.md
│   ├── verify_safety_model.py  # checks the REAL local models on this machine
│   ├── make_samples.py         # regenerate sample files
│   ├── mock_ollama.py          # test double used ONLY by automated tests
│   └── datasets/               # dataset audit, cleaning, evaluation (stdlib only)
├── dataset_audit/              # inventory, relevance, cleaning and test reports + evaluation results
├── datasets/                   # git-ignored data (see datasets/README.md)
├── audit_report/               # security audit: findings, root causes, automated results
├── tests/                      # pytest suite (tests/audit = data-driven audit cases)
└── docs/                       # presentation outline, demo script, team plan, checklist, screenshots/
```

## 6. Installation

### macOS (Apple Silicon or Intel)

```bash
# 1. System tools
brew install python@3.11 tesseract ollama

# 2. Local model (≈2 GB download; use qwen2.5:1.5b on 8 GB RAM machines)
ollama serve            # leave running in its own terminal (or open the Ollama app)
ollama pull qwen2.5:3b
ollama pull llama-guard3:1b   # content-safety classifier (~1 GB) – required: requests are blocked without it

# 3. Project
cd guardrail-gateway
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Windows (PowerShell)

See **[WINDOWS_SETUP.md](WINDOWS_SETUP.md)** for a complete step-by-step guide for a fresh Windows PC (including troubleshooting). In short:

```powershell
# Install Python 3.12 (python.org), Ollama (ollama.com/download), Tesseract (UB Mannheim build)
ollama pull qwen2.5:3b
ollama pull llama-guard3:1b
cd guardrail-gateway
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run.py
```

### Linux (Ubuntu/Debian)

```bash
sudo apt install -y python3-venv tesseract-ocr
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5:3b
ollama pull llama-guard3:1b
cd guardrail-gateway && python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## 7. Running

Easiest: double-click the starter file (see [Quick start](#quick-start-one-click-for-reviewers)). Manually:

```bash
source .venv/bin/activate          # Windows: .venv\Scripts\Activate.ps1
python run.py                      # → open http://127.0.0.1:8000
```

The sidebar shows four green lights when everything is ready: **Local LLM**, **Policy store: ChromaDB**, **Safety model**, **OCR engine**. If the LLM light is red, start `ollama serve`. If the safety-model light is red, run `ollama pull llama-guard3:1b` – until then every request is blocked (fail closed) and the UI says why.

Pre-demo checks (in a second terminal, with the app running):

```bash
python scripts/smoke_test.py            # 19 end-to-end checks through the real API and real models
python scripts/verify_safety_model.py   # both models installed, verdict format, false-positive rate, end-to-end
```

Reset all demo data: stop the server and delete the `data/` folder.

## 8. Demo scenarios

The welcome screen has one-click cards that fill the composer. You still press **Send** yourself.

| # | Who | Input | Expected outcome |
|---|---|---|---|
| 1 | Asha (employee) | "Explain the difference between symmetric and asymmetric encryption…" | **ALLOW** – original prompt → Qwen answers |
| 2 | Asha | Refund email with *Customer name / Email / Phone* (all MEDIUM) | **Review required** → click *Redact & send* → **REDACT & ALLOW** with `[NAME REDACTED]`, `[EMAIL REDACTED]`, `[PHONE NUMBER REDACTED]` |
| 3 | Asha | "My Aadhaar is … and I was diagnosed with type 2 diabetes…" | HIGH → censored automatically: `[AADHAAR NUMBER REDACTED]`, `[MEDICAL INFORMATION REDACTED]` |
| 4 | Asha | "My netbanking password is Pune@2026 …" | Single CRITICAL secret → `[PASSWORD REDACTED]`, question still answered |
| 5 | Asha | `.env`-style config with an AWS key + DB URL | **BLOCK** – secrets file, safe redaction impossible (AUP-5) |
| 6 | Asha | "CONFIDENTIAL – Project Falcon acquisition term sheet…" | **MANAGER APPROVAL** – held encrypted, tracker shows "Review by Rahul Mehta" |
| 7 | Asha | `samples/meeting_notes.png` (image) | OCR extracts text → email/phone (MEDIUM) → review → redacted |
| 8 | Asha | `samples/customer_export.csv` | Bulk personal records → **MANAGER APPROVAL** (identifiers stay redacted even after approval) |
| 9 | Asha | `samples/server_config_screenshot.png` | Secret read by OCR → **BLOCK** |
| 10 | Asha | "how to dissolve a body in sulfuric acid" | Harmful intent → **BLOCK** under AUP-12 |
| 11 | Asha | `samples/corrupted_image.png` or `unsupported_file.bin` | Can't be scanned → **BLOCK (fail closed)** |
| 12 | Rahul (manager) | Shield → Approval queue → *Review held content* → Approve | Gateway forwards the held request once; Asha's chat updates with the answer |
| 13 | Meera (admin) | Shield → overview (severity chart), audit log (per-detection metadata), policy management | Turn **strict mode** on → scenario 2 is redacted without the review step |

Switch identity with the **Demo identity** selector in the sidebar (bottom left).

## 9. Security design

* **Fail closed everywhere:** unscannable attachments, missing policy clauses, missing approver and pipeline errors all mean nothing is forwarded.
* **Signed forward tickets:** the decision engine issues an HMAC ticket bound to the request ID, the decision and the SHA-256 of the exact text. `llm.py` refuses to send anything without a matching ticket, so unscreened or modified content can't reach the model through any code path.
* **Approval is a real gate:** held content is encrypted at rest, decrypted only for the assigned manager's review and for the single release to the LLM, then deleted. Self-approval and approval by other managers are refused server-side (HTTP 403).
* **Audit hygiene:** the audit log stores the strictly censored prompt (even when the user chose *Send anyway*), per-detection metadata without values, and only metadata (length + categories) for confidential, source-code or bulk-record requests. Chat history stores censored text only, and model replies are re-screened before storage. Logs record exception types, never content. Tests scan the raw SQLite files and the captured logs for planted secrets.
* **Evasion resistance:** Unicode NFKC normalisation and zero-width-character stripping run before detection.
* **Preventing bypass:** Ollama listens on `127.0.0.1:11434` by default, so other machines can't reach it. Never set `OLLAMA_HOST=0.0.0.0`. In production, run Ollama in a private network (e.g. a Docker network marked `internal`) that only the gateway container can reach, and put SSO in front of the gateway.

## 10. Testing

The automated tests need **no Ollama, no models and no datasets**: they use a recording stand-in for Ollama (see below), and the dataset tests skip themselves when `datasets/` is empty. After `pip install -r requirements.txt`:

```bash
python scripts/run_audit.py        # whole suite + audit report (audit_report/AUDIT_REPORT.md, per-case PASS/FAIL)
pytest -q                          # unit + pipeline + API + security + dataset tests
python scripts/datasets/evaluate.py all   # benchmark against CredDetX + Nemotron-PII (needs datasets/)
python scripts/smoke_test.py       # against the running app (real Ollama)
python scripts/verify_safety_model.py   # checks the two real local models on this machine
```

The security audit (`tests/audit/`, `tests/test_security_workflow.py`) covers content-safety enforcement, bypass paths (attachments, OCR, split messages, hidden characters, extra form fields), sensitive information, OCR edge cases (rotation, small, blurry, faint text), policy hierarchy, approvals, access control, concurrency, audit logging and dashboard integrity. Results and root causes are in [`audit_report/`](audit_report/).

The pipeline tests use `scripts/mock_ollama.py`, a tiny recording stand-in for Ollama (it plays both the assistant and the safety model, reacting only to neutral test markers such as `[[GUARD:S1]]`), to **prove what reached the model**:
BLOCK, pending-approval and pending-review requests send nothing, censored requests send only placeholders, *Send anyway* still redacts CRITICAL/HIGH values, approval forwards exactly once and only after the assigned manager approves, rejection deletes the held content, the LLM client rejects content without a valid ticket, and the audit DB files contain none of the planted secrets. The mock is never used by `run.py`. `tests/test_severity.py` has positive **and** negative cases for every severity level, plus the context rules, overlap merging, consistent placeholders, log hygiene and the database migration.

## 10a. Datasets and evaluation

The hackathon dataset pack (`AI_GuardRail_Datasets.zip`) was audited file by file. The full reports are in
[`dataset_audit/`](dataset_audit/):

* [inventory](dataset_audit/dataset_inventory.csv)
* [relevance and requirement map](dataset_audit/relevance_report.md)
* [cleaning](dataset_audit/cleaning_report.md)
* [test and evaluation report](dataset_audit/test_report.md)

| Dataset | Use in this project |
|---|---|
| **Sample AI usage policies** (6 files) | Parsed into **27 reference clauses** (`policy/reference_policies.json`) and indexed in ChromaDB beside the 21 governing AUP clauses. The best match per detected category is shown in the screening panel. They never decide an outcome; a test enforces this. Each clause records which AUP clause it maps to and whether the gateway enforces it. One clause, **CRP-2** ("block any prompt with credentials"), is stricter than the gateway's redact-then-forward rule. An admin can set AUP-5 to BLOCK to follow it literally. |
| **CredDetX v0.1** (3,027 texts, 4,016 labelled secrets, 8,824 look-alikes) | Benchmark for credential detection. The dev split was used for error analysis and the test split only for reporting. |
| **NVIDIA Nemotron-PII** (2 × 100,000 documents, 55 PII labels) | Benchmark for personal-data detection, on stratified 2,000-document samples. |
| EasyOCR and Microsoft Presidio | **Excluded.** These are source-code archives, not datasets, and need PyTorch or spaCy model downloads. Tesseract already covers OCR. Both are kept inside the original ZIP. |

Measured on the held-out splits before → after the dataset-driven detector work:

| | Before | After |
|---|---|---|
| Secret detection (CredDetX test) – recall | 0.49 | **0.77** |
| Secret detection (CredDetX test) – precision | 0.64 | **0.76** |
| Secret detection (CredDetX test) – F1 | 0.56 | **0.77** |
| Secrets that would still reach the LLM | 31.5 % | **15.0 %** |
| Personal data (Nemotron eval) – recall on 20 core PII types | 53.6 % | **82.7 %** |
| Core PII values that would still reach the LLM (redact / strict mode) | 45.4 % | **16.6 %** |

No dataset value is stored in git, logs, reports or the UI. `datasets/` is git-ignored, and the reports contain counts only.
No model was trained: the datasets measure the gateway's explainable rules, and error patterns from the dev splits
were turned into new rules.

To reproduce, see [`datasets/README.md`](datasets/README.md):

```bash
python scripts/datasets/build_processed.py && python scripts/datasets/evaluate.py all
```

## 11. Team responsibilities (3 members)

| Member | Owns | Files | Integration point |
|---|---|---|---|
| **Member 1 – Security & Backend** | Detection, redaction, decision engine, approval gate, vault, audit DB | `backend/scanner/entities.py`, `detectors.py`, `classifier.py`, `redactor.py`, `policy/severity_policy.json`, `decision.py`, `approvals.py`, `vault.py`, `db.py` | `Finding` objects → `decide()`; audit row schema |
| **Member 2 – Frontend & UX** | Chat UI, live screening panel, governance panel, charts | `frontend/index.html`, `styles.css`, `app.js` | NDJSON event stream from `/api/chat`; JSON endpoints in `main.py` |
| **Member 3 – AI, Policy & Integration** | Ollama/Qwen, ChromaDB policy store, OCR/attachments, pipeline wiring, dataset evaluation, tests, demo | `backend/llm.py`, `policy/`, `backend/policy/`, `scanner/ocr.py`, `attachments.py`, `pipeline.py`, `scripts/datasets/`, `dataset_audit/`, `tests/`, `docs/` | `retrieve()` output → decision engine; `run_guardrail()` events |

## 12. Known limitations (honest list)

* **Detection is pattern-based, and measured.** On held-out benchmark data:
  * About 23 % of labelled secrets are still missed (CredDetX test recall 0.77), and 15 % would reach the model in clear text.
  * About 17 % of core personal-data values would reach the model (Nemotron eval). Most of these are unlabelled street addresses outside India, coordinates and unlabelled IDs.
  * Free-text names, sensitive attributes, paraphrased secrets, non-English text and confidential content without markers are the main gaps.

  Policy retrieval informs the decision but **does not by itself guarantee compliance**. Adding an NER model (Presidio/spaCy) is the next step. See [`dataset_audit/test_report.md`](dataset_audit/test_report.md).
* The CredDetX scores come from a re-implementation of its headline metric, because the official `score.py` was not in the dataset pack. They are indicative, not an official benchmark result.
* The organisation policy pack's **CRP-2** ("block any prompt with credentials") is stricter than the gateway's default. Credentials are redacted and never forwarded, but the rest of the prompt is. Set AUP-5 to BLOCK in Shield → Policy management to follow CRP-2 literally.
* The gateway deliberately redacts AWS access-key IDs and service-account key IDs. CredDetX counts these as identifiers, not secrets, so they show up as false alarms in its evaluation.
* **Content safety depends on the local Llama Guard model.** The automated suite proves the gateway *enforces* its verdicts (nothing classified unsafe, unverifiable or unapproved reaches Qwen), but it uses a mock, so it does not measure how accurately the real model judges real prompts. Llama Guard 3 1B is small: it can miss reworded, coded or non-English requests and can occasionally flag harmless ones. `llama-guard3:8b` is more accurate if the machine has the memory. Run `scripts/verify_safety_model.py` after installing, and test unsafe prompts of your own through the UI.
* The built-in harmful-use rules (the first layer) match a short list of intent phrases. They are a fast backstop, not the main safety control.
* The confidential-keyword lexicon can over-trigger (e.g. *"what does 'confidential' mean?"* → approval). That errs on the safe side but adds friction.
* Embeddings are lightweight feature-hashing vectors (offline, no download). A neural model would improve semantic matching; category-based retrieval already guarantees the governing clause is found.
* Scanned PDFs without a text layer are blocked rather than OCR'd.
* By default identity is a **demo selector** (`X-Demo-User` header), which anyone could spoof. Use `GG_AUTH_MODE=pin` outside presentations (PIN sign-in with signed cookies); production needs SSO.
* Any local process on the same computer can reach Ollama on `127.0.0.1:11434` directly; the gateway cannot prevent that. It only guarantees that nothing reaches the model *through the gateway* without screening. Keep Ollama on localhost (never `OLLAMA_HOST=0.0.0.0`) and do not give users accounts on the gateway machine.
* OCR reads printed text; handwriting, very small (≈8 px) or very blurred text may be unreadable. Unreliable reads are blocked; images with no readable text forward nothing.
* Approved requests are answered as single turns and aren't added to multi-turn chat context, so confidential text never enters the general history.
* Private photographs, voice recordings and personal movement history aren't analysed as such. Images are only OCR'd and their pixels are never forwarded, and audio files are unsupported, so they fail closed.
* Blocking every CRITICAL secret found by OCR is deliberately conservative: OCR can split a key, leaving fragments that redaction would miss.
* Single-node SQLite; no request expiry for pending approvals (pending *reviews* expire after 30 minutes).

## 13. Future scope

NER-based PII detection (Presidio) · neural embeddings · OCR for scanned PDFs · SSO/OIDC + real org chart · approval expiry and escalation · browser extension / API proxy mode for third-party AI tools · SIEM export (Splunk/ELK) · per-department policies · response-side scanning (DLP on model output).

---
*All names, emails, numbers, keys and company details in this repository are synthetic.*
