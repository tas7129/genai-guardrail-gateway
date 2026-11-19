# Security & functionality audit – findings, fixes and verification

Date: 19 Nov 2026. A full backup of the project was taken before any change was made.

Per-test results are in [`AUDIT_REPORT.md`](AUDIT_REPORT.md) and [`audit_results.csv`](audit_results.csv), produced by
`python scripts/run_audit.py`.

## 1. Findings, root causes and fixes

| # | Finding | Root cause | Fix | Regression tests |
|---|---|---|---|---|
| 1 | Many harmful or inappropriate requests were allowed: 43 of 150 cases failed in the first baseline, nearly all of them content-safety or bypass cases | The only harm detection was a short list of fixed regex phrases on the raw text. It had no understanding of intent or context, no handling of other languages or disguised spelling, no conversation memory, and whole categories were missing | A **local safety classifier, Llama Guard 3 (`llama-guard3:1b`) via Ollama**, added as a mandatory pipeline step (`backend/safety_guard.py`). It classifies exactly the text that could be forwarded, including attachment and OCR text, together with the recent conversation. Category actions are set in `policy/safety_policy.json`. The built-in rules remain as a backstop. Qwen stays the assistant; Llama Guard only classifies. | `tests/test_security_workflow.py` (verdicts, fail-closed, attachments, context, "every assistant request was cleared"); audit cases K01–K26 |
| 2 | If the safety check could not run, nothing defined what happened | The control did not exist | **Fail closed.** A missing model, HTTP error, timeout or unreadable verdict all lead to BLOCK under new clause **AUP-22** (category `SAFETY_CHECK`). Fail-open has to be configured explicitly, and each such request is recorded in the audit log. | K15–K18; `test_no_verdict_fails_closed`, `test_missing_safety_model…`, `test_fail_open_is_explicit…` |
| 3 | Admins could weaken the harmful-content or unscannable-attachment clauses (e.g. set AUP-12 to ALLOW) | The policy API accepted any action for any clause | **Mandatory controls**: harmful content, the content-safety check and unscannable attachments are always BLOCK. The policy API refuses weaker actions (HTTP 403), and the decision engine enforces the minimum even if a stored clause were altered. | L09; `test_admin_cannot_weaken_mandatory_controls`, `test_engine_enforces_mandatory_minimum…` |
| 4 | Approved requests were released without being screened again; a tampered vault entry crashed the release thread and left the request stuck in "forwarding" | The release path trusted the held content | **Re-check on release**: detectors, built-in rules and the safety model run again before forwarding. Failed or tampered releases are marked `release_blocked`, nothing is sent, and an event is logged. | `test_approval_rechecks…`, `test_approval_release_blocked…`, `test_recheck_catches…`, `test_tampered_vault_payload…` |
| 5 | Rotated scans produced garbage OCR text that was treated as readable; small, faint and blurry text was not handled | OCR ran a single pass with no orientation detection and no reliability rule | **Multi-pass OCR**: orientation detection with 90°/180°/270° fallback, ×2 upscaling with sharpening, and contrast enhancement. Below 45 % confidence the attachment **fails closed**; noise-level output (below 30 %) counts as "no text", so nothing from that image is forwarded. | O05–O10, O12 |
| 6 | IFSC codes were redacted as if they were bank account numbers; usernames were not detected | IFSC was registered under `BANK_ACCOUNT` (HIGH); there was no username detector | IFSC → `IFSC` (LOW, public branch code, noted only); new `USERNAME` detector (MEDIUM) | P05, P06, P18 |
| 7 | Safeguarding questions mentioning self-harm were blocked | The built-in rule matched the bare term "self-harm" regardless of context | Removed that bare-term alternative; context is judged by the safety model | F18 |
| 8 | Identity could be spoofed: the `X-Demo-User` header is trusted | Hackathon demo design | Optional **PIN sign-in mode** (`GG_AUTH_MODE=pin`): PBKDF2-hashed PINs, HttpOnly SameSite=Strict HMAC-signed cookie, header ignored, lock-out after 5 wrong PINs. Demo mode stays the default for presentations and is documented as not secure. | `test_pin_mode_ignores_spoofed_identity_and_locks_out` |
| 9 | The dashboard could not show whether the guarantees held | Missing metrics | **Content-safety statistics** and **integrity counters**: blocked, unapproved, unreviewed or unsafe requests that reached the model must be 0. These are recomputed from the audit log on every refresh. | `test_dashboard_matches_database_and_integrity_is_clean`; smoke test check 18 |
| 10 | The screening panel did not separate the checks the brief asks for | UI design | **Five grouped checks**: Sensitive Information Detection, Attachment and OCR Inspection, Content Safety Check, Policy Retrieval, Final Security Decision. The eight real backend steps are nested inside them, and the decision card shows the safety verdict and support resources. | `test_steps_are_reported_in_order`; UI check |
| 11 | Windows portability gaps | Tesseract is not on PATH after the Windows installer; console encodings; Pillow version | Automatic Tesseract detection (plus `TESSERACT_CMD`), console-safe output in all scripts, Pillow ≥ 10.1, `WINDOWS_SETUP.md` | Suite run with `EncodingWarning` treated as an error |
| 12 | *(Found in the test harness during this work)* The audit folder's own `conftest.py` re-imported the shared fixtures, so the case suite's "reached the assistant" checks looked at an empty log | Two `conftest` modules: the second started a second mock server | Removed it. The report now shows 49 of 49 allowed or redacted cases reaching the assistant and 0 of 50 blocked, held or under-review cases doing so. | Every audit case |

Checked and already correct (now covered by explicit tests):

* Users cannot read other users' conversations or requests, and cannot attach to them.
* Employees and managers cannot use admin endpoints.
* Managers can act only on their own team's approvals.
* No route proxies Ollama, and extra form fields cannot skip screening.
* Empty, oversized and over-attached requests are rejected.
* Twelve simultaneous requests did not mix users, decisions or secrets.
* Every screening is logged, and no raw values appear in the database file, the audit API or the dashboard API.

## 2. What was actually tested

The build environment was Linux with Python 3.13, Tesseract 5.3.4 and headless Chrome. ChromaDB was not installed, so the in-memory policy store was used. Ollama was **not** available, so `scripts/mock_ollama.py` played both models.

| Test | Result |
|---|---|
| `pytest -q tests` (full suite) | **348 passed, 1 skipped** (the ChromaDB-backend test) |
| `scripts/run_audit.py`, data-driven cases | **99 / 99 passed**: content-safety enforcement 18, bypass 8, sensitive information 18, attachments/OCR 17, policy 10, false positives 28 |
| `scripts/run_audit.py`, other tests | **249 passed, 1 skipped** of 250 (workflow, access control, approvals, policy hierarchy, concurrency, audit/dashboard, detectors, severity, datasets, OCR, API) |
| `scripts/smoke_test.py` against a live server (mock models) | **19 / 19** |
| `scripts/verify_safety_model.py` (mock models) | 8 / 8. This checks the plumbing only, not model quality. |
| UI in headless Chrome | Grouped checks, the safety-blocked decision card and the dashboard cards render with no JavaScript errors |
| Test suite with `EncodingWarning` as an error | Passed: no file I/O depends on the platform's default encoding |
| Dataset benchmarks after the detector changes | Unchanged (CredDetX dev F1 0.786; Nemotron dev core recall 81.9 %) |

## 3. Not verified here (and how to verify)

| Item | Why | How to verify |
|---|---|---|
| **Accuracy of the real Llama Guard model** on real prompts, and its false-positive rate | No Ollama in the build environment. The project's VM on the Mac cannot reach the Mac's `localhost`. | `python scripts/verify_safety_model.py` (format, false-positive rate on 25 ordinary prompts, end-to-end). Then type unsafe prompts of your own in the chat and confirm the Content Safety Check blocks them. |
| Real Qwen answers through the new pipeline | Same reason | `python scripts/smoke_test.py` with Ollama running |
| ChromaDB code path for the new `kind` metadata filter | ChromaDB is not installable in the build environment | `pytest -q` on a machine with ChromaDB, plus the sidebar showing `ChromaDB · 49` |
| Windows | No Windows machine was available. The guide is based on the official installers' documentation and the code changes above. | Follow `WINDOWS_SETUP.md` sections 9.1–9.4 |
| PIN-mode browser dialogs | Covered at API level only | Set `GG_AUTH_MODE=pin`, restart, switch users in the sidebar |
| Latency | It depends on the machine; the first request loads both models | Watch the per-step timings in the screening panel |

## 4. Remaining limitations

* Llama Guard 3 **1B** is small. It can miss reworded, coded or non-English requests and occasionally flags harmless ones. `llama-guard3:8b` is more accurate if RAM allows.
* Self-harm statements are blocked with support resources rather than answered. This is the conservative choice for a workplace assistant, and it can be changed in `policy/safety_policy.json`.
* Demo identity mode is spoofable by design; use PIN mode outside presentations, and SSO in production.
* Local processes on the gateway PC can call Ollama directly. Keep Ollama on 127.0.0.1 and do not give users accounts on that PC.
* OCR cannot read handwriting or very small (about 8 px) text. Unreliable reads are blocked rather than guessed.
