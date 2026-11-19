# Test and evaluation report – dataset integration

Every number below comes from commands that were **actually run** on 19 Nov 2026 in the build environment:
Linux, Python 3.13, no ChromaDB installed (see §4). The raw outputs are in `dataset_audit/evaluation/*.json`.
These files contain counts only, no dataset values.

## 1. Automated tests

| Suite | Command | Result |
|---|---|---|
| Full pytest suite | `pytest -q` | **196 passed, 2 skipped** (157 before this work + 39 new in `tests/test_datasets.py`) |
| Skipped | – | `tests/test_api.py` (needs `httpx`) and `test_chromadb_backend_used_when_installed` (needs `chromadb`). Neither package is installed in the build container. Both are in `requirements.txt`, so they run on the team's machines. |
| End-to-end smoke test against the running app (mock LLM) | `python scripts/smoke_test.py` | **16/16 checks passed** |
| UI check (headless Chrome) | screening panel and Policy management tab | Reference clauses render, no JavaScript errors |

New tests in `tests/test_datasets.py`:

* **Policy pack.** All 27 reference clauses are well formed. Retrieval returns governing AUP-5 first, plus exactly one CRP clause.
* **Reference clauses never decide.** A reference clause can never govern a decision, even when it is listed first. If *only* reference clauses are retrieved, the gateway fails closed (BLOCK).
* **API.** `/api/policy` lists both the governing and the reference clauses.
* **New detectors.** 16 positive cases, each with an invented value. 8 negative cases: type annotations, `os.environ` references, vault paths, Stripe publishable keys, Indian postal PIN codes, cache keys and variable names.
* **Simulator parity.** `gateway_sim.screen_text()` reaches the same decision as the real `run_guardrail()` pipeline on 9 prompts, including all demo scenarios.
* **Regression floors on the dev splits.** CredDetX recall ≥ 0.78 and precision ≥ 0.72; Nemotron core recall ≥ 80 %. These tests are skipped automatically when the datasets are not present.

### The four PS16 decisions still work

They were verified by the smoke test, the pipeline tests and the parity tests:

| Decision | Result |
|---|---|
| ALLOW | General question forwarded unchanged |
| REDACT AND ALLOW | Aadhaar and diagnosis replaced; the single password becomes `[PASSWORD REDACTED]` |
| BLOCK | `.env` secrets file blocked; harmful request blocked; unscannable attachment blocked; OCR-read secret blocked |
| MANAGER APPROVAL | Confidential brief held. A wrong manager or self-approval gets 403. The assigned manager's approval releases the request exactly once. |

USER_REVIEW and strict mode were verified as well.

## 2. Detection quality before and after (CredDetX – secrets)

Method:

* Every text goes through the gateway's own text path (`scripts/datasets/gateway_sim.py`).
* A gold secret counts as **found** if a censoring finding (severity above LOW) overlaps it.
* Precision counts credential-type findings only (CredDetX labels secrets, not personal data), with at most 5 false positives per text.
* Gold policy is `strict`, the dataset default. The official `score.py` is not in the ZIP, so this is a close re-implementation of the headline metric, not the official scorer.
* Rules were developed on **dev** only. **test** was run once before the changes and once after.

| CredDetX **test** (2,425 texts, 3,213 secrets) | Before | After |
|---|---|---|
| Recall | 0.494 | **0.770** |
| Precision (capped) | 0.636 | **0.761** |
| F1 | 0.556 | **0.765** |
| Hard negatives flagged | 11.3 % | **9.5 %** |
| Secret-free texts with a credential finding | 34.0 % | **30.7 %** |
| **Secrets that would reach the LLM in clear text** (fully or partly) | 31.5 % | **15.0 %** |
| Texts where at least one secret would reach the LLM | 36.6 % | **18.9 %** |
| … if every held request were later approved | 39.4 % | **17.8 %** |

The CredDetX authors publish baselines for open-source scanners on the same test split, under the same `strict` policy and scored by their own tool:

* gitleaks: F1 0.522
* detect-secrets: F1 0.422
* trufflehog: F1 0.332

Because our scorer is a re-implementation, treat this as an indication, not a formal ranking.

Recall by label on test, before → after:

| Label | Before → after (%) |
|---|---|
| PASSWORD | 33 → 68 |
| WEBHOOK_SECRET | 10 → 89 |
| GENERIC_SECRET | 21 → 69 |
| SESSION_SECRET | 29 → 78 |
| CERTIFICATE_SECRET | 2 → 79 |
| CLOUD_CREDENTIAL | 34 → 89 |
| ENCRYPTION_KEY | 48 → 67 |
| DATABASE_CREDENTIAL | 67 → 83 |
| ACCESS_TOKEN | 69 → 76 |
| API_KEY | 64 → 67 |
| PRIVATE_KEY | 99 → 99 |
| JWT | 100 → 100 |

Most remaining "hard negatives flagged" are two kinds the gateway redacts **on purpose**:

* AWS access-key IDs (`AKIA…`): 424/424
* service-account `private_key_id`: 90/127

CredDetX counts both as identifiers, not secrets. Redacting them costs the user nothing and avoids leaking account identifiers. Without these two kinds, the false-alarm rate on hard negatives is **2.5 %** (165 of 6,625).

## 3. Detection quality before and after (Nemotron-PII – personal data)

Method:

* Runs on the 2,000-document **eval** sample from the test file, stratified by locale and format.
* **Core** = 20 labels the policy says must not reach the model in clear text (e-mail, phone, address, date of birth, SSN, national/tax ID, card, CVV, PIN, account number, password, API key, cookie, medical record, health-plan ID, biometric ID, employee ID, coordinates).
* **Quasi** = 14 context-dependent labels (names, user names, IP addresses, plates, sensitive attributes, …).
* "Exposed" means the characters of a labelled value would be forwarded.

| Nemotron **eval** (2,000 docs, 4,734 core spans) | Before | After |
|---|---|---|
| Core recall | 53.6 % | **82.7 %** |
| Core values exposed – user chooses *Redact & send* (or strict mode) | 45.4 % | **16.6 %** |
| Core values exposed – user chooses *Send anyway* on every review | 81.0 % | 60.6 % |
| Documents with at least one core value exposed | 67.7 % | **31.3 %** |
| Quasi recall | 9.8 % | 10.2 % |

Core recall per label after the changes:

| Recall | Labels |
|---|---|
| ≥ 90 % | SSN 100, e-mail 98, DOB 97, fax 94, health-plan ID 94, medical record 92, phone 90 |
| 70–89 % | biometric ID 87, national ID 88, account number 85, CVV 81, password 80, tax ID 73, cookie 71, PIN 71 |
| < 70 % | API key 66, employee ID 63, card 61, coordinates 53, **street address 38** |

How to read these results:

* **Send anyway.** The *Send anyway* row is the price of the non-strict review option: by design, MEDIUM items (e-mail, phone, date of birth, address) can be forwarded if the user insists. In **strict mode** the exposure is 16.6 % whatever the user chooses. This matches organisation policy clause DPP-2.
* **Values classed as LOW.** Some missed card numbers and SSNs were detected but classed **LOW**, because they are sequential "documented example" values (for example `…3456 7890 1234`), which the gateway deliberately does not censor. This is policy-consistent behaviour, not a detector miss.
* **Free-text detection gaps.** Unlabelled street addresses outside India, names, and sensitive attributes in free text remain the main gaps. Quasi recall is low because the gateway intentionally does not flag a name or attribute on its own (README §3a). Closing these gaps needs an NER model, which is listed as future work and was not added, to respect the dependency constraint.

## 4. What changed in the product

* **New detection rules** in `backend/scanner/detectors.py`, all found through dev-split error analysis:
  * secrets identified by key name (`*_SECRET`, `*_PASS`, `passphrase`, `SIGNING_SECRET`, `*_key` with a high-entropy value, `props.put("…", "…")`, `key set to …`)
  * user/password pairs (`admin / …`, `pass: …`, *"rotated the password to …"*)
  * HTTP Basic auth (decoded to check it is `user:password`) and `curl -u`
  * incoming-webhook URLs (Slack, Discord, Teams, Zapier, Google Chat)
  * PKCS#12/PFX bundles
  * labelled identifiers in forms, tables and prose: account number, card number (also when it fails the Luhn check, if it is labelled), CVV, PIN, medical record, health-plan ID, national ID, tax ID, employee ID, biometric ID, DOB in ISO format, cookie, phone
  * a filter that drops "secrets" that only *refer* to a secret (environment variables, vault paths, code expressions, type names, bcrypt hashes)
* **Two new entity types:** `GENERIC_SECRET` (CRITICAL) and `NATIONAL_ID` (HIGH). There are now 84.
* **Stripe publishable keys** (`pk_live_…`) are no longer flagged, because they are public by design.
* **Indian postal "PIN code"** values are protected from being read as card PINs.
* **Policy knowledge base:** 27 reference clauses were added to ChromaDB, together with retrieval, the decision safeguard, the API and the UI changes described in the relevance report.

## 5. Not verified here, and how to verify

* **ChromaDB path.** The ChromaDB branch of the new reference-clause lookup (`where = {"$and": [category, kind]}`) could not be executed, because `chromadb` is not installed in the build container. The in-memory branch was tested. On a team machine run `pytest -q`: with chromadb installed, `test_chromadb_backend_used_when_installed` and the policy tests then exercise the ChromaDB path. Start the app and check that Shield → Policy management shows "ChromaDB · 48 clauses".
* **Model responses.** Real Ollama/Qwen responses were not part of this run; the mock LLM was used. Run `python scripts/smoke_test.py` with Ollama running before recording the demo.
