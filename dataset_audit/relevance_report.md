# Dataset audit: inventory, relevance and requirement mapping

Source: `AI_GuardRail_Datasets.zip` (464,182,683 bytes, SHA-256 `cf15900b…b32dc`; every CRC is valid).
The ZIP was **moved, not changed**, to `datasets/original/AI_GuardRail_Datasets.zip`.
Each file's full record (size, SHA-256, record count, fields, nulls, duplicates, integrity errors, licence) is in
[`dataset_inventory.csv`](dataset_inventory.csv). Distributions and quality checks are in
[`inventory_stats.json`](inventory_stats.json). Both are produced by `scripts/datasets/audit_inventory.py`.

**Privacy rule followed throughout.** No report, log or test in this repository contains a value taken from a dataset.
Only counts, field names, label names and hashes appear. Where error analysis was needed, values were masked to their
shape (for example `Aaaa9999!`).

## 1. What the ZIP contains

| # | Dataset | Files | Size | What it actually is (verified) |
|---|---|---|---|---|
| 1 | **Sample AI usage policies** | 6 `.txt` | 3.7 KB | Six short policies (Data Privacy, Source Code & IP, Credentials, Confidential Information, Image & Attachment, AI Usage Governance). They contain 20 numbered clauses and 1 Markdown policy with 6 sections, all in English. The files are UTF-8 with CRLF line endings. |
| 2 | **CredDetX v0.1** (CobuildX AI) | `dev.jsonl`, `test.jsonl` + README, DATASHEET, labelling guide | 19.5 MB | A span-level benchmark for secret detection. It has 3,027 synthetic texts (602 dev / 2,425 test): code, configs, logs, tickets, chats and documents. These contain 4,016 gold secret spans in 12 labels and 8,824 annotated hard negatives (look-alikes that are not secrets) of 21 kinds. 467 texts contain no secret. Licence: CC BY 4.0. |
| 3 | **NVIDIA Nemotron-PII** | `train-…parquet`, `test-…parquet` + README | 307 MB | Synthetic, persona-based documents with span annotations for 55 PII/PHI labels. Each file has **100,000 rows**. Licence: CC BY 4.0. |
| 4 | **EasyOCR** | `EasyOCR-master.zip` + README, LICENSE | 79 MB | The source code of the OCR library: 313 files, 76 `.py`, no model weights. It is **software, not a dataset**. Licence: Apache-2.0. |
| 5 | **Microsoft Presidio** | `presidio-main.zip` + README, LICENSE | 108 MB | The source code of the PII SDK: 891 files, 498 `.py`, plus test fixtures and 14 DICOM sample images. It is **software, not a dataset**. Licence: MIT. |

### Verified facts that differ from the documentation

* **Nemotron-PII rows.** The README says "100,000 records (50k train / 50k test)", but each Parquet file holds 100,000 rows.
  Each `uid` appears exactly twice per file, 50,000 rows apart: once with `locale = us` and once with
  `locale = intl`. The text differs, and the domain and document type are the same.
  So these are **paired locale variants, not duplicates**. The unique key is `(uid, locale)`.
  No `uid` or text is shared between the train and test files. The train file contains one exact duplicate text.
* **Nemotron-PII span text.** The offsets are always valid (0 errors in 1,675,796 spans).
  In 25,536 spans the `text` field does not equal `text[start:end]`.
  12,571 of those store a number as an integer (`42` instead of `"42"`).
  The other 12,965 differ only in letter case (for example `hispanic` against `Hispanic`).
  None point at the wrong place, so the offsets are taken as the ground truth.
* **CredDetX.** It matches its datasheet exactly: there are 0 offset errors, 0 duplicate ids or texts, no overlap between dev and test, and no span that overlaps a negative.
  The no-secret flag agrees with the spans in every text, and the benchmark canary string is present in every record.
  The `score.py` script that the README mentions is **not included in the ZIP**.
* **Sensitive content.** Both labelled datasets are fully synthetic, according to their cards.
  CredDetX contains secret-shaped values whose checksums are valid (its authors warn not to use them), and Nemotron contains realistic synthetic PII.
  Both are treated as **sensitive-shaped data**: they are kept out of git and out of the UI, demos and audit logs.

## 2. Relevance classification

| Dataset | Class | Decision | Reason |
|---|---|---|---|
| Sample AI usage policies | **A – directly relevant** | **Integrated** into the ChromaDB knowledge base as 27 *reference* clauses | These are PS16's "sample AI usage policy". They map clause by clause onto the gateway's 21 governing clauses (§4). |
| CredDetX | **A – directly relevant** | **Integrated as an evaluation benchmark** (read in place, never copied, never used for training) | Measures the credential detection behind the BLOCK and REDACT outcomes. The hard negatives measure false alarms. |
| Nemotron-PII | **A – directly relevant** | **Integrated as an evaluation benchmark** (stratified 2,000-document samples) | Measures PII detection and how much personal data would still reach the model. |
| EasyOCR | **C – not relevant as a dataset** | **Excluded** (kept inside the original ZIP; its README and LICENSE are in `datasets/excluded/`) | It is an OCR engine, not data. It needs PyTorch plus a model download at runtime, while Tesseract already meets the OCR requirement and is tested. The brief says not to add large dependencies just to look more advanced. |
| Microsoft Presidio | **C – not relevant as a dataset** | **Excluded** (same handling) | It is a detection SDK, not data. It needs spaCy and a language-model download. Its test fixtures are unlabelled for our purpose. It remains listed as future work (README §13). |

**Class B (indirectly relevant) and class D (harmful or unsuitable):** no dataset falls into either.
No content was found that should be excluded as harmful. The secret-shaped and PII-shaped values are handled under the privacy rule above rather than excluded, because evaluating against them is exactly their purpose.

**Why the labelled datasets are not used to train anything.** The brief says
*"do not let an unvalidated model independently authorize sensitive information to be sent to the LLM"*.
The gateway's decisions therefore stay rule-based and explainable.
The datasets measure those rules, and a subset of error patterns found on the **dev** splits only was used to add new detection rules.
The CredDetX authors also ask that their test split not be used for tuning and that the data not enter training corpora.

## 3. Requirement → dataset map

| PS16 / project requirement | Dataset used | How |
|---|---|---|
| Retrieve relevant clauses of a sample AI usage policy from ChromaDB | Sample policies | 27 clauses are indexed beside the 21 governing AUP clauses. The best match per detected category is shown in the screening panel and in Shield → Policy management. |
| Detect API keys, access tokens, passwords, credentials, source-code secrets | CredDetX | Span-level recall and precision, false alarms on 21 kinds of hard negative, and secret exposure measured end to end. Dev was used for error analysis; test is used only for reporting. |
| Detect email, phone, customer/employee data, financial, medical and ID numbers | Nemotron-PII | Recall per label for 20 "core" labels that the policy says must never reach the model, and for 14 "quasi" labels that depend on context. Exposure is measured after redaction. |
| BLOCK / REDACT AND ALLOW decisions behave correctly | CredDetX, Nemotron | Every text is run through `scripts/datasets/gateway_sim.py`, which mirrors the pipeline. A test asserts that it agrees with `run_guardrail`. |
| Do not block legitimate text | CredDetX negatives and no-secret texts | The rate at which look-alikes (hashes, IDs, placeholders, environment-variable references) and secret-free texts are flagged. |
| OCR of images | *none suitable* | Neither labelled dataset contains images. OCR stays covered by `samples/meeting_notes.png` and the OCR tests. |
| Manager approval, audit logging, dashboard | *none needed* | These are workflow requirements and are covered by the existing pipeline, API and smoke tests. |

## 4. How the organisation policy pack relates to the gateway

Every source clause was reviewed and mapped. `consistency` is stored with each clause in
`policy/reference_policies.json` and shown in the governance panel.

| Result | Clauses | Notes |
|---|---|---|
| Consistent | 21 | Source code, confidential information, attachments/OCR, approval, audit and exceptions match the gateway's behaviour. |
| Partly enforced | DPP-2, DPP-3, DPP-4 | **DPP-2** says personal information *must* be redacted, but outside strict mode MEDIUM items can be sent after a warning. Turning strict mode on makes the gateway follow DPP-2 literally. **DPP-3/4**: bulk personal records are held for manager approval rather than blocked or anonymised. |
| **Conflict** | **CRP-2** | The clause says *"Any prompt containing active credentials must be blocked."* The gateway (AUP-5, from the team's own severity specification) replaces each credential with a placeholder and forwards the rest. It blocks only when safe redaction is impossible. Either way, the credential never reaches the model. GOV-7 says the pack *"supplements … and does not override"* the technical rules, so behaviour was **not changed**. An admin can follow CRP-2 literally by setting AUP-5 to **BLOCK** in Shield → Policy management (one click, re-indexed live). |
| Advisory | CRP-4, GOV-6 | These are procedural duties (rotate exposed credentials; enforcement). They are shown as guidance only. |

Reference clauses are stored with `action = REFERENCE` and `kind = reference`. They **cannot govern a decision**:
the category lookup returns only governing clauses, and `decision.py` skips reference clauses as a second safeguard
(this is covered by `tests/test_datasets.py`).
