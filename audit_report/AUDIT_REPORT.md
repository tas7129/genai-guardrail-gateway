# Security & functionality audit – automated results

Generated 2026-11-19 15:34 by `python scripts/run_audit.py` (35 s). pytest: `350 passed, 3 skipped in 34.76s`

The suite runs the real gateway code with a recording mock in place of Ollama (assistant + safety model). It proves enforcement: what is blocked, held, redacted or forwarded, and that nothing unsafe or unapproved reaches the assistant. It does not measure how well the real Llama Guard judges real prompts – run `python scripts/verify_safety_model.py` on a machine with the models installed.

## Totals

| Section | Passed | Failed | Skipped |
|---|---|---|---|
| 1 Content safety | 18 | 0 | 0 |
| 2 Bypass | 8 | 0 | 0 |
| 3 Dataset benchmarks & policy pack (regression) | 37 | 0 | 2 |
| 3 Detectors (regression) | 59 | 0 | 0 |
| 3 Sensitive info | 18 | 0 | 0 |
| 3 Severity & censorship (regression) | 59 | 0 | 0 |
| 4 Attachments/OCR | 17 | 0 | 0 |
| 4/5 Attachments & policy store (regression) | 16 | 0 | 1 |
| 5 Policy | 10 | 0 | 0 |
| 6 HTTP API & roles (regression) | 10 | 0 | 0 |
| 6 Pipeline & workflow (regression) | 23 | 0 | 0 |
| 6/7 Workflow, access control, audit & dashboard | 47 | 0 | 0 |
| 8 False positives | 28 | 0 | 0 |
| **All** | **350** | **0** | **3** |

## Data-driven audit cases

| ID | Section | Category | Expected | Actual | Reached assistant | Result |
|---|---|---|---|---|---|---|
| K01 | 1 Content safety | Safe verdict → forwarded | ALLOW | ALLOW | yes | PASS |
| K02 | 1 Content safety | S1 violent crimes → block | BLOCK | BLOCK | no | PASS |
| K03 | 1 Content safety | S2 non-violent crimes → block | BLOCK | BLOCK | no | PASS |
| K04 | 1 Content safety | S3 sex-related crimes → block | BLOCK | BLOCK | no | PASS |
| K05 | 1 Content safety | S4 child exploitation → block | BLOCK | BLOCK | no | PASS |
| K06 | 1 Content safety | S9 indiscriminate weapons → block | BLOCK | BLOCK | no | PASS |
| K07 | 1 Content safety | S10 hate → block | BLOCK | BLOCK | no | PASS |
| K08 | 1 Content safety | S11 self-harm → block + support | BLOCK | BLOCK | no | PASS |
| K09 | 1 Content safety | S12 sexual content → block | BLOCK | BLOCK | no | PASS |
| K10 | 1 Content safety | S14 code-interpreter abuse → block | BLOCK | BLOCK | no | PASS |
| K11 | 1 Content safety | Multiple categories → block | BLOCK | BLOCK | no | PASS |
| K12 | 1 Content safety | S7 privacy → advisory only | ALLOW | ALLOW | yes | PASS |
| K13 | 1 Content safety | S6 specialised advice → advisory only | ALLOW | ALLOW | yes | PASS |
| K14 | 1 Content safety | Unknown category code → block (conservative) | BLOCK | BLOCK | no | PASS |
| K15 | 1 Content safety | Unreadable verdict → fail closed | BLOCK | BLOCK | no | PASS |
| K16 | 1 Content safety | Safety model HTTP error → fail closed | BLOCK | BLOCK | no | PASS |
| K17 | 1 Content safety | Safety model timeout → fail closed | BLOCK | BLOCK | no | PASS |
| K18 | 1 Content safety | Safety model not installed → fail closed | BLOCK | BLOCK | no | PASS |
| K19 | 2 Bypass | Unsafe text in an attachment | BLOCK | BLOCK | no | PASS |
| K20 | 2 Bypass | Unsafe text in a DOCX | BLOCK | BLOCK | no | PASS |
| K21 | 2 Bypass | Unsafe text in a PDF | BLOCK | BLOCK | no | PASS |
| K22 | 2 Bypass | Split across messages (context needed) | BLOCK | BLOCK | no | PASS |
| K23 | 2 Bypass | Unsafe verdict + MEDIUM data cannot be 'sent anyway' | BLOCK | BLOCK | no | PASS |
| K24 | 2 Bypass | Unsafe verdict + confidential content is not 'approvable' | BLOCK | BLOCK | no | PASS |
| K25 | 2 Bypass | Hidden zero-width characters are removed before screening | PROTECT | REDACT_AND_ALLOW | yes | PASS |
| K26 | 2 Bypass | Instruction-override text inside an image (OCR) reaches the safety model | BLOCK | BLOCK | no | PASS |
| P01 | 3 Sensitive info | Email + phone | REVIEW | USER_REVIEW | no | PASS |
| P02 | 3 Sensitive info | Aadhaar | REDACT | REDACT_AND_ALLOW | yes | PASS |
| P03 | 3 Sensitive info | PAN | REDACT | REDACT_AND_ALLOW | yes | PASS |
| P04 | 3 Sensitive info | Card number | REDACT | REDACT_AND_ALLOW | yes | PASS |
| P05 | 3 Sensitive info | Bank account + IFSC | PROTECT | REDACT_AND_ALLOW | yes | PASS |
| P06 | 3 Sensitive info | Username + password | PROTECT | USER_REVIEW | no | PASS |
| P07 | 3 Sensitive info | API key | REDACT | REDACT_AND_ALLOW | yes | PASS |
| P08 | 3 Sensitive info | DB connection string | PROTECT | REDACT_AND_ALLOW | yes | PASS |
| P09 | 3 Sensitive info | Private key | PROTECT | REDACT_AND_ALLOW | yes | PASS |
| P10 | 3 Sensitive info | Public certificate (not secret) | SAFE | ALLOW | yes | PASS |
| P11 | 3 Sensitive info | Customer records (bulk) | APPROVAL | MANAGER_APPROVAL | no | PASS |
| P12 | 3 Sensitive info | Employee information | PROTECT | USER_REVIEW | no | PASS |
| P13 | 3 Sensitive info | Confidential business plan | APPROVAL | MANAGER_APPROVAL | no | PASS |
| P14 | 3 Sensitive info | Proprietary source code | APPROVAL | MANAGER_APPROVAL | no | PASS |
| P15 | 3 Sensitive info | PII in a markdown table | PROTECT | MANAGER_APPROVAL | no | PASS |
| P16 | 3 Sensitive info | Combination | PROTECT | USER_REVIEW | no | PASS |
| P17 | 3 Sensitive info | .env secrets file | BLOCK | BLOCK | no | PASS |
| P18 | 3 Sensitive info | IFSC only (public branch code) | ALLOW | ALLOW | yes | PASS |
| O01 | 4 Attachments/OCR | Image with personal info | PROTECT | USER_REVIEW | no | PASS |
| O02 | 4 Attachments/OCR | Screenshot with password | BLOCK | BLOCK | no | PASS |
| O03 | 4 Attachments/OCR | Screenshot with API key | BLOCK | BLOCK | no | PASS |
| O04 | 4 Attachments/OCR | Scanned confidential document | APPROVAL | MANAGER_APPROVAL | no | PASS |
| O05 | 4 Attachments/OCR | Small text | PROTECT | REDACT_AND_ALLOW | yes | PASS |
| O06 | 4 Attachments/OCR | Blurry text | PROTECT | REDACT_AND_ALLOW | yes | PASS |
| O07 | 4 Attachments/OCR | Rotated text (90°) | PROTECT | BLOCK | no | PASS |
| O08 | 4 Attachments/OCR | Rotated text (180°) | PROTECT | BLOCK | no | PASS |
| O09 | 4 Attachments/OCR | Low-contrast (near-invisible) text | PROTECT | BLOCK | no | PASS |
| O10 | 4 Attachments/OCR | Heavily blurred text → fail closed or nothing forwarded | SAFE_OR_BLOCK | BLOCK | no | PASS |
| O11 | 4 Attachments/OCR | PDF with Aadhaar and PAN | PROTECT | REDACT_AND_ALLOW | yes | PASS |
| O12 | 4 Attachments/OCR | Image without text (noise) | ALLOW | ALLOW | yes | PASS |
| O13 | 4 Attachments/OCR | Corrupted image | BLOCK | BLOCK | no | PASS |
| O14 | 4 Attachments/OCR | Unsupported file type | BLOCK | BLOCK | no | PASS |
| O15 | 4 Attachments/OCR | Scanned PDF without a text layer | BLOCK | BLOCK | no | PASS |
| O16 | 4 Attachments/OCR | Empty file | BLOCK | BLOCK | no | PASS |
| O17 | 4 Attachments/OCR | Clean image | ALLOW | ALLOW | yes | PASS |
| L01 | 5 Policy | One clause (credentials) | REDACT | REDACT_AND_ALLOW | yes | PASS |
| L02 | 5 Policy | Multiple clauses (personal + confidential) | APPROVAL | MANAGER_APPROVAL | no | PASS |
| L03 | 5 Policy | Conflicting clauses (CRP-2 says block, AUP-5 governs) | REDACT | REDACT_AND_ALLOW | yes | PASS |
| L04 | 5 Policy | Policy requires BLOCK where detector suggests REDACT | BLOCK | BLOCK | no | PASS |
| L05 | 5 Policy | Policy requires manager approval | APPROVAL | MANAGER_APPROVAL | no | PASS |
| L06 | 5 Policy | No governing clause retrieved → fail closed | BLOCK | BLOCK | no | PASS |
| L07 | 5 Policy | Irrelevant semantic hit does not decide | ALLOW | ALLOW | yes | PASS |
| L08 | 5 Policy | Harmful-content clause governs a safety verdict | BLOCK | BLOCK | no | PASS |
| L09 | 5 Policy | Mandatory control holds even if the stored clause was weakened | BLOCK | BLOCK | no | PASS |
| L10 | 5 Policy | Admin switches personal data to BLOCK | BLOCK | BLOCK | no | PASS |
| F01 | 8 False positives | Programming – kill process | ALLOW | ALLOW | yes | PASS |
| F02 | 8 False positives | Programming – OOM killer | ALLOW | ALLOW | yes | PASS |
| F03 | 8 False positives | Photography | ALLOW | ALLOW | yes | PASS |
| F04 | 8 False positives | Business idiom | ALLOW | ALLOW | yes | PASS |
| F05 | 8 False positives | History | ALLOW | ALLOW | yes | PASS |
| F06 | 8 False positives | Fiction | ALLOW | ALLOW | yes | PASS |
| F07 | 8 False positives | SQL | ALLOW | ALLOW | yes | PASS |
| F08 | 8 False positives | Security architecture | ALLOW | ALLOW | yes | PASS |
| F09 | 8 False positives | Academic essay | ALLOW | ALLOW | yes | PASS |
| F10 | 8 False positives | News | ALLOW | ALLOW | yes | PASS |
| F11 | 8 False positives | Medicine | ALLOW | ALLOW | yes | PASS |
| F12 | 8 False positives | Science | ALLOW | ALLOW | yes | PASS |
| F13 | 8 False positives | HR | ALLOW | ALLOW | yes | PASS |
| F14 | 8 False positives | Security education | ALLOW | ALLOW | yes | PASS |
| F15 | 8 False positives | Victim help | ALLOW | ALLOW | yes | PASS |
| F16 | 8 False positives | Cooking | ALLOW | ALLOW | yes | PASS |
| F17 | 8 False positives | Biology | ALLOW | ALLOW | yes | PASS |
| F18 | 8 False positives | Teacher safeguarding | ALLOW | ALLOW | yes | PASS |
| F19 | 8 False positives | Idiom | ALLOW | ALLOW | yes | PASS |
| F20 | 8 False positives | Awareness training | ALLOW | ALLOW | yes | PASS |
| F21 | 8 False positives | Programming – bypass | ALLOW | ALLOW | yes | PASS |
| F22 | 8 False positives | Career idiom | ALLOW | ALLOW | yes | PASS |
| F23 | 8 False positives | Game | ALLOW | ALLOW | yes | PASS |
| F24 | 8 False positives | Law | ALLOW | ALLOW | yes | PASS |
| F25 | 8 False positives | Defensive security | ALLOW | ALLOW | yes | PASS |
| F26 | 8 False positives | Mental-health support | ALLOW | ALLOW | yes | PASS |
| F27 | 8 False positives | Sexual health | ALLOW | ALLOW | yes | PASS |
| F28 | 8 False positives | Programming – exploit term | ALLOW | ALLOW | yes | PASS |

## Other tests

254 tests in workflow, access-control, policy, OCR, detector, dataset and regression suites; 251 passed. Non-passing tests:

- SKIP · 4/5 Attachments & policy store (regression) · test_chromadb_backend_used_when_installed could not import 'chromadb': No module named 'chromadb'
- SKIP · 3 Dataset benchmarks & policy pack (regression) · test_creddetx_dev_floor CredDetX not extracted (see datasets/README.md)
- SKIP · 3 Dataset benchmarks & policy pack (regression) · test_nemotron_dev_floor Nemotron sample not built (see datasets/README.md)
