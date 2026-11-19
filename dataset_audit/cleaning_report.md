# Validation and cleaning report

All cleaning is done by one reproducible script, `scripts/datasets/build_processed.py`. It uses only the
standard library, plus the bundled pure-Python Parquet reader `scripts/datasets/parquet_lite.py`, so pyarrow
is not needed. The script reads the originals read-only and writes new files.

**No original file was modified or deleted.**

* The original ZIP was moved into `datasets/original/`.
* Its relevant members were extracted to `datasets/original/extracted/`, and their SHA-256 hashes are recorded in
  `dataset_inventory.csv`.
* The two tool archives (EasyOCR and Presidio, 187 MB together) were **not** extracted. They remain only inside the original ZIP.

Input and output hashes, the sampling seed and every transformation count are in `datasets/processed/MANIFEST.json`.

## 1. Sample AI usage policies → `policy/reference_policies.json` (27 clauses)

| Check | Result |
|---|---|
| Encoding | All 6 files are valid UTF-8 |
| Structure | 5 files with 4 numbered clauses each; 1 Markdown file with 6 sections |
| Duplicated clauses | None. The overlaps are with the gateway's own AUP clauses and are recorded in `maps_to`, not removed. |

| Transformation | Count | Why |
|---|---|---|
| CRLF → LF line endings | 6 files | Consistent text in the vector store |
| Hard-wrapped lines joined, whitespace collapsed | 16 line joins | Each clause becomes one retrievable sentence |
| Markdown bullet lists joined into one clause per section | 4 sections | Keeps a section's rules together for retrieval |
| Closing statement of the governance policy split into its own clause (GOV-7) | 1 | It is a distinct rule: the pack "supplements and does not override" the gateway's technical rules |
| Metadata added: id, title, category, `maps_to`, `consistency`, source file and clause number | 27 clauses | Traceability and the governance-panel table. Titles were written for the UI; the clause **text is unchanged**. |

## 2. CredDetX → used in place (no copy)

| Check | dev | test |
|---|---|---|
| Records / invalid JSON lines | 602 / 0 | 2,425 / 0 |
| Empty texts | 0 | 0 |
| Duplicate ids / duplicate texts | 0 / 0 | 0 / 0 |
| Span or negative offsets out of range | 0 | 0 |
| `no_secret` flag inconsistent with spans | 0 | 0 |
| Secret span overlapping an annotated negative | 0 | 0 |
| Records missing the benchmark canary | 0 | 0 |
| Ids or texts shared between splits | 0 | 0 |

**Transformations: none.** The data is clean, so it is evaluated exactly as published. Making a cleaned copy would
only have created a redundant second set of secret-shaped values on disk.

One evaluation-time step changes no data: each span is trimmed of surrounding whitespace before checking whether its
characters would be forwarded.

## 3. Nemotron-PII → `datasets/processed/nemotron_{dev,eval}.jsonl`

| Check | train file | test file |
|---|---|---|
| Rows (footer = rows read) | 100,000 | 100,000 |
| Null / empty values in any column | 0 | 0 |
| `uid` appearing twice | 50,000 (us/intl pairs – not duplicates) | 50,000 (same) |
| Exact duplicate texts | 1 | 0 |
| Rows without any span | 6 | 1 |
| Span lists that fail to parse | 0 | 0 |
| Offsets out of range | 0 | 0 |
| Span `text` ≠ `text[start:end]` | 12,594 | 12,942 |
| Overlapping spans | 24 | 34 |

| Transformation | train | test | Why |
|---|---|---|---|
| Rows dropped: exact duplicate text | 1 | 0 | No double counting |
| Rows dropped: no spans | 6 | 1 | Nothing to evaluate |
| Span text that is an integer, normalised to the string at the offsets | 5,824 | 6,747 | Data type only; the offsets are correct |
| Span text that differs only in case, normalised to the string at the offsets | 6,770 | 6,195 | The labeller lower-cased the value; the offsets are correct |
| Rows dropped because the offsets point at different text | 0 | 0 | The check stays in place as a safeguard |
| Columns dropped: `document_description`, `text_tagged`, span `text` | all | all | Not needed. `text_tagged` and span `text` are second copies of every PII value, and removing them halves the amount of sensitive-shaped text on disk. |
| Spans parsed with `ast.literal_eval` (never `eval`) | all | all | The column holds Python literals, not JSON |
| **Stratified sample**: 500 per locale (us/intl) × format (structured/unstructured), reservoir sampling, seed 16 | 2,000 docs · 16,186 spans | 2,000 docs · 17,062 spans | Balanced coverage and fast evaluation. Train becomes the **dev** sample, used for error analysis; test becomes the **eval** sample, used only for reporting. |

## 4. Excluded material

`datasets/excluded/` holds only the READMEs and licences of EasyOCR and Presidio, kept for attribution, plus
`EXCLUDED.md`, which explains why. The archives themselves were not extracted, so no redundant copy exists.

## 5. Rebuilding

```bash
python scripts/datasets/audit_inventory.py     # inventory CSV + stats (about 2 min, reads 200k Parquet rows)
python scripts/datasets/build_processed.py     # reference policies + Nemotron samples + MANIFEST
python scripts/datasets/evaluate.py all        # evaluation JSON in dataset_audit/evaluation/
```

The build is deterministic: the same seed and the same inputs give the same output hashes, as recorded in `MANIFEST.json`.
