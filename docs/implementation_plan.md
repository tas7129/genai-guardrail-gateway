# Implementation Plan — one-day hackathon, 3 members

## Responsibilities and file ownership

| Workstream | Area | Owns |
|---|---|---|
| 1 | Security & Backend | `backend/scanner/entities.py`, `detectors.py`, `classifier.py`, `policy/severity_policy.json`, `scanner/redactor.py`, `decision.py`, `approvals.py`, `vault.py`, `db.py`, `auth.py` |
| 2 | Frontend & UX | `frontend/index.html`, `frontend/styles.css`, `frontend/app.js`, slide visuals |
| 3 | AI, Policy & Integration | `backend/llm.py`, `backend/policy/*`, `policy/ai_usage_policy.json`, `scanner/ocr.py`, `scanner/attachments.py`, `pipeline.py`, `main.py`, `tests/`, `docs/`, demo video |

## Integration contracts (agree these first)

1. **Finding** (`detectors.py`): `type, category, start, end, value (memory only), source, level, confidence, method, action`, plus `public()` for the UI and `audit()` for the log.
2. **Retrieved clause** (`store.retrieve`): `id, title, category, action, text, remediation, score, match`.
3. **Decision** (`decision.decide`): `action, risk_level, risk_score, governing[], explanation, remediation[], clause_refs[]`.
4. **Event stream** (`/api/chat`, NDJSON): `start → step(running/done) ×7 → decision → llm_start → token* → llm_done | llm_error → done`. USER_REVIEW continues on `/api/requests/{id}/review` with `review_result → llm_* → done`.
5. **Audit row** (`db.audit_log`): see the schema in `db.py`. Only sanitized text or safe metadata.

## Milestones (≈ 9 hours)

| Time | Milestone | Done when |
|---|---|---|
| 0:00–0:45 | Setup: Python venv, Ollama + `qwen2.5:3b`, Tesseract, repo skeleton | `python run.py` serves the page; `ollama run qwen2.5:3b` answers |
| 0:45–2:30 | M1 detectors + redactor · M2 chat layout · M3 policy JSON + ChromaDB store + LLM client | `pytest tests/test_detectors.py` green; retrieval returns AUP-5 for "aws key" |
| 2:30–4:00 | M1 decision engine + audit DB · M2 streaming screening panel · M3 attachments + OCR + pipeline | Four decisions visible in the UI end to end |
| 4:00–5:30 | M1 approval vault + role checks · M2 governance panel + charts · M3 tests | Manager approve/reject works; dashboard reads real data |
| 5:30–6:30 | Integration & bug-bash: all demo scenarios, smoke test | `pytest -q` and `scripts/smoke_test.py` pass |
| 6:30–8:00 | Slides, README polish, record the demo video | Video 4–5 min, slides ≤ 7 |
| 8:00–9:00 | Buffer, final push to GitHub, submission form | Checklist complete |

## Fallbacks (if something breaks on the day)

| Problem | Reliable minimum |
|---|---|
| Safety model missing → every request blocked | `ollama pull llama-guard3:1b` (fail closed is intentional; the sidebar light shows the state) |
| Laptop too slow for `qwen2.5:3b` | `ollama pull qwen2.5:1.5b`, then set `OLLAMA_MODEL=qwen2.5:1.5b` in `.env` (still local and PS16-compliant) |
| `pip install chromadb` fails | Gateway starts with the in-memory policy store; the UI shows "fallback" in amber (stated openly). Fix by using Python 3.11 |
| Tesseract missing | Images fail closed (BLOCK) and the OCR light is red; install with `brew install tesseract` |
| Ollama crashes mid-demo | Screening/decisions still work; the chat says the local model didn't answer; restart `ollama serve` |
