# Final Submission Checklist

## Deliverable 1 – GitHub repository
- [ ] `pytest -q` passes on a team laptop (with `chromadb` and `httpx` installed, nothing skipped)
- [ ] `ollama list` shows `qwen2.5:3b` **and** `llama-guard3:1b`
- [ ] Double-clicking `Start Guardrail Gateway.command` (Mac) / `.bat` (Windows) opens the app with no Setup-check banner (`python launcher.py --check` → all OK)
- [ ] After `git clone` on a second machine the `.command` file is still executable (Git keeps the bit; `.gitattributes` keeps line endings)
- [ ] `python scripts/verify_safety_model.py` → 8/8 with real Ollama
- [ ] `python scripts/smoke_test.py` → 19/19 with real Ollama
- [ ] `python scripts/run_audit.py` → 0 failed (report in `audit_report/AUDIT_REPORT.md`)
- [x] README team table filled with real names
- [ ] `.gitignore` excludes `data/`, `.venv/`, `.env`, `*.db`, `*.key` (run `git status` and confirm none are staged)
- [ ] No real credentials or personal data anywhere (all samples are synthetic)
- [ ] Repo contains: frontend, backend, scanner, OCR, ChromaDB retrieval, decision engine, LLM integration, database, sample policy, tests, README, requirements, gitignore

Repository: **https://github.com/tas7129/genai-guardrail-gateway**. To publish later changes:

```bash
git status                                  # check that no data/, .venv/ or .env is listed
git add -A && git commit -m "Describe the change"
git push
```

## Deliverable 2 – Presentation (≤ 7 slides)
- [ ] Title (project, PS16, team, hackathon) · Problem · Solution · Features · Technical approach · Working output · Plan & future scope
- [ ] Replace screenshot placeholders with screenshots from **your** running app
- [ ] Only implemented features claimed (see README §12 for limitations)

## Deliverable 3 – Demo video (4–5 min)
- [ ] Follows `docs/demo_video_script.md`
- [ ] Shows all four decisions (plus the MEDIUM review step), severity table, OCR, policy clauses, local LLM answer, approval, dashboard, audit log
- [ ] All three members introduced
- [ ] Uploaded and link set to "anyone with the link can view"
