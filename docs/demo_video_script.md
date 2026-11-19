# Demo Video Script — GenAI Guardrail Gateway (target 4:30)

Record at 1440×900 or 1920×1080, browser zoom 100%, dark mode. Use **real Ollama** (green "Local LLM" light). Run `python scripts/smoke_test.py` beforehand, then **delete `data/`** and restart `python run.py` so the dashboard starts clean and fills up during the recording.

| Time | Speaker | On screen | Narration (say roughly this) |
|---|---|---|---|
| 0:00–0:20 | Member 1 | Title slide / team on camera | "Hi, we're *[names]*, and this is the GenAI Guardrail Gateway, our solution to PS16, AI Usage Governance." |
| 0:20–0:50 | Member 1 | Slide 2 (problem) | "Employees paste source code, customer records and confidential plans into AI tools every day. Banning AI doesn't work, and governance teams have no visibility. We need AI that's safe by default." |
| 0:50–1:20 | Member 3 | Slide 3 (architecture) | "Our gateway sits between the employee and a local Qwen model running in Ollama. Before anything reaches the model, a Guardrail Agent runs five checks: sensitive-information detection, attachment and OCR inspection, a content-safety check by a second local model, Llama Guard, policy retrieval from ChromaDB, and a final security decision. Llama Guard only classifies – it never answers – and if it can't give a verdict, the request is blocked. The assistant never makes the security decision, so prompt injection can't talk its way past it." |
| 1:20–1:45 | Member 2 | App, Asha. Click **General question** → Send | "Asha asks a normal question. Watch the screening panel: these are real backend steps with real timings. No violations, so the clause on public information allows it and Qwen answers locally." |
| 1:45–2:15 | Member 2 | **Customer follow-up email** → Send. Point at the detection table, then click **Redact & send** | "Now customer details. The agent finds a name, an email and a phone number, all MEDIUM severity, with a confidence score and detection method for each. Nothing is sent yet: Asha reviews them and chooses Redact & send, so only placeholders like EMAIL REDACTED reach the model." |
| 2:15–2:40 | Member 2 | **Identity & health details** → Send, then **Paste a .env secrets file** → Send | "An Aadhaar number and a diagnosis are HIGH, so they're censored automatically and the question is still answered. A pasted secrets file is different: other lines could also be secrets, so safe redaction isn't possible and AUP-5 blocks it." |
| 2:40–3:00 | Member 2 | **Screenshot of meeting notes** → Send. Expand the attachment to show OCR text | "Attachments are screened too. Tesseract OCR reads this screenshot, the email and phone inside the image are redacted, and the image itself is never sent." |
| 3:00–3:20 | Member 2 | **Board meeting brief** → Send. Show tracker | "Confidential deal details for Project Falcon fall under AUP-6, so the request is encrypted and held. It can't go anywhere until her manager decides." |
| 3:20–3:50 | Member 1 | Switch identity → **Rahul (manager)**. Shield → Approval queue → Review held content → note → **Approve**. Switch back to Asha, open the conversation | "Rahul is Asha's assigned manager, and only he can open and approve this. Other managers and Asha herself get a 403. He approves, the gateway releases the request to Qwen exactly once, and Asha's chat updates with the answer." |
| 3:50–4:15 | Member 3 | Switch → **Meera (admin)**. Shield → Overview, Audit log (expand a row), Policy management | "The governance team sees organisation-wide trends, violation categories and a full audit trail, with no raw secrets stored, plus CSV export. Policies live in ChromaDB, and changing a clause here changes the next decision." |
| 4:15–4:35 | Member 3 | Slide 6/7 or team on camera | "So employees keep using AI, sensitive data never leaves unprotected, managers stay in control of confidential work, and governance finally has visibility. Thank you!" |

## Recording checklist

- [ ] Ollama running, `qwen2.5:3b` pulled, sidebar shows three green lights
- [ ] `python scripts/smoke_test.py` → all checks pass
- [ ] Stopped the server, deleted `data/`, restarted (clean dashboard)
- [ ] Browser notifications muted, bookmarks bar hidden, zoom 100%
- [ ] Shown: ALLOW, REDACT & ALLOW, BLOCK, MANAGER APPROVAL
- [ ] Shown: image upload + OCR text, policy clause retrieval, local LLM response
- [ ] Shown: manager approve, dashboard charts, audit log
- [ ] All three members appear / speak; total length 4–5 min
- [ ] Only synthetic data on screen

**Tip:** Qwen on a laptop can take 5–20 s for the first answer while the model loads. Send one warm-up prompt before you start recording.
