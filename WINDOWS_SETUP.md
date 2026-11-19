# Running the GenAI Guardrail Gateway on Windows

This guide is for a **fresh Windows 10 (22H2 or newer) or Windows 11 PC** with no development tools installed.
Everything runs locally. No paid services or cloud APIs are used, and no API keys are needed.

**Time needed:** about 30–45 minutes, most of it downloads (about 4 GB in total).

**Hardware**

| | Recommended | Minimum |
|---|---|---|
| RAM | 16 GB | 8 GB (use the smaller assistant model, see step 4) |
| Free disk space | 6 GB | 6 GB |
| GPU | Not required | — |

> Every command below goes into **PowerShell**. To open it: press the Windows key, type *PowerShell* and press Enter.
> Where you see `C:\path\to\guardrail-gateway`, use the folder you actually copied the project to.

---

## Fastest way: double-click

1. Copy the project folder to the PC (see step 1 below for which folders to leave out).
2. Double-click **`Start Guardrail Gateway.bat`** in the project folder.
   * No Python yet? It offers to install Python 3.12 with winget. Afterwards close the window and double-click the file again.
   * Windows SmartScreen may warn about a downloaded file: click **More info → Run anyway**.
3. Answer **Y** when it offers to install Ollama or Tesseract. It then creates the Python environment, downloads the two local models (about 3.5 GB once, with progress) and opens **http://127.0.0.1:8000** in your browser.
4. Keep the black window open while you use the app; close it to stop.

If anything fails, the window says what is missing, and steps 2–7 below do the same work by hand. Run `py launcher.py --check` to repeat the checks without starting the app.

---

## 1. Copy the project to the Windows PC

Copy the `guardrail-gateway` folder, for example to `C:\Projects\guardrail-gateway`, **without** these folders:

| Folder | Why leave it out |
|---|---|
| `.venv` | Python environment built for macOS; it does not work on Windows. It is rebuilt in step 5. |
| `data` | Audit database, encryption keys and demo history. It is created fresh on first start. Copy it only if you deliberately want the old history *and* keys moved; keep it private. |
| `datasets` | Optional. Large (about 800 MB), only used for the dataset benchmarks. Leave it out unless you will run them. |
| `__pycache__`, `.pytest_cache` | Temporary files. |

`.env` is not part of the project by default and holds no secrets. Copy it only if you created one.

---

## 2. Install Python 3.12

1. Go to <https://www.python.org/downloads/windows/> and download the **Windows installer (64-bit)** for **Python 3.12.x**.
   Version 3.12 is recommended because every dependency has ready-made Windows packages for it.
2. Run the installer and, on the first screen, **tick "Add python.exe to PATH"**, then click **Install Now**.
3. Close and reopen PowerShell, then check:

   ```powershell
   py -3.12 --version
   ```

   Expected: `Python 3.12.x`.

---

## 3. Install Tesseract OCR (reads text from images)

1. Open <https://github.com/UB-Mannheim/tesseract/wiki> and download the latest **64-bit Windows installer** (`tesseract-ocr-w64-setup-5.x.x.exe`).
2. Run it and keep the default folder `C:\Program Files\Tesseract-OCR`. English language data is included. You do not need to edit PATH: the gateway finds Tesseract in that folder automatically.
3. Check:

   ```powershell
   & "C:\Program Files\Tesseract-OCR\tesseract.exe" --version
   ```

   If you installed it somewhere else, see *Troubleshooting → OCR engine missing*.

---

## 4. Install Ollama and the two local models

The gateway uses **two local models**, both served by Ollama on `127.0.0.1:11434`:

| Model | Role | Download |
|---|---|---|
| `qwen2.5:3b` | The assistant that answers users | ≈ 1.9 GB |
| `llama-guard3:1b` | Content-safety **classifier only**: it never answers users. Every request is checked by it before Qwen sees anything. | ≈ 1.6 GB |

1. Download **OllamaSetup.exe** from <https://ollama.com/download> and run it. No administrator rights are needed. Ollama then runs in the background, shown by a llama icon in the system tray.
2. In a **new** PowerShell window:

   ```powershell
   ollama pull qwen2.5:3b
   ollama pull llama-guard3:1b
   ollama list
   ```

   `ollama list` must show both models.

**PCs with 8 GB RAM:** use the smaller assistant model instead.

```powershell
ollama pull qwen2.5:1.5b
```

Then put `OLLAMA_MODEL=qwen2.5:1.5b` in `.env` (see step 6).

> **Do not** set `OLLAMA_HOST=0.0.0.0`. Ollama must stay on `127.0.0.1` so that only the gateway on this PC can reach the models.

---

## 5. Create the Python environment and install dependencies

```powershell
cd C:\path\to\guardrail-gateway
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

* Once the environment is active, the prompt starts with `(.venv)`. Activate it this way in **every new PowerShell window** before running the project.
* If PowerShell says *"running scripts is disabled on this system"*, run the following once and then activate again:

  ```powershell
  Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
  ```

* `pip install` takes 2–5 minutes. The largest package is `chromadb`, which provides the policy vector store.

---

## 6. Optional settings (`.env`)

The defaults work without any configuration. To change something, copy the example file and edit it:

```powershell
Copy-Item .env.example .env
notepad .env
```

| Setting | Default | When to change |
|---|---|---|
| `OLLAMA_MODEL` | `qwen2.5:3b` | `qwen2.5:1.5b` on 8 GB PCs |
| `SAFETY_MODEL` | `llama-guard3:1b` | `llama-guard3:8b` for better accuracy if you have 16 GB+ RAM (run `ollama pull llama-guard3:8b` first) |
| `SAFETY_FAIL_MODE` | `closed` | Keep `closed`: if the safety model is missing or silent, requests are blocked. |
| `SAFETY_TIMEOUT_S` | `60` | Increase to `120` on slow PCs if the first request times out |
| `GG_AUTH_MODE` | `demo` | `pin` = every demo user signs in with a PIN (see step 8) |
| `GG_PORT` | `8000` | If port 8000 is already used |
| `TESSERACT_CMD` | auto-detected | Only if Tesseract is installed outside `C:\Program Files\Tesseract-OCR` |

---

## 7. Start the application

Make sure Ollama is running (llama icon in the tray). Then:

```powershell
cd C:\path\to\guardrail-gateway
.\.venv\Scripts\Activate.ps1
python run.py
```

Open **<http://127.0.0.1:8000>** in a browser.

The sidebar (bottom left) should show **four green lights**:

| Light | Shows |
|---|---|
| Local LLM | `qwen2.5:3b` |
| Policy store | `ChromaDB · 49` (22 governing + 27 reference clauses) |
| Safety model | `llama-guard3:1b` |
| OCR engine | `Tesseract 5.x` |

* **ChromaDB and the database need no setup.** On the first start the gateway creates `data\audit.db` (SQLite), `data\chroma\` (the policy vector index) and its encryption keys automatically.
* **Reset all demo data:** stop the server, delete the `data` folder and start again.
* **Stop the server:** press `Ctrl + C` in the PowerShell window.

---

## 8. Optional: PIN sign-in instead of the demo identity switcher

In the default `demo` mode, anyone can pick any demo user in the sidebar. That is convenient for presentations but is **not secure**. To require sign-in:

1. Set `GG_AUTH_MODE=pin` in `.env` and restart.
2. On first start the gateway writes the six demo PINs to `data\DEMO_PINS.txt`. Note them, then delete the file.
3. Switching user in the sidebar now asks for that user's PIN. Five wrong PINs lock that user out for 5 minutes.

The smoke test (step 9.3) only works in `demo` mode.

---

## 9. Run the tests and verify each feature

Open a **second** PowerShell window, `cd` to the project and activate `.venv` as in step 7.

### 9.1 Automated test suite (no models needed; about 1 minute)

```powershell
python scripts\run_audit.py
```

Expected result: `… passed` with **0 failed**. It writes `audit_report\AUDIT_REPORT.md` with PASS/FAIL for every case.

* This suite uses a built-in *mock* of Ollama. It proves the gateway's enforcement logic, not the quality of the real models' judgements.
* A few tests are skipped, not failed, when optional parts are missing: the ChromaDB backend test if ChromaDB is not installed, and the two dataset-benchmark tests if the `datasets` folder was not copied.

### 9.2 The real local models (Ollama must be running; about 1–2 minutes)

```powershell
python scripts\verify_safety_model.py
```

It checks that:

* both models are installed;
* the safety model replies in the expected `safe` / `unsafe + category` format;
* how many ordinary prompts it wrongly flags (false positives);
* three prompts work end to end through the real models.

Expected: `8/8 checks passed`.

### 9.3 End-to-end smoke test (with `python run.py` running in the first window)

```powershell
python scripts\smoke_test.py
```

Expected: `19/19 checks passed`. It covers the four decisions, review, OCR, approval, the safety model, the dashboard and the integrity counters.

### 9.4 Manual feature checklist (in the browser)

| # | Do this | Expected |
|---|---|---|
| 1 | Click the *encryption* example card, then **Send** | Five checks pass, then **Allowed**, and Qwen answers |
| 2 | Type `My netbanking password is Pune@2026x, why am I logged out?` | **Redacted & allowed**: the model receives `[PASSWORD REDACTED]` |
| 3 | Type `Draft a reply to rohan.k@inboxly.in about the refund` | **Review required**. Click *Redact & send* to send the censored version. |
| 4 | Attach `samples\meeting_notes.png` | The OCR step shows extracted words, and the e-mail/phone are flagged |
| 5 | Attach `samples\server_config_screenshot.png` | **Blocked**: a secret was read by OCR |
| 6 | Attach `samples\corrupted_image.png` | **Blocked**: the attachment could not be scanned (fail closed) |
| 7 | Type `CONFIDENTIAL – summarise the Project Falcon acquisition term sheet` | **Manager approval**. Switch to *Rahul Mehta*, open Shield → Approval queue → Approve, then switch back to Asha to see the answer. |
| 8 | Type a request **you** consider unacceptable for company AI use | **Content Safety Check** fails, the decision is **Blocked**, and Qwen receives nothing |
| 9 | Switch to *Meera Iyer (admin)*, open Shield → Security overview | Totals, content-safety statistics and **Integrity checks all 0 ✓** |
| 10 | Stop Ollama (tray icon → Quit) and send any message | **Blocked**: no safety verdict (fail closed). Restart Ollama afterwards. |

---

## 10. Troubleshooting common Windows errors

| Symptom | Cause | Fix |
|---|---|---|
| `py` / `python` is not recognised, or typing `python` opens the Microsoft Store | Python is not on PATH, or the Store alias is intercepting it | Re-run the Python installer and tick *Add python.exe to PATH*. Use `py -3.12`. Or turn off *Settings → Apps → Advanced app settings → App execution aliases → python.exe / python3.exe*. |
| `.\.venv\Scripts\Activate.ps1 cannot be loaded because running scripts is disabled` | PowerShell execution policy | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, or use **Command Prompt** with `.venv\Scripts\activate.bat` |
| `ModuleNotFoundError: No module named 'starlette'` (or any other package) | The virtual environment is not active | Run `.\.venv\Scripts\Activate.ps1`; the prompt must start with `(.venv)` |
| `pip install` fails building **chromadb** / *"Microsoft Visual C++ 14.0 or greater is required"* | No ready-made package for your Python version (usually Python 3.13+, or 32-bit Python) | Install **64-bit Python 3.12** and recreate `.venv` (delete the folder, repeat step 5). **Temporary workaround:** install everything except ChromaDB with `pip install starlette uvicorn python-multipart pytesseract "Pillow>=10.1" pypdf python-docx cryptography pytest httpx` and put `POLICY_BACKEND=memory` in `.env`. The gateway then uses its built-in in-memory policy store, which deviates from the ChromaDB requirement, so fix it before the demo. |
| Sidebar: **Local LLM offline** | Ollama is not running | Start *Ollama* from the Start menu (llama icon in the tray). Test with `Invoke-RestMethod http://127.0.0.1:11434/api/tags` |
| Sidebar: **model not pulled** / **Safety model: not installed**; every request is blocked with *"safety model … is not installed – run: ollama pull …"* | A model is missing (this blocking is fail-closed by design) | `ollama pull qwen2.5:3b` and `ollama pull llama-guard3:1b`, then `ollama list` |
| First message blocked with *"safety model unreachable (TimeoutError)"* | Models load slowly on first use, especially on 8 GB PCs | Send again (the model stays loaded for about 5 minutes), or set `SAFETY_TIMEOUT_S=120` in `.env` |
| Answers are very slow, or Ollama reports *"model requires more system memory"* | Not enough RAM for both models | Close other apps; use `OLLAMA_MODEL=qwen2.5:1.5b` |
| Sidebar: **OCR engine missing** / *"TesseractNotFoundError"* | Tesseract is not installed, or installed in an unusual folder | Install it (step 3). If it is in another folder, add `TESSERACT_CMD=D:\Tools\Tesseract-OCR\tesseract.exe` to `.env` |
| *"Error loading eng.traineddata"* | Tesseract language data is missing | Re-run the Tesseract installer and keep *English* selected |
| `[Errno 10048] … only one usage of each socket address` | Port 8000 is in use (often a second copy of the gateway) | Close the other window, or set `GG_PORT=8001` in `.env` and open `http://127.0.0.1:8001` |
| `sqlite3.OperationalError: database is locked` | Two gateways are using the same `data` folder | Run only one `python run.py` |
| Windows Defender Firewall asks to allow Python | Python opened a local port | Click **Cancel** (or allow *Private* only). The gateway listens on 127.0.0.1 and needs no firewall opening. |
| `UnicodeEncodeError` or `?` characters in the console | Old console code page | Harmless; the scripts never crash on these characters. To see them correctly, use **Windows Terminal**. |
| Squares instead of progress bars during `ollama pull` | Old console font | Cosmetic only; use Windows Terminal |
| Browser shows an old page after an update | Cached files | Press `Ctrl + F5` |
| Smoke test prints *"needs GG_AUTH_MODE=demo"* | PIN mode is on | Set `GG_AUTH_MODE=demo` while running the smoke test |
| Antivirus quarantines or slows `pip install` | Real-time scanning of many small files | Wait or retry. If files were quarantined, restore them and add the project folder as an exclusion. |

If something else goes wrong, start the gateway with `python run.py` and read the first error lines. The gateway logs the error *type* only, never prompt content.
