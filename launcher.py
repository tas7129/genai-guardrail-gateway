"""One-click launcher for the GenAI Guardrail Gateway.

Double-click "Start Guardrail Gateway.command" (macOS) or
"Start Guardrail Gateway.bat" (Windows), or run:  python launcher.py

What it does, every time (it only does work that is still missing):
  1. Creates the Python environment (.venv) and installs requirements.txt
     (first run, or when requirements.txt changed).
  2. Makes sure Ollama is running – starts it if it is installed but stopped;
     offers to install it with winget (Windows) / Homebrew (macOS) if missing.
  3. Downloads the two local models if they are missing (with progress):
     the assistant (qwen2.5:3b) and the content-safety classifier (llama-guard3:1b).
  4. Checks Tesseract OCR (offers to install it) and ChromaDB.
  5. Starts the gateway and opens http://127.0.0.1:8000 in the browser.
Close the window or press Ctrl+C to stop the gateway.

Options:  --check  (checks only, no start)   --yes  (install missing tools without asking)
          --no-browser                         --no-venv (use the current Python, for developers)
This file uses only the Python standard library, so it runs before anything is installed.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

for _s in (sys.stdout, sys.stderr):  # never crash on a non-ASCII character in old Windows consoles
    try:
        _s.reconfigure(errors="replace")
    except Exception:
        pass

ROOT = Path(__file__).resolve().parent
VENV = ROOT / ".venv"
REQ = ROOT / "requirements.txt"
MARKER = VENV / ".requirements.sha256"
IS_WIN = os.name == "nt"
IS_MAC = sys.platform == "darwin"
ARGS = set(sys.argv[1:])
ASSUME_YES = "--yes" in ARGS


# ───────────────────────────── output helpers ─────────────────────────────
def say(msg: str = "") -> None:
    print(msg, flush=True)


def step(n: int, total: int, msg: str) -> None:
    say("\n[%d/%d] %s" % (n, total, msg))


def ok(msg: str) -> None:
    say("      OK   " + msg)


def warn(msg: str) -> None:
    say("      !!   " + msg)


def fail(msg: str, hint: str = "") -> None:
    say("\n  ✗ " + msg)
    if hint:
        say("    " + hint.replace("\n", "\n    "))
    pause_and_exit(1)


def pause_and_exit(code: int) -> None:
    if sys.stdin and sys.stdin.isatty() and "--no-pause" not in ARGS:
        try:
            input("\nPress Enter to close this window…")
        except (EOFError, KeyboardInterrupt):
            pass
    sys.exit(code)


def ask(question: str) -> bool:
    if ASSUME_YES:
        return True
    if not (sys.stdin and sys.stdin.isatty()):
        return False
    try:
        return input("      ?    %s [Y/n] " % question).strip().lower() in ("", "y", "yes")
    except (EOFError, KeyboardInterrupt):
        return False


def run(cmd, **kw) -> int:
    say("      $    " + " ".join(str(c) for c in cmd))
    return subprocess.call([str(c) for c in cmd], **kw)


# ───────────────────────────── 1. Python environment ──────────────────────
def venv_python() -> Path:
    return VENV / ("Scripts/python.exe" if IS_WIN else "bin/python")


def in_project_venv() -> bool:
    try:
        return Path(sys.prefix).resolve() == VENV.resolve()
    except OSError:
        return False


def bootstrap_venv() -> None:
    """Runs with the system Python: create/refresh .venv, then re-run this file inside it."""
    say("GenAI Guardrail Gateway – launcher")
    step(1, 5, "Python environment")
    if sys.version_info < (3, 10):
        fail("Python %s is too old." % platform.python_version(),
             "Install Python 3.12 from https://www.python.org/downloads/ and run the launcher again.")
    if sys.version_info >= (3, 13):
        warn("Python %s detected – 3.12 is recommended (ChromaDB may lack ready-made packages for newer versions)."
             % platform.python_version())
    if not venv_python().exists():
        say("      Creating the project environment (.venv)…")
        if run([sys.executable, "-m", "venv", VENV]) != 0 or not venv_python().exists():
            fail("Could not create the Python environment.",
                 "On Debian/Ubuntu install python3-venv first. On Windows reinstall Python with default options.")
    want = hashlib.sha256(REQ.read_bytes()).hexdigest()
    have = MARKER.read_text(encoding="utf-8").strip() if MARKER.exists() else ""
    if want != have:
        say("      Installing Python packages (first run takes 2–5 minutes)…")
        run([venv_python(), "-m", "pip", "install", "--disable-pip-version-check", "-q", "--upgrade", "pip"])
        if run([venv_python(), "-m", "pip", "install", "--disable-pip-version-check", "-r", REQ]) != 0:
            fail("Installing the Python packages failed.",
                 "Check the internet connection and try again. If the error mentions chromadb or\n"
                 "'Microsoft Visual C++', install 64-bit Python 3.12 (see WINDOWS_SETUP.md, Troubleshooting).")
        MARKER.write_text(want, encoding="utf-8")
        ok("packages installed")
    else:
        ok("environment ready (.venv)")
    # continue inside the environment
    code = subprocess.call([str(venv_python()), str(Path(__file__).resolve()), "--in-venv", *sys.argv[1:]])
    sys.exit(code)


# ───────────────────────────── 2. Ollama ──────────────────────────────────
def http_json(url: str, timeout: float = 3.0, data: dict | None = None):
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"} if body else {},
                                 method="POST" if body else "GET")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def ollama_up(url: str) -> bool:
    try:
        http_json(url + "/api/tags", 2.0)
        return True
    except Exception:
        return False


def find_ollama() -> list:
    """Command(s) that start the Ollama server, best option first."""
    cands = []
    if IS_MAC and Path("/Applications/Ollama.app").exists():
        cands.append(["open", "-g", "-a", "Ollama"])
    if IS_WIN:
        local = Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Ollama"
        for exe in (local / "ollama app.exe", local / "ollama.exe"):
            if exe.exists():
                cands.append([str(exe)] if exe.name.startswith("ollama app") else [str(exe), "serve"])
    exe = shutil.which("ollama")
    if exe:
        cands.append([exe, "serve"])
    return cands


def start_detached(cmd: list) -> None:
    log = open(ROOT / "data" / "ollama-launcher.log", "ab")  # noqa: SIM115 – kept open for the child
    kw = {"stdout": log, "stderr": log, "stdin": subprocess.DEVNULL}
    if IS_WIN:
        kw["creationflags"] = 0x00000008 | 0x00000200  # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    else:
        kw["start_new_session"] = True
    subprocess.Popen(cmd, **kw)


def install_ollama() -> bool:
    if IS_WIN and shutil.which("winget"):
        if ask("Ollama is not installed. Install it now with winget?"):
            return run(["winget", "install", "-e", "--id", "Ollama.Ollama", "--accept-package-agreements",
                        "--accept-source-agreements"]) == 0
    elif IS_MAC and shutil.which("brew"):
        if ask("Ollama is not installed. Install it now with Homebrew?"):
            return run(["brew", "install", "ollama"]) == 0
    elif sys.platform.startswith("linux"):
        say("      Install Ollama with:  curl -fsSL https://ollama.com/install.sh | sh")
    return False


def ensure_ollama(url: str) -> None:
    step(2, 5, "Local AI runtime (Ollama)")
    if ollama_up(url):
        ok("Ollama is running at %s" % url)
        return
    cands = find_ollama()
    if not cands and install_ollama():
        cands = find_ollama()
    if not cands:
        fail("Ollama is not installed.",
             "Download it from https://ollama.com/download (no admin rights needed), then run the launcher again.")
    (ROOT / "data").mkdir(exist_ok=True)
    say("      Starting Ollama…")
    start_detached(cands[0])
    for _ in range(60):
        if ollama_up(url):
            ok("Ollama started")
            return
        time.sleep(1)
    fail("Ollama did not start within 60 seconds.",
         "Start the Ollama app manually (Start menu / Applications), then run the launcher again.")


def pull_model(url: str, name: str) -> bool:
    req = urllib.request.Request(url + "/api/pull", data=json.dumps({"model": name, "stream": True}).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    last = ""
    try:
        with urllib.request.urlopen(req, timeout=3600) as resp:
            for raw in resp:
                line = raw.decode("utf-8", "replace").strip()
                if not line:
                    continue
                ev = json.loads(line)
                if ev.get("error"):
                    say("\n      error: %s" % ev["error"])
                    return False
                total, done = ev.get("total"), ev.get("completed")
                status = ev.get("status", "")
                if total and done is not None:
                    msg = "      %-22s %5.1f%%  %6.0f / %.0f MB" % (status[:22], 100.0 * done / total, done / 1e6, total / 1e6)
                else:
                    msg = "      %s" % status
                if msg != last:
                    print("\r" + msg.ljust(70), end="", flush=True)
                    last = msg
        print()
        return True
    except Exception as exc:
        say("\n      download failed: %s" % exc)
        return False


def ensure_models(url: str, models: list) -> None:
    step(3, 5, "Local models")
    tags = [m.get("name", "") for m in http_json(url + "/api/tags", 5).get("models", [])]
    for role, name in models:
        if any(t in (name, name + ":latest") or t.replace(":latest", "") == name for t in tags):
            ok("%s: %s" % (role, name))
            continue
        say("      Downloading %s model %s (one-time, about 1–2 GB)…" % (role, name))
        if not pull_model(url, name):
            fail("Could not download %s." % name, "Check the internet connection, then run the launcher again.")
        ok("%s: %s downloaded" % (role, name))


# ───────────────────────────── 4. OCR / ChromaDB / port ───────────────────
def ensure_ocr_and_store() -> None:
    step(4, 5, "OCR engine and policy store")
    from backend.scanner.ocr import ocr_status
    avail, ver = ocr_status()
    if not avail:
        installed = False
        if IS_WIN and shutil.which("winget") and ask("Tesseract OCR is not installed. Install it now with winget?"):
            installed = run(["winget", "install", "-e", "--id", "UB-Mannheim.TesseractOCR",
                             "--accept-package-agreements", "--accept-source-agreements"]) == 0
        elif IS_MAC and shutil.which("brew") and ask("Tesseract OCR is not installed. Install it now with Homebrew?"):
            installed = run(["brew", "install", "tesseract"]) == 0
        if installed:
            import backend.scanner.ocr as ocr_mod
            ocr_mod._CONFIGURED = False
            avail, ver = ocr_status()
    if avail:
        ok("Tesseract %s" % ver.replace("tesseract", "").strip())
    else:
        warn("Tesseract OCR not found – the app runs, but image attachments will be blocked (fail closed).")
        warn("Install: Windows https://github.com/UB-Mannheim/tesseract/wiki · macOS: brew install tesseract")
    try:
        import chromadb  # noqa: F401
        ok("ChromaDB available")
    except Exception:
        from backend import config
        os.environ["POLICY_BACKEND"] = "memory"
        config.POLICY_BACKEND = "memory"
        warn("ChromaDB could not be loaded – using the built-in in-memory policy store for this run.")


def port_free(host: str, port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) != 0


def gateway_already_running(host: str, port: int) -> bool:
    try:
        return "safety_model" in http_json("http://%s:%d/api/health" % (host, port), 3)
    except Exception:
        return False


# ───────────────────────────── 5. start ───────────────────────────────────
KNOWN_FLAGS = {"--check", "--yes", "--no-browser", "--no-venv", "--no-pause", "--in-venv", "--help", "-h"}


def main() -> None:
    unknown = sorted(a for a in ARGS if a not in KNOWN_FLAGS)
    if unknown or "--help" in ARGS or "-h" in ARGS:
        say(__doc__ or "")
        if unknown:
            say("Unknown option(s): " + ", ".join(unknown))
        sys.exit(2 if unknown else 0)
    if "--in-venv" not in ARGS and "--no-venv" not in ARGS and not in_project_venv():
        bootstrap_venv()
        return
    sys.path.insert(0, str(ROOT))
    os.chdir(ROOT)
    from backend import config

    ensure_ollama(config.OLLAMA_URL)
    models = [("assistant", config.OLLAMA_MODEL)]
    if config.SAFETY_MODEL.lower() not in ("", "off", "none", "disabled"):
        models.append(("safety classifier", config.SAFETY_MODEL))
    ensure_models(config.OLLAMA_URL, models)
    ensure_ocr_and_store()

    step(5, 5, "Guardrail Gateway")
    host, port = config.HOST, config.PORT
    url = "http://%s:%d" % ("127.0.0.1" if host in ("0.0.0.0", "") else host, port)
    if not port_free(host, port):
        if gateway_already_running(host, port):
            ok("already running at %s" % url)
            if "--no-browser" not in ARGS and "--check" not in ARGS:
                webbrowser.open(url)
            pause_and_exit(0)
        for p in range(port + 1, port + 20):
            if port_free(host, p):
                warn("port %d is busy – using %d" % (port, p))
                port, url = p, "http://127.0.0.1:%d" % p
                os.environ["GG_PORT"] = str(p)
                break
    if "--check" in ARGS:
        ok("all checks done – start without --check to run the gateway")
        pause_and_exit(0)

    def open_when_ready():
        for _ in range(120):
            try:
                http_json(url + "/api/health", 3)
                say("\n  ✓ Guardrail Gateway is running:  %s" % url)
                say("    Keep this window open while you use it. Close it (or press Ctrl+C) to stop.\n")
                if "--no-browser" not in ARGS:
                    webbrowser.open(url)
                return
            except Exception:
                time.sleep(0.5)
        say("  The gateway did not answer within 60 s – see the messages above.")

    threading.Thread(target=open_when_ready, daemon=True).start()
    import logging

    import uvicorn
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        uvicorn.run("backend.main:app", host=host, port=port, log_level="warning")
    except KeyboardInterrupt:
        pass
    say("Gateway stopped.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        say("\nStopped.")
    except SystemExit:
        raise
    except Exception as exc:  # show a readable message instead of a vanishing window
        say("\nUnexpected error: %s: %s" % (exc.__class__.__name__, exc))
        pause_and_exit(1)
