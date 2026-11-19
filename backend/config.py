"""Central configuration. Every value can be overridden with an environment variable.

Beginners: you normally do not need to change anything here. Copy `.env.example`
to `.env` only if you want a different model or port.
"""
from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _load_dotenv() -> None:
    """Tiny .env loader (avoids an extra dependency)."""
    env_file = BASE_DIR / ".env"
    if not env_file.exists():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_dotenv()

DATA_DIR = Path(os.environ.get("GG_DATA_DIR", BASE_DIR / "data"))
DB_PATH = DATA_DIR / "audit.db"
CHROMA_DIR = DATA_DIR / "chroma"
VAULT_KEY_PATH = DATA_DIR / "vault.key"
TICKET_KEY_PATH = DATA_DIR / "ticket.key"
SESSION_KEY_PATH = DATA_DIR / "session.key"
PIN_FILE = DATA_DIR / "demo_pins.json"
PIN_PLAINTEXT_FILE = DATA_DIR / "DEMO_PINS.txt"

# Identity: "demo" = pick any demo user in the sidebar (hackathon default, NOT secure);
#           "pin"  = each demo user signs in with a PIN, signed session cookie (see backend/sessions.py)
AUTH_MODE = os.environ.get("GG_AUTH_MODE", "demo").lower()

POLICY_SEED_FILE = BASE_DIR / "policy" / "ai_usage_policy.json"
# Organisation policy pack from the hackathon dataset (reference clauses: retrieved and shown, never decide)
POLICY_REFERENCE_FILE = BASE_DIR / "policy" / "reference_policies.json"
FRONTEND_DIR = BASE_DIR / "frontend"
SAMPLES_DIR = BASE_DIR / "samples"

# Local LLM (Ollama). The gateway is the ONLY component that talks to Ollama.
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5:3b")
LLM_TIMEOUT_S = float(os.environ.get("LLM_TIMEOUT_S", "180"))

# Content-safety classifier (local, via the same Ollama). It only classifies; it never answers.
# Set SAFETY_MODEL=off to disable (NOT recommended – harmful requests then rely on built-in rules only).
SAFETY_MODEL = os.environ.get("SAFETY_MODEL", "llama-guard3:1b")
SAFETY_TIMEOUT_S = float(os.environ.get("SAFETY_TIMEOUT_S", "60"))
SAFETY_FAIL_MODE = os.environ.get("SAFETY_FAIL_MODE", "closed").lower()   # closed (block) | open (warn only)
SAFETY_CHUNK_CHARS = int(os.environ.get("SAFETY_CHUNK_CHARS", "6000"))
SAFETY_MAX_CHUNKS = int(os.environ.get("SAFETY_MAX_CHUNKS", "12"))
SAFETY_POLICY_FILE = BASE_DIR / "policy" / "safety_policy.json"

# Policy store backend: "chroma" (default) or "memory" (fallback / tests).
POLICY_BACKEND = os.environ.get("POLICY_BACKEND", "chroma")

# Limits
MAX_PROMPT_CHARS = int(os.environ.get("MAX_PROMPT_CHARS", "20000"))
MAX_FILE_MB = float(os.environ.get("MAX_FILE_MB", "5"))
MAX_FILES = int(os.environ.get("MAX_FILES", "5"))
MAX_ATTACHMENT_CHARS_FORWARDED = 6000

# A request with this many (or more) personal identifiers is treated as a
# bulk export of customer / employee records and needs manager approval.
BULK_PERSONAL_THRESHOLD = int(os.environ.get("BULK_PERSONAL_THRESHOLD", "5"))

HOST = os.environ.get("GG_HOST", "127.0.0.1")
PORT = int(os.environ.get("GG_PORT", "8000"))

ORG_NAME = "Nimbus Technologies"  # synthetic demo organisation


def ensure_data_dir() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
