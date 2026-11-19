"""Test setup: isolated data directory + a recording mock LLM.

The mock LLM (scripts/mock_ollama.py) logs every request body it receives,
which lets tests prove exactly what did – and did not – reach the model.
"""
import json
import os
import socket
import sys
import tempfile
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

_TMP = Path(tempfile.mkdtemp(prefix="guardrail_test_"))
_LLM_LOG = _TMP / "llm_requests.jsonl"


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


_PORT = _free_port()
os.environ["GG_DATA_DIR"] = str(_TMP / "data")
os.environ["OLLAMA_URL"] = "http://127.0.0.1:%d" % _PORT
os.environ["OLLAMA_MODEL"] = "qwen2.5:3b"
os.environ["SAFETY_MODEL"] = "llama-guard3:1b"
os.environ["SAFETY_TIMEOUT_S"] = "1.5"

import mock_ollama  # noqa: E402

_SERVER = mock_ollama.serve(_PORT, str(_LLM_LOG))

from backend import main  # noqa: E402

main.bootstrap()


class LLMLog:
    def reset(self):
        _LLM_LOG.write_text("", encoding="utf-8")

    def all_requests(self):
        if not _LLM_LOG.exists():
            return []
        return [json.loads(l) for l in _LLM_LOG.read_text(encoding="utf-8").splitlines() if l.strip()]

    def requests(self):
        """Requests to the ASSISTANT model (Qwen) only."""
        return [r for r in self.all_requests() if not str(r.get("model", "")).startswith("llama-guard")]

    def guard_requests(self):
        """Requests to the SAFETY model only."""
        return [r for r in self.all_requests() if str(r.get("model", "")).startswith("llama-guard")]

    def user_messages(self):
        return [r["messages"][-1]["content"] for r in self.requests()]


@pytest.fixture
def llm_log():
    log = LLMLog()
    log.reset()
    return log


@pytest.fixture
def data_dir():
    return _TMP / "data"


def wait_for(predicate, timeout=6.0):
    end = time.time() + timeout
    while time.time() < end:
        if predicate():
            return True
        time.sleep(0.05)
    return False
