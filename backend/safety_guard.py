"""Content-safety classification with a local safety model (Llama Guard 3 via Ollama).

The safety model is a *classifier only*: it never answers the user. The gateway
sends it the text that would be forwarded to the assistant (prompt plus the
screened attachment text, with sensitive values already replaced) together
with the recent conversation, and reads back a verdict:

    safe                     -> no content-safety objection
    unsafe\\nS1,S10           -> hazard categories from the Llama Guard 3 taxonomy

What each category does is configured in policy/safety_policy.json:
BLOCK categories stop the request before it can reach the assistant model;
WARN categories are recorded and shown but do not block on their own (privacy
and intellectual property are handled by the gateway's own detectors).

Fail closed: if the safety model is not installed, not reachable, times out
or returns something that is not a valid verdict, the request is BLOCKED
(unless an administrator explicitly sets SAFETY_FAIL_MODE=open).
"""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import config

_POLICY_CACHE: Optional[dict] = None


def safety_policy() -> dict:
    global _POLICY_CACHE
    if _POLICY_CACHE is None:
        _POLICY_CACHE = json.loads(config.SAFETY_POLICY_FILE.read_text(encoding="utf-8"))
    return _POLICY_CACHE


def enabled() -> bool:
    return config.SAFETY_MODEL.lower() not in ("", "off", "none", "disabled")


@dataclass
class GuardVerdict:
    status: str                      # "safe" | "unsafe" | "error" | "disabled"
    categories: List[str] = field(default_factory=list)   # e.g. ["S1", "S10"]
    blocking: List[str] = field(default_factory=list)     # categories whose action is BLOCK
    advisory: List[str] = field(default_factory=list)     # categories whose action is WARN
    model: str = ""
    ms: int = 0
    chunks: int = 0
    error: str = ""

    def labels(self, codes: List[str]) -> List[str]:
        cats = safety_policy()["categories"]
        return ["%s %s" % (c, cats.get(c, {}).get("label", "Unknown category")) for c in codes]

    def public(self) -> dict:
        return {"status": self.status, "model": self.model, "ms": self.ms, "chunks": self.chunks,
                "categories": self.labels(self.categories), "blocking": self.labels(self.blocking),
                "advisory": self.labels(self.advisory), "error": self.error,
                "fail_mode": config.SAFETY_FAIL_MODE}


_VERDICT = re.compile(r"^\s*(safe|unsafe)[\s,:]*([Ss]\d{1,2}(?:\s*,\s*[Ss]\d{1,2})*)?\s*\.?\s*$")


def parse_verdict(text: str) -> Optional[tuple]:
    """Return ("safe", []) / ("unsafe", ["S1", ...]) or None if the reply is not a valid verdict."""
    m = _VERDICT.match(text or "")
    if not m:
        return None
    if m.group(1) == "safe":
        return "safe", []
    codes = [c.strip().upper() for c in (m.group(2) or "").split(",") if c.strip()]
    if not codes:
        return None  # "unsafe" without a category is treated as unreadable -> fail closed
    return "unsafe", codes  # unknown codes default to BLOCK in classify()


def _ask(messages: List[Dict[str, str]]) -> str:
    body = json.dumps({"model": config.SAFETY_MODEL, "messages": messages, "stream": False,
                       "options": {"temperature": 0}}).encode("utf-8")
    req = urllib.request.Request(config.OLLAMA_URL + "/api/chat", data=body,
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=config.SAFETY_TIMEOUT_S) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    if data.get("error"):
        raise RuntimeError(str(data["error"])[:200])
    return (data.get("message") or {}).get("content", "")


def _chunks(text: str, size: int, overlap: int = 400) -> List[str]:
    if len(text) <= size:
        return [text]
    out, i = [], 0
    while i < len(text):
        out.append(text[i:i + size])
        i += size - overlap
    return out


def classify(text: str, history: Optional[List[Dict[str, str]]] = None) -> GuardVerdict:
    """Classify the user turn `text` in the context of `history` (earlier screened turns)."""
    if not enabled():
        return GuardVerdict(status="disabled", model="", error="safety model disabled (SAFETY_MODEL=off)")
    t0 = time.perf_counter()
    v = GuardVerdict(status="safe", model=config.SAFETY_MODEL)
    pieces = _chunks(text or "", config.SAFETY_CHUNK_CHARS)
    if len(pieces) > config.SAFETY_MAX_CHUNKS:
        v.status, v.error = "error", "content too long to classify (%d chunks, limit %d)" % (len(pieces), config.SAFETY_MAX_CHUNKS)
        v.ms = int((time.perf_counter() - t0) * 1000)
        return v
    context = [{"role": m["role"], "content": m["content"][:2000]} for m in (history or [])
               if m.get("role") in ("user", "assistant") and m.get("content")][-4:]
    while context and context[0]["role"] != "user":   # the taxonomy prompt expects user/assistant alternation
        context.pop(0)
    cats: List[str] = []
    try:
        for piece in pieces:
            reply = _ask(context + [{"role": "user", "content": piece}])
            parsed = parse_verdict(reply)
            if parsed is None:
                v.status, v.error = "error", "safety model returned an unreadable verdict"
                break
            if parsed[0] == "unsafe":
                v.status = "unsafe"
                cats += [c for c in parsed[1] if c not in cats]
            v.chunks += 1
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:200]
        v.status = "error"
        v.error = ("safety model '%s' is not installed – run: ollama pull %s" % (config.SAFETY_MODEL, config.SAFETY_MODEL)
                   if exc.code == 404 or "not found" in detail else "safety model HTTP %s" % exc.code)
    except Exception as exc:
        v.status, v.error = "error", "safety model unreachable (%s)" % exc.__class__.__name__
    v.categories = cats
    rules = safety_policy()["categories"]
    v.blocking = [c for c in cats if rules.get(c, {}).get("action", "BLOCK") == "BLOCK"]
    v.advisory = [c for c in cats if c not in v.blocking]
    v.ms = int((time.perf_counter() - t0) * 1000)
    return v


def status() -> dict:
    """For /api/health: is the safety model installed?"""
    if not enabled():
        return {"enabled": False, "model": "", "available": False, "fail_mode": config.SAFETY_FAIL_MODE}
    try:
        with urllib.request.urlopen(config.OLLAMA_URL + "/api/tags", timeout=2.5) as resp:
            models = [m.get("name", "") for m in json.loads(resp.read().decode("utf-8")).get("models", [])]
        want = config.SAFETY_MODEL
        ok = any(m in (want, want + ":latest", want.replace(":latest", "")) for m in models)
        return {"enabled": True, "model": want, "available": ok, "fail_mode": config.SAFETY_FAIL_MODE}
    except Exception as exc:
        return {"enabled": True, "model": config.SAFETY_MODEL, "available": False,
                "fail_mode": config.SAFETY_FAIL_MODE, "error": exc.__class__.__name__}
