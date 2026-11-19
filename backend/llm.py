"""Local LLM client (Ollama).

This is the only module that talks to the model, and every call requires a
ForwardTicket issued by the guardrail for the exact text being sent.
Ollama listens on 127.0.0.1 by default, so other machines cannot bypass the
gateway; see README "Preventing bypass" for hardening steps.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Dict, Iterator, List

from . import config
from .vault import ForwardTicket, verify_ticket

SYSTEM_PROMPT = (
    "You are Nimbus Assist, the internal AI assistant of %s. Every user message has already been "
    "screened by the Guardrail Gateway. Sensitive values may have been replaced with placeholders such "
    "as [EMAIL REDACTED] or [PHONE NUMBER 2 REDACTED]: keep placeholders exactly as written and never try "
    "to guess or invent the original values. Be concise, helpful and professional. Use Markdown for structure when useful."
    % config.ORG_NAME
)


class LLMUnavailable(Exception):
    pass


def status() -> dict:
    try:
        with urllib.request.urlopen(config.OLLAMA_URL + "/api/tags", timeout=2.5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        models = [m.get("name", "") for m in data.get("models", [])]
        wanted = config.OLLAMA_MODEL
        candidates = {wanted, wanted + ":latest", wanted.replace(":latest", "")}
        available = any(m in candidates for m in models)
        return {"online": True, "model": wanted, "model_available": available, "models": models,
                "url": config.OLLAMA_URL}
    except Exception as exc:
        return {"online": False, "model": config.OLLAMA_MODEL, "model_available": False, "models": [],
                "url": config.OLLAMA_URL, "error": str(exc)}


def build_messages(history: List[Dict[str, str]], user_content: str) -> List[Dict[str, str]]:
    msgs = [{"role": "system", "content": SYSTEM_PROMPT}]
    msgs += [{"role": m["role"], "content": m["content"]} for m in history if m["role"] in ("user", "assistant")]
    msgs.append({"role": "user", "content": user_content})
    return msgs


def chat_stream(messages: List[Dict[str, str]], ticket: ForwardTicket) -> Iterator[str]:
    """Yield response text chunks. Raises PermissionError without a valid ticket."""
    verify_ticket(ticket, messages[-1]["content"])
    body = json.dumps({
        "model": config.OLLAMA_MODEL,
        "messages": messages,
        "stream": True,
        "options": {"temperature": 0.4},
    }).encode("utf-8")
    req = urllib.request.Request(config.OLLAMA_URL + "/api/chat", data=body,
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        resp = urllib.request.urlopen(req, timeout=config.LLM_TIMEOUT_S)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        raise LLMUnavailable("Ollama returned HTTP %s: %s" % (exc.code, detail))
    except Exception as exc:
        raise LLMUnavailable("Local LLM unreachable at %s (%s). Is `ollama serve` running?"
                             % (config.OLLAMA_URL, exc))
    with resp:
        for raw in resp:
            line = raw.decode("utf-8").strip()
            if not line:
                continue
            try:
                chunk = json.loads(line)
            except ValueError:
                continue
            if chunk.get("error"):
                raise LLMUnavailable(chunk["error"])
            text = (chunk.get("message") or {}).get("content", "")
            if text:
                yield text
            if chunk.get("done"):
                break


def chat(messages: List[Dict[str, str]], ticket: ForwardTicket) -> str:
    return "".join(chat_stream(messages, ticket))
