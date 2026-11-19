"""Cryptographic helpers.

* Vault: requests waiting for manager approval are encrypted (Fernet / AES-128-CBC
  + HMAC) before they touch disk, and deleted after the decision.
* Forward tickets: an HMAC-signed "permission slip" created by the decision
  engine. The LLM client refuses to send anything without a valid ticket whose
  hash matches the exact text being sent, so no code path can forward
  unscreened content by accident.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.fernet import Fernet

from . import config

FORWARDABLE_DECISIONS = {"ALLOW", "REDACT_AND_ALLOW", "APPROVED"}


def _load_or_create_key(path: Path, generator) -> bytes:
    config.ensure_data_dir()
    if path.exists():
        return path.read_bytes().strip()
    key = generator()
    path.write_bytes(key)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


def _fernet() -> Fernet:
    return Fernet(_load_or_create_key(config.VAULT_KEY_PATH, Fernet.generate_key))


def encrypt_json(obj) -> bytes:
    return _fernet().encrypt(json.dumps(obj).encode("utf-8"))


def decrypt_json(token: bytes):
    return json.loads(_fernet().decrypt(token).decode("utf-8"))


# ---------------------------------------------------------------------------
# Forward tickets
# ---------------------------------------------------------------------------
def _ticket_key() -> bytes:
    return _load_or_create_key(config.TICKET_KEY_PATH, lambda: os.urandom(32).hex().encode())


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ForwardTicket:
    request_id: str
    decision: str
    content_sha256: str
    signature: str


def issue_ticket(request_id: str, decision: str, text: str) -> ForwardTicket:
    if decision not in FORWARDABLE_DECISIONS:
        raise PermissionError("decision %s may not be forwarded to the LLM" % decision)
    h = content_hash(text)
    sig = hmac.new(_ticket_key(), ("%s|%s|%s" % (request_id, decision, h)).encode(), hashlib.sha256).hexdigest()
    return ForwardTicket(request_id, decision, h, sig)


def verify_ticket(ticket: ForwardTicket, text: str) -> None:
    if ticket is None:
        raise PermissionError("no forward ticket – content was not cleared by the guardrail")
    if ticket.decision not in FORWARDABLE_DECISIONS:
        raise PermissionError("ticket decision %s is not forwardable" % ticket.decision)
    if content_hash(text) != ticket.content_sha256:
        raise PermissionError("content differs from what the guardrail cleared")
    expected = hmac.new(_ticket_key(), ("%s|%s|%s" % (ticket.request_id, ticket.decision, ticket.content_sha256)).encode(),
                        hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, ticket.signature):
        raise PermissionError("forward ticket signature invalid")
