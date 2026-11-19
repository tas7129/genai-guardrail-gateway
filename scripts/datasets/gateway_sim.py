"""Offline replica of the gateway's text path, for dataset evaluation.

`screen_text()` runs exactly the steps `backend.pipeline.run_guardrail` runs on
a prompt with no attachments – normalise, detect, classify, bulk check, decide,
redact – but without the database, ChromaDB, the vault or the LLM, so tens of
thousands of texts can be scored quickly. Governing clauses come straight from
policy/ai_usage_policy.json (the same file the gateway seeds its policy from).

tests/test_datasets.py checks that this replica reaches the same decision as the
real pipeline on every demo prompt, so the two cannot silently drift apart.
"""
from __future__ import annotations

import copy
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.decision import decide  # noqa: E402
from backend.scanner import classifier  # noqa: E402
from backend.scanner import detectors as det  # noqa: E402
from backend.scanner.redactor import Redactor  # noqa: E402

_CLAUSES = json.loads((ROOT / "policy" / "ai_usage_policy.json").read_text(encoding="utf-8"))["clauses"]


@dataclass
class ScreenResult:
    text: str                      # normalised text the detectors saw
    findings: List[det.Finding]
    decision: str                  # ALLOW / REDACT_AND_ALLOW / USER_REVIEW / MANAGER_APPROVAL / BLOCK
    risk_level: str
    forwarded_strict: Optional[str]  # what reaches the LLM (None = nothing is forwarded now)
    forwarded_send_anyway: Optional[str]  # USER_REVIEW worst case: the user picks "Send anyway"
    released_if_approved: Optional[str]  # MANAGER_APPROVAL: what the approval would release


def severity_policy(strict: bool = False) -> dict:
    p = copy.deepcopy(classifier.default_policy())
    p["strict_mode"] = bool(strict)
    return p


def screen_text(raw: str, policy: Optional[dict] = None, is_code_file: bool = False) -> ScreenResult:
    policy = policy or severity_policy()
    text, _ = det.normalize_text(raw)
    findings = det.detect(text, "prompt", is_code_file=is_code_file)
    classifier.classify(findings, {"prompt": text}, ocr_sources=set(), policy=policy)
    bulk = det.bulk_personal_finding(findings)
    if bulk:
        bulk.action = "request"
        findings.append(bulk)
    flagged = [f for f in findings if f.level != "LOW" or f.scope == "request"]
    categories = list(dict.fromkeys(f.category for f in flagged))
    wanted = set(categories or ["PUBLIC"])
    retrieved = [c for c in _CLAUSES if c["category"] in wanted]
    decision = decide(categories, flagged, retrieved, policy.get("document_level_action", "MANAGER_APPROVAL"))
    red = Redactor(findings)
    strict_text, _ = red.redact(text, findings, lambda f: f.action in ("redact", "review", "block"))
    warn_text, _ = red.redact(text, findings, lambda f: f.action in ("redact", "block"))
    action = decision.action
    if action == "ALLOW":
        fwd, anyway = text, text
    elif action == "REDACT_AND_ALLOW":
        fwd, anyway = strict_text, strict_text
    elif action == "USER_REVIEW":
        fwd, anyway = strict_text, warn_text
    else:  # MANAGER_APPROVAL (held) or BLOCK: nothing is forwarded at screening time
        fwd, anyway = None, None
    released = strict_text if action == "MANAGER_APPROVAL" else None
    return ScreenResult(text, findings, action, decision.risk_level, fwd, anyway, released)
