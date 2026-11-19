"""Data-driven security audit. Every case in cases.py goes through the REAL
pipeline (run_guardrail) with the recording mock Ollama, which plays both the
assistant model and the safety model. Per case we record section, category,
expected, actual decision, whether anything reached the ASSISTANT model, and
PASS/FAIL with the reason – appended to $AUDIT_RESULTS (JSONL) when set
(scripts/run_audit.py builds the report from it)."""
import json
import os
import secrets as _secrets
import sys
from pathlib import Path

# Fixtures come from tests/conftest.py (applied by pytest automatically). This folder deliberately has
# no conftest.py of its own: a second "conftest" module would shadow it and start a second mock server.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import pytest

import mock_ollama
from backend import auth, config, db
from backend.pipeline import UploadedFile, run_guardrail
from backend.policy import store as policy_store

from cases import CASES, EXPECT

ASHA = auth.USERS["asha"]
RESULTS = os.environ.get("AUDIT_RESULTS")
ORDER = ["ALLOW", "REDACT_AND_ALLOW", "USER_REVIEW", "MANAGER_APPROVAL", "BLOCK"]


def _record(row):
    if RESULTS:
        with open(RESULTS, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")


def _set_clause(cid, action, via_api=True):
    before = next(c for c in db.policy_all() if c["id"] == cid)["action"]
    if via_api:
        db.policy_update(cid, "meera", action=action)
    else:  # simulate a tampered / mis-edited database row
        with db.connect() as conn:
            conn.execute("UPDATE policy_clauses SET action = ? WHERE id = ?", (action, cid))
    policy_store.index_clauses(db.policy_all())
    return before


@pytest.fixture
def setup_hook(request, monkeypatch):
    name = request.param
    restore = None
    if name == "aup5_block":
        restore = ("AUP-5", _set_clause("AUP-5", "BLOCK"))
    elif name == "aup3_block":
        restore = ("AUP-3", _set_clause("AUP-3", "BLOCK"))
    elif name == "aup12_weakened_in_db":
        restore = ("AUP-12", _set_clause("AUP-12", "ALLOW", via_api=False))
    elif name == "no_governing":
        real = policy_store.retrieve
        monkeypatch.setattr(policy_store, "retrieve",
                            lambda *a, **k: [c for c in real(*a, **k) if c.get("kind") == "reference"])
    elif name == "guard_missing":
        monkeypatch.setattr(config, "SAFETY_MODEL", "llama-guard3:missing")
    elif name == "guard_ocr_marker":
        real_reply = mock_ollama.guard_reply

        def reply(messages):
            last = (messages or [{}])[-1].get("content", "")
            return (200, "unsafe\nS2") if "GUARD S2 marker" in last else real_reply(messages)
        monkeypatch.setattr(mock_ollama, "guard_reply", reply)
    yield
    if restore:
        cid, action = restore
        with db.connect() as conn:
            conn.execute("UPDATE policy_clauses SET action = ? WHERE id = ?", (action, cid))
        policy_store.index_clauses(db.policy_all())


def _run(prompt, files, conv):
    events = list(run_guardrail(ASHA, prompt, files, conv))
    start = next(e for e in events if e["type"] == "start")
    dec = next(e for e in events if e["type"] == "decision")
    return start["conversation_id"], dec, events


@pytest.mark.parametrize("case,setup_hook", [(c, c.get("setup")) for c in CASES],
                         ids=[c["id"] for c in CASES], indirect=["setup_hook"])
def test_audit_case(case, setup_hook, llm_log):
    conv = "C-AUD" + _secrets.token_hex(3).upper()
    for h in case.get("history", []):
        conv, _, _ = _run(h, [], conv)
    llm_log.reset()
    files = [UploadedFile(n, f()) for n, f in case.get("files", [])]
    conv, dec, events = _run(case["prompt"], files, conv)
    d = dec["decision"]
    actual = d["action"]
    sent = llm_log.user_messages()
    guard_calls = llm_log.guard_requests()
    problems = []
    if actual not in EXPECT[case["expect"]]:
        problems.append("decision %s not in %s" % (actual, sorted(EXPECT[case["expect"]])))
    if actual in ("BLOCK", "MANAGER_APPROVAL", "USER_REVIEW") and sent:
        problems.append("content reached the assistant model although the decision was %s" % actual)
    if actual == "ALLOW" and sent and case["prompt"].strip()[:40] not in sent[-1]:
        problems.append("ALLOW did not forward the original prompt")
    if sent and not guard_calls and case.get("setup") != "guard_missing":
        problems.append("content reached the assistant without a safety-model check")
    row = db.get_audit(dec["request_id"])
    for s in case.get("secret", []):
        if any(s in m for m in sent):
            problems.append("a protected value reached the assistant model")
        if s in json.dumps(row, ensure_ascii=False):
            problems.append("a protected value was written to the audit log")
    if not row or row["decision"] != actual:
        problems.append("decision not recorded in the audit log")
    refs = set(d.get("clause_refs") or [])
    for g in case.get("governing", []):
        if g not in refs:
            problems.append("expected governing clause %s not applied (got %s)" % (g, sorted(refs)))
    for g in case.get("not_governing", []):
        if g in refs:
            problems.append("reference clause %s must not govern" % g)
    for g in d.get("governing", []):  # every applied clause is reflected in the final decision
        if ORDER.index(g["action"]) > ORDER.index(actual):
            problems.append("clause %s required %s but decision was %s" % (g.get("clause_id"), g["action"], actual))
    if case.get("support") and not dec.get("support"):
        problems.append("support resources not shown")
    _record({"id": case["id"], "section": case["section"], "category": case["category"],
             "expected": case["expect"], "actual": actual, "forwarded": bool(sent),
             "result": "PASS" if not problems else "FAIL", "reason": "; ".join(problems)})
    assert not problems, "; ".join(problems)
