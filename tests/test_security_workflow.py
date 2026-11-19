"""Security & workflow audit (sections 5–7 of the audit brief) plus the local
safety-model integration. Content safety is driven through neutral markers that
the mock safety model understands ("[[GUARD:S1]]" → "unsafe\\nS1"); see
scripts/mock_ollama.py. All data is synthetic."""
import json
import threading
import time

import pytest

pytest.importorskip("starlette.testclient")
from starlette.testclient import TestClient  # noqa: E402

import mock_ollama  # noqa: E402
from backend import approvals, auth, config, db, safety_guard, sessions  # noqa: E402
from backend.decision import decide  # noqa: E402
from backend.main import app  # noqa: E402
from backend.pipeline import UploadedFile, run_guardrail  # noqa: E402
from backend.policy import store as policy_store  # noqa: E402
from backend.scanner import detectors as det  # noqa: E402

from conftest import wait_for  # noqa: E402

ASHA, VIKRAM = auth.USERS["asha"], auth.USERS["vikram"]
PW = "Blue#Mango42"


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def run(prompt, files=None, user=ASHA, conv=None):
    events = list(run_guardrail(user, prompt, files or [], conv))
    return events, next(e for e in events if e["type"] == "decision")


def chat(client, user, prompt, **extra):
    r = client.post("/api/chat", headers={"X-Demo-User": user}, data=dict({"prompt": prompt}, **extra))
    return r, [json.loads(line) for line in r.text.splitlines() if line.strip()] if r.status_code == 200 else []


# ── Safety model: verdict parsing ─────────────────────────────────────────
@pytest.mark.parametrize("reply,expected", [
    ("safe", ("safe", [])), ("\n\nunsafe\nS1", ("unsafe", ["S1"])), ("unsafe\nS1,S10", ("unsafe", ["S1", "S10"])),
    ("unsafe S2", ("unsafe", ["S2"])), ("unsafe", None), ("I think it's fine", None), ("", None), ("safe-ish", None),
])
def test_verdict_parsing(reply, expected):
    assert safety_guard.parse_verdict(reply) == expected


# ── Safety model: enforcement ─────────────────────────────────────────────
def test_safe_prompt_is_classified_then_forwarded(llm_log):
    _, dec = run("Explain unit testing in two lines.")
    assert dec["decision"]["action"] == "ALLOW" and dec["safety"]["status"] == "safe"
    guard = llm_log.guard_requests()
    assert len(guard) == 1 and guard[0]["model"] == config.SAFETY_MODEL
    assert guard[0]["messages"][-1]["content"] == "Explain unit testing in two lines."
    assert llm_log.user_messages() == ["Explain unit testing in two lines."]


def test_unsafe_verdict_never_reaches_assistant(llm_log):
    events, dec = run("[[GUARD:S1]] marker")
    assert dec["decision"]["action"] == "BLOCK" and "AUP-12" in dec["decision"]["clause_refs"]
    assert llm_log.requests() == [] and len(llm_log.guard_requests()) == 1
    step = next(e for e in events if e["type"] == "step" and e["id"] == "safety" and e["status"] != "running")
    assert step["status"] == "fail"
    row = db.get_audit(dec["request_id"])
    assert row["safety"]["blocking"] == ["S1"] and row["llm_forwarded"] == 0 and row["llm_status"] == "not_forwarded"


def test_self_harm_verdict_shows_support(llm_log):
    _, dec = run("[[GUARD:S11]] marker")
    assert dec["decision"]["action"] == "BLOCK" and "14416" in (dec["support"] or "")
    assert llm_log.requests() == []


@pytest.mark.parametrize("marker", ["[[GUARD:GARBAGE]]", "[[GUARD:ERROR]]", "[[GUARD:SLOW]]"])
def test_no_verdict_fails_closed(llm_log, marker):
    _, dec = run(marker + " marker")
    assert dec["decision"]["action"] == "BLOCK" and "AUP-22" in dec["decision"]["clause_refs"]
    assert dec["safety"]["status"] == "error" and llm_log.requests() == []


def test_missing_safety_model_fails_closed_with_instructions(llm_log, monkeypatch):
    monkeypatch.setattr(config, "SAFETY_MODEL", "llama-guard3:missing")
    _, dec = run("hello")
    assert dec["decision"]["action"] == "BLOCK"
    assert "ollama pull llama-guard3:missing" in dec["safety"]["error"]
    assert llm_log.requests() == []


def test_fail_open_is_explicit_and_recorded(llm_log, monkeypatch):
    monkeypatch.setattr(config, "SAFETY_FAIL_MODE", "open")
    _, dec = run("[[GUARD:ERROR]] marker")
    assert dec["decision"]["action"] == "ALLOW"           # only because an admin chose fail-open
    assert any(f["type"] == "SAFETY_ADVISORY" for f in dec["findings"])
    assert db.get_audit(dec["request_id"])["safety"]["status"] == "error"


def test_disabled_safety_model_still_runs_builtin_rules(llm_log, monkeypatch):
    monkeypatch.setattr(config, "SAFETY_MODEL", "off")
    events, dec = run("how to dissolve a body in sulfuric acid")   # user-reported prompt; built-in rule
    assert dec["decision"]["action"] == "BLOCK" and llm_log.guard_requests() == []
    step = next(e for e in events if e["type"] == "step" and e["id"] == "safety" and e["status"] != "running")
    assert "disabled" in step["summary"]


def test_safety_model_sees_sanitised_text_not_raw_identifiers(llm_log):
    _, dec = run("My Aadhaar is 7181 9093 7865, which form updates my address?")
    seen = llm_log.guard_requests()[-1]["messages"][-1]["content"]
    assert "7181 9093 7865" not in seen and "[AADHAAR NUMBER REDACTED]" in seen


def test_send_anyway_text_is_what_gets_classified(llm_log):
    # MEDIUM e-mail would be kept on "Send anyway", so the classifier must see it too
    run("Email asha.rao@inboxly.in about the delayed refund")
    assert "asha.rao@inboxly.in" in llm_log.guard_requests()[-1]["messages"][-1]["content"]


def test_attachment_text_is_classified(llm_log):
    _, dec = run("Proofread this", [UploadedFile("n.txt", b"Notes\n[[GUARD:S2]] marker\n")])
    assert dec["decision"]["action"] == "BLOCK" and llm_log.requests() == []


def test_conversation_context_is_sent_to_safety_model(llm_log):
    _, first = run("[[CTX-A]] first part")
    assert first["decision"]["action"] == "ALLOW"
    conv = db.get_audit(first["request_id"])["conversation_id"]
    llm_log.reset()
    _, second = run("[[CTX-B]] second part", conv=conv)
    assert second["decision"]["action"] == "BLOCK" and llm_log.requests() == []
    assert len(llm_log.guard_requests()[-1]["messages"]) >= 3   # earlier turns were included


def test_every_assistant_request_was_cleared_by_the_safety_model(llm_log):
    for p in ("What is Kubernetes?", "My password is %s, why am I logged out?" % PW, "Summarise agile in 3 bullets"):
        run(p)
    reqs = llm_log.all_requests()
    for i, r in enumerate(reqs):
        if r["model"] == config.OLLAMA_MODEL:
            text = r["messages"][-1]["content"]
            assert any(g["model"] == config.SAFETY_MODEL and g["messages"][-1]["content"] == text for g in reqs[:i])


# ── Approval workflow ─────────────────────────────────────────────────────
def _approve(rid, manager="rahul"):
    return approvals.decide(rid, auth.USERS[manager], "approve")


def test_rejected_request_is_never_forwarded(llm_log):
    _, dec = run("CONFIDENTIAL – Project Falcon acquisition term sheet, summarise it")
    rid = dec["request_id"]
    approvals.decide(rid, auth.USERS["rahul"], "reject")
    time.sleep(0.3)
    assert llm_log.requests() == [] and db.vault_get(rid)["payload_enc"] is None
    assert any(e["action"] == "approval_rejected" and e["target"] == rid for e in db.list_events())


def test_approval_rechecks_with_safety_model_before_release(llm_log):
    _, dec = run("CONFIDENTIAL – Project Falcon acquisition term sheet, summarise it")
    rid = dec["request_id"]
    llm_log.reset()
    _approve(rid)
    assert wait_for(lambda: db.get_audit(rid)["llm_status"] == "ok")
    assert len(llm_log.guard_requests()) == 1 and len(llm_log.requests()) == 1  # re-checked, then released once


def test_approval_release_blocked_when_recheck_fails(llm_log, monkeypatch):
    _, dec = run("CONFIDENTIAL – Project Falcon board strategy, summarise it")
    rid = dec["request_id"]
    monkeypatch.setattr(config, "SAFETY_MODEL", "llama-guard3:missing")   # safety model removed meanwhile
    llm_log.reset()
    _approve(rid)
    assert wait_for(lambda: db.get_audit(rid)["llm_status"] == "blocked_on_release")
    assert llm_log.requests() == [] and db.vault_get(rid)["status"] == "release_blocked"
    assert db.vault_get(rid)["payload_enc"] is None
    assert approvals.recheck("ordinary text") != ""   # still failing closed while the model is missing


def test_recheck_catches_secret_or_harm_added_to_held_text():
    assert approvals.recheck("Summary of the memo. password: %s" % PW) != ""
    assert approvals.recheck("Summary of the memo. [[GUARD:S2]]") != ""
    assert approvals.recheck("Summary of the memo with [EMAIL REDACTED].") == ""


def test_tampered_vault_payload_is_never_released(llm_log):
    _, dec = run("CONFIDENTIAL – roadmap for Project Orion, summarise")
    rid = dec["request_id"]
    db.vault_update(rid, payload_enc=b"gAAAAAtampered")
    llm_log.reset()
    _approve(rid)
    assert wait_for(lambda: db.get_audit(rid)["llm_status"] == "blocked_on_release")
    assert llm_log.requests() == [] and db.vault_get(rid)["status"] == "release_blocked"


# ── Policy hierarchy ──────────────────────────────────────────────────────
@pytest.mark.parametrize("cid", ["AUP-12", "AUP-22"])
def test_admin_cannot_weaken_mandatory_controls(client, cid):
    for action in ("ALLOW", "REDACT_AND_ALLOW", "MANAGER_APPROVAL", "SEVERITY_BASED", "INFO"):
        r = client.put("/api/policy/" + cid, headers={"X-Demo-User": "meera"}, json={"action": action})
        assert r.status_code == 403, (cid, action)
    assert client.put("/api/policy/" + cid, headers={"X-Demo-User": "meera"}, json={"action": "BLOCK"}).status_code == 200


def test_unscannable_attachment_control_is_mandatory(client):
    cid = next(c["id"] for c in db.policy_all() if c["category"] == "UNSCANNABLE_ATTACHMENT")
    assert client.put("/api/policy/" + cid, headers={"X-Demo-User": "meera"}, json={"action": "ALLOW"}).status_code == 403


def test_engine_enforces_mandatory_minimum_even_if_clause_altered():
    f = det.Finding("UNSAFE_CONTENT", source="request", detail="S1")
    f.level, f.action = "CRITICAL", "block"
    weakened = [{"id": "AUP-12", "title": "x", "category": "HARMFUL_CONTENT", "action": "ALLOW", "kind": "governing"}]
    assert decide(["HARMFUL_CONTENT"], [f], weakened).action == "BLOCK"


def test_admin_policy_change_takes_effect_and_is_logged(client, llm_log):
    try:
        assert client.put("/api/policy/AUP-3", headers={"X-Demo-User": "meera"}, json={"action": "BLOCK"}).status_code == 200
        _, dec = run("Draft a reply to rohan.k@inboxly.in about the refund")
        assert dec["decision"]["action"] == "BLOCK" and llm_log.requests() == []
        assert any(e["action"] == "policy_updated" and e["target"] == "AUP-3" for e in db.list_events())
    finally:
        client.put("/api/policy/AUP-3", headers={"X-Demo-User": "meera"}, json={"action": "SEVERITY_BASED"})


# ── Access control (demo identity mode) ───────────────────────────────────
def test_users_cannot_read_each_others_history_or_requests(client):
    _, ev = chat(client, "vikram", "Explain CRM pipelines briefly")
    dec = next(e for e in ev if e["type"] == "decision")
    conv = next(e for e in ev if e["type"] == "start")["conversation_id"]
    assert client.get("/api/conversations/" + conv, headers={"X-Demo-User": "asha"}).status_code == 404
    assert client.get("/api/requests/" + dec["request_id"], headers={"X-Demo-User": "asha"}).status_code == 403
    assert all(c["id"] != conv for c in client.get("/api/conversations", headers={"X-Demo-User": "asha"}).json())
    # attaching a new message to someone else's conversation starts a new one instead
    _, ev2 = chat(client, "asha", "hello", conversation_id=conv)
    assert next(e for e in ev2 if e["type"] == "start")["conversation_id"] != conv


@pytest.mark.parametrize("method,path,body", [
    ("get", "/api/events", None), ("get", "/api/audit.csv", None), ("put", "/api/policy/AUP-3", {"action": "BLOCK"}),
    ("post", "/api/policy/reset", {}), ("put", "/api/severity-policy", {"strict_mode": True}),
])
def test_employees_and_managers_cannot_use_admin_controls(client, method, path, body):
    for user in ("asha", "rahul"):
        kw = {"headers": {"X-Demo-User": user}}
        if body is not None:
            kw["json"] = body
        assert getattr(client, method)(path, **kw).status_code == 403, (user, path)


def test_manager_scope_is_limited_to_own_team(client):
    _, ev = chat(client, "vikram", "CONFIDENTIAL – Sales pricing strategy for Q3, summarise")
    rid = next(e for e in ev if e["type"] == "decision")["request_id"]
    assert client.get("/api/approvals/" + rid, headers={"X-Demo-User": "rahul"}).status_code == 403
    assert client.post("/api/approvals/%s/decision" % rid, headers={"X-Demo-User": "rahul"},
                       json={"action": "approve"}).status_code == 403
    rows = client.get("/api/audit", headers={"X-Demo-User": "rahul"}).json()
    assert all(r["user_id"] in ("asha", "rahul") for r in rows)


def test_no_route_exposes_the_models_directly(client):
    for path in ("/api/generate", "/api/tags", "/ollama/api/chat", "/v1/chat/completions", "/api/llm"):
        assert client.post(path, json={"model": "qwen2.5:3b", "prompt": "hi"}).status_code in (404, 405)
    paths = {r.path for r in app.routes}
    assert not any("ollama" in p or "generate" in p for p in paths)


def test_extra_form_fields_cannot_skip_screening(client, llm_log):
    _, ev = chat(client, "asha", "[[GUARD:S2]] marker", skip_screening="true", decision="ALLOW", forward="1")
    assert next(e for e in ev if e["type"] == "decision")["decision"]["action"] == "BLOCK"
    assert llm_log.requests() == []


def test_empty_and_oversized_requests_are_rejected(client):
    assert client.post("/api/chat", headers={"X-Demo-User": "asha"}, data={"prompt": "   "}).status_code == 400
    big = "a" * (config.MAX_PROMPT_CHARS + 1)
    assert client.post("/api/chat", headers={"X-Demo-User": "asha"}, data={"prompt": big}).status_code == 400
    files = [("files", ("f%d.txt" % i, b"x", "text/plain")) for i in range(config.MAX_FILES + 1)]
    assert client.post("/api/chat", headers={"X-Demo-User": "asha"}, data={"prompt": "x"}, files=files).status_code == 400


# ── PIN sign-in mode ──────────────────────────────────────────────────────
def test_pin_mode_ignores_spoofed_identity_and_locks_out(client, monkeypatch, tmp_path):
    monkeypatch.setattr(config, "AUTH_MODE", "pin")
    monkeypatch.setattr(config, "PIN_FILE", tmp_path / "pins.json")
    monkeypatch.setattr(config, "PIN_PLAINTEXT_FILE", tmp_path / "PINS.txt")
    sessions._FAILS.clear()
    assert sessions.ensure_pins()
    pins = dict(line.split() for line in (tmp_path / "PINS.txt").read_text(encoding="utf-8").splitlines()[1:])
    client.cookies.clear()
    assert client.get("/api/conversations", headers={"X-Demo-User": "meera"}).status_code == 401   # header ignored
    assert client.post("/api/login", json={"user": "asha", "pin": "000000" if pins["asha"] != "000000" else "111111"}).status_code == 401
    r = client.post("/api/login", json={"user": "asha", "pin": pins["asha"]})
    assert r.status_code == 200 and sessions.SESSION_COOKIE in r.cookies
    assert client.get("/api/conversations").status_code == 200
    assert client.get("/api/events", headers={"X-Demo-User": "meera"}).status_code == 403          # still asha
    client.cookies.set(sessions.SESSION_COOKIE, r.cookies[sessions.SESSION_COOKIE].replace("asha.", "meera.", 1))
    assert client.get("/api/conversations").status_code == 401                                      # tampered
    for _ in range(5):
        client.post("/api/login", json={"user": "rahul", "pin": "bad"})
    assert client.post("/api/login", json={"user": "rahul", "pin": pins["rahul"]}).status_code == 429
    client.cookies.clear()


# ── Concurrency ───────────────────────────────────────────────────────────
def test_simultaneous_requests_do_not_mix_users_or_decisions(llm_log):
    results = {}

    def worker(i):
        user = ASHA if i % 2 == 0 else VIKRAM
        marker = "MARK%03d" % i
        prompt = ("%s password: Pw#%04dXy" % (marker, i)) if i % 3 == 0 else ("%s explain caching briefly" % marker)
        _, dec = run(prompt, user=user)
        results[i] = (user["id"], marker, dec)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(12)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert len(results) == 12
    for i, (uid, marker, dec) in results.items():
        row = db.get_audit(dec["request_id"])
        assert row["user_id"] == uid
        assert dec["decision"]["action"] == ("REDACT_AND_ALLOW" if i % 3 == 0 else "ALLOW")
    for msg in llm_log.user_messages():
        assert len([m for _, m, _ in results.values() if m in msg]) == 1        # each message carries one request
        assert "Pw#" not in msg                                                  # no password leaked across


# ── Audit log & dashboard ─────────────────────────────────────────────────
def test_dashboard_matches_database_and_integrity_is_clean(client):
    chat(client, "asha", "What is a REST API?")
    chat(client, "asha", "[[GUARD:S1]] marker")
    chat(client, "asha", "My password is %s" % PW)
    s = client.get("/api/governance/overview", headers={"X-Demo-User": "meera"}).json()
    with db.connect() as conn:
        total = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        blocked = conn.execute("SELECT COUNT(*) FROM audit_log WHERE decision='BLOCK'").fetchone()[0]
        fwd = conn.execute("SELECT COUNT(*) FROM audit_log WHERE llm_forwarded=1").fetchone()[0]
    assert s["total"] == total and s["decisions"]["BLOCK"] == blocked and s["llm_forwarded"] == fwd
    assert s["safety"]["unsafe"] >= 1 and s["safety"]["checked"] >= 3
    assert all(v == 0 for v in s["integrity"].values()), s["integrity"]


def test_every_screening_is_logged_with_user_time_decision_and_safety(client):
    before = len(db.list_audit(limit=100000))
    _, ev = chat(client, "vikram", "Explain OKRs")
    rid = next(e for e in ev if e["type"] == "decision")["request_id"]
    row = db.get_audit(rid)
    assert len(db.list_audit(limit=100000)) == before + 1
    assert row["user_id"] == "vikram" and row["ts"] and row["decision"] == "ALLOW" and row["safety"]["status"] == "safe"


def test_logs_and_dashboard_views_hold_no_raw_values(client, data_dir):
    chat(client, "asha", "My Aadhaar is 7181 9093 7865 and my password is %s" % PW)
    blob = (data_dir / "audit.db").read_bytes()
    assert PW.encode() not in blob and b"7181 9093 7865" not in blob
    for path in ("/api/audit", "/api/governance/overview"):
        text = client.get(path, headers={"X-Demo-User": "meera"}).text
        assert PW not in text and "7181 9093 7865" not in text
