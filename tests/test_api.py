"""HTTP-level tests (requires httpx for Starlette's TestClient)."""
import json

import pytest

pytest.importorskip("starlette.testclient")  # needs httpx on recent Starlette versions
from starlette.testclient import TestClient  # noqa: E402

from backend.main import app  # noqa: E402


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def stream_chat(client, user, prompt):
    r = client.post("/api/chat", headers={"X-Demo-User": user}, data={"prompt": prompt})
    assert r.status_code == 200
    return [json.loads(line) for line in r.text.splitlines() if line.strip()]


def test_health(client):
    h = client.get("/api/health").json()
    assert h["llm"]["online"] and "policy_store" in h and "ocr" in h


def test_unknown_user_rejected(client):
    assert client.get("/api/conversations", headers={"X-Demo-User": "mallory"}).status_code == 401


def test_chat_stream_and_role_checks(client):
    events = stream_chat(client, "asha", "CONFIDENTIAL roadmap for Project Orion")
    dec = next(e for e in events if e["type"] == "decision")
    rid = dec["request_id"]
    assert dec["decision"]["action"] == "MANAGER_APPROVAL"
    # employee cannot open the approval review; other manager cannot decide
    assert client.get("/api/approvals/" + rid, headers={"X-Demo-User": "asha"}).status_code == 403
    r = client.post("/api/approvals/%s/decision" % rid, headers={"X-Demo-User": "priya"}, json={"action": "approve"})
    assert r.status_code == 403
    r = client.post("/api/approvals/%s/decision" % rid, headers={"X-Demo-User": "rahul"}, json={"action": "reject"})
    assert r.status_code == 200 and r.json()["status"] == "rejected"


def test_admin_only_endpoints(client):
    assert client.put("/api/policy/AUP-3", headers={"X-Demo-User": "asha"}, json={"action": "BLOCK"}).status_code == 403
    assert client.get("/api/audit.csv", headers={"X-Demo-User": "rahul"}).status_code == 403
    assert client.get("/api/audit.csv", headers={"X-Demo-User": "meera"}).status_code == 200


def test_employee_sees_only_own_audit(client):
    stream_chat(client, "vikram", "hello from sales")
    rows = client.get("/api/audit", headers={"X-Demo-User": "asha"}).json()
    assert rows and all(r["user_id"] == "asha" for r in rows)


def test_review_endpoint_and_severity_policy(client):
    events = stream_chat(client, "asha", "Email rohan.k@inboxly.in about the refund")
    dec = next(e for e in events if e["type"] == "decision")
    assert dec["decision"]["action"] == "USER_REVIEW"
    rid = dec["request_id"]
    r = client.post("/api/requests/%s/review" % rid, headers={"X-Demo-User": "vikram"}, json={"choice": "send"})
    assert r.status_code == 404  # not the requester
    r = client.post("/api/requests/%s/review" % rid, headers={"X-Demo-User": "asha"}, json={"choice": "redact"})
    assert r.status_code == 200
    first = json.loads(r.text.splitlines()[0])
    assert first["type"] == "review_result" and first["decision"] == "REDACT_AND_ALLOW"
    # severity policy: everyone can read, only admin can change
    assert client.get("/api/severity-policy", headers={"X-Demo-User": "asha"}).json()["strict_mode"] is False
    assert client.put("/api/severity-policy", headers={"X-Demo-User": "asha"}, json={"strict_mode": True}).status_code == 403
    r = client.put("/api/severity-policy", headers={"X-Demo-User": "meera"}, json={"strict_mode": True})
    assert r.status_code == 200 and r.json()["effective_actions"]["MEDIUM"] == "redact"
    client.put("/api/severity-policy", headers={"X-Demo-User": "meera"}, json={"strict_mode": False})


# ---------------------------------------------------------------- one-click setup: model download endpoint
def _pull(client, which, user="meera"):
    return client.post("/api/setup/pull", headers={"X-Demo-User": user}, json={"which": which})


def test_setup_pull_streams_progress_for_configured_model(client):
    r = _pull(client, "safety")
    assert r.status_code == 200
    lines = [json.loads(x) for x in r.text.splitlines() if x.strip()]
    assert lines and all(x["model"] for x in lines)
    assert not any(x.get("error") for x in lines)
    assert lines[-1]["status"] == "success"


def test_setup_pull_only_allows_the_two_configured_models(client):
    for bad in ("", "qwen2.5:72b", "../../etc", "llama-guard3:1b"):
        assert _pull(client, bad).status_code == 400
    r = client.post("/api/setup/pull", headers={"X-Demo-User": "meera", "Content-Type": "application/json"}, content=b"not json")
    assert r.status_code == 400


def test_setup_pull_requires_a_known_user(client):
    assert _pull(client, "safety", user="mallory").status_code == 401


def test_setup_pull_refused_from_another_machine():
    with TestClient(app, client=("10.1.2.3", 50000)) as remote:
        assert _pull(remote, "safety").status_code == 403
