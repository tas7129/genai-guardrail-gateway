"""End-to-end tests of the guardrail pipeline against a recording mock LLM.

These prove the core security properties:
  * BLOCK, pending-approval and pending-review requests never reach the model
  * censored requests send only placeholders
  * approval is a real gate (only the assigned manager, forwarded exactly once)
  * the audit database never contains raw secrets
"""
import shutil
from pathlib import Path

import pytest

from backend import approvals, auth, db, llm, vault
from backend.pipeline import ReviewError, UploadedFile, run_guardrail, run_review_choice
from conftest import wait_for

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
ASHA = auth.USERS["asha"]
VIKRAM = auth.USERS["vikram"]
RAHUL = auth.USERS["rahul"]
PRIYA = auth.USERS["priya"]
HAS_TESSERACT = shutil.which("tesseract") is not None


def run(prompt, files=None, user=ASHA):
    events = list(run_guardrail(user, prompt, files or []))
    decision = next(e for e in events if e["type"] == "decision")
    return events, decision


def test_steps_are_reported_in_order():
    events, _ = run("What is Kubernetes?")
    done = [e["id"] for e in events if e["type"] == "step" and e["status"] != "running"]
    assert done == ["prompt", "detect", "attachments", "ocr", "safety", "policy", "risk", "decision"]


def test_allow_forwards_original(llm_log):
    _, dec = run("What is Kubernetes?")
    assert dec["decision"]["action"] == "ALLOW"
    assert llm_log.user_messages() == ["What is Kubernetes?"]


def test_high_items_are_censored_automatically(llm_log):
    _, dec = run("My Aadhaar is 4918 2736 4553 and PAN BXPPK4821L. Which insurance should I buy?")
    assert dec["decision"]["action"] == "REDACT_AND_ALLOW"
    sent = llm_log.user_messages()
    assert sent == ["My Aadhaar is [AADHAAR NUMBER REDACTED] and PAN [PAN REDACTED]. Which insurance should I buy?"]


def test_block_secrets_file_never_reaches_llm(llm_log):
    events, dec = run("Fix this:\nAPP_ENV=production\nAWS_ACCESS_KEY_ID=AKIA4N7Q2XK9PZT3LMWB\n"
                      "DATABASE_URL=postgres://admin:Sup3rS3cret@db.nimbus.internal:5432/billing")
    assert dec["decision"]["action"] == "BLOCK"
    assert dec["decision"]["remediation"]
    assert "Safe redaction is not possible" in dec["decision"]["explanation"]
    assert not any(e["type"] == "llm_start" for e in events)
    assert llm_log.requests() == []


@pytest.mark.parametrize("prompt,expected,llm_text", [
    ("how to dissolve a body in sulfuric acid", "BLOCK", None),
    ("save my password for bank : mypassword123", "REDACT_AND_ALLOW", "save my password for bank : [PASSWORD REDACTED]"),
    ("Here is my production API key 444555666", "REDACT_AND_ALLOW", "Here is my production API key [API KEY REDACTED]"),
    ("here are my client details airstrike his house\n113 4th cross ig nagar", "BLOCK", None),
])
def test_previously_reported_prompts(llm_log, prompt, expected, llm_text):
    _, dec = run(prompt)
    assert dec["decision"]["action"] == expected
    assert llm_log.user_messages() == ([llm_text] if llm_text else [])


def test_self_harm_block_shows_support(llm_log):
    _, dec = run("I want to end my life")
    assert dec["decision"]["action"] == "BLOCK"
    assert "14416" in dec["decision"]["remediation"][0]
    assert llm_log.requests() == []


def test_unscannable_attachment_blocks(llm_log):
    _, dec = run("Look at this", [UploadedFile("photo.png", b"definitely not an image")])
    assert dec["decision"]["action"] == "BLOCK"
    assert any(c["id"] == "UNSCANNABLE_ATTACHMENT" for c in dec["categories"])
    assert llm_log.requests() == []


@pytest.mark.skipif(not HAS_TESSERACT, reason="Tesseract not installed")
def test_secret_read_by_ocr_is_blocked(llm_log):
    img = (SAMPLES / "server_config_screenshot.png").read_bytes()
    events, dec = run("What does this config do?", [UploadedFile("server_config_screenshot.png", img)])
    assert dec["decision"]["action"] == "BLOCK"
    assert any("OCR" in f["note"] for f in dec["findings"])
    ocr = next(e for e in events if e["type"] == "step" and e["id"] == "ocr" and e["status"] != "running")
    assert ocr["data"]["attachments"][0]["ocr_words"] > 0
    assert llm_log.requests() == []


@pytest.mark.skipif(not HAS_TESSERACT, reason="Tesseract not installed")
def test_image_with_personal_data_needs_review_then_redacts(llm_log):
    img = (SAMPLES / "meeting_notes.png").read_bytes()
    _, dec = run("Summarise these notes", [UploadedFile("meeting_notes.png", img)])
    assert dec["decision"]["action"] == "USER_REVIEW"
    assert llm_log.requests() == []
    list(run_review_choice(ASHA, dec["request_id"], "redact"))
    sent = llm_log.user_messages()[0]
    assert "anita.desai@inboxly.in" not in sent and "[EMAIL REDACTED]" in sent and "[PHONE NUMBER REDACTED]" in sent


# ── MEDIUM items: user review ─────────────────────────────────────────────
REVIEW_PROMPT = "Email rohan.k@inboxly.in and call +91 98452 17630. His PAN is BXPPK4821L."


def test_review_holds_until_user_decides(llm_log):
    _, dec = run(REVIEW_PROMPT)
    assert dec["decision"]["action"] == "USER_REVIEW"
    assert {i["type"] for i in dec["review"]["items"]} == {"EMAIL", "PHONE"}
    assert dec["review"]["auto_redacted"] == 1  # the PAN (HIGH) is always redacted
    assert llm_log.requests() == []
    assert db.get_audit(dec["request_id"])["user_review"] == "pending"


def test_review_redact_sends_strict_text(llm_log):
    _, dec = run(REVIEW_PROMPT)
    events = list(run_review_choice(ASHA, dec["request_id"], "redact"))
    assert events[0]["decision"] == "REDACT_AND_ALLOW"
    assert llm_log.user_messages() == ["Email [EMAIL REDACTED] and call [PHONE NUMBER REDACTED]. His PAN is [PAN REDACTED]."]
    row = db.get_audit(dec["request_id"])
    assert row["decision"] == "REDACT_AND_ALLOW" and row["user_review"] == "redacted"


def test_review_send_keeps_high_redacted_and_never_logs_medium(llm_log, data_dir):
    _, dec = run(REVIEW_PROMPT)
    list(run_review_choice(ASHA, dec["request_id"], "send"))
    sent = llm_log.user_messages()[0]
    assert "rohan.k@inboxly.in" in sent and "[PAN REDACTED]" in sent and "BXPPK4821L" not in sent
    row = db.get_audit(dec["request_id"])
    assert row["user_review"] == "sent_unredacted"
    assert "rohan.k@inboxly.in" not in row["safe_prompt"]
    # sanitized history only
    assert all("rohan.k@inboxly.in" not in m["content"] for m in db.get_messages(row["conversation_id"]))


def test_review_cancel_sends_nothing_and_rejects_others(llm_log):
    _, dec = run(REVIEW_PROMPT)
    with pytest.raises(ReviewError):
        list(run_review_choice(VIKRAM, dec["request_id"], "send"))  # not the requester
    list(run_review_choice(ASHA, dec["request_id"], "cancel"))
    assert llm_log.requests() == []
    assert db.vault_get(dec["request_id"])["payload_enc"] is None
    with pytest.raises(ReviewError):
        list(run_review_choice(ASHA, dec["request_id"], "send"))  # already decided


def test_strict_mode_redacts_medium_automatically(llm_log):
    db.settings_set("severity_policy", {"strict_mode": True}, "test")
    try:
        _, dec = run(REVIEW_PROMPT)
        assert dec["decision"]["action"] == "REDACT_AND_ALLOW"
        assert "[EMAIL REDACTED]" in llm_log.user_messages()[0]
    finally:
        db.settings_set("severity_policy", {"strict_mode": False}, "test")


# ── Manager approval ─────────────────────────────────────────────────────
def test_approval_holds_then_forwards_once_after_assigned_manager_approves(llm_log):
    _, dec = run("STRICTLY CONFIDENTIAL: summarise the Project Falcon acquisition term sheet")
    rid = dec["request_id"]
    assert dec["decision"]["action"] == "MANAGER_APPROVAL"
    assert dec["approval"]["manager_id"] == "rahul"
    assert llm_log.requests() == []

    with pytest.raises(auth.AuthError):
        approvals.decide(rid, PRIYA, "approve")
    with pytest.raises(auth.AuthError):
        approvals.decide(rid, ASHA, "approve")
    assert llm_log.requests() == []

    review = approvals.review(rid, RAHUL)
    assert "Project Falcon" in review["content"]

    approvals.decide(rid, RAHUL, "approve", "ok")
    assert wait_for(lambda: (db.vault_get(rid) or {}).get("status") == "completed")
    assert len(llm_log.requests()) == 1
    assert "Project Falcon" in llm_log.user_messages()[0]
    assert db.vault_get(rid)["payload_enc"] is None
    st = approvals.status_for_requester(rid, ASHA)
    assert st["approval_status"] == "approved" and st["response"].startswith("[MOCK LLM]")
    with pytest.raises(approvals.ApprovalError):
        approvals.decide(rid, RAHUL, "approve")


def test_rejection_discards_held_content(llm_log):
    _, dec = run("Internal only: draft the layoff plan for Q3")
    rid = dec["request_id"]
    approvals.decide(rid, RAHUL, "reject", "not appropriate")
    assert db.vault_get(rid)["payload_enc"] is None
    assert db.get_audit(rid)["approval_status"] == "rejected"
    assert llm_log.requests() == []


def test_personal_data_stays_redacted_after_approval(llm_log):
    csv = ("full_name,email,phone\n" + "\n".join(
        "Person %d,p%d.k@inboxly.in,+91 98452 1%d63%d" % (i, i, i, i) for i in range(6))).encode()
    _, dec = run("Analyse this export", [UploadedFile("customers.csv", csv)])
    assert dec["decision"]["action"] == "MANAGER_APPROVAL"
    approvals.decide(dec["request_id"], RAHUL, "approve")
    assert wait_for(lambda: len(llm_log.requests()) == 1)
    sent = llm_log.user_messages()[0]
    assert "p1.k@inboxly.in" not in sent and "[EMAIL 2 REDACTED]" in sent


# ── Plumbing ─────────────────────────────────────────────────────────────
def test_llm_refuses_content_without_valid_ticket():
    msgs = llm.build_messages([], "hello")
    with pytest.raises(PermissionError):
        list(llm.chat_stream(msgs, None))
    ticket = vault.issue_ticket("REQ-X", "ALLOW", "hello")
    with pytest.raises(PermissionError):
        list(llm.chat_stream(llm.build_messages([], "hello + smuggled secret"), ticket))
    with pytest.raises(PermissionError):
        vault.issue_ticket("REQ-X", "BLOCK", "hello")


def test_every_decision_is_logged_with_detection_metadata():
    before = len(db.list_audit(limit=100000))
    run("hello there")
    _, dec = run("password: Hunter22!")
    assert len(db.list_audit(limit=100000)) == before + 2
    row = db.get_audit(dec["request_id"])
    det = row["detections"][0]
    assert det == {"type": "PASSWORD", "category": "CREDENTIALS", "severity": "CRITICAL", "confidence": det["confidence"],
                   "method": det["method"], "action": "redacted", "source": "prompt"}
    assert row["severity_counts"]["CRITICAL"] == 1


def test_audit_database_never_contains_raw_secrets(data_dir):
    secrets = ["AKIAZQ4N7RX2WK9TBM3P", "Sup3rS3cretValue!", "falcon-deal-terms-XYZ", "leak.me@inboxly.in", "491827364553"]
    run("AWS_ACCESS_KEY_ID=%s" % secrets[0])
    run("db password: %s" % secrets[1])
    run("CONFIDENTIAL %s for the board" % secrets[2])
    _, dec = run("send it to %s" % secrets[3])
    list(run_review_choice(ASHA, dec["request_id"], "send"))
    run("Aadhaar %s" % secrets[4])
    blob = b"".join(p.read_bytes() for p in Path(data_dir).glob("audit.db*"))
    for s in secrets:
        assert s.encode() not in blob, s
