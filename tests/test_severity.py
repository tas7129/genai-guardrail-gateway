"""Severity-based censorship: positive and negative cases for every level,
context rules, censorship requirements and leak checks."""
import logging
import sqlite3

import pytest

from backend import auth, config, db
from backend.pipeline import run_guardrail
from backend.scanner import classifier
from backend.scanner import detectors as d
from backend.scanner.redactor import Redactor

ASHA = auth.USERS["asha"]


def classified(text, **kw):
    found = d.detect(text)
    classifier.classify(found, {"prompt": text}, policy=classifier.default_policy(), **kw)
    return found


def by_type(text):
    return {f.type: f for f in classified(text)}


def decision(text):
    events = list(run_guardrail(ASHA, text, []))
    return next(e for e in events if e["type"] == "decision")


# ── LEVEL 1 · CRITICAL ──────────────────────────────────────────────────────
@pytest.mark.parametrize("text,etype,placeholder", [
    ("my password is Pune@2026", "PASSWORD", "[PASSWORD REDACTED]"),
    ("api_key = 'zq81ksl02mdk38fj'", "API_KEY", "[API KEY REDACTED]"),
    ("Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123", "ACCESS_TOKEN", "[ACCESS TOKEN REDACTED]"),
    ("Your OTP is 482913", "OTP", "[OTP REDACTED]"),
    ("card cvv 731", "CARD_CVV_PIN", "[CVV/PIN REDACTED]"),
    ("my ATM pin is 4821", "CARD_CVV_PIN", "[CVV/PIN REDACTED]"),
    ("netbanking user id rkumar1988", "BANK_LOGIN", "[BANK LOGIN REDACTED]"),
    ("seed phrase: apple river stone cloud bright ocean tiger lemon paper quiet music forest", "SEED_PHRASE",
     "[WALLET SEED PHRASE REDACTED]"),
    ("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----", "PRIVATE_KEY",
     "[PRIVATE KEY REDACTED]"),
])
def test_critical_positive(text, etype, placeholder):
    f = by_type(text)[etype]
    assert f.level == "CRITICAL" and f.action == "redact"
    sanitized, _ = Redactor([f]).redact(text, [f])
    assert placeholder in sanitized and f.value not in sanitized


@pytest.mark.parametrize("text", [
    "The password must be at least 12 characters long.",
    "Explain how OTP-based login works.",
    "The token limit for this model is 4096.",
    "What is a PIN code for Pune?",
    "Rotate API keys every 90 days.",
])
def test_critical_negative(text):
    assert [f for f in classified(text) if f.level == "CRITICAL"] == []


def test_documented_example_credentials_are_low():
    f = by_type("AWS docs use AKIAIOSFODNN7EXAMPLE as the sample access key")["AWS_ACCESS_KEY"]
    assert f.level == "LOW" and f.action == "allow" and "placeholder" in f.note
    f = by_type("set api_key = YOUR_API_KEY_HERE_123 in the config")["API_KEY"]
    assert f.level == "LOW"


def test_critical_blocked_when_safe_redaction_impossible():
    text = "APP_ENV=prod\nDB_HOST=10.0.0.5\nDB_PASSWORD=Hunter22!x"
    f = by_type(text)["PASSWORD"]
    assert f.action == "block" and "config file" in f.note
    many = "pwd: Aa1!aa22 token=Zq81ksl02mdk38fj otp 482913 cvv 731"
    assert all(x.action == "block" for x in classified(many) if x.level == "CRITICAL")


def test_critical_from_ocr_is_blocked():
    text = "AWS_ACCESS_KEY_ID=AKIAQ3N7RZ5WMB2K4TQX"
    found = d.detect(text, source="shot.png")
    classifier.classify(found, {"shot.png": text}, ocr_sources={"shot.png"}, policy=classifier.default_policy())
    assert found[0].action == "block" and found[0].method.startswith("OCR")


# ── LEVEL 2 · HIGH ──────────────────────────────────────────────────────────
@pytest.mark.parametrize("text,etype", [
    ("Aadhaar 4918 2736 4553", "AADHAAR"),
    ("PAN BXPPK4821L", "PAN"),
    ("passport no: K4821937", "PASSPORT"),
    ("account number 50100234567812", "BANK_ACCOUNT"),
    ("card 4539 1488 0343 6467", "CREDIT_CARD"),
    ("I was diagnosed with type 2 diabetes", "MEDICAL_DIAGNOSIS"),
    ("she is pregnant", "REPRODUCTIVE_HEALTH"),
    ("my 9 year old son Aarav", "CHILD_NAME"),
    ("lat: 12.9716, long: 77.5946", "GPS_COORDINATES"),
    ("FIR No: 245/2026", "CASE_NUMBER"),
    ("ssh into 10.0.3.12", "INTERNAL_IP"),
])
def test_high_positive(text, etype):
    f = by_type(text)[etype]
    assert f.level == "HIGH" and f.action == "redact"


@pytest.mark.parametrize("text", [
    "What are the common symptoms of diabetes?",
    "What is a PAN card used for?",
    "Explain the visa application process for Germany.",
    "My home router is 192.168.1.1, how do I reset it?",
    "How do I open a bank account online?",
])
def test_high_negative(text):
    assert [f for f in classified(text) if f.level in ("HIGH", "CRITICAL")] == []


def test_high_is_censored_and_context_preserved():
    dec = decision("My Aadhaar is 4918 2736 4553 and I was diagnosed with asthma. Which insurance covers inhalers?")
    assert dec["decision"]["action"] == "REDACT_AND_ALLOW"
    assert dec["sanitized_prompt"] == ("My Aadhaar is [AADHAAR NUMBER REDACTED] and I was diagnosed with "
                                       "[MEDICAL INFORMATION REDACTED]. Which insurance covers inhalers?")


def test_children_context_raises_personal_data_to_high():
    f = by_type("My daughter is 8 years old and her school is at 14 Park Street Kolkata")["ADDRESS"]
    assert f.level == "HIGH" and f.category == d.CHILDREN_DATA and f.placeholder_prefix == "CHILD ADDRESS"


def test_live_location_address_is_high():
    f = by_type("I am currently at 113 4th cross ig nagar, come pick me up")["ADDRESS"]
    assert f.level == "HIGH" and f.category == d.LOCATION_DATA


# ── LEVEL 3 · MEDIUM ────────────────────────────────────────────────────────
@pytest.mark.parametrize("text,etype", [
    ("email me at rohan.k@gmail.com", "EMAIL"),
    ("call me on +91 98452 17630", "PHONE"),
    ("my client lives at 22 MG Road, Bengaluru", "ADDRESS"),
    ("DOB: 14/07/1991", "DATE_OF_BIRTH"),
    ("Employee ID: E10234", "EMPLOYEE_ID"),
    ("pay me at rohan.k@okaxis", "UPI_ID"),
    ("salary: 18,00,000", "SALARY"),
    ("He is a devout Muslim", "RELIGION"),
    ("[12/03/24, 10:15 PM] Priya: hi\n[12/03/24, 10:16 PM] Rahul: ok", "CHAT_PARTICIPANT"),
])
def test_medium_positive(text, etype):
    f = by_type(text)[etype]
    assert f.level == "MEDIUM" and f.action == "review"


def test_medium_strict_mode_redacts():
    policy = classifier.default_policy()
    policy["strict_mode"] = True
    found = d.detect("email me at rohan.k@gmail.com")
    classifier.classify(found, {"prompt": "email me at rohan.k@gmail.com"}, policy=policy)
    assert found[0].action == "redact"


@pytest.mark.parametrize("text", [
    "Contact support@nimbus.in for help",
    "Call our toll-free number 1800-425-1234",
    "Our office is located at 22 MG Road, Bengaluru",
    "Write a short history of Buddhism in India",
    "What is the caste system?",
])
def test_medium_negative(text):
    assert [f for f in classified(text) if f.level in ("MEDIUM", "HIGH", "CRITICAL")] == []


# ── LEVEL 4 · LOW ───────────────────────────────────────────────────────────
def test_low_items_are_noted_but_not_censored():
    dec = decision("Send the invoice to billing@example.com, the docs example address")
    assert dec["decision"]["action"] == "ALLOW"
    assert dec["low_notes"] == 1
    assert dec["findings"][0]["severity"] == "LOW" and dec["findings"][0]["action_taken"] == "not censored (low risk)"


def test_example_label_does_not_override_validation():
    # labelled as an example AND fails the Verhoeff checksum → LOW
    assert by_type("e.g. an Aadhaar like 4567 8912 3456")["AADHAAR"].level == "LOW"
    # labelled as an example but passes validation → still treated as real
    f = by_type("for example my Aadhaar 4918 2736 4553")["AADHAAR"]
    assert f.level == "HIGH" and "treated as real" in f.note


def test_name_alone_is_not_sensitive():
    assert classified("Can you summarise what Rohan Verma said in the meeting?") == []


# ── Censorship requirements ─────────────────────────────────────────────────
def test_multiple_and_repeated_values_are_consistent():
    text = "a.k@gmail.com, b.k@gmail.com and again a.k@gmail.com; PAN BXPPK4821L"
    found = classified(text)
    out, _ = Redactor(found).redact(text, found, lambda f: True)
    assert out == "[EMAIL 1 REDACTED], [EMAIL 2 REDACTED] and again [EMAIL 1 REDACTED]; PAN [PAN REDACTED]"


def test_overlapping_detections_never_leave_fragments():
    text = "Use postgres://svc:Hunter22x@db01.nimbus.internal:5432/app please"
    found = classified(text)
    out, _ = Redactor(found).redact(text, found, lambda f: True)
    assert out == "Use [DATABASE CREDENTIALS REDACTED] please"
    for frag in ("Hunter22x", "db01", "nimbus.internal", "5432"):
        assert frag not in out


def test_screening_output_has_required_fields_and_never_full_values():
    dec = decision("My Aadhaar is 4918 2736 4553, email rohan.k@gmail.com, password: Pune@2026x")
    for f in dec["findings"]:
        for key in ("category", "type", "severity", "confidence", "method", "action_taken", "masked"):
            assert key in f
        assert f["masked"] not in ("491827364553", "4918 2736 4553", "rohan.k@gmail.com", "Pune@2026x")
    assert dec["severity_counts"]["HIGH"] == 1 and dec["severity_counts"]["MEDIUM"] == 1


def test_no_sensitive_values_in_logs(caplog):
    secrets = ["Pune@2026x", "4918 2736 4553", "rohan.k@gmail.com", "zq81ksl02mdk38fj"]
    with caplog.at_level(logging.DEBUG):
        decision("password: %s, Aadhaar %s, email %s, api_key=%s" % tuple(secrets))
        decision("APP_ENV=x\nDB_PASSWORD=%s\nAPI_KEY=%s" % (secrets[0], secrets[3]))
    for s in secrets:
        assert s not in caplog.text


def test_existing_database_is_migrated(tmp_path, monkeypatch):
    old = tmp_path / "old.db"
    conn = sqlite3.connect(str(old))
    conn.execute("CREATE TABLE audit_log (request_id TEXT PRIMARY KEY, ts TEXT NOT NULL, user_id TEXT, user_name TEXT, "
                 "role TEXT, team TEXT, conversation_id TEXT, decision TEXT, risk_level TEXT, risk_score INTEGER, "
                 "categories TEXT, finding_types TEXT, clause_refs TEXT, approval_status TEXT, assigned_manager TEXT, "
                 "approver TEXT, approval_ts TEXT, approval_note TEXT, safe_prompt TEXT, prompt_chars INTEGER, "
                 "attachments TEXT, llm_forwarded INTEGER DEFAULT 0, llm_status TEXT, llm_model TEXT, explanation TEXT, "
                 "screening_ms INTEGER)")  # the v1 schema
    conn.commit()
    conn.close()
    monkeypatch.setattr(config, "DB_PATH", old)
    db.init_db()
    cols = {r[1] for r in sqlite3.connect(str(old)).execute("PRAGMA table_info(audit_log)")}
    assert {"severity_counts", "detections", "max_severity", "user_review"} <= cols
