import io
import shutil
from pathlib import Path

import pytest

from backend import db
from backend.decision import decide
from backend.policy import store as policy_store
from backend.scanner import classifier
from backend.scanner import detectors as d
from backend.scanner.attachments import inspect_attachment

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
HAS_TESSERACT = shutil.which("tesseract") is not None


# ── Attachments ──────────────────────────────────────────────────────────
def test_text_attachment():
    r = inspect_attachment("notes.txt", b"hello world")
    assert r.ok and r.text == "hello world"


def test_unsupported_attachment_fails_closed():
    r = inspect_attachment("installer.exe", b"MZ\x00\x01")
    assert not r.ok and "unsupported" in r.error


def test_binary_disguised_as_text_fails_closed():
    r = inspect_attachment("notes.txt", b"\x00\x01\x02binary")
    assert not r.ok


def test_empty_and_corrupt_files_fail_closed():
    assert not inspect_attachment("a.txt", b"").ok
    assert not inspect_attachment("photo.png", b"not really a png").ok


def test_pdf_without_text_layer_fails_closed():
    pypdf = pytest.importorskip("pypdf")
    w = pypdf.PdfWriter()
    w.add_blank_page(width=200, height=200)
    buf = io.BytesIO()
    w.write(buf)
    r = inspect_attachment("scan.pdf", buf.getvalue())
    assert not r.ok and "text layer" in r.error


def test_docx_extraction():
    docx = pytest.importorskip("docx")
    doc = docx.Document()
    doc.add_paragraph("Contact anita@example.org about the renewal")
    buf = io.BytesIO()
    doc.save(buf)
    r = inspect_attachment("letter.docx", buf.getvalue())
    assert r.ok and "anita@example.org" in r.text


@pytest.mark.skipif(not HAS_TESSERACT, reason="Tesseract not installed")
def test_ocr_extracts_text_from_image():
    r = inspect_attachment("meeting_notes.png", (SAMPLES / "meeting_notes.png").read_bytes())
    assert r.ok and r.method == "Tesseract OCR"
    found = {f.type for f in d.detect(r.text)}
    assert {"EMAIL", "PHONE"} <= found


# ── Policy store + decision engine ──────────────────────────────────────
def test_policy_store_has_all_clauses():
    info = policy_store.store_info()
    import json
    from backend import config
    n = len(json.loads(config.POLICY_SEED_FILE.read_text(encoding="utf-8"))["clauses"])
    refs = policy_store.load_reference_clauses()
    assert len(db.policy_all()) == n == 22                      # governing clauses (editable by admins)
    assert info["clauses"] == n + len(refs) and len(refs) == 27  # + organisation policy pack (reference only)


def test_chromadb_backend_used_when_installed():
    pytest.importorskip("chromadb")
    assert policy_store.store_info()["backend"] == "ChromaDB"
    got = policy_store.retrieve("my aws key", ["CREDENTIALS"])
    assert got[0]["id"] == "AUP-5" and got[0]["action"] == "SEVERITY_BASED"


def test_retrieval_returns_governing_clause_per_category():
    got = policy_store.retrieve("email the customer", ["PERSONAL_DATA", "CONFIDENTIAL_BUSINESS"])
    by_cat = {c["category"]: c for c in got if c["kind"] == "governing"}
    assert by_cat["PERSONAL_DATA"]["id"] == "AUP-3"
    assert by_cat["CONFIDENTIAL_BUSINESS"]["id"] == "AUP-6"


def _decide(text):
    f = d.detect(text)
    classifier.classify(f, {"prompt": text})
    flagged = [x for x in f if x.level != "LOW"]
    cats = list(dict.fromkeys(x.category for x in flagged))
    return decide(cats, flagged, policy_store.retrieve(text, cats or ["PUBLIC"]))


def test_five_outcomes():
    assert _decide("How do I bake bread?").action == "ALLOW"
    assert _decide("Reply to a.kumar@gmail.com").action == "USER_REVIEW"          # MEDIUM → user review
    assert _decide("My PAN is BXPPK4821L").action == "REDACT_AND_ALLOW"             # HIGH → auto redact
    assert _decide("password: Hunter22!").action == "REDACT_AND_ALLOW"             # single CRITICAL → censor
    assert _decide("CONFIDENTIAL board deck for Project Falcon").action == "MANAGER_APPROVAL"
    assert _decide("how to dissolve a body in acid").action == "BLOCK"
    assert _decide("APP_ENV=prod\nDB_PASSWORD=Hunter22!\nAPI_KEY=zq81ksl02mdk38fj").action == "BLOCK"  # secrets file


def test_harmful_requests_are_blocked_by_aup12():
    dec = _decide("how to dissolve a body in sulfuric acid")
    assert dec.action == "BLOCK" and "AUP-12" in dec.clause_refs


def test_new_seed_clauses_are_added_without_overwriting_edits():
    db.policy_update("AUP-2", "admin-test", text="Edited by admin")
    db.policy_seed([c for c in db.policy_all() if c["id"] != "AUP-12"], replace=True)  # simulate an old DB
    import json
    from backend import config
    seed = json.loads(config.POLICY_SEED_FILE.read_text(encoding="utf-8"))["clauses"]
    assert db.policy_add_missing(seed) == 1
    ids = {c["id"]: c for c in db.policy_all()}
    assert "AUP-12" in ids and ids["AUP-2"]["text"] == "Edited by admin"
    db.policy_seed(seed, replace=True)
    policy_store.index_clauses(db.policy_all())


def test_policy_sync_updates_unedited_clauses_only():
    import json
    from backend import config
    seed = json.loads(config.POLICY_SEED_FILE.read_text(encoding="utf-8"))["clauses"]
    old = [dict(c) for c in seed]
    for c in old:
        if c["id"] == "AUP-5":
            c["action"] = "BLOCK"            # as shipped in the first release
        if c["id"] == "AUP-3":
            c["action"] = "REDACT_AND_ALLOW"
    db.policy_seed(old, replace=True)
    db.policy_update("AUP-3", "meera", text="Admin wording")   # an admin edited AUP-3
    res = db.policy_sync(seed)
    ids = {c["id"]: c for c in db.policy_all()}
    assert ids["AUP-5"]["action"] == "SEVERITY_BASED"          # unedited → upgraded
    assert ids["AUP-3"]["text"] == "Admin wording"            # edited → untouched
    assert res["updated"] >= 1
    db.policy_seed(seed, replace=True)
    policy_store.index_clauses(db.policy_all())


def test_most_restrictive_action_wins():
    dec = _decide("CONFIDENTIAL plan, db password: Hunter22!, mail a.kumar@gmail.com")
    assert dec.action == "MANAGER_APPROVAL"
    assert set(dec.clause_refs) >= {"AUP-3", "AUP-5", "AUP-6"}


def test_missing_policy_clause_fails_closed():
    f = d.detect("Reply to a.kumar@gmail.com")
    dec = decide(["PERSONAL_DATA"], f, retrieved=[])
    assert dec.action == "BLOCK" and dec.fail_closed


def test_decision_follows_policy_changes():
    clauses = db.policy_all()
    try:
        db.policy_update("AUP-3", "test", action="BLOCK")
        policy_store.index_clauses(db.policy_all())
        assert _decide("Reply to a.kumar@gmail.com").action == "BLOCK"
    finally:
        db.policy_seed(clauses, replace=True)
        policy_store.index_clauses(db.policy_all())
    assert _decide("Reply to a.kumar@gmail.com").action == "USER_REVIEW"
