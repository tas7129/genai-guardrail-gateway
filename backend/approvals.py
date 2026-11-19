"""Manager-approval workflow – a genuine authorization gate.

* `hold()` encrypts the screened request and stores it in the vault. Nothing is
  sent to the LLM.
* Only the requester's assigned manager can `review()` or `decide()`.
* Approve -> the gateway (not the browser) decrypts the held content and
  SCREENS IT AGAIN (sensitive-data detectors, harmful-use rules and the local
  safety model) – policies or models may have changed since it was held. Only
  if that re-check passes does it issue an APPROVED forward ticket, send it to
  the local LLM in the background, store the response encrypted for the
  requester and delete the held prompt. A failed re-check releases nothing.
* Reject -> the held content is deleted immediately.
"""
from __future__ import annotations

import threading
from typing import Optional

from . import config, db, llm, safety_guard
from .auth import USERS, AuthError
from .vault import decrypt_json, encrypt_json, issue_ticket

_decision_lock = threading.Lock()


class ApprovalError(Exception):
    status = 400


def hold(request_id: str, forward_text: str, conversation_id: str) -> None:
    db.vault_put(request_id, encrypt_json({"forward_text": forward_text, "conversation_id": conversation_id}))


def _load(request_id: str) -> dict:
    row = db.get_audit(request_id)
    if not row or row["decision"] != "MANAGER_APPROVAL":
        err = ApprovalError("approval request not found")
        err.status = 404
        raise err
    return row


def _check_manager(row: dict, manager: dict) -> None:
    if manager["id"] == row["user_id"]:
        raise AuthError("you cannot approve your own request")
    if manager["id"] != row["assigned_manager"]:
        raise AuthError("only the assigned manager (%s) can act on this request"
                        % USERS.get(row["assigned_manager"] or "", {}).get("name", "unknown"))


def review(request_id: str, manager: dict) -> dict:
    """Return the held content for the assigned manager to read before deciding."""
    row = _load(request_id)
    _check_manager(row, manager)
    held = db.vault_get(request_id)
    if row["approval_status"] != "pending" or not held or not held.get("payload_enc"):
        return {"request": row, "content": None, "note": "content is no longer held (request %s)" % row["approval_status"]}
    payload = decrypt_json(held["payload_enc"])
    db.add_event(manager["id"], "approval_reviewed", request_id, "held content viewed by assigned manager")
    return {"request": row, "content": payload["forward_text"], "note": "Decrypted for review. Personal identifiers remain redacted."}


def decide(request_id: str, manager: dict, action: str, note: str = "") -> dict:
    if action not in ("approve", "reject"):
        raise ApprovalError("action must be approve or reject")
    with _decision_lock:
        row = _load(request_id)
        _check_manager(row, manager)
        if row["approval_status"] != "pending":
            raise ApprovalError("request already %s" % row["approval_status"])
        note = (note or "").strip()[:500]
        if action == "reject":
            db.vault_update(request_id, payload_enc=None, status="rejected")
            db.update_audit(request_id, approval_status="rejected", approver=manager["id"],
                            approval_ts=db.now_iso(), approval_note=note, llm_status="not_forwarded")
            db.add_event(manager["id"], "approval_rejected", request_id, note)
            return {"request_id": request_id, "status": "rejected"}

        db.vault_update(request_id, status="approved")
        db.update_audit(request_id, approval_status="approved", approver=manager["id"],
                        approval_ts=db.now_iso(), approval_note=note, llm_status="forwarding")
        db.add_event(manager["id"], "approval_granted", request_id, note)
    threading.Thread(target=_forward_approved, args=(request_id,), daemon=True).start()
    return {"request_id": request_id, "status": "approved"}


def recheck(text: str) -> str:
    """Screen held content again just before release. Returns "" if it may go, else the reason."""
    from .scanner import classifier
    from .scanner import detectors as det
    found = det.detect(text, "approval-release")
    classifier.classify(found, {"approval-release": text})
    harmful = [f for f in found if f.category == det.HARMFUL_CONTENT]
    if harmful:
        return "harmful-use rules matched on release (%s)" % ", ".join(sorted({f.label for f in harmful}))
    secrets = [f for f in found if f.category == det.CREDENTIALS and f.level == "CRITICAL"]
    if secrets:
        return "an unredacted secret was found on release"
    v = safety_guard.classify(text)
    if v.blocking:
        return "local safety model: %s" % ", ".join(v.labels(v.blocking))
    if v.status == "error" and config.SAFETY_FAIL_MODE != "open":
        return "local safety model gave no verdict (%s) – failing closed" % v.error
    return ""


def _forward_approved(request_id: str) -> None:
    held = db.vault_get(request_id)
    if not held or not held.get("payload_enc"):
        return
    try:
        payload = decrypt_json(held["payload_enc"])
        text = payload["forward_text"]
    except Exception as exc:  # tampered or corrupted vault entry: release nothing
        db.vault_update(request_id, payload_enc=None, status="release_blocked",
                        response_enc=encrypt_json({"error": "Approved, but not sent: the held content failed its integrity check."}))
        db.update_audit(request_id, llm_status="blocked_on_release")
        db.add_event("gateway", "release_blocked", request_id, "vault integrity check failed (%s)" % exc.__class__.__name__)
        return
    reason = recheck(text)
    if reason:
        db.vault_update(request_id, payload_enc=None, status="release_blocked",
                        response_enc=encrypt_json({"error": "Approved, but not sent: the release re-check failed (%s)." % reason}))
        db.update_audit(request_id, llm_status="blocked_on_release")
        db.add_event("gateway", "release_blocked", request_id, reason)
        return
    ticket = issue_ticket(request_id, "APPROVED", text)
    try:
        response = llm.chat(llm.build_messages([], text), ticket)
        db.vault_update(request_id, payload_enc=None, response_enc=encrypt_json({"response": response}),
                        status="completed")
        db.update_audit(request_id, llm_forwarded=1, llm_status="ok")
    except llm.LLMUnavailable as exc:
        # keep the held payload so the requester can retry once the LLM is back
        db.vault_update(request_id, status="llm_error",
                        response_enc=encrypt_json({"error": str(exc)}))
        db.update_audit(request_id, llm_status="unreachable")


def retry(request_id: str, user: dict) -> dict:
    row = _load(request_id)
    if row["user_id"] != user["id"]:
        raise AuthError("only the requester can retry")
    held = db.vault_get(request_id)
    if not held or held["status"] != "llm_error":
        raise ApprovalError("nothing to retry")
    db.vault_update(request_id, status="approved", response_enc=None)
    threading.Thread(target=_forward_approved, args=(request_id,), daemon=True).start()
    return {"request_id": request_id, "status": "approved"}


def status_for_requester(request_id: str, user: dict) -> dict:
    row = db.get_audit(request_id)
    if not row:
        err = ApprovalError("request not found")
        err.status = 404
        raise err
    if row["user_id"] != user["id"] and user["role"] != "admin" and row.get("assigned_manager") != user["id"]:
        raise AuthError("not your request")
    held = db.vault_get(request_id) or {}
    out = {
        "request_id": request_id, "decision": row["decision"], "approval_status": row["approval_status"],
        "approver": USERS.get(row.get("approver") or "", {}).get("name"),
        "approval_note": row.get("approval_note"), "approval_ts": row.get("approval_ts"),
        "assigned_manager": USERS.get(row.get("assigned_manager") or "", {}).get("name"),
        "vault_status": held.get("status"), "response": None, "error": None,
    }
    # The response is only ever decrypted for the original requester.
    if row["user_id"] == user["id"] and held.get("response_enc"):
        data = decrypt_json(held["response_enc"])
        out["response"] = data.get("response")
        out["error"] = data.get("error")
    return out


def pending_count(manager_id: str) -> int:
    return len(db.list_audit(approval_status="pending", assigned_manager=manager_id, limit=1000))

