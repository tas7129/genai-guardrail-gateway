"""The Guardrail Agent.

`run_guardrail()` is a generator that performs the screening steps and
yields an event after each real step completes. The web layer streams these
events to the browser as NDJSON, so the screening panel the user sees is a
live trace of backend work – not an animation.

    1 prompt      Prompt inspection (normalisation, hidden-character removal)
    2 detect      Sensitive information detection in the prompt
    3 attachments Attachment inspection + text extraction (fail closed)
    4 ocr         OCR of images (Tesseract) + detection on extracted text
    5 safety      Content-safety check: built-in harmful-use rules + local safety model
                  (Llama Guard via Ollama) on exactly the text that could be forwarded
    6 policy      Policy retrieval from ChromaDB (category + semantic)
    7 risk        Risk assessment (decision engine)
    8 decision    Final decision: forward / redact / ask the user / block / hold for approval

The UI groups these into five checks (GROUPS): Sensitive Information Detection,
Attachment and OCR Inspection, Content Safety Check, Policy Retrieval and Final
Security Decision.

Only after the final decision – and only for ALLOW / REDACT_AND_ALLOW – does content go to
the local LLM, with a signed forward ticket. USER_REVIEW holds the request
(encrypted) until the user chooses "Redact & send", "Send anyway" or "Cancel"
(`run_review_choice`).
"""
from __future__ import annotations

import secrets
import time
from collections import Counter
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional

from . import approvals, config, db, llm, safety_guard
from .decision import DECISION_LABELS, action_taken, decide
from .policy import store as policy_store
from .scanner import classifier
from .scanner import detectors as det
from .scanner.attachments import inspect_attachment
from .scanner.redactor import Redactor, highlight_segments
from .vault import decrypt_json, encrypt_json, issue_ticket

GROUPS = [
    {"id": "sensitive", "title": "Sensitive Information Detection"},
    {"id": "attachments", "title": "Attachment and OCR Inspection"},
    {"id": "safety", "title": "Content Safety Check"},
    {"id": "policy", "title": "Policy Retrieval"},
    {"id": "decision", "title": "Final Security Decision"},
]
STEPS = [
    {"id": "prompt", "title": "Prompt inspection", "group": "sensitive"},
    {"id": "detect", "title": "Sensitive information detection", "group": "sensitive"},
    {"id": "attachments", "title": "Attachment inspection", "group": "attachments"},
    {"id": "ocr", "title": "OCR processing", "group": "attachments"},
    {"id": "safety", "title": "Content safety classification", "group": "safety"},
    {"id": "policy", "title": "Policy retrieval (vector store)", "group": "policy"},
    {"id": "risk", "title": "Risk assessment", "group": "decision"},
    {"id": "decision", "title": "Final security decision", "group": "decision"},
]
SUPPORT_MESSAGE = ("If you are going through a difficult time, you are not alone: please talk to someone you trust, the "
                   "Employee Assistance Programme, or Tele-MANAS on 14416 (India, free, 24×7).")

# Detected category -> procedural clauses that explain how the action is carried out
TOKEN_CATEGORIES = {det.PERSONAL_DATA, det.FINANCIAL_DATA, det.CREDENTIALS, det.MEDICAL_DATA, det.LEGAL_GOVERNMENT,
                    det.LOCATION_DATA, det.PRIVATE_COMMUNICATIONS, det.SENSITIVE_ATTRIBUTES, det.CHILDREN_DATA,
                    det.SECURITY_TECHNICAL}
PROCEDURAL = {c: ["SEVERITY", "REDACTION"] for c in TOKEN_CATEGORIES}
PROCEDURAL.update({det.BULK_PERSONAL_DATA: ["APPROVAL"], det.CONFIDENTIAL_BUSINESS: ["APPROVAL"], det.SOURCE_CODE: ["APPROVAL"]})
REVIEW_TTL_S = 30 * 60
OUTCOME = {"ALLOW": "allowed", "REDACT_AND_ALLOW": "modified", "USER_REVIEW": "awaiting your review",
           "MANAGER_APPROVAL": "held for manager approval", "BLOCK": "blocked"}


class ReviewError(Exception):
    status = 400


@dataclass
class UploadedFile:
    name: str
    data: bytes


def new_request_id() -> str:
    return "REQ-" + secrets.token_hex(3).upper()


def _ms(t0: float) -> int:
    return int(round((time.perf_counter() - t0) * 1000))


def _running(step: str) -> dict:
    return {"type": "step", "id": step, "status": "running"}


def _done(step: str, status: str, summary: str, ms: int, data: Optional[dict] = None) -> dict:
    return {"type": "step", "id": step, "status": status, "summary": summary, "ms": ms, "data": data or {}}


def _summarise(findings: List[det.Finding]) -> str:
    c = Counter(f.label for f in findings)
    return ", ".join("%s ×%d" % (k, v) if v > 1 else k for k, v in c.most_common())


def run_guardrail(user: dict, prompt: str, files: List[UploadedFile],
                  conversation_id: Optional[str] = None) -> Iterator[dict]:
    t_start = time.perf_counter()
    request_id = new_request_id()
    if conversation_id and db.conversation_owner(conversation_id) not in (None, user["id"]):
        conversation_id = None  # never attach to someone else's conversation
    conv_id = conversation_id or "C-" + secrets.token_hex(4).upper()
    yield {"type": "start", "request_id": request_id, "conversation_id": conv_id, "steps": STEPS, "groups": GROUPS}

    # 1 ── Prompt inspection ───────────────────────────────────────────────
    yield _running("prompt")
    t = time.perf_counter()
    text, hidden = det.normalize_text(prompt)
    lines = text.count("\n") + 1 if text else 0
    summary = "%d characters, %d line%s" % (len(text), lines, "" if lines == 1 else "s")
    if hidden:
        summary += " · removed %d hidden character%s" % (hidden, "" if hidden == 1 else "s")
    if files:
        summary += " · %d attachment%s" % (len(files), "" if len(files) == 1 else "s")
    yield _done("prompt", "warn" if hidden else "done", summary, _ms(t),
                {"chars": len(text), "hidden_removed": hidden, "attachments": len(files)})

    # 2 ── Sensitive information detection (prompt) ───────────────────────
    yield _running("detect")
    t = time.perf_counter()
    prompt_findings = det.detect(text, "prompt")
    yield _done(
        "detect", "warn" if prompt_findings else "done",
        ("%d instance%s: %s" % (len(prompt_findings), "" if len(prompt_findings) == 1 else "s",
                                _summarise(prompt_findings))) if prompt_findings else "No sensitive data in prompt text",
        _ms(t),
        {"findings": [f.public() for f in prompt_findings],
         "highlights": highlight_segments(text, prompt_findings)},
    )

    # 3 ── Attachment inspection (documents / text / code) ────────────────
    att_results = []
    att_findings: List[det.Finding] = []
    att_texts: Dict[str, str] = {}
    ocr_sources: set = set()
    images = [f for f in files if _is_image(f.name)]
    documents = [f for f in files if not _is_image(f.name)]

    def _inspect(group: List[UploadedFile]):
        out = []
        for up in group:
            res = inspect_attachment(up.name, up.data)
            found: List[det.Finding] = []
            if res.ok:
                found = det.detect(res.text, source=res.name, is_code_file=res.is_code)
                att_texts[res.name] = res.text
                if res.kind == "image":
                    ocr_sources.add(res.name)
            else:
                found = [det.Finding("ATTACHMENT_ERROR", source=res.name, detail=res.error, method="attachment inspection",
                                     confidence=1.0)]
            att_findings.extend(found)
            info = res.public()
            info["findings"] = [f.public() for f in found]
            if res.ok:
                info["preview"] = highlight_segments(res.text, found, max_chars=1500)
            out.append(info)
        return out

    yield _running("attachments")
    t = time.perf_counter()
    if not files:
        yield _done("attachments", "skipped", "No attachments", _ms(t))
    elif not documents:
        yield _done("attachments", "done",
                    "%d image%s – routed to OCR" % (len(images), "" if len(images) == 1 else "s"), _ms(t),
                    {"attachments": [{"name": i.name, "kind": "image", "size": len(i.data), "ok": True,
                                      "routed": "ocr"} for i in images]})
    else:
        infos = _inspect(documents)
        att_results += infos
        failed = [i for i in infos if not i["ok"]]
        n_find = sum(len([f for f in i["findings"] if f["type"] != "ATTACHMENT_ERROR"]) for i in infos)
        summary = "%d file%s inspected" % (len(infos), "" if len(infos) == 1 else "s")
        if n_find:
            summary += " · %d finding%s" % (n_find, "" if n_find == 1 else "s")
        if failed:
            summary += " · %d could not be scanned (fail closed)" % len(failed)
        yield _done("attachments", "fail" if failed else ("warn" if n_find else "done"), summary, _ms(t),
                    {"attachments": infos})

    # 4 ── OCR ───────────────────────────────────────────────────────────────
    yield _running("ocr")
    t = time.perf_counter()
    if not images:
        yield _done("ocr", "skipped", "No images attached", _ms(t))
    else:
        infos = _inspect(images)
        att_results += infos
        failed = [i for i in infos if not i["ok"]]
        words = sum(i.get("ocr_words") or 0 for i in infos)
        n_find = sum(len([f for f in i["findings"] if f["type"] != "ATTACHMENT_ERROR"]) for i in infos)
        summary = "%d word%s extracted from %d image%s" % (words, "" if words == 1 else "s", len(infos),
                                                         "" if len(infos) == 1 else "s")
        if n_find:
            summary += " · %d finding%s" % (n_find, "" if n_find == 1 else "s")
        if failed:
            summary += " · %d failed (fail closed)" % len(failed)
        yield _done("ocr", "fail" if failed else ("warn" if n_find else "done"), summary, _ms(t),
                    {"attachments": infos})

    all_findings = prompt_findings + att_findings
    texts = dict(att_texts)
    texts["prompt"] = text
    sev_policy = classifier.get_policy()
    context = classifier.classify(all_findings, texts, ocr_sources=ocr_sources, policy=sev_policy)
    bulk = det.bulk_personal_finding(all_findings)
    if bulk:
        bulk.action = "request"
        all_findings.append(bulk)
    # LOW findings are noted but are not policy violations
    flagged = [f for f in all_findings if f.level != "LOW" or f.scope == "request"]
    low_notes = [f for f in all_findings if f not in flagged]
    categories = list(dict.fromkeys(f.category for f in flagged))

    # Text that could reach the assistant (built now so the safety model sees exactly that)
    redactor = Redactor(all_findings)
    strict = lambda f: f.action in ("redact", "review", "block")  # noqa: E731 – everything that is not LOW
    warn_only = lambda f: f.action in ("redact", "block")          # noqa: E731 – keeps MEDIUM items (user's choice)
    sanitized_prompt, replacements = redactor.redact(text, prompt_findings, strict)
    forward_strict, forward_warn = sanitized_prompt, redactor.redact(text, prompt_findings, warn_only)[0]
    for name, att_text in att_texts.items():
        f_for = [f for f in att_findings if f.source == name]
        clean, reps = redactor.redact(att_text, f_for, strict)
        clean_warn = redactor.redact(att_text, f_for, warn_only)[0]
        replacements += reps
        if clean.strip():
            forward_strict += "\n\n--- Attachment: %s (screened text) ---\n%s" % (name, clean[: config.MAX_ATTACHMENT_CHARS_FORWARDED])
            forward_warn += "\n\n--- Attachment: %s (screened text) ---\n%s" % (name, clean_warn[: config.MAX_ATTACHMENT_CHARS_FORWARDED])

    # 5 ── Content safety (built-in rules + local safety model) ─────────────
    yield _running("safety")
    t = time.perf_counter()
    rule_hits = [f for f in all_findings if f.category == det.HARMFUL_CONTENT]
    history = db.get_messages(conv_id, limit=6) if conversation_id else []
    # forward_warn is the superset of what any path (incl. "Send anyway") could forward
    verdict = safety_guard.classify(forward_warn, history) if forward_warn.strip() else \
        safety_guard.GuardVerdict(status="safe", model=config.SAFETY_MODEL)
    safety_findings = guard_findings(verdict)
    all_findings += safety_findings
    flagged += [f for f in safety_findings if f.level != "LOW"]
    low_notes += [f for f in safety_findings if f.level == "LOW"]
    categories = list(dict.fromkeys(f.category for f in flagged))
    support = any(f.type == "SELF_HARM" for f in all_findings) or any(
        safety_guard.safety_policy()["categories"].get(c, {}).get("support") for c in verdict.categories)
    blocked_by_model = bool(verdict.blocking)
    if verdict.status == "disabled":
        s_status, s_summary = "warn", "Safety model disabled (SAFETY_MODEL=off) – built-in rules only"
    elif verdict.status == "error":
        s_status = "fail" if config.SAFETY_FAIL_MODE != "open" else "warn"
        s_summary = "Safety model gave no verdict: %s – %s" % (
            verdict.error, "failing closed" if s_status == "fail" else "fail-open configured (not recommended)")
    elif blocked_by_model or rule_hits:
        s_status = "fail"
        s_summary = "Unsafe: %s" % ", ".join(verdict.labels(verdict.blocking) + [f.label for f in rule_hits])
    elif verdict.advisory:
        s_status, s_summary = "warn", "Advisory: %s (not blocking)" % ", ".join(verdict.labels(verdict.advisory))
    else:
        s_status, s_summary = "done", "Safe · %s · %d ms" % (verdict.model, verdict.ms)
    yield _done("safety", s_status, s_summary, _ms(t),
                {"verdict": verdict.public(), "rule_hits": [f.public() for f in rule_hits],
                 "context_turns": len(history)})

    # 5 ── Policy retrieval ────────────────────────────────────────────────
    yield _running("policy")
    t = time.perf_counter()
    # The retrieval query never contains raw identifiers or secrets.
    query_text, _ = Redactor(all_findings).redact(text, prompt_findings, lambda f: True)
    extra = [p for c in categories for p in PROCEDURAL.get(c, [])]
    retrieved = policy_store.retrieve(query_text, categories or ["PUBLIC"], k=3, extra_categories=extra)
    info = policy_store.store_info()
    yield _done("policy", "done",
                "%d clause%s retrieved from %s" % (len(retrieved), "" if len(retrieved) == 1 else "s",
                                                    info["backend"]),
                _ms(t),
                {"backend": info["backend"], "note": info["note"],
                 "clauses": [_clause_public(c) for c in retrieved]})

    # 6 ── Risk assessment (severity classification + decision engine) ─────
    yield _running("risk")
    t = time.perf_counter()
    decision = decide(categories, flagged, retrieved, sev_policy.get("document_level_action", "MANAGER_APPROVAL"))
    if support:
        decision.remediation.insert(0, SUPPORT_MESSAGE)
    if context["unsafe_redaction"] and decision.action == "BLOCK":
        why = {"ocr": "a secret was read from an image by OCR, where fragments could survive redaction",
               "secrets_file": "the text looks like a secrets/config file, so neighbouring values may also be secrets",
               "too_many_secrets": "the request contains many separate secrets"}
        decision.explanation += " Safe redaction is not possible because " + "; ".join(
            why[u] for u in context["unsafe_redaction"]) + "."
    approver = None
    if decision.action == "MANAGER_APPROVAL":
        from .auth import USERS
        approver = USERS.get(user.get("manager") or "")
        if approver is None:
            decision.action = "BLOCK"
            decision.risk_level = "CRITICAL"
            decision.explanation += " No approving manager is configured for your account, so the request is blocked."
    sev_counts = classifier.severity_counts(all_findings)
    sev_text = " · ".join("%d %s" % (n, lvl) for lvl, n in sev_counts.items() if n)
    yield _done("risk", {"LOW": "done", "MEDIUM": "warn", "HIGH": "warn", "CRITICAL": "fail"}[decision.risk_level],
                "Risk %s (%d/100) · %s" % (decision.risk_level, decision.risk_score, sev_text or "no violations"),
                _ms(t), {"governing": decision.governing, "risk_level": decision.risk_level,
                         "risk_score": decision.risk_score, "severity_counts": sev_counts,
                         "strict_mode": context["strict_mode"], "child_context": context["child_context"]})

    # 7 ── Final decision ──────────────────────────────────────────────────
    yield _running("decision")
    t = time.perf_counter()
    action = decision.action
    for f in all_findings:
        f.action_taken = action_taken(f, action)

    withhold = any(f.scope == "document" for f in flagged) or bool(bulk)
    if action == "ALLOW":
        safe_prompt = text[:2000]
    elif action == "MANAGER_APPROVAL" or withhold:
        safe_prompt = "[content withheld from audit log · %d chars · %s%s]" % (
            len(text), ", ".join(categories),
            " · held encrypted in approval vault" if action == "MANAGER_APPROVAL" else "")
    else:  # REDACT / USER_REVIEW / BLOCK: every non-LOW value is replaced
        safe_prompt = sanitized_prompt[:2000]

    approval_status = None
    review = None
    if action == "MANAGER_APPROVAL":
        approval_status = "pending"
        approvals.hold(request_id, forward_strict, conv_id)
    elif action == "USER_REVIEW":
        warn_has_redactions = any(f.action == "redact" and f.redactable for f in all_findings)
        db.vault_put(request_id, encrypt_json({"kind": "review", "strict": forward_strict, "warn": forward_warn,
                                               "warn_has_redactions": warn_has_redactions,
                                               "conversation_id": conv_id, "created": time.time()}),
                     status="review_pending")
        review_items = [f for f in all_findings if f.action == "review"]
        review = {"status": "pending", "ttl_minutes": REVIEW_TTL_S // 60,
                  "items": [f.public() for f in review_items],
                  "auto_redacted": len([f for f in all_findings if f.action == "redact" and f.redactable]),
                  "strict_preview": sanitized_prompt}

    title = sanitized_prompt.strip().split("\n")[0][:60] if action in ("ALLOW", "REDACT_AND_ALLOW", "USER_REVIEW") else \
        "%s · %s" % ({"BLOCK": "Blocked", "MANAGER_APPROVAL": "Held for approval"}[action],
                     det.CATEGORY_LABELS.get(categories[0], "request") if categories else "request")
    db.upsert_conversation(conv_id, user["id"], title or "Attachment request")
    screening_ms = _ms(t_start)
    db.insert_audit({
        "request_id": request_id, "ts": db.now_iso(), "user_id": user["id"], "user_name": user["name"],
        "role": user["role"], "team": user["team"], "conversation_id": conv_id,
        "decision": action, "risk_level": decision.risk_level, "risk_score": decision.risk_score,
        "categories": categories, "finding_types": dict(Counter(f.type for f in flagged)),
        "clause_refs": decision.clause_refs, "approval_status": approval_status,
        "assigned_manager": approver["id"] if approver else None,
        "safe_prompt": safe_prompt, "prompt_chars": len(text),
        "attachments": [{"name": a["name"], "kind": a.get("kind"), "ok": a["ok"], "error": a.get("error", "")}
                        for a in att_results],
        "llm_forwarded": 0, "llm_status": "pending" if action in ("ALLOW", "REDACT_AND_ALLOW") else "not_forwarded",
        "llm_model": config.OLLAMA_MODEL, "explanation": decision.explanation, "screening_ms": screening_ms,
        "severity_counts": sev_counts, "detections": [f.audit() for f in all_findings],
        "max_severity": decision.risk_level, "user_review": "pending" if action == "USER_REVIEW" else None,
        "safety": {"status": verdict.status, "model": verdict.model, "categories": verdict.categories,
                   "blocking": verdict.blocking, "ms": verdict.ms, "error": verdict.error,
                   "fail_mode": config.SAFETY_FAIL_MODE,
                   "rule_hits": [f.type for f in rule_hits]},
    })
    yield _done("decision", {"ALLOW": "done", "REDACT_AND_ALLOW": "warn", "USER_REVIEW": "warn",
                             "MANAGER_APPROVAL": "hold", "BLOCK": "fail"}[action], DECISION_LABELS[action], _ms(t))

    yield {
        "type": "decision",
        "request_id": request_id,
        "decision": decision.public(),
        "outcome": OUTCOME[action],
        "categories": [{"id": c, "label": det.CATEGORY_LABELS.get(c, c)} for c in categories],
        "findings": [f.public() for f in all_findings],
        "severity_counts": sev_counts,
        "low_notes": len(low_notes),
        "context": context,
        "replacements": replacements,
        "sanitized_prompt": sanitized_prompt if action in ("REDACT_AND_ALLOW", "MANAGER_APPROVAL", "USER_REVIEW") else None,
        "clauses": [_clause_public(c) for c in retrieved],
        "approval": {"status": "pending", "manager_id": approver["id"], "manager_name": approver["name"]}
        if action == "MANAGER_APPROVAL" else None,
        "review": review,
        "screening_ms": screening_ms,
        "forwarded": action in ("ALLOW", "REDACT_AND_ALLOW"),
        "safety": verdict.public(),
        "support": SUPPORT_MESSAGE if support else None,
    }

    # ── Forward to local LLM (only ALLOW / REDACT_AND_ALLOW) ──────────────
    if action in ("ALLOW", "REDACT_AND_ALLOW"):
        for ev in _forward(request_id, action, forward_strict, forward_strict, conv_id):
            yield ev
    yield {"type": "done", "request_id": request_id, "total_ms": _ms(t_start)}


def _forward(request_id: str, action: str, forward_text: str, history_text: str, conv_id: str) -> Iterator[dict]:
    """Send cleared text to the local LLM (signed ticket) and stream the answer.
    Conversation history only ever stores the strictly sanitized text."""
    ticket = issue_ticket(request_id, action, forward_text)
    history = db.get_messages(conv_id, limit=12)
    messages = llm.build_messages(history, forward_text)
    yield {"type": "llm_start", "model": config.OLLAMA_MODEL}
    t = time.perf_counter()
    chunks: List[str] = []
    try:
        for chunk in llm.chat_stream(messages, ticket):
            chunks.append(chunk)
            yield {"type": "token", "text": chunk}
        db.add_message(conv_id, request_id, "user", history_text)
        db.add_message(conv_id, request_id, "assistant", _sanitize_for_storage("".join(chunks)))
        db.update_audit(request_id, llm_forwarded=1, llm_status="ok")
        yield {"type": "llm_done", "ms": _ms(t)}
    except llm.LLMUnavailable as exc:
        db.update_audit(request_id, llm_forwarded=1 if chunks else 0, llm_status="error" if chunks else "unreachable")
        yield {"type": "llm_error", "message": str(exc)}


def guard_findings(verdict: "safety_guard.GuardVerdict") -> List[det.Finding]:
    """Turn the safety model's verdict into request-level findings for the decision engine."""
    out: List[det.Finding] = []
    method = "local safety model (%s)" % (verdict.model or config.SAFETY_MODEL)
    if verdict.blocking:
        f = det.Finding("UNSAFE_CONTENT", source="request", detail=", ".join(verdict.labels(verdict.blocking)),
                        method=method, confidence=0.9)
        f.level, f.action = "CRITICAL", "block"
        out.append(f)
    if verdict.advisory:
        f = det.Finding("SAFETY_ADVISORY", source="request", detail=", ".join(verdict.labels(verdict.advisory)),
                        method=method, confidence=0.9)
        f.level, f.action = "LOW", "allow"
        out.append(f)
    if verdict.status == "error":
        if config.SAFETY_FAIL_MODE == "open":
            f = det.Finding("SAFETY_ADVISORY", source="request", detail="no verdict (%s); fail-open configured" % verdict.error,
                            method=method, confidence=1.0)
            f.level, f.action = "LOW", "allow"
        else:
            f = det.Finding("SAFETY_CHECK_FAILED", source="request", detail=verdict.error, method=method, confidence=1.0)
            f.level, f.action = "CRITICAL", "block"
        out.append(f)
    return out


def _sanitize_for_storage(text: str) -> str:
    """Model replies can echo values the user chose to send; history keeps them censored."""
    found = det.detect(text, "response")
    classifier.classify(found, {"response": text})
    return Redactor(found).redact(text, found)[0]


def run_review_choice(user: dict, request_id: str, choice: str) -> Iterator[dict]:
    """Continue a USER_REVIEW request after the user decides.

    choice = "redact" → every MEDIUM item is replaced too (strict text)
             "send"   → MEDIUM items are sent as typed; CRITICAL/HIGH stay redacted
             "cancel" → held content is deleted, nothing is sent
    """
    if choice not in ("redact", "send", "cancel"):
        raise ReviewError("choice must be redact, send or cancel")
    row = db.get_audit(request_id)
    if not row or row["user_id"] != user["id"]:
        err = ReviewError("request not found")
        err.status = 404
        raise err
    if row["decision"] != "USER_REVIEW" or row.get("user_review") != "pending":
        raise ReviewError("this request is not waiting for your review")
    held = db.vault_get(request_id)
    if not held or not held.get("payload_enc"):
        raise ReviewError("the held request is no longer available")
    payload = decrypt_json(held["payload_enc"])
    if time.time() - float(payload.get("created", 0)) > REVIEW_TTL_S:
        db.vault_update(request_id, payload_enc=None, status="review_expired")
        db.update_audit(request_id, user_review="expired")
        raise ReviewError("the review window expired – please send the message again")

    t0 = time.perf_counter()
    review_state = {"redact": "redacted", "send": "sent_unredacted", "cancel": "cancelled"}[choice]
    detections = row.get("detections") or []
    for d in detections:
        if d.get("action") == "awaiting user review":
            d["action"] = {"redact": "redacted (user choice)", "send": "sent unredacted after warning (user choice)",
                           "cancel": "request cancelled by user"}[choice]
    if choice == "cancel":
        db.vault_update(request_id, payload_enc=None, status="review_cancelled")
        db.update_audit(request_id, user_review=review_state, detections=detections, llm_status="not_forwarded")
        db.add_event(user["id"], "review_cancelled", request_id, "user cancelled after warning")
        yield {"type": "review_result", "request_id": request_id, "choice": choice, "decision": "USER_REVIEW",
               "label": "Cancelled", "forwarded": False}
        yield {"type": "done", "request_id": request_id, "total_ms": _ms(t0)}
        return

    text = payload["strict"] if choice == "redact" else payload["warn"]
    decision = "REDACT_AND_ALLOW" if (choice == "redact" or payload.get("warn_has_redactions")) else "ALLOW"
    db.vault_update(request_id, payload_enc=None, status="review_done")
    db.update_audit(request_id, decision=decision, user_review=review_state, detections=detections, llm_status="pending")
    db.add_event(user["id"], "review_" + review_state, request_id,
                 "MEDIUM items %s" % ("redacted" if choice == "redact" else "sent after warning"))
    yield {"type": "review_result", "request_id": request_id, "choice": choice, "decision": decision,
           "label": DECISION_LABELS[decision], "forwarded": True,
           "sanitized_prompt": payload["strict"] if choice == "redact" else None}
    for ev in _forward(request_id, decision, text, payload["strict"], payload["conversation_id"]):
        yield ev
    yield {"type": "done", "request_id": request_id, "total_ms": _ms(t0)}


def _is_image(name: str) -> bool:
    from .scanner.attachments import IMAGE_EXT
    lower = (name or "").lower()
    return any(lower.endswith(ext) for ext in IMAGE_EXT)


def _clause_public(c: dict) -> dict:
    return {"id": c["id"], "title": c["title"], "category": c["category"], "action": c["action"],
            "text": c["text"], "remediation": c.get("remediation", ""), "score": c.get("score"),
            "match": c.get("match"), "kind": c.get("kind") or "governing", "policy": c.get("policy") or "",
            "source_ref": c.get("source_ref") or "", "consistency": c.get("consistency") or "",
            "consistency_note": c.get("consistency_note") or ""}
