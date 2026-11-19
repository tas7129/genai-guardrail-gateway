"""Guardrail Gateway web server (Starlette – the ASGI toolkit FastAPI is built on).

Run:  python run.py        (or)   uvicorn backend.main:app --port 8000
"""
from __future__ import annotations

import csv
import io
import json
import urllib.parse
import urllib.request
import logging
from contextlib import asynccontextmanager

from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response, StreamingResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from . import approvals, auth, config, db, llm, pipeline, safety_guard, sessions
from .decision import CLAUSE_ACTIONS, MANDATORY_MIN, PRECEDENCE
from .scanner import classifier
from .policy import store as policy_store
from .scanner.ocr import ocr_status

log = logging.getLogger("guardrail")


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------
def bootstrap() -> None:
    config.ensure_data_dir()
    db.init_db()
    seed = json.loads(config.POLICY_SEED_FILE.read_text(encoding="utf-8"))
    sync = db.policy_sync(seed["clauses"])  # first run: all clauses; upgrades: new + unedited clauses
    if sync["added"] or sync["updated"]:
        log.info("Policy sync: %d clause(s) added, %d updated from the sample policy", sync["added"], sync["updated"])
    policy_store.index_clauses(db.policy_all())
    if config.AUTH_MODE == "pin" and sessions.ensure_pins():
        log.info("PIN sign-in enabled: demo PINs written to %s", config.PIN_PLAINTEXT_FILE)
    host = urllib.parse.urlparse(config.OLLAMA_URL).hostname or ""
    if host not in ("127.0.0.1", "localhost", "::1"):
        log.warning("OLLAMA_URL points to %s – Ollama should listen on 127.0.0.1 only so users cannot bypass the gateway", host)
    info = policy_store.store_info()
    log.info("Policy store: %s (%d clauses) %s", info["backend"], info["clauses"], info["note"])


@asynccontextmanager
async def lifespan(app):
    await run_in_threadpool(bootstrap)
    yield


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def current_user(request: Request) -> dict:
    if config.AUTH_MODE == "pin":
        uid = sessions.verify(request.cookies.get(sessions.SESSION_COOKIE))
        if not uid:
            e = auth.AuthError("sign in required")
            e.status = 401
            raise e
        return auth.get_user(uid)
    uid = request.headers.get("x-demo-user") or request.query_params.get("as")
    return auth.get_user(uid)


async def login(request: Request):
    if config.AUTH_MODE != "pin":
        return err("sign-in is only used when GG_AUTH_MODE=pin", 400)
    body = await request.json()
    uid = str(body.get("user", "")).strip().lower()
    problem = await run_in_threadpool(sessions.check_pin, uid, str(body.get("pin", "")))
    if problem:
        db.add_event(uid or "unknown", "login_failed", uid or "-", problem)
        return err(problem, 429 if "too many" in problem else 401)
    db.add_event(uid, "login", uid, "PIN sign-in")
    resp = JSONResponse({"user": auth.public_user(auth.get_user(uid))})
    resp.set_cookie(sessions.SESSION_COOKIE, sessions.issue(uid), max_age=sessions.SESSION_TTL_S, httponly=True,
                    samesite="strict", path="/")
    return resp


async def logout(request: Request):
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(sessions.SESSION_COOKIE, path="/")
    return resp


async def session_info(request: Request):
    uid = sessions.verify(request.cookies.get(sessions.SESSION_COOKIE)) if config.AUTH_MODE == "pin" else None
    return JSONResponse({"mode": config.AUTH_MODE, "user": uid})


def err(message: str, status: int = 400) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status)


# ---------------------------------------------------------------------------
# Pages & system
# ---------------------------------------------------------------------------
async def index(request: Request):
    return FileResponse(config.FRONTEND_DIR / "index.html")


async def health(request: Request):
    llm_status = await run_in_threadpool(llm.status)
    ocr_ok, ocr_ver = ocr_status()
    guard = await run_in_threadpool(safety_guard.status)
    return JSONResponse({"llm": llm_status, "safety_model": guard, "auth_mode": config.AUTH_MODE,
                         "policy_store": policy_store.store_info(),
                         "ocr": {"available": ocr_ok, "version": ocr_ver}, "org": config.ORG_NAME})


async def setup_pull(request: Request):
    """Download a MISSING configured model through the local Ollama (readiness banner button).
    Only the two configured models can be pulled, and only from the gateway machine itself."""
    current_user(request)
    if (request.client.host if request.client else "") not in ("127.0.0.1", "::1", "localhost", "testclient"):
        return err("model downloads can only be started on the gateway machine itself", 403)
    try:
        body = await request.json()
    except ValueError:
        return err("expected a JSON body like {\"which\": \"safety\"}", 400)
    model = {"assistant": config.OLLAMA_MODEL, "safety": config.SAFETY_MODEL}.get(str((body or {}).get("which", "")) if isinstance(body, dict) else "")
    if not model or model.lower() in ("off", "none", "disabled"):
        return err("unknown model", 400)

    def stream():
        req = urllib.request.Request(config.OLLAMA_URL + "/api/pull", data=json.dumps({"model": model, "stream": True}).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        failed = None
        try:
            with urllib.request.urlopen(req, timeout=3600) as resp:
                for raw in resp:
                    line = raw.decode("utf-8", "replace").strip()
                    if line:
                        ev = json.loads(line)
                        failed = ev.get("error") or failed
                        yield json.dumps({"model": model, "status": ev.get("status", ""), "error": ev.get("error"),
                                          "total": ev.get("total"), "completed": ev.get("completed")}) + "\n"
            if not failed:
                db.add_event("gateway", "model_downloaded", model, "via readiness banner")
        except Exception as exc:
            yield json.dumps({"model": model, "error": "download failed (%s) – is Ollama running?" % exc.__class__.__name__}) + "\n"

    return StreamingResponse(stream(), media_type="application/x-ndjson")


async def users(request: Request):
    out = []
    for u in auth.USERS.values():
        pu = auth.public_user(u)
        if u["role"] == "manager" or any(x.get("manager") == u["id"] for x in auth.USERS.values()):
            pu["pending_approvals"] = approvals.pending_count(u["id"])
        out.append(pu)
    return JSONResponse(out)


# ---------------------------------------------------------------------------
# Chat (the guarded path to the LLM)
# ---------------------------------------------------------------------------
async def chat(request: Request):
    user = current_user(request)
    form = await request.form(max_files=config.MAX_FILES + 1, max_fields=20)
    prompt = str(form.get("prompt") or "")
    conversation_id = str(form.get("conversation_id") or "") or None
    uploads = []
    for item in form.getlist("files"):
        if hasattr(item, "read"):
            uploads.append(pipeline.UploadedFile(item.filename or "attachment", await item.read()))
    if not prompt.strip() and not uploads:
        return err("Type a message or attach a file.")
    if len(prompt) > config.MAX_PROMPT_CHARS:
        return err("Prompt exceeds %d characters." % config.MAX_PROMPT_CHARS)
    if len(uploads) > config.MAX_FILES:
        return err("At most %d attachments per message." % config.MAX_FILES)

    def stream():
        try:
            for event in pipeline.run_guardrail(user, prompt, uploads, conversation_id):
                yield json.dumps(event) + "\n"
        except Exception as exc:  # fail closed: nothing has been forwarded
            # log the exception type only – a traceback could contain prompt fragments
            log.error("guardrail pipeline failed: %s", exc.__class__.__name__)
            yield json.dumps({"type": "error", "message": "Guardrail error – request not forwarded (%s)"
                              % exc.__class__.__name__}) + "\n"

    return StreamingResponse(stream(), media_type="application/x-ndjson",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


async def conversations(request: Request):
    user = current_user(request)
    return JSONResponse(await run_in_threadpool(db.list_conversations, user["id"]))


async def conversation_detail(request: Request):
    user = current_user(request)
    cid = request.path_params["cid"]
    if db.conversation_owner(cid) != user["id"]:
        return err("conversation not found", 404)
    rows = list(reversed(db.list_audit(conversation_id=cid, limit=100)))
    msgs = {m["request_id"]: m["content"] for m in db.get_messages(cid, limit=200) if m["role"] == "assistant"}
    turns = []
    for r in rows:
        response = msgs.get(r["request_id"])
        if r["decision"] == "MANAGER_APPROVAL":
            st = approvals.status_for_requester(r["request_id"], user)
            response = st.get("response")
        turns.append({"request_id": r["request_id"], "ts": r["ts"], "decision": r["decision"],
                      "risk_level": r["risk_level"], "categories": r["categories"], "clause_refs": r["clause_refs"],
                      "safe_prompt": r["safe_prompt"], "approval_status": r["approval_status"],
                      "explanation": r["explanation"], "attachments": r["attachments"], "response": response,
                      "llm_status": r["llm_status"], "user_review": r.get("user_review"),
                      "severity_counts": r.get("severity_counts"), "detections": r.get("detections")})
    return JSONResponse({"id": cid, "turns": turns})


async def request_status(request: Request):
    user = current_user(request)
    return JSONResponse(await run_in_threadpool(approvals.status_for_requester, request.path_params["rid"], user))


async def request_review(request: Request):
    """The user's answer to a USER_REVIEW warning: redact / send / cancel (streams the LLM answer)."""
    user = current_user(request)
    body = await request.json()
    gen = pipeline.run_review_choice(user, request.path_params["rid"], str(body.get("choice", "")))
    first = await run_in_threadpool(next, gen)  # validation errors surface here as HTTP errors

    def stream():
        yield json.dumps(first) + "\n"
        try:
            for event in gen:
                yield json.dumps(event) + "\n"
        except Exception as exc:
            log.error("review continuation failed: %s", exc.__class__.__name__)
            yield json.dumps({"type": "error", "message": "Guardrail error (%s)" % exc.__class__.__name__}) + "\n"

    return StreamingResponse(stream(), media_type="application/x-ndjson",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


async def severity_policy_get(request: Request):
    current_user(request)
    return JSONResponse(classifier.public_policy())


async def severity_policy_put(request: Request):
    user = current_user(request)
    auth.require_role(user, "admin")
    body = await request.json()
    current = db.settings_get("severity_policy") or {}
    changes = []
    if "strict_mode" in body:
        current["strict_mode"] = bool(body["strict_mode"])
        changes.append("strict_mode=%s" % current["strict_mode"])
    if "min_confidence" in body:
        val = float(body["min_confidence"])
        if not 0 <= val <= 1:
            return err("min_confidence must be between 0 and 1")
        current["min_confidence"] = val
        changes.append("min_confidence=%.2f" % val)
    if "level_actions" in body:
        acts = {k: v for k, v in dict(body["level_actions"]).items()
                if k in ("CRITICAL", "HIGH", "MEDIUM", "LOW") and v in classifier.VALID_ACTIONS}
        current.setdefault("level_actions", {}).update(acts)
        changes.append("level_actions=%s" % acts)
    db.settings_set("severity_policy", current, user["id"])
    db.add_event(user["id"], "severity_policy_updated", "severity_policy", ", ".join(changes))
    return JSONResponse(classifier.public_policy())


async def request_retry(request: Request):
    user = current_user(request)
    return JSONResponse(await run_in_threadpool(approvals.retry, request.path_params["rid"], user))


# ---------------------------------------------------------------------------
# Approvals
# ---------------------------------------------------------------------------
async def approvals_list(request: Request):
    user = current_user(request)
    status = request.query_params.get("status", "")
    if user["role"] == "admin":
        rows = db.list_audit(decision="MANAGER_APPROVAL", approval_status=status)
    elif user["role"] == "manager":
        rows = db.list_audit(decision="MANAGER_APPROVAL", approval_status=status, assigned_manager=user["id"])
    else:
        rows = db.list_audit(user_ids=[user["id"]], decision="MANAGER_APPROVAL", approval_status=status)
    for r in rows:
        r["requester"] = auth.USERS.get(r["user_id"], {}).get("name")
        r["assigned_manager_name"] = auth.USERS.get(r.get("assigned_manager") or "", {}).get("name")
        r["can_decide"] = r.get("assigned_manager") == user["id"] and r["approval_status"] == "pending"
    return JSONResponse(rows)


async def approval_review(request: Request):
    user = current_user(request)
    auth.require_role(user, "manager", "admin")
    return JSONResponse(await run_in_threadpool(approvals.review, request.path_params["rid"], user))


async def approval_decision(request: Request):
    user = current_user(request)
    body = await request.json()
    result = await run_in_threadpool(approvals.decide, request.path_params["rid"], user,
                                     str(body.get("action", "")), str(body.get("note", "")))
    return JSONResponse(result)


# ---------------------------------------------------------------------------
# Governance dashboard
# ---------------------------------------------------------------------------
async def overview(request: Request):
    user = current_user(request)
    scope = auth.scope_user_ids(user)
    data = await run_in_threadpool(db.stats, scope)
    data["scope"] = {"employee": "My activity", "manager": "Team %s" % user["team"],
                     "admin": "Organisation-wide"}[user["role"]]
    data["pending_for_me"] = approvals.pending_count(user["id"])
    data["safety_model"] = {"model": config.SAFETY_MODEL if safety_guard.enabled() else "", "fail_mode": config.SAFETY_FAIL_MODE}
    data["safety"]["labels"] = {k: v["label"] for k, v in safety_guard.safety_policy()["categories"].items()}
    data["recent_violations"] = db.list_audit(user_ids=scope, violations_only=True, limit=6)
    return JSONResponse(data)


async def audit_list(request: Request):
    user = current_user(request)
    q = request.query_params
    rows = await run_in_threadpool(
        lambda: db.list_audit(user_ids=auth.scope_user_ids(user), decision=q.get("decision", ""),
                              category=q.get("category", ""), violations_only=q.get("violations") == "1",
                              limit=min(int(q.get("limit", "200") or 200), 1000)))
    return JSONResponse(rows)


async def audit_csv(request: Request):
    user = current_user(request)
    auth.require_role(user, "admin")
    rows = db.list_audit(limit=100000)
    buf = io.StringIO()
    cols = ["request_id", "ts", "user_id", "user_name", "role", "team", "decision", "risk_level", "risk_score",
            "categories", "finding_types", "clause_refs", "approval_status", "assigned_manager", "approver",
            "approval_ts", "llm_forwarded", "llm_status", "screening_ms", "safe_prompt"]
    w = csv.writer(buf)
    w.writerow(cols)
    for r in rows:
        w.writerow([json.dumps(r[c]) if isinstance(r.get(c), (list, dict)) else r.get(c) for c in cols])
    db.add_event(user["id"], "audit_exported", "audit_log", "%d rows" % len(rows))
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=guardrail_audit_log.csv"})


async def events(request: Request):
    user = current_user(request)
    auth.require_role(user, "admin")
    return JSONResponse(db.list_events())


# ---------------------------------------------------------------------------
# Policy knowledge base
# ---------------------------------------------------------------------------
async def policy_list(request: Request):
    current_user(request)
    return JSONResponse({"clauses": db.policy_all(), "reference": policy_store.load_reference_clauses(),
                         "store": policy_store.store_info()})


async def policy_update(request: Request):
    user = current_user(request)
    auth.require_role(user, "admin")
    body = await request.json()
    fields = {}
    if "action" in body:
        if body["action"] not in CLAUSE_ACTIONS:
            return err("invalid action")
        current = next((c for c in db.policy_all() if c["id"] == request.path_params["cid"]), None)
        floor = MANDATORY_MIN.get((current or {}).get("category", ""))
        if floor and (body["action"] not in PRECEDENCE or PRECEDENCE[body["action"]] < PRECEDENCE[floor]):
            return err("%s is a mandatory safety control and cannot be set below %s" % (current["id"], floor), 403)
        fields["action"] = body["action"]
    for k in ("title", "text", "remediation"):
        if k in body:
            if not str(body[k]).strip():
                return err("%s cannot be empty" % k)
            fields[k] = str(body[k]).strip()[:4000]
    clause = db.policy_update(request.path_params["cid"], user["id"], **fields)
    if not clause:
        return err("clause not found", 404)
    await run_in_threadpool(policy_store.index_clauses, db.policy_all())
    db.add_event(user["id"], "policy_updated", clause["id"],
                 ", ".join("%s=%s" % (k, v if k == "action" else "(edited)") for k, v in fields.items()))
    return JSONResponse({"clause": clause, "store": policy_store.store_info()})


async def policy_reset(request: Request):
    user = current_user(request)
    auth.require_role(user, "admin")
    seed = json.loads(config.POLICY_SEED_FILE.read_text(encoding="utf-8"))
    db.policy_seed(seed["clauses"], replace=True)
    await run_in_threadpool(policy_store.index_clauses, db.policy_all())
    db.add_event(user["id"], "policy_reset", "all", "restored sample policy")
    return JSONResponse({"clauses": db.policy_all(), "reference": policy_store.load_reference_clauses(),
                         "store": policy_store.store_info()})


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
async def auth_error(request: Request, exc: auth.AuthError):
    return err(str(exc), getattr(exc, "status", 403))


async def approval_error(request: Request, exc: approvals.ApprovalError):
    return err(str(exc), getattr(exc, "status", 400))


async def review_error(request: Request, exc: pipeline.ReviewError):
    return err(str(exc), getattr(exc, "status", 400))


routes = [
    Route("/", index),
    Route("/api/health", health),
    Route("/api/users", users),
    Route("/api/login", login, methods=["POST"]),
    Route("/api/logout", logout, methods=["POST"]),
    Route("/api/session", session_info),
    Route("/api/setup/pull", setup_pull, methods=["POST"]),
    Route("/api/chat", chat, methods=["POST"]),
    Route("/api/conversations", conversations),
    Route("/api/conversations/{cid}", conversation_detail),
    Route("/api/requests/{rid}", request_status),
    Route("/api/requests/{rid}/retry", request_retry, methods=["POST"]),
    Route("/api/requests/{rid}/review", request_review, methods=["POST"]),
    Route("/api/severity-policy", severity_policy_get, methods=["GET"]),
    Route("/api/severity-policy", severity_policy_put, methods=["PUT"]),
    Route("/api/approvals", approvals_list),
    Route("/api/approvals/{rid}", approval_review),
    Route("/api/approvals/{rid}/decision", approval_decision, methods=["POST"]),
    Route("/api/governance/overview", overview),
    Route("/api/audit", audit_list),
    Route("/api/audit.csv", audit_csv),
    Route("/api/events", events),
    Route("/api/policy", policy_list),
    Route("/api/policy/reset", policy_reset, methods=["POST"]),
    Route("/api/policy/{cid}", policy_update, methods=["PUT"]),
    Mount("/static", StaticFiles(directory=str(config.FRONTEND_DIR)), name="static"),
    Mount("/samples", StaticFiles(directory=str(config.SAMPLES_DIR)), name="samples"),
]

app = Starlette(routes=routes, lifespan=lifespan,
                exception_handlers={auth.AuthError: auth_error, approvals.ApprovalError: approval_error,
                                    pipeline.ReviewError: review_error})
