"""SQLite persistence: audit log, approval vault, policy clauses, governance events
and sanitized chat history.

Rule enforced throughout: the audit tables never receive raw secrets or
unredacted confidential text. Held (pending-approval) content lives only in
`held_requests`, encrypted, and is deleted once a manager decides.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Iterable, List, Optional

from . import config

_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    request_id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    user_id TEXT, user_name TEXT, role TEXT, team TEXT,
    conversation_id TEXT,
    decision TEXT, risk_level TEXT, risk_score INTEGER,
    categories TEXT, finding_types TEXT, clause_refs TEXT,
    approval_status TEXT, assigned_manager TEXT, approver TEXT, approval_ts TEXT, approval_note TEXT,
    safe_prompt TEXT, prompt_chars INTEGER, attachments TEXT,
    llm_forwarded INTEGER DEFAULT 0, llm_status TEXT, llm_model TEXT,
    explanation TEXT, screening_ms INTEGER,
    severity_counts TEXT, detections TEXT, max_severity TEXT, user_review TEXT, safety TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);

CREATE TABLE IF NOT EXISTS held_requests (
    request_id TEXT PRIMARY KEY,
    payload_enc BLOB,
    response_enc BLOB,
    status TEXT,
    created TEXT, updated TEXT
);

CREATE TABLE IF NOT EXISTS policy_clauses (
    id TEXT PRIMARY KEY, title TEXT, category TEXT, action TEXT, severity INTEGER,
    text TEXT, remediation TEXT, version INTEGER, updated TEXT, updated_by TEXT
);

CREATE TABLE IF NOT EXISTS governance_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT, actor TEXT, action TEXT, target TEXT, detail TEXT
);

CREATE TABLE IF NOT EXISTS conversations (
    id TEXT PRIMARY KEY, user_id TEXT, title TEXT, created TEXT, updated TEXT
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY, value TEXT, updated TEXT, updated_by TEXT
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id TEXT, request_id TEXT, role TEXT, content TEXT, ts TEXT
);
"""

JSON_FIELDS = ("categories", "finding_types", "clause_refs", "attachments", "severity_counts", "detections", "safety")
# columns added after the first release – created on startup for existing databases
MIGRATION_COLUMNS = {"severity_counts": "TEXT", "detections": "TEXT", "max_severity": "TEXT", "user_review": "TEXT",
                     "safety": "TEXT"}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect() -> sqlite3.Connection:
    config.ensure_data_dir()
    conn = sqlite3.connect(str(config.DB_PATH), timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> None:
    with _lock, connect() as conn:
        conn.executescript(SCHEMA)
        existing = {r[1] for r in conn.execute("PRAGMA table_info(audit_log)").fetchall()}
        for col, typ in MIGRATION_COLUMNS.items():
            if col not in existing:
                conn.execute("ALTER TABLE audit_log ADD COLUMN %s %s" % (col, typ))


def _row(r: sqlite3.Row) -> dict:
    d = dict(r)
    for k in JSON_FIELDS:
        if k in d and isinstance(d[k], str):
            try:
                d[k] = json.loads(d[k])
            except ValueError:
                pass
    if "llm_forwarded" in d:
        d["llm_forwarded"] = bool(d["llm_forwarded"])
    return d


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------
def insert_audit(row: dict) -> None:
    row = dict(row)
    for k in JSON_FIELDS:
        if k in row and not isinstance(row[k], str):
            row[k] = json.dumps(row[k])
    cols = ", ".join(row.keys())
    qs = ", ".join("?" for _ in row)
    with _lock, connect() as conn:
        conn.execute("INSERT INTO audit_log (%s) VALUES (%s)" % (cols, qs), list(row.values()))


def update_audit(request_id: str, **fields) -> None:
    if not fields:
        return
    for k in JSON_FIELDS:
        if k in fields and not isinstance(fields[k], str):
            fields[k] = json.dumps(fields[k])
    sets = ", ".join("%s = ?" % k for k in fields)
    with _lock, connect() as conn:
        conn.execute("UPDATE audit_log SET %s WHERE request_id = ?" % sets, list(fields.values()) + [request_id])


def get_audit(request_id: str) -> Optional[dict]:
    with connect() as conn:
        r = conn.execute("SELECT * FROM audit_log WHERE request_id = ?", (request_id,)).fetchone()
    return _row(r) if r else None


def list_audit(user_ids: Optional[Iterable[str]] = None, decision: str = "", category: str = "",
               approval_status: str = "", assigned_manager: str = "", conversation_id: str = "",
               violations_only: bool = False, limit: int = 200) -> List[dict]:
    q = "SELECT * FROM audit_log WHERE 1=1"
    args: list = []
    if user_ids is not None:
        ids = list(user_ids) or ["__none__"]
        q += " AND user_id IN (%s)" % ",".join("?" for _ in ids)
        args += ids
    if decision:
        q += " AND decision = ?"
        args.append(decision)
    if category:
        q += " AND categories LIKE ?"
        args.append('%%"%s"%%' % category)
    if approval_status:
        q += " AND approval_status = ?"
        args.append(approval_status)
    if assigned_manager:
        q += " AND assigned_manager = ?"
        args.append(assigned_manager)
    if conversation_id:
        q += " AND conversation_id = ?"
        args.append(conversation_id)
    if violations_only:
        q += " AND (decision != 'ALLOW' OR user_review = 'sent_unredacted')"
    q += " ORDER BY ts DESC, rowid DESC LIMIT ?"
    args.append(int(limit))
    with connect() as conn:
        return [_row(r) for r in conn.execute(q, args).fetchall()]


def stats(user_ids: Optional[Iterable[str]] = None) -> dict:
    rows = list_audit(user_ids=user_ids, limit=100000)
    decisions = Counter(r["decision"] for r in rows)
    approvals = Counter(r["approval_status"] for r in rows if r["decision"] == "MANAGER_APPROVAL")
    categories: Counter = Counter()
    types: Counter = Counter()
    users: Counter = Counter()
    for r in rows:
        for c in r.get("categories") or []:
            categories[c] += 1
        for t, n in (r.get("finding_types") or {}).items():
            types[t] += n
        users[r.get("user_name") or r.get("user_id")] += 1
    severities: Counter = Counter()
    for r in rows:
        for lvl, n in (r.get("severity_counts") or {}).items():
            severities[lvl] += n
    reviews = Counter(r.get("user_review") for r in rows if r.get("user_review"))
    forwarded = sum(1 for r in rows if r.get("llm_forwarded"))
    safety = Counter((r.get("safety") or {}).get("status") for r in rows if r.get("safety"))
    safety_cats: Counter = Counter()
    for r in rows:
        for c in (r.get("safety") or {}).get("blocking") or []:
            safety_cats[c] += 1
    rule_blocks = sum(1 for r in rows if (r.get("safety") or {}).get("rule_hits"))
    # integrity counters – every one of these must be 0
    integrity = {
        "blocked_but_forwarded": sum(1 for r in rows if r["decision"] == "BLOCK" and r.get("llm_forwarded")),
        "unapproved_but_forwarded": sum(1 for r in rows if r["decision"] == "MANAGER_APPROVAL"
                                        and r.get("approval_status") != "approved" and r.get("llm_forwarded")),
        "unreviewed_but_forwarded": sum(1 for r in rows if r.get("user_review") in ("pending", "cancelled", "expired")
                                        and r.get("llm_forwarded")),
        "unsafe_but_forwarded": sum(1 for r in rows if ((r.get("safety") or {}).get("blocking")
                                                        or ((r.get("safety") or {}).get("status") == "error"
                                                            and (r.get("safety") or {}).get("fail_mode") != "open"))
                                    and r.get("llm_forwarded")),
    }
    integrity_notes = {
        "forwarded_under_fail_open": sum(1 for r in rows if (r.get("safety") or {}).get("status") == "error"
                                         and (r.get("safety") or {}).get("fail_mode") == "open" and r.get("llm_forwarded")),
    }
    screening = [r["screening_ms"] for r in rows if r.get("screening_ms") is not None]
    return {
        "total": len(rows),
        "decisions": {k: decisions.get(k, 0) for k in ("ALLOW", "REDACT_AND_ALLOW", "BLOCK", "MANAGER_APPROVAL")},
        "awaiting_review": decisions.get("USER_REVIEW", 0),
        "severities": {k: severities.get(k, 0) for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
        "reviews": {k: reviews.get(k, 0) for k in ("pending", "redacted", "sent_unredacted", "cancelled", "expired")},
        "approvals": {k: approvals.get(k, 0) for k in ("pending", "approved", "rejected")},
        "categories": dict(categories.most_common()),
        "finding_types": dict(types.most_common(10)),
        "users": dict(users.most_common(10)),
        "llm_forwarded": forwarded,
        "safety": {"checked": sum(safety.values()), "safe": safety.get("safe", 0), "unsafe": safety.get("unsafe", 0),
                   "errors": safety.get("error", 0), "disabled": safety.get("disabled", 0),
                   "rule_blocks": rule_blocks, "categories": dict(safety_cats.most_common())},
        "integrity": integrity,
        "integrity_notes": integrity_notes,
        "avg_screening_ms": round(sum(screening) / len(screening)) if screening else 0,
        "trend": _trend(rows),
    }


def _trend(rows: List[dict]) -> dict:
    """Bucket requests by hour (last 12h) when all activity is recent, else by day (14 days)."""
    now = datetime.now(timezone.utc)
    stamps = []
    for r in rows:
        try:
            stamps.append((datetime.fromisoformat(r["ts"]), r["decision"]))
        except (TypeError, ValueError):
            continue
    hourly = not stamps or min(s for s, _ in stamps) > now - timedelta(hours=12)
    if hourly:
        start = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=11)
        buckets = [start + timedelta(hours=i) for i in range(12)]
        step = timedelta(hours=1)
    else:
        start = now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=13)
        buckets = [start + timedelta(days=i) for i in range(14)]
        step = timedelta(days=1)
    series = {d: [0] * len(buckets) for d in ("ALLOW", "REDACT_AND_ALLOW", "BLOCK", "MANAGER_APPROVAL")}
    for ts, dec in stamps:
        if ts < start or dec not in series:
            continue
        idx = int((ts - start) / step)
        if 0 <= idx < len(buckets):
            series[dec][idx] += 1
    return {"granularity": "hour" if hourly else "day",
            "buckets": [b.isoformat() for b in buckets], "series": series}


# ---------------------------------------------------------------------------
# Vault (held requests)
# ---------------------------------------------------------------------------
def vault_put(request_id: str, payload_enc: bytes, status: str = "pending") -> None:
    with _lock, connect() as conn:
        conn.execute("INSERT INTO held_requests (request_id, payload_enc, status, created, updated) VALUES (?,?,?,?,?)",
                     (request_id, payload_enc, status, now_iso(), now_iso()))


def vault_get(request_id: str) -> Optional[dict]:
    with connect() as conn:
        r = conn.execute("SELECT * FROM held_requests WHERE request_id = ?", (request_id,)).fetchone()
    return dict(r) if r else None


def vault_update(request_id: str, **fields) -> None:
    fields["updated"] = now_iso()
    sets = ", ".join("%s = ?" % k for k in fields)
    with _lock, connect() as conn:
        conn.execute("UPDATE held_requests SET %s WHERE request_id = ?" % sets, list(fields.values()) + [request_id])


# ---------------------------------------------------------------------------
# Policy clauses (source of truth; ChromaDB is the retrieval index)
# ---------------------------------------------------------------------------
def policy_count() -> int:
    with connect() as conn:
        return conn.execute("SELECT COUNT(*) FROM policy_clauses").fetchone()[0]


def policy_seed(clauses: List[dict], replace: bool = False) -> None:
    with _lock, connect() as conn:
        if replace:
            conn.execute("DELETE FROM policy_clauses")
        for c in clauses:
            conn.execute(
                "INSERT OR REPLACE INTO policy_clauses (id, title, category, action, severity, text, remediation,"
                " version, updated, updated_by) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (c["id"], c["title"], c["category"], c["action"], int(c.get("severity", 0)), c["text"],
                 c.get("remediation", ""), 1, now_iso(), "seed"))


def policy_sync(clauses: List[dict]) -> dict:
    """Bring the database in line with the sample policy file:
    * clauses missing from the database are added;
    * clauses still exactly as seeded (never edited by an admin) are updated;
    * clauses an admin edited are left alone."""
    added = updated = 0
    with connect() as conn:
        rows = {r["id"]: dict(r) for r in conn.execute("SELECT * FROM policy_clauses").fetchall()}
    for c in clauses:
        row = rows.get(c["id"])
        if row is None:
            policy_seed([c])
            added += 1
        elif row.get("updated_by") == "seed" and any(
                str(row.get(k) or "") != str(c.get(k) or "") for k in ("title", "category", "action", "text", "remediation")):
            with _lock, connect() as conn:
                conn.execute("UPDATE policy_clauses SET title=?, category=?, action=?, severity=?, text=?, remediation=?, "
                             "version=?, updated=? WHERE id=?",
                             (c["title"], c["category"], c["action"], int(c.get("severity", 0)), c["text"],
                              c.get("remediation", ""), int(row.get("version") or 1) + 1, now_iso(), c["id"]))
            updated += 1
    return {"added": added, "updated": updated}


def settings_get(key: str) -> Optional[dict]:
    with connect() as conn:
        r = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return json.loads(r["value"]) if r else None


def settings_set(key: str, value: dict, actor: str) -> None:
    with _lock, connect() as conn:
        conn.execute("INSERT OR REPLACE INTO settings (key, value, updated, updated_by) VALUES (?,?,?,?)",
                     (key, json.dumps(value), now_iso(), actor))


def policy_add_missing(clauses: List[dict]) -> int:
    """Insert seed clauses whose IDs are not in the database yet (keeps admin edits)."""
    with connect() as conn:
        existing = {r[0] for r in conn.execute("SELECT id FROM policy_clauses").fetchall()}
    missing = [c for c in clauses if c["id"] not in existing]
    if missing:
        policy_seed(missing)
    return len(missing)


def policy_all() -> List[dict]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM policy_clauses").fetchall()
    out = [dict(r) for r in rows]
    out.sort(key=lambda c: int(c["id"].split("-")[-1]) if c["id"].split("-")[-1].isdigit() else 999)
    return out


def policy_update(clause_id: str, actor: str, **fields) -> Optional[dict]:
    allowed = {k: v for k, v in fields.items() if k in ("title", "action", "text", "remediation", "severity")}
    with _lock, connect() as conn:
        r = conn.execute("SELECT * FROM policy_clauses WHERE id = ?", (clause_id,)).fetchone()
        if not r:
            return None
        allowed["version"] = int(r["version"] or 1) + 1
        allowed["updated"] = now_iso()
        allowed["updated_by"] = actor
        sets = ", ".join("%s = ?" % k for k in allowed)
        conn.execute("UPDATE policy_clauses SET %s WHERE id = ?" % sets, list(allowed.values()) + [clause_id])
        r = conn.execute("SELECT * FROM policy_clauses WHERE id = ?", (clause_id,)).fetchone()
    return dict(r)


# ---------------------------------------------------------------------------
# Governance events (approvals, policy changes)
# ---------------------------------------------------------------------------
def add_event(actor: str, action: str, target: str, detail: str = "") -> None:
    with _lock, connect() as conn:
        conn.execute("INSERT INTO governance_events (ts, actor, action, target, detail) VALUES (?,?,?,?,?)",
                     (now_iso(), actor, action, target, detail))


def list_events(limit: int = 100) -> List[dict]:
    with connect() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM governance_events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()]


# ---------------------------------------------------------------------------
# Conversations (sanitized history only – exactly what the LLM saw)
# ---------------------------------------------------------------------------
def upsert_conversation(conv_id: str, user_id: str, title: str) -> None:
    with _lock, connect() as conn:
        r = conn.execute("SELECT id FROM conversations WHERE id = ?", (conv_id,)).fetchone()
        if r:
            conn.execute("UPDATE conversations SET updated = ? WHERE id = ?", (now_iso(), conv_id))
        else:
            conn.execute("INSERT INTO conversations (id, user_id, title, created, updated) VALUES (?,?,?,?,?)",
                         (conv_id, user_id, title[:80], now_iso(), now_iso()))


def conversation_owner(conv_id: str) -> Optional[str]:
    with connect() as conn:
        r = conn.execute("SELECT user_id FROM conversations WHERE id = ?", (conv_id,)).fetchone()
    return r["user_id"] if r else None


def list_conversations(user_id: str) -> List[dict]:
    with connect() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM conversations WHERE user_id = ? ORDER BY updated DESC LIMIT 50", (user_id,)).fetchall()]


def add_message(conv_id: str, request_id: str, role: str, content: str) -> None:
    with _lock, connect() as conn:
        conn.execute("INSERT INTO messages (conversation_id, request_id, role, content, ts) VALUES (?,?,?,?,?)",
                     (conv_id, request_id, role, content, now_iso()))


def get_messages(conv_id: str, limit: int = 20) -> List[dict]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM messages WHERE conversation_id = ? ORDER BY id DESC LIMIT ?",
                            (conv_id, limit)).fetchall()
    return [dict(r) for r in reversed(rows)]


def _severity_overrides() -> Optional[dict]:
    try:
        return settings_get("severity_policy")
    except sqlite3.Error:
        return None


# Let the classifier read admin overrides (strict mode etc.) without a circular import.
from .scanner import classifier as _classifier  # noqa: E402

_classifier._override_loader = _severity_overrides
