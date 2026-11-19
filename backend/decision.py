"""Decision engine: combines detection/classification results with the policy
clauses retrieved from the knowledge base (ChromaDB).

For every detected category the engine looks up the governing clause that was
retrieved and reads its `action`:

  * an explicit action (ALLOW, REDACT_AND_ALLOW, USER_REVIEW, MANAGER_APPROVAL,
    BLOCK) applies to the whole category – this is how an admin can, for
    example, switch personal data to BLOCK;
  * SEVERITY_BASED means "follow the severity policy": each finding's planned
    action (set by scanner/classifier.py) is mapped to a decision –
        redact   → REDACT_AND_ALLOW      review → USER_REVIEW
        allow    → ALLOW                 block  → BLOCK
        document → the configured document-level action (manager approval)

The most restrictive outcome wins:
    BLOCK > MANAGER_APPROVAL > USER_REVIEW > REDACT_AND_ALLOW > ALLOW

Policy hierarchy (highest first):
  1. Mandatory controls (MANDATORY_MIN below) – harmful content, an unavailable
     content-safety check and unscannable attachments are always BLOCK. An admin
     cannot weaken them (main.policy_update refuses) and the engine enforces the
     minimum even if a stored clause were altered.
  2. Governing clauses (kind = governing) retrieved for each detected category.
  3. The severity policy, for clauses whose action is SEVERITY_BASED.
  Reference clauses (organisation policy pack) are shown but never decide.

If a category has no governing clause in the retrieved set, the engine fails
closed (BLOCK). Retrieval informs the decision; it does not by itself guarantee
compliance – detection coverage matters just as much (README "Known limitations").
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .scanner.detectors import CATEGORY_LABELS, Finding
from .scanner.entities import SEVERITY_RANK

PRECEDENCE = {"ALLOW": 0, "REDACT_AND_ALLOW": 1, "USER_REVIEW": 2, "MANAGER_APPROVAL": 3, "BLOCK": 4}
CLAUSE_ACTIONS = list(PRECEDENCE) + ["SEVERITY_BASED", "INFO"]
DECISION_LABELS = {
    "ALLOW": "Allowed",
    "REDACT_AND_ALLOW": "Redacted & allowed",
    "USER_REVIEW": "Review required",
    "MANAGER_APPROVAL": "Manager approval required",
    "BLOCK": "Blocked",
}
# Mandatory minimum outcome per category – cannot be relaxed by policy edits.
MANDATORY_MIN = {"HARMFUL_CONTENT": "BLOCK", "SAFETY_CHECK": "BLOCK", "UNSCANNABLE_ATTACHMENT": "BLOCK"}
FINDING_ACTION_TO_DECISION = {"redact": "REDACT_AND_ALLOW", "review": "USER_REVIEW", "allow": "ALLOW", "block": "BLOCK"}
RISK_SCORE = {"LOW": 5, "MEDIUM": 40, "HIGH": 65, "CRITICAL": 88}


@dataclass
class Decision:
    action: str
    risk_level: str
    risk_score: int
    governing: List[dict] = field(default_factory=list)
    explanation: str = ""
    remediation: List[str] = field(default_factory=list)
    clause_refs: List[str] = field(default_factory=list)
    fail_closed: bool = False

    def public(self) -> dict:
        return {
            "action": self.action, "label": DECISION_LABELS[self.action], "risk_level": self.risk_level,
            "risk_score": self.risk_score, "governing": self.governing, "explanation": self.explanation,
            "remediation": self.remediation, "clause_refs": self.clause_refs, "fail_closed": self.fail_closed,
        }


def _summary(findings: List[Finding]) -> str:
    c: Counter = Counter()
    for f in findings:
        c[(f.label, f.level)] += 1
    return ", ".join("%s%s %s" % (lbl, " ×%d" % n if n > 1 else "", lvl) for (lbl, lvl), n in c.most_common())


def decide(categories: List[str], findings: List[Finding], retrieved: List[dict],
           document_action: str = "MANAGER_APPROVAL") -> Decision:
    by_category: Dict[str, dict] = {}
    for clause in retrieved:
        if clause.get("kind") == "reference" or clause.get("action") == "REFERENCE":
            continue  # organisation policy-pack clauses explain; they never govern
        by_category.setdefault(clause["category"], clause)

    governed = list(categories) if categories else ["PUBLIC"]
    governing: List[dict] = []
    final = "ALLOW"
    fail_closed = False
    for cat in governed:
        clause = by_category.get(cat)
        if clause is None or clause.get("action") not in CLAUSE_ACTIONS:
            fail_closed = True
            governing.append({"category": cat, "clause_id": None, "action": "BLOCK",
                              "reason": "no governing policy clause retrieved – failing closed"})
            final = "BLOCK"
            continue
        cat_findings = [f for f in findings if f.category == cat]
        mode = clause["action"]
        if mode == "SEVERITY_BASED":
            action = "ALLOW"
            for f in cat_findings:
                a = document_action if f.action == "document" else FINDING_ACTION_TO_DECISION.get(f.action, "BLOCK")
                if PRECEDENCE[a] > PRECEDENCE[action]:
                    action = a
        elif mode == "INFO":
            action = "ALLOW"
        else:
            action = mode
        floor = MANDATORY_MIN.get(cat)
        if floor and PRECEDENCE[action] < PRECEDENCE[floor]:
            action = floor  # mandatory control: a clause edited below its minimum is ignored
        governing.append({"category": cat, "category_label": CATEGORY_LABELS.get(cat, cat), "clause_id": clause["id"],
                          "clause_title": clause["title"], "action": action, "mode": mode,
                          "instances": len(cat_findings), "summary": _summary(cat_findings)})
        if PRECEDENCE[action] > PRECEDENCE[final]:
            final = action

    # risk = highest severity actually present (LOW findings do not raise risk)
    levels = [f.level for f in findings if f.level != "LOW"]
    top = max(levels, key=lambda lv: SEVERITY_RANK[lv]) if levels else "LOW"
    if final == "BLOCK" and top != "CRITICAL" and fail_closed:
        top = "CRITICAL"
    risk_score = min(100, RISK_SCORE[top] + min(9, len(levels)))

    parts = []
    deciding = [g for g in governing if g["action"] == final]
    for g in deciding:
        if g.get("clause_id") is None:
            parts.append("No policy clause governs %s, so the gateway fails closed." % g["category"])
        elif g["category"] == "PUBLIC":
            parts.append("No sensitive data detected. %s (%s) permits forwarding the original prompt."
                         % (g["clause_id"], g["clause_title"]))
        elif g["mode"] == "SEVERITY_BASED":
            parts.append("%s detected (%s). %s applies severity-based censorship → %s."
                         % (g["category_label"], g["summary"], g["clause_id"], DECISION_LABELS[final].lower()))
        else:
            parts.append("%s detected (%s). %s (%s) requires: %s."
                         % (g["category_label"], g["summary"], g["clause_id"], g["clause_title"], DECISION_LABELS[final].lower()))
    others = [g for g in governing if g["action"] != final and g.get("clause_id")]
    if others:
        parts.append("Also applicable: " + "; ".join(
            "%s → %s" % (g["clause_id"], DECISION_LABELS[g["action"]].lower()) for g in others) + ".")

    remediation = []
    for g in deciding:
        clause = by_category.get(g["category"])
        if clause and clause.get("remediation") and g["category"] != "PUBLIC":
            remediation.append(clause["remediation"])
    if final == "USER_REVIEW":
        remediation.append("Choose “Redact & send” to replace the highlighted items with placeholders, "
                           "or “Send anyway” if sharing them is genuinely necessary.")

    refs = [g["clause_id"] for g in governing if g.get("clause_id")]
    return Decision(action=final, risk_level=top, risk_score=risk_score, governing=governing,
                    explanation=" ".join(parts), remediation=remediation, clause_refs=refs, fail_closed=fail_closed)


def action_taken(f: Finding, final: str, user_choice: Optional[str] = None) -> str:
    """Human-readable censorship action for one finding, given the final decision."""
    if f.scope == "request":
        return {"BLOCK": "request blocked"}.get(final, "flagged")
    if final == "BLOCK":
        return "request blocked – not forwarded"
    if f.scope == "document":
        return "held for manager approval" if final == "MANAGER_APPROVAL" else "flagged"
    if f.action == "allow":
        return "not censored (low risk)"
    if f.action == "redact":
        return "redacted – request held for approval" if final == "MANAGER_APPROVAL" else "redacted"
    if f.action == "review":
        if final == "MANAGER_APPROVAL":
            return "redacted – request held for approval"
        if user_choice == "redact":
            return "redacted (user choice)"
        if user_choice == "send":
            return "sent unredacted after warning (user choice)"
        if user_choice == "cancel":
            return "request cancelled by user"
        return "awaiting user review"
    return f.action
