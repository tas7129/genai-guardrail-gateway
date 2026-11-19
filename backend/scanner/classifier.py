"""Contextual classification + severity-based censorship actions.

Runs after detection. For every finding it decides:

  level       CRITICAL / HIGH / MEDIUM / LOW  (entity default, adjusted by context)
  confidence  0..1                            (detector base, adjusted by context)
  note        why the level was adjusted     (shown in the UI)
  action      redact | review | allow | block | document | request

Context rules (pattern matching alone is not enough):
  * documented example / placeholder values (AKIAIOSFODNN7EXAMPLE, …@example.com,
    <API_KEY>, 1234567890, 4111 1111 1111 1111 …) → LOW
  * "for example …" next to a value only lowers the level when the value ALSO
    fails validation – a user calling a real-looking number "fictional" is not
    trusted on their word
  * public business contacts (info@, support@, toll-free numbers, office addresses) → LOW
  * generic / documentation network addresses (127.0.0.1, 192.168.1.1, 203.0.113.x) → LOW
  * requests about a minor raise personal data to "children's information" (HIGH)
  * an address next to "live location" / "currently at" becomes live location (HIGH)
  * findings below the configured confidence threshold → LOW

Then the configurable severity policy (policy/severity_policy.json + admin
settings) maps each level to an action, and CRITICAL secrets are switched to
"block" when safe redaction cannot be guaranteed.
"""
from __future__ import annotations

import copy
import json
import re
from typing import Dict, Iterable, List, Optional, Set

from .. import config
from .detectors import Finding
from .entities import CHILD_ELEVATED_TYPES, CHILDREN_DATA, LOCATION_DATA, SEVERITY_RANK

SEVERITY_POLICY_FILE = config.BASE_DIR / "policy" / "severity_policy.json"
VALID_ACTIONS = {"redact", "review", "allow", "block"}

# ── policy loading ─────────────────────────────────────────────────────────
_override_loader = None  # set by backend.db at import to avoid a circular import


def default_policy() -> dict:
    return json.loads(SEVERITY_POLICY_FILE.read_text(encoding="utf-8"))


def get_policy() -> dict:
    policy = default_policy()
    if _override_loader:
        try:
            overrides = _override_loader() or {}
        except Exception:
            overrides = {}
        if "strict_mode" in overrides:
            policy["strict_mode"] = bool(overrides["strict_mode"])
        if "min_confidence" in overrides:
            policy["min_confidence"] = float(overrides["min_confidence"])
        for lvl, act in (overrides.get("level_actions") or {}).items():
            if lvl in policy["levels"] and act in VALID_ACTIONS:
                policy["levels"][lvl]["action"] = act
    return policy


def level_action(policy: dict, level: str) -> str:
    spec = policy["levels"].get(level, {"action": "redact"})
    if policy.get("strict_mode") and spec.get("strict_action"):
        return spec["strict_action"]
    return spec.get("action", "redact")


def public_policy() -> dict:
    p = copy.deepcopy(get_policy())
    p["effective_actions"] = {lvl: level_action(p, lvl) for lvl in p["levels"]}
    return p


# ── context patterns ───────────────────────────────────────────────────────
PLACEHOLDER_VALUE = re.compile(
    r"(?i)(example|sample|dummy|placeholder|your[_\-\s]?(?:api|key|token|password|secret|name|email|number|id|pass)|xxx|"
    r"\*{3,}|•{3,}|<[^>]*>|\{\{[^}]*\}\}|\$\{[^}]*\}|changeme|change_me|redacted|\bfake\b|lorem|ipsum|\.\.\.)")
KNOWN_DOC_VALUES = {
    "akiaiosfodnn7example", "wjalrxutnfemi/k7mdeng/bpxrficyexamplekey", "4111111111111111", "4242424242424242",
    "5555555555554444", "5105105105105100", "378282246310005", "4000056655665556", "abcde1234f", "aaaaa0000a",
    "123456789", "123-45-6789", "078-05-1120", "999999999999",
}
RESERVED_EMAIL = re.compile(r"(?i)@(?:[\w\-]+\.)*(?:example\.(?:com|org|net|in)|test|invalid|localhost|example)$")
ROLE_LOCALPARTS = {"info", "contact", "support", "help", "helpdesk", "sales", "hr", "careers", "jobs", "press", "media",
                   "admin", "office", "enquiries", "enquiry", "inquiries", "hello", "noreply", "no-reply", "customercare",
                   "care", "feedback", "team", "service", "billing", "accounts", "marketing", "partners", "investors"}
PERSONAL_EMAIL_DOMAINS = {"gmail.com", "yahoo.com", "yahoo.co.in", "outlook.com", "hotmail.com", "live.com", "icloud.com",
                          "protonmail.com", "proton.me", "rediffmail.com", "aol.com", "zoho.com", "ymail.com", "me.com"}
EXAMPLE_CONTEXT = re.compile(r"(?i)(?:\be\.g\.|\b(?:for example|for instance|example|sample|dummy|fictional|fictitious|"
                             r"placeholder|mock|test data|made[\s\-]up|hypothetical)\b)")
BUSINESS_ADDRESS_CONTEXT = re.compile(r"(?i)\b(?:office|headquarters|hq|head\s+office|registered\s+office|corporate\s+office|"
                                      r"campus|showroom|store|branch|located\s+at|visit\s+us|our\s+address|company\s+address|"
                                      r"factory|plant|outlet|restaurant|hotel|mall|museum|station|airport)\b")
RESIDENTIAL_CONTEXT = re.compile(r"(?i)\b(?:lives?|living|stay(?:s|ing)?|home|residence|resident|reside|house|flat|"
                                 r"my\s+place|his\s+place|her\s+place|client|customer|patient|tenant|daughter|son|child)\b")
LIVE_LOCATION_CONTEXT = re.compile(r"(?i)\b(?:live\s+location|current\s+location|right\s+now|currently\s+at|i\s+am\s+at|"
                                   r"i'm\s+at|we\s+are\s+at|tracking|whereabouts|heading\s+to)\b")
CHILD_CONTEXT = re.compile(
    r"(?i)\b(?:my|his|her|our|their)\s+(?:\d{1,2}[\s\-](?:year|yr)s?[\s\-]old\s+)?(?:son|daughter|child|children|kids?|nephew|niece|"
    r"grandson|granddaughter|baby|toddler|stepson|stepdaughter)\b|\b(?:[1-9]|1[0-7])[\s\-](?:year|yr)s?[\s\-]old\b|"
    r"\b(?:class|grade|std\.?|standard)\s+(?:[1-9]|1[0-2]|[ivx]{1,4})\b|\b(?:kindergarten|pre-?school|lkg|ukg|primary\s+school|"
    r"minor|juvenile|school\s+student|schoolboy|schoolgirl|child's|ward)\b")
TOLL_FREE = re.compile(r"^\s*(?:\+?91[\s\-]?)?1[\s\-]?8[06]0")
GENERIC_IPS = {"127.0.0.1", "0.0.0.0", "255.255.255.255", "192.168.0.1", "192.168.1.1", "10.0.0.1", "8.8.8.8", "8.8.4.4",
               "1.1.1.1", "1.0.0.1", "::1"}
DOC_IP = re.compile(r"^(?:192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|255\.255\.)")
ASSIGNMENT_LINE = re.compile(r"(?m)^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.\-]*\s*[=:]\s*\S+")
NUMERIC_TYPES = {"PHONE", "AADHAAR", "CREDIT_CARD", "BANK_ACCOUNT", "SSN", "OTP", "CARD_CVV_PIN", "EMPLOYEE_ID"}
VALIDATED_TYPES = {"AADHAAR": "checksum_valid"}


def _digits(v: str) -> str:
    return re.sub(r"\D", "", v)


def _sequential(d: str, run: int = 8) -> bool:
    if len(d) < run:
        return False
    if len(set(d)) == 1:
        return True
    asc = desc = 1
    for a, b in zip(d, d[1:]):
        asc = asc + 1 if int(b) == (int(a) + 1) % 10 else 1
        desc = desc + 1 if int(b) == (int(a) - 1) % 10 else 1
        if asc >= run or desc >= run:
            return True
    return False


def _is_placeholder(f: Finding) -> bool:
    v = f.value.strip()
    low = v.lower()
    if PLACEHOLDER_VALUE.search(v):
        return True
    if re.sub(r"[\s\-]", "", low) in KNOWN_DOC_VALUES or low in KNOWN_DOC_VALUES:
        return True
    if f.type == "EMAIL" and RESERVED_EMAIL.search(v):
        return True
    if f.type in NUMERIC_TYPES and _sequential(_digits(v)):
        return True
    if f.type == "SSN":
        area = _digits(v)[:3]
        if area in ("000", "666") or area.startswith("9"):
            return True
    return False


def _set_level(f: Finding, level: str, note: str, confidence: Optional[float] = None) -> None:
    f.level = level
    f.note = (f.note + "; " if f.note else "") + note
    if confidence is not None:
        f.confidence = confidence


def classify(findings: List[Finding], texts: Dict[str, str], ocr_sources: Iterable[str] = (),
             policy: Optional[dict] = None) -> dict:
    """Mutates findings in place. Returns a summary of request-level context."""
    policy = policy or get_policy()
    ocr_sources = set(ocr_sources)
    overrides = policy.get("entity_severity_overrides") or {}
    child_ctx = any(CHILD_CONTEXT.search(t or "") for t in texts.values())
    child_min = policy.get("children_minimum_severity", "HIGH")
    min_conf = float(policy.get("min_confidence", 0.5))

    for f in findings:
        if f.type in overrides and overrides[f.type] in SEVERITY_RANK:
            f.level = overrides[f.type]
        if f.source in ocr_sources:
            f.method = "OCR → " + f.method
            f.confidence = max(0.0, f.confidence - 0.05)
        if f.scope != "token" or not f.has_span:
            continue
        text = texts.get(f.source, "")
        before = text[max(0, f.start - 80): f.start]
        near = text[max(0, f.start - 60): f.start]

        # 1 placeholders / documented example values
        if _is_placeholder(f):
            _set_level(f, "LOW", "documented example or placeholder value", 0.3)
        # 2 "for example" context: only trusted when validation also fails
        elif EXAMPLE_CONTEXT.search(near):
            vkey = VALIDATED_TYPES.get(f.type)
            if vkey and f.extra.get(vkey) is False:
                _set_level(f, "LOW", "labelled as an example and fails validation", 0.35)
            else:
                f.confidence = max(0.0, f.confidence - 0.1)
                f.note = (f.note + "; " if f.note else "") + "labelled as an example, but the value passes validation – treated as real"
        elif f.type == "AADHAAR" and f.extra.get("checksum_valid") is False:
            f.note = (f.note + "; " if f.note else "") + "checksum failed, treated as real because it is labelled as Aadhaar"

        if f.level != "LOW":
            # 3 public business information
            if f.type == "EMAIL":
                local, _, domain = f.value.lower().partition("@")
                if local in ROLE_LOCALPARTS:
                    _set_level(f, "LOW", "public business contact address")
                elif domain in PERSONAL_EMAIL_DOMAINS:
                    f.label_override = "Personal email address"
            elif f.type == "PHONE" and TOLL_FREE.search(f.value):
                _set_level(f, "LOW", "public toll-free business number")
            elif f.type == "ADDRESS":
                if LIVE_LOCATION_CONTEXT.search(before):
                    f.category_override = LOCATION_DATA
                    f.label_override = "Live location (address)"
                    f.placeholder_override = "LOCATION"
                    _set_level(f, "HIGH", "address given as a live / current location")
                elif BUSINESS_ADDRESS_CONTEXT.search(before) and not RESIDENTIAL_CONTEXT.search(before):
                    _set_level(f, "LOW", "public business address")
            elif f.type in ("IP_ADDRESS", "INTERNAL_IP") and (f.value in GENERIC_IPS or DOC_IP.match(f.value)
                                                               or f.value.startswith("127.")):
                _set_level(f, "LOW", "generic or documentation network address")

        # 4 children's information
        if child_ctx and f.level != "LOW" and f.type in CHILD_ELEVATED_TYPES:
            f.category_override = CHILDREN_DATA
            f.label_override = "Child's " + (f.label_override or f.entity.label).lower()
            f.placeholder_override = "CHILD " + (f.placeholder_override or f.entity.placeholder)
            if SEVERITY_RANK[f.level] < SEVERITY_RANK.get(child_min, 3):
                f.level = child_min
            f.note = (f.note + "; " if f.note else "") + "request concerns a minor"

        # 5 confidence threshold
        if f.level != "LOW" and f.confidence < min_conf:
            _set_level(f, "LOW", "below the %.0f%% confidence threshold" % (min_conf * 100))

    # ── actions ────────────────────────────────────────────────────────
    for f in findings:
        if f.scope == "document":
            f.action = "document"
        elif f.scope == "request":
            f.action = "request"
        else:
            f.action = level_action(policy, f.level)

    # CRITICAL secrets: block when safe redaction cannot be guaranteed
    rules = policy.get("critical_unsafe_redaction") or {}
    unsafe: List[str] = []
    critical = [f for f in findings if f.scope == "token" and f.level == "CRITICAL" and f.action == "redact"]
    if critical:
        if rules.get("block_if_found_in_ocr_text", True):
            for f in critical:
                if f.source in ocr_sources:
                    f.action = "block"
                    f.note = (f.note + "; " if f.note else "") + "secret read by OCR – fragments may survive redaction"
                    if "ocr" not in unsafe:
                        unsafe.append("ocr")
        if rules.get("block_if_secrets_file", True):
            min_lines = int(rules.get("secrets_file_min_assignment_lines", 3))
            for src, text in texts.items():
                if len(ASSIGNMENT_LINE.findall(text or "")) >= min_lines and any(f.source == src for f in critical):
                    for f in critical:
                        if f.source == src:
                            f.action = "block"
                            f.note = (f.note + "; " if f.note else "") + "secrets/config file – neighbouring values may also be secrets"
                    if "secrets_file" not in unsafe:
                        unsafe.append("secrets_file")
        limit = int(rules.get("block_if_distinct_critical_at_least", 4) or 0)
        if limit and len({f.value for f in critical}) >= limit:
            for f in critical:
                f.action = "block"
            unsafe.append("too_many_secrets")
    return {"child_context": child_ctx, "unsafe_redaction": unsafe, "strict_mode": bool(policy.get("strict_mode"))}


def severity_counts(findings: Iterable[Finding]) -> Dict[str, int]:
    out = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        out[f.level] = out.get(f.level, 0) + 1
    return out
