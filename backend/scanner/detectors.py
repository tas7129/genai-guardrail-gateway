"""Sensitive-data detectors.

Deterministic, explainable detection: regular expressions plus validators (Luhn
for cards, Verhoeff for Aadhaar, range checks for IPs/GPS), labelled-field
patterns ("Passport No: …"), and context lexicons that only fire when a value is
tied to a person ("I was diagnosed with …", not "symptoms of diabetes").

Every detector returns `Finding` objects with exact character spans, a detection
method and a base confidence. `classifier.py` then applies context rules
(placeholders, public business info, children, OCR …) and the configurable
severity policy.

Why not an LLM classifier? A security decision must not be something a user can
"talk" the system out of (prompt injection). The local LLM never decides whether
content is allowed; it only answers prompts that have already been cleared.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Callable, Iterable, List, Optional, Tuple

from .. import config
from .entities import (
    BULK_PERSONAL_DATA, CATEGORY_LABELS, CATEGORY_PRIORITY, CHILDREN_DATA, CONFIDENTIAL_BUSINESS, CREDENTIALS,
    ENTITIES, FINANCIAL_DATA, HARMFUL_CONTENT, LEGAL_GOVERNMENT, LOCATION_DATA, MEDICAL_DATA, PERSONAL_DATA,
    PERSONAL_IDENTIFIER_TYPES, PRIVATE_COMMUNICATIONS, SECURITY_TECHNICAL, SENSITIVE_ATTRIBUTES, SEVERITY_RANK,
    SAFETY_CHECK, SOURCE_CODE, SPEC_GROUP, UNSCANNABLE_ATTACHMENT,
)

__all__ = [
    "Finding", "detect", "normalize_text", "bulk_personal_finding", "mask_value", "luhn_valid", "verhoeff_valid",
    "CATEGORY_LABELS", "CREDENTIALS", "PERSONAL_DATA", "FINANCIAL_DATA", "MEDICAL_DATA", "CONFIDENTIAL_BUSINESS",
    "LEGAL_GOVERNMENT", "LOCATION_DATA", "PRIVATE_COMMUNICATIONS", "SENSITIVE_ATTRIBUTES", "CHILDREN_DATA",
    "SECURITY_TECHNICAL", "SOURCE_CODE", "BULK_PERSONAL_DATA", "UNSCANNABLE_ATTACHMENT", "HARMFUL_CONTENT", "SAFETY_CHECK",
]


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    type: str
    start: int = -1
    end: int = -1
    value: str = ""  # raw value: kept in memory only, never logged, stored or returned
    source: str = "prompt"
    detail: str = ""
    extra: dict = field(default_factory=dict)
    method: str = "pattern"
    confidence: float = 0.85
    level: str = ""                 # severity level after classification
    note: str = ""                  # context explanation from the classifier
    action: str = ""                # planned action: redact / review / allow / block / document / request
    action_taken: str = ""          # what finally happened (set after the decision)
    category_override: str = ""
    placeholder_override: str = ""
    label_override: str = ""

    def __post_init__(self) -> None:
        if not self.level:
            self.level = ENTITIES[self.type].severity

    # entity metadata ------------------------------------------------------
    @property
    def entity(self):
        return ENTITIES[self.type]

    @property
    def category(self) -> str:
        return self.category_override or self.entity.category

    @property
    def label(self) -> str:
        return self.label_override or self.entity.label

    @property
    def placeholder_prefix(self) -> str:
        return self.placeholder_override or self.entity.placeholder

    @property
    def scope(self) -> str:
        return self.entity.scope

    @property
    def severity(self) -> int:
        return SEVERITY_RANK.get(self.level, 1)

    @property
    def has_span(self) -> bool:
        return self.start >= 0 and self.end > self.start

    @property
    def redactable(self) -> bool:
        return self.has_span and bool(self.placeholder_prefix) and self.scope == "token"

    def masked(self) -> str:
        return mask_value(self.value, self.category, self.scope)

    def public(self) -> dict:
        """Safe representation for the UI / API: never contains the raw value."""
        return {
            "type": self.type,
            "label": self.label,
            "category": self.category,
            "category_label": CATEGORY_LABELS.get(self.category, self.category),
            "group": SPEC_GROUP.get(self.category, ""),
            "severity": self.level,
            "severity_rank": self.severity,
            "confidence": round(self.confidence, 2),
            "method": self.method,
            "scope": self.scope,
            "action": self.action,
            "action_taken": self.action_taken,
            "note": self.note,
            "source": self.source,
            "masked": self.masked() if self.value else "",
            "detail": self.detail,
            "start": self.start,
            "end": self.end,
        }

    def audit(self) -> dict:
        """Even smaller record for the audit log (no value, no mask)."""
        return {"type": self.type, "category": self.category, "severity": self.level,
                "confidence": round(self.confidence, 2), "method": self.method,
                "action": self.action_taken or self.action, "source": self.source if self.source == "prompt" else "attachment"}


def mask_value(value: str, category: str, scope: str = "token") -> str:
    """Never return the complete original value of a sensitive token."""
    v = (value or "").strip()
    if not v:
        return ""
    if scope in ("document", "request"):
        return v  # keyword/phrase that triggered a classification, not a sensitive value
    if category == CREDENTIALS or category == FINANCIAL_DATA and len(v) <= 6:
        return (v[:4] + "•" * 8) if len(v) >= 16 else (v[:1] + "•" * min(8, max(3, len(v) - 1)))
    if len(v) <= 4:
        return "•" * len(v)
    if len(v) <= 8:
        return v[0] + "•" * (len(v) - 2) + v[-1]
    return v[:2] + "•" * min(8, max(3, len(v) - 4)) + v[-2:]


# ---------------------------------------------------------------------------
# Normalisation (defeats simple evasion such as zero-width characters)
# ---------------------------------------------------------------------------
_ZERO_WIDTH = re.compile("[\u200b\u200c\u200d\u2060\ufeff\u00ad]")


def normalize_text(text: str) -> Tuple[str, int]:
    """Return (normalised_text, number_of_hidden_chars_removed)."""
    text = unicodedata.normalize("NFKC", text or "")
    cleaned, n = _ZERO_WIDTH.subn("", text)
    return cleaned.replace("\r\n", "\n"), n


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------
def luhn_valid(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19 or len(set(digits)) == 1:
        return False
    total, parity = 0, len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def verhoeff_valid(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    c = 0
    for i, d in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][d]]
    return c == 0


def _has_digit(v: str) -> bool:
    return any(ch.isdigit() for ch in v)


# ---------------------------------------------------------------------------
# Rule table: (type, regex, group, method, confidence, validator)
# group 0 = whole match, n = capture group n (only that part is redacted)
# ---------------------------------------------------------------------------
Rule = Tuple[str, "re.Pattern", int, str, float, Optional[Callable[[str], bool]]]
_SEP = r"\s*(?:no\.?|number|num|#|id)?\s*(?:is\s+)?[:#=\-]?\s*"

RULES: List[Rule] = [
    # ── C · Credentials ────────────────────────────────────────────────
    ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----|\Z)"),
     0, "pattern", 0.99, None),
    ("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 0, "pattern", 0.97, None),
    ("AWS_SECRET_KEY", re.compile(r"(?i)aws_?secret(?:_access)?_?key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})"),
     1, "pattern + label", 0.97, None),
    ("GITHUB_TOKEN", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{22,})\b"), 0, "pattern", 0.97, None),
    ("API_KEY", re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_\-]{20,}"), 0, "pattern", 0.95, None),
    ("API_KEY", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"), 0, "pattern", 0.95, None),  # pk_ = public
    ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}"), 0, "pattern", 0.95, None),
    ("API_KEY", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}"), 0, "pattern", 0.95, None),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"), 0, "pattern", 0.97, None),
    ("ACCESS_TOKEN", re.compile(r"(?i)\bbearer\s+([A-Za-z0-9_\-\.=~+/]{20,})"), 1, "pattern + keyword", 0.92, None),
    ("CONNECTION_STRING", re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@'\"]+:[^\s@/'\"]+@[^\s'\"]+"),
     0, "pattern", 0.95, None),
    ("REFRESH_TOKEN", re.compile(r"(?i)\brefresh[_\s\-]?token\b['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-.~+/=]{12,})"),
     1, "pattern + label", 0.92, None),
    ("ENCRYPTION_KEY", re.compile(
        r"(?i)\b(?:encryption|aes|des|3des|hmac|signing|master|kms|jwt[_\s\-]?secret|fernet|cipher)[_\s\-]?key\b['\"]?"
        r"\s*(?:[:=]|\bis\b)\s*['\"]?([A-Za-z0-9+/=_\-]{16,})"), 1, "pattern + label", 0.92, None),
    ("SESSION_COOKIE", re.compile(
        r"(?i)\b(?:session[_\s\-]?(?:id|token|cookie|key)|sessionid|phpsessid|jsessionid|asp\.net_sessionid|connect\.sid|"
        r"auth[_\s\-]?cookie)\b['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9%._\-]{16,})"), 1, "pattern + label", 0.92, None),
    ("SESSION_COOKIE", re.compile(r"(?im)^\s*cookie\s*:\s*(.{16,})$"), 1, "pattern + label", 0.9, None),
    ("OTP", re.compile(
        r"(?i)\b(?:otp|one[\s\-]time\s+(?:password|passcode|code|pin)|verification\s+code|2fa\s+code|security\s+code|"
        r"auth(?:entication)?\s+code|login\s+code)\b(?:\s+(?:is|was))?\s*[:=\-]?\s*(\d{4,8})\b"), 1, "pattern + keyword", 0.93, None),
    ("RECOVERY_CODE", re.compile(
        r"(?i)\b(?:recovery|backup)\s+codes?\b(?:\s+(?:are|is))?\s*[:=\-]?\s*((?:[A-Za-z0-9]{4,10}(?:-[A-Za-z0-9]{3,10})?[ \t,;]*){1,12})"),
     1, "pattern + keyword", 0.9, _has_digit),
    ("CLOUD_CREDENTIAL", re.compile(r"(?i)\bAccountKey=([A-Za-z0-9+/=]{20,})"), 1, "pattern", 0.95, None),
    ("CLOUD_CREDENTIAL", re.compile(r"(?i)\bSharedAccessSignature=([^\s;\"']{12,})"), 1, "pattern", 0.95, None),
    ("CLOUD_CREDENTIAL", re.compile(r"(?i)\"private_key_id\"\s*:\s*\"([a-f0-9]{20,})\""), 1, "pattern", 0.95, None),
    ("CLOUD_CREDENTIAL", re.compile(
        r"(?i)\b(?:gcp|azure|aws|cloud|service[_\s\-]?account)[_\s\-]?(?:secret|credentials?|key)\b['\"]?\s*[:=]\s*['\"]?([^\s'\"]{12,})"),
     1, "pattern + label", 0.9, None),
    # ── B · Financial ──────────────────────────────────────────────────
    ("CARD_CVV_PIN", re.compile(r"(?i)\b(?:cvv2?|cvc2?|card\s+verification\s+(?:value|code))\b\s*(?:is|:|=|-)?\s*(\d{3,4})\b"),
     1, "pattern + keyword", 0.95, None),
    ("CARD_CVV_PIN", re.compile(r"(?i)\b(?:atm|card|debit\s+card|credit\s+card|upi|m|t|login|net\s*banking)[\s\-]?pin\b\s*(?:is|:|=|-)?\s*(\d{4,6})\b"),
     1, "pattern + keyword", 0.94, None),
    ("CARD_CVV_PIN", re.compile(r"(?i)\bpin\b(?!\s*code)(?!code)\s*(?:number\s*)?(?:is|:|=|-)?\s*(\d{4})(?!\d)"),
     1, "pattern + keyword", 0.85, None),
    ("BANK_LOGIN", re.compile(
        r"(?i)\b(?:net\s*banking|internet\s*banking|online\s*banking|bank(?:ing)?)\s+(?:user\s*(?:id|name)|login(?:\s*id)?|customer\s*id|crn)\b"
        r"\s*(?:is|:|=|-)?\s*([A-Za-z0-9._@\-]{4,40})"), 1, "pattern + keyword", 0.92, None),
    ("UPI_ID", re.compile(
        r"(?i)\b([a-z0-9._\-]{2,64}@(?:ok(?:axis|hdfcbank|icici|sbi)|ybl|ibl|axl|paytm|upi|apl|fbl|kotak|icici|sbi|hdfcbank|"
        r"axisbank|airtel|jio|freecharge|barodampay|idfcbank|yapl|rapl|pthdfc|ptsbi|ptaxis|ptyes))\b"), 1, "pattern", 0.93, None),
    ("BANK_ACCOUNT", re.compile(r"(?i)\b(?:a/c|acct|account|bank\s+account|savings\s+account|current\s+account)" + _SEP + r"(\d{9,18})\b"),
     1, "pattern + label", 0.93, None),
    ("BANK_ACCOUNT", re.compile(r"(?i)\b(?:iban)\s*[:#=\-]?\s*([A-Z]{2}\d{2}[A-Z0-9 ]{11,30})"), 1, "pattern + label", 0.93, None),
    # IFSC identifies a bank branch (public); the account number next to it is what is sensitive
    ("IFSC", re.compile(r"(?i)\bifsc(?:\s*code)?\s*[:#=\-]?\s*([A-Z]{4}0[A-Z0-9]{6})\b"), 1, "pattern + label", 0.9, None),
    ("TAX_RECORD", re.compile(
        r"(?i)\b(?:itr(?:\s*ack(?:nowledg(?:e)?ment)?)?|income\s+tax\s+return|tax\s+return|form\s*-?\s*16|tds\s+certificate)" + _SEP +
        r"([A-Z0-9\-/]{6,20})"), 1, "pattern + label", 0.88, _has_digit),
    ("INSURANCE_POLICY", re.compile(r"(?i)\b(?:insurance\s+)?policy" + _SEP + r"([A-Z0-9/\-]{6,20})\b"),
     1, "pattern + label", 0.85, _has_digit),
    ("TRANSACTION_ID", re.compile(r"(?i)\b(?:transaction|txn|utr|upi\s+ref(?:erence)?|payment\s+ref(?:erence)?|order)" + _SEP +
                                  r"([A-Z0-9\-]{8,30})\b"), 1, "pattern + label", 0.85, _has_digit),
    ("CRYPTO_PRIVATE_KEY", re.compile(r"(?i)\b(?:private\s*key|priv\s*key|wallet\s*key|secret\s*key)\s*(?:is|:|=|-)?\s*(?:0x)?([a-f0-9]{64})\b"),
     1, "pattern + label", 0.97, None),
    ("CRYPTO_PRIVATE_KEY", re.compile(r"\b(5[HJK][1-9A-HJ-NP-Za-km-z]{49}|[KL][1-9A-HJ-NP-Za-km-z]{51})\b"), 1, "pattern (WIF)", 0.9, None),
    ("SEED_PHRASE", re.compile(r"(?i)\b(?:seed|recovery|mnemonic|secret|backup)\s+(?:phrase|words)\b\s*(?:is|:|=|-)?\s*((?:[a-z]{3,8}[ \t,]+){11,23}[a-z]{3,8})\b"),
     1, "pattern + keyword", 0.95, None),
    # ── A · PII identifiers ────────────────────────────────────────────
    ("PASSPORT", re.compile(r"(?i)\bpassport" + _SEP + r"([A-Z][0-9]{7}|[A-Z]{1,2}[0-9]{6,8}|[0-9]{9})\b"), 1, "pattern + label", 0.93, None),
    ("DRIVING_LICENCE", re.compile(r"(?i)\b(?:driving\s+licen[cs]e|driver'?s?\s+licen[cs]e|\bDL)" + _SEP +
                                   r"([A-Z]{2}[\-\s]?\d{2}[\-\s]?\d{4}[\-\s]?\d{7}|[A-Z0-9\-]{8,16})\b"), 1, "pattern + label", 0.9, _has_digit),
    ("DRIVING_LICENCE", re.compile(r"\b([A-Z]{2}\-?\d{2}[\-\s]?(?:19|20)\d{2}\s?\d{7})\b"), 1, "pattern", 0.8, None),
    ("VOTER_ID", re.compile(r"(?i)\b(?:voter(?:'s)?\s*(?:id|card)|epic)" + _SEP + r"([A-Z]{3}\d{7})\b"), 1, "pattern + label", 0.93, None),
    ("BIOMETRIC", re.compile(
        r"(?i)\b(?:fingerprint|iris|retina|face\s*(?:print|template|embedding|id)|voice\s*print|biometric)\s*(?:template|hash|data|scan|id|minutiae|vector)?"
        r"\s*[:=]\s*([A-Za-z0-9+/=\-\[\], .]{16,})"), 1, "pattern + label", 0.9, None),
    ("EMPLOYEE_ID", re.compile(r"(?i)\b(?:employee|emp|staff|personnel)\s*(?:id|no\.?|number|code)\s*(?:is|:|#|=|-)?\s*([A-Z]{0,4}-?\d{3,10})\b"),
     1, "pattern + label", 0.9, None),
    ("STUDENT_RECORD", re.compile(
        r"(?i)\b(?:roll\s*(?:no\.?|number)|admission\s*(?:no\.?|number)|student\s*id|enrol(?:l)?ment\s*(?:no\.?|number)|registration\s*no\.?)"
        r"\s*(?:is|:|#|=|-)?\s*([A-Z0-9/\-]{3,20})\b"), 1, "pattern + label", 0.88, _has_digit),
    # ── F · Legal & government ─────────────────────────────────────────
    ("CASE_NUMBER", re.compile(
        r"(?i)\b(?:case|suit|petition|writ\s+petition|appeal|fir|complaint|cnr|crime|criminal\s+case|o\.s\.)\s*(?:no\.?|number|#)\s*[:#\-]?\s*"
        r"([A-Z0-9][A-Z0-9/\-.()]{2,30})"), 1, "pattern + label", 0.9, _has_digit),
    ("VISA_DETAILS", re.compile(
        r"(?i)\b(?:visa|oci(?:\s*card)?|green\s*card|pr\s*card|i-94|a-number|alien\s*registration|residence\s*permit|work\s*permit|brp)"
        r"\s*(?:no\.?|number|#|id)?\s*(?:is|:|#|=|-)?\s*([A-Z0-9]{6,15})\b"), 1, "pattern + label", 0.88, _has_digit),
    # ── G · Location ────────────────────────────────────────────────────
    ("GPS_COORDINATES", re.compile(r"(?i)\blat(?:itude)?\s*[:=]?\s*(-?\d{1,2}\.\d{3,})[\s,;]+lon(?:g(?:itude)?)?\s*[:=]?\s*(-?\d{1,3}\.\d{3,})"),
     0, "pattern + label", 0.95, None),
    ("LIVE_LOCATION", re.compile(r"https?://(?:www\.)?(?:google\.[a-z.]+/maps|maps\.google\.[a-z.]+|maps\.app\.goo\.gl|goo\.gl/maps|maps\.apple\.com)\S*"),
     0, "pattern", 0.95, None),
    ("TRAVEL_BOOKING", re.compile(r"(?i)\b(?:pnr|booking\s+(?:ref(?:erence)?|id|no\.?|number|code)|confirmation\s+(?:code|number)|e-?ticket\s+(?:no\.?|number))"
                                  r"\s*(?:is|:|#|=|-)?\s*([A-Z0-9]{6,13})\b"), 1, "pattern + label", 0.88, _has_digit),
    ("VEHICLE_NUMBER", re.compile(r"\b([A-Z]{2}[ \-]?\d{1,2}[ \-]?[A-Z]{1,3}[ \-]?\d{4})\b"), 1, "pattern", 0.8, None),
    # ── K · Technical ──────────────────────────────────────────────────
    ("INTERNAL_HOST", re.compile(r"(?i)\b((?:[a-z0-9\-]+\.)+(?:internal|corp|intranet|lan))\b"), 1, "pattern", 0.85, None),
]

_BORN_ON = re.compile(
    r"(?i)\b(?:born\s+on|birth\s*day\s+is|birthdate\s+is|d\.o\.b\.?)\s*[:\-]?\s*(\d{1,2}[/.\-]\d{1,2}[/.\-]\d{2,4}|\d{1,2}(?:st|nd|rd|th)?\s+"
    r"(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*,?\s+\d{4})")
_GPS_PAIR = re.compile(r"(?<![\d.])(-?\d{1,2}\.\d{4,})\s*,\s*(-?\d{1,3}\.\d{4,})(?![\d.])")
_IPV4 = re.compile(r"(?<![\d.])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?![\d.])")
_IPV6 = re.compile(r"(?i)(?<![:\w])((?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6})?)(?![:\w])")

# ── Core PII / credential patterns (kept from the original detector) ────────
RE = {
    "GENERIC_API_KEY": re.compile(
        r"(?i)\b([a-z0-9_\-]*(?:api[_\-]?key|apikey|access[_\-]?token|auth[_\-]?token|secret[_\-]?key|client[_\-]?secret|private[_\-]?token))\b"
        r"['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.=/+]{12,})"
    ),
    "PASSWORD": re.compile(
        r"(?i)(?:\b|_)(?:password|passwd|pwd|passcode|passphrase)\b['\"]?\s*(?:[:=]|\bis\b|\bwas\b)\s*['\"]?([^\s'\",;]{4,64})"
    ),
    "PASSWORD_LOOSE": re.compile(
        r"(?i)(?:\b|_)(?:password|passwd|pwd|passcode)\b(?:[ \t]+[A-Za-z']+){1,5}?[ \t]*(?::|=|\bis\b|\bwas\b)[ \t]*['\"]?([^\s'\",;]{4,64})"
    ),
    "KEYWORD_SECRET": re.compile(
        r"(?i)\b(?:api[\s_\-]?key|access[\s_\-]?key|secret[\s_\-]?key|client[\s_\-]?secret|auth(?:entication)?[\s_\-]?token|"
        r"access[\s_\-]?token|bearer[\s_\-]?token|refresh[\s_\-]?token|token|secret|license[\s_\-]?key)\b"
        r"(?:[ \t]+(?:is|was|=|:|for|of))?[ \t]*[:=]?[ \t]*['\"]?([A-Za-z0-9_\-\./+=]{4,})"
    ),
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}\b"),
    "PHONE": re.compile(
        r"(?<![\w+])(?:\+?91[\s\-]?)?[6-9]\d{4}[\s\-]?\d{5}(?!\d)"
        r"|(?<![\w+])\+\d{1,3}[\s\-]?\(?\d{1,4}\)?(?:[\s\-]?\d{2,4}){2,4}(?!\d)"
        r"|\(\d{3}\)\s?\d{3}[\-\s]\d{4}(?!\d)"
        r"|(?<!\d)\d{3}-\d{3}-\d{4}(?!\d)"
        r"|(?<!\d)1[\-\s]?8[06]0[\-\s]?\d{3}[\-\s]?\d{4}(?!\d)"
    ),
    "AADHAAR": re.compile(r"(?<!\d)[2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4}(?!\d)"),
    "PAN": re.compile(r"\b[A-Z]{3}[PCHABGJLFT][A-Z]\d{4}[A-Z]\b"),
    "SSN": re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"),
    "CREDIT_CARD": re.compile(r"(?<!\d)(?:\d[ \-]?){12,18}\d(?!\d)"),
}

# Words that follow "password is ..." in normal sentences (not secrets).
_PASSWORD_STOPWORDS = {
    "required", "needed", "incorrect", "wrong", "invalid", "expired", "missing",
    "empty", "strong", "weak", "correct", "reset", "changed", "the", "not", "too",
    "very", "case", "sensitive", "mandatory", "optional", "stored", "hashed",
    "being", "still", "only", "should", "must", "will", "same", "different",
    "policy", "field", "length", "complex", "secure", "insecure", "null", "none",
    "manager", "protected", "encrypted", "<password>", "****", "xxxx", "redacted",
    "placeholder", "hidden", "something", "for", "and", "that", "this",
}

_STREET_WORDS = r"(?:cross|road|street|lane|nagar|colony|avenue|marg|chowk|enclave|apartments?|residency|towers?|society|bazaar|gali)"
_UNLABELLED_ADDRESS = re.compile(
    r"(?i)(?<![\w.])\d{1,5}(?:[ \t]*[/\-][ \t]*\d{1,4})?[a-z]?,?[ \t]+"
    r"(?:\d{1,2}(?:st|nd|rd|th)[ \t]+(?:main|cross|block|stage|phase|floor)\b|(?:[a-z.]+[ \t]+){0,3}" + _STREET_WORDS + r"\b)"
    r"(?:[ \t,]+(?!(?:and|or|to|for|the|with|please|tomorrow|today|tonight|at|on|in|by|from|is|was|before|after|"
    r"about|regarding|asap|now|then|so|but|come|go|pick|call|please|meet|send|bring|i|we|you|he|she|they|it|my|me|"
    r"his|her|our|their|can|will|should|need|want|lives|stays|near|opposite|behind)\b)[a-z.]+){0,3}"
)

_LABELLED_PERSONAL = re.compile(
    r"(?im)\b(customer name|client name|employee name|patient name|candidate name|full name|child(?:'s)? name|"
    r"student name|ward name|account holder(?: name)?|home address|residential address|postal address|address|"
    r"date of birth|dob|annual salary|salary|ctc|compensation)\s*[:=\-]\s*"
    r"((?:(?!\b(?:customer name|full name|name|address|dob|date of birth|e-?mail|phone|mobile|salary|ctc|"
    r"account|ifsc|aadhaar|pan|passport|born)\b\s*(?:[:=\-]|on\b))[^\n|;]){2,80})"
)
_LABEL_TYPE = [
    ("child", "CHILD_NAME"), ("student", "PERSON_NAME"), ("ward", "CHILD_NAME"),
    ("name", "PERSON_NAME"), ("holder", "PERSON_NAME"), ("address", "ADDRESS"),
    ("birth", "DATE_OF_BIRTH"), ("dob", "DATE_OF_BIRTH"), ("salary", "SALARY"),
    ("ctc", "SALARY"), ("compensation", "SALARY"),
]

_SENSITIVE_COLUMNS = {
    "name": "PERSON_NAME", "full_name": "PERSON_NAME", "customer_name": "PERSON_NAME",
    "employee_name": "PERSON_NAME", "first_name": "PERSON_NAME", "last_name": "PERSON_NAME",
    "client_name": "PERSON_NAME", "email": "EMAIL", "email_address": "EMAIL", "e_mail": "EMAIL",
    "phone": "PHONE", "mobile": "PHONE", "phone_number": "PHONE", "contact": "PHONE",
    "address": "ADDRESS", "city_address": "ADDRESS", "dob": "DATE_OF_BIRTH",
    "date_of_birth": "DATE_OF_BIRTH", "salary": "SALARY", "ctc": "SALARY",
    "aadhaar": "AADHAAR", "aadhar": "AADHAAR", "pan": "PAN", "ssn": "SSN", "passport": "PASSPORT",
    "account": "BANK_ACCOUNT", "account_number": "BANK_ACCOUNT", "account_no": "BANK_ACCOUNT",
    "iban": "BANK_ACCOUNT", "card": "CREDIT_CARD", "card_number": "CREDIT_CARD", "upi": "UPI_ID", "upi_id": "UPI_ID",
    "employee_id": "EMPLOYEE_ID", "emp_id": "EMPLOYEE_ID", "diagnosis": "MEDICAL_RECORD",
}

# ── E · Confidential business lexicon (synthetic organisation: Nimbus Technologies) ──
CONFIDENTIAL_STRONG = [
    "strictly confidential", "company confidential", "confidential", "internal only",
    "internal use only", "do not distribute", "not for distribution", "not for external",
    "under nda", "trade secret", "board eyes only", "internal memo", "confidential contract",
    "internal financial report", "board minutes",
]
PROJECT_CODENAMES = ["project falcon", "project orion", "project nebula"]
CONFIDENTIAL_WEAK = [
    "merger", "acquisition", "acquire", "acquiring", "unreleased", "unannounced",
    "revenue forecast", "earnings", "pricing strategy", "roadmap", "board meeting",
    "board deck", "layoff", "layoffs", "restructuring", "term sheet", "valuation",
    "due diligence", "quarterly results", "profit margin", "go-to-market", "business strategy",
    "customer database", "employee records", "meeting transcript", "internal document",
]

# ── Document-level markers for F, K, L ─────────────────────────────────────
DOC_MARKERS = [
    ("LEGAL_MARKER", re.compile(
        r"(?i)\b(?:attorney[\s\-]client\s+privileged?|privileged\s*(?:&|and)\s*confidential|legally\s+privileged|under\s+seal|"
        r"sealed\s+(?:court\s+)?(?:record|document|order|case)|sub[\s\-]judice|classified\s+(?:document|information|report|material|cable|file)|"
        r"top\s+secret|for\s+official\s+use\s+only|restricted\s*[\-–:]\s*government|charge\s*sheet|case\s+diary|under\s+investigation\s+by|"
        r"confidential\s+government\s+correspondence|non[\s\-]public\s+(?:legal\s+)?proceedings?)\b")),
    ("SECURITY_MARKER", re.compile(
        r"(?i)\b(?:zero[\s\-]?day|0[\s\-]day|unpatched\s+(?:vulnerability|vuln|cve|bug|flaw)|undisclosed\s+(?:vulnerability|vuln|bug|flaw|exploit)|"
        r"not\s+yet\s+(?:been\s+)?(?:patched|disclosed)|embargoed\s+(?:cve|vulnerability|advisory)|"
        r"pen(?:etration)?[\s\-]?test(?:ing)?\s+(?:report|findings|results|credentials)|vapt\s+report|"
        r"security\s+architecture\s+(?:document|doc|diagram)|network\s+(?:topology|diagram)\s+(?:of|for)\s+(?:our|the\s+company|prod(?:uction)?)|"
        r"firewall\s+(?:rules?|config(?:uration)?)\s+(?:for|of)\s+(?:our|prod(?:uction)?|the\s+company)|iptables\s+-[AI]\b|vpn\s+config(?:uration)?)\b")),
    ("IP_MARKER", re.compile(
        r"(?i)\b(?:unpublished\s+(?:research|paper|results|manuscript|data|findings|study)|patent\s+(?:pending|application|draft|filing)|"
        r"provisional\s+patent|invention\s+disclosure|proprietary\s+(?:dataset|data\s*set|algorithm|model\s+weights|design|formula)|"
        r"confidential\s+(?:design|blueprint|schematic|drawings?|cad)|manuscript\s+under\s+review|licensed\s+proprietary|"
        r"licensed\s+under\s+nda|not\s+for\s+redistribution|internal\s+r\s*&\s*d|research\s+and\s+development\s+(?:report|results|plan))\b")),
]

# ── D · Medical (only when tied to a person) ───────────────────────────────
_MED_TERMS = {
    "MENTAL_HEALTH": ["clinical depression", "depression", "anxiety disorder", "anxiety", "bipolar disorder", "bipolar",
                      "schizophrenia", "ptsd", "ocd", "adhd", "eating disorder", "anorexia", "bulimia", "panic disorder",
                      "panic attacks", "insomnia", "postpartum depression"],
    "REPRODUCTIVE_HEALTH": ["pregnant", "pregnancy", "miscarriage", "abortion", "ivf", "infertility", "endometriosis", "pcos", "pcod"],
    "GENETIC_INFO": ["brca1", "brca2", "brca mutation", "sickle cell", "thalassemia", "thalassaemia", "down syndrome",
                     "huntington's", "huntingtons", "cystic fibrosis", "genetic disorder", "a genetic mutation"],
    "DISABILITY_INFO": ["visually impaired", "blind", "deaf", "hearing impaired", "a wheelchair user", "wheelchair-bound",
                        "paralysed", "paralyzed", "locomotor disability", "intellectual disability", "cerebral palsy",
                        "dyslexia", "dyslexic", "an amputee", "autism", "autistic", "a disability"],
    "MEDICAL_DIAGNOSIS": ["type 1 diabetes", "type 2 diabetes", "diabetes", "diabetic", "hypertension", "high blood pressure",
                          "breast cancer", "lung cancer", "cancer", "leukemia", "leukaemia", "a tumour", "a tumor", "tumour", "tumor",
                          "hiv", "aids", "hepatitis b", "hepatitis c", "hepatitis", "tuberculosis", "asthma", "copd", "epilepsy",
                          "a stroke", "heart disease", "kidney disease", "ckd", "cirrhosis", "covid-19", "covid", "thyroid",
                          "hypothyroidism", "migraine", "arthritis", "alzheimer's", "dementia", "parkinson's", "multiple sclerosis",
                          "an std", "herpes", "syphilis", "gonorrhea", "dengue", "malaria", "typhoid", "a heart condition"],
}
_TERM_TYPE = {t: k for k, ts in _MED_TERMS.items() for t in ts}
_MED_ALT = "|".join(re.escape(t) for t in sorted(_TERM_TYPE, key=len, reverse=True))
_MED_MOD = r"(?:(?:stage\s+\w+|type\s+[12]|severe|mild|chronic|acute|early|late[\s\-]stage|clinical|moderate)\s+)?"
_MED_PERSONAL = [
    re.compile(r"(?i)\b(?:diagnosed\s+with|suffering\s+from|suffers\s+from|tested\s+positive\s+for|(?:being\s+)?treated\s+for|"
               r"undergoing\s+(?:treatment|chemo(?:therapy)?|dialysis|therapy)\s+for|admitted\s+(?:to\s+(?:the\s+)?hospital\s+)?(?:for|with)|"
               r"recovering\s+from|on\s+medication\s+for|living\s+with|battling|(?:has|have|had|with)\s+a\s+(?:family\s+)?history\s+of)\s+"
               r"(" + _MED_MOD + r"(?:" + _MED_ALT + r"))\b"),
    re.compile(r"(?i)\b(?:I|I'm|I\s+am|he|she|they|he's|she's|my\s+[a-z\-]+|his\s+[a-z\-]+|her\s+[a-z\-]+|their\s+[a-z\-]+|"
               r"the\s+patient|patient|our\s+employee|the\s+employee|employee|the\s+candidate|candidate|[A-Z][a-z]+)\s+"
               r"(?:has|have|had|is|was|am|are|got|has\s+been|was\s+found\s+to\s+have)\s+(?:been\s+)?(?:diagnosed\s+with\s+)?"
               r"(" + _MED_MOD + r"(?:" + _MED_ALT + r"))\b"),
]
_MED_LABELLED = re.compile(
    r"(?i)\b(?:diagnosis|medical\s+history|medical\s+condition|medication|prescription|rx|blood\s+group|blood\s+type|hba1c|"
    r"blood\s+sugar|fasting\s+sugar|bp\s+reading|test\s+results?|lab\s+results?|report\s+findings|mrn|uhid|patient\s+id|"
    r"genetic\s+test(?:\s+result)?|disability(?:\s+percentage)?)\s*[:=\-]\s*([^\n;|]{2,60})")
_PRESCRIPTION = re.compile(
    r"(?i)\b(?:prescribed|taking|on)\s+((?:[A-Za-z\-]+\s+){0,2}\d+(?:\.\d+)?\s*(?:mg|mcg|ml|iu|units?)\b"
    r"(?:\s+(?:once|twice|thrice|daily|od|bd|tds|bid|tid|qid|at\s+night|every\s+\d+\s+hours))*)")

# ── I · Sensitive personal attributes (tied to a person) ───────────────────
_ATTR_TERMS = {
    "RELIGION": ["hindu", "muslim", "christian", "sikh", "jain", "buddhist", "jewish", "parsi", "zoroastrian",
                 "atheist", "agnostic", "catholic", "protestant"],
    "CASTE": ["dalit", "brahmin", "kshatriya", "vaishya", "shudra", "obc", "sc/st", "scheduled caste", "scheduled tribe", "adivasi"],
    "SEXUAL_ORIENTATION": ["gay", "lesbian", "bisexual", "homosexual", "asexual", "pansexual", "queer"],
    "GENDER_IDENTITY": ["transgender", "trans woman", "trans man", "non-binary", "nonbinary", "genderqueer", "genderfluid", "intersex"],
}
_ATTR_TYPE = {t: k for k, ts in _ATTR_TERMS.items() for t in ts}
_ATTR_ALT = "|".join(re.escape(t) for t in sorted(_ATTR_TYPE, key=len, reverse=True))
_PARTIES = (r"BJP|INC|Congress|AAP|CPI\(M\)|CPI|CPM|TMC|DMK|AIADMK|BSP|Samajwadi\s+Party|Shiv\s+Sena|JD\(U\)|RJD|NCP|"
            r"Republican\s+Party|Democratic\s+Party|Labour\s+Party|Conservative\s+Party")
_ATTR_PATTERNS = [
    (None, re.compile(r"(?i)\b(?:I\s+am|I'm|he\s+is|she\s+is|he's|she's|they\s+are|they're|my\s+[a-z\-]+\s+is|his\s+[a-z\-]+\s+is|"
                      r"her\s+[a-z\-]+\s+is|employee\s+is|candidate\s+is|applicant\s+is|[A-Z][a-z]+\s+is)\s+"
                      r"(?:(?:a|an|openly|devout|practi[sc]ing|born|proud)\s+){0,3}(" + _ATTR_ALT + r")\b")),
    ("POLITICAL_AFFILIATION", re.compile(r"(?:\b(?i:member|supporter|worker|volunteer|office[\s\-]bearer)\s+(?i:of|for)\s+(?:the\s+)?)(" + _PARTIES + r")\b")),
    ("POLITICAL_AFFILIATION", re.compile(r"(?i)\b(?:is|am|are)\s+an?\s+((?:" + _PARTIES + r")\s+(?:supporter|member|worker|voter|loyalist))\b")),
    ("UNION_MEMBERSHIP", re.compile(r"(?i)\b(?:is|am|are|was|has\s+been|became)\s+(?:a\s+)?(member\s+of\s+(?:the\s+)?(?:[\w\-]+\s+){0,4}(?:trade\s+)?union)\b")),
    ("UNION_MEMBERSHIP", re.compile(r"(?i)\b(?:he|she|I|employee)\s+(?:is|am)\s+(?:a\s+)?(union\s+member)\b")),
    ("ETHNICITY", re.compile(r"(?i)\b(?:is|am|are)\s+of\s+([a-z]+(?:\s+[a-z]+)?\s+(?:descent|ethnicity|origin))\b")),
]
_ATTR_LABELLED = re.compile(
    r"(?i)\b(religion|caste|sub-?caste|ethnicity|race|sexual\s+orientation|gender\s+identity|political\s+(?:affiliation|party|views)|"
    r"party\s+membership|union\s+membership)\s*[:=\-]\s*([A-Za-z][A-Za-z /()\-]{1,40})")
_ATTR_LABEL_TYPE = [("religion", "RELIGION"), ("caste", "CASTE"), ("ethnic", "ETHNICITY"), ("race", "ETHNICITY"),
                    ("orientation", "SEXUAL_ORIENTATION"), ("gender", "GENDER_IDENTITY"), ("politic", "POLITICAL_AFFILIATION"),
                    ("party", "POLITICAL_AFFILIATION"), ("union", "UNION_MEMBERSHIP")]

# ── H · Private communications ─────────────────────────────────────────────
_CHAT_LINE = re.compile(
    r"(?m)^\[?\d{1,2}[/.\-]\d{1,2}[/.\-]\d{2,4},?\s+\d{1,2}:\d{2}(?::\d{2})?\s*(?:[APap]\.?[Mm]\.?)?\]?\s*(?:[\-–]\s*)?([^:\n]{1,40}?):\s")
_EMAIL_HEADER = re.compile(r"(?mi)^(?:from|to|cc|bcc)\s*:\s*(.+?)\s*$")
_VCARD_FN = re.compile(r"(?m)^(?:FN|N):(.+)$")

# ── J · Children ───────────────────────────────────────────────────────────
_CHILD_NAME = re.compile(
    r"(?i:\b(?:my|his|her|our|their)\s+(?:\d{1,2}[\s\-](?:year|yr)s?[\s\-]old\s+)?(?:son|daughter|child|kid|nephew|niece|grandson|"
    r"granddaughter|stepson|stepdaughter|baby\s+(?:boy|girl)))(?:'s\s+name\s+is|,|\s+named|\s+called|\s+is)?\s+([A-Z][a-z]{1,20})\b")
_NOT_NAMES = {"Is", "The", "And", "But", "Who", "He", "She", "Has", "Was", "Will", "Can", "In", "At", "On", "To", "From"}

# ── Harmful or prohibited use (intent phrases, not single words) ────────────
_PEOPLE = (r"(?:him|her|them|me|us|you|someone|somebody|anyone|people|a\s+person|a\s+human|"
           r"(?:my|his|her|their|your|our|the)\s+(?:wife|husband|boss|manager|colleague|co-?worker|neighbou?r|friend|"
           r"teacher|father|mother|dad|mom|mum|brother|sister|child|children|kids?|son|daughter|ex|girlfriend|"
           r"boyfriend|family|landlord|client|customer|employees?|team|president|minister|police|crowd|students?))")
_PLACES = r"(?:(?:his|her|their|my|your|the|a|our)\s+(?:house|home|office|school|building|car|shop|hospital|temple|mosque|church|village))"
_HARMFUL_PATTERNS = [
    ("VIOLENCE", re.compile(
        r"(?i)\b(?:kill|murder|stab|shoot|strangle|poison|kidnap|abduct|assassinate|behead|torture|beat\s+up|"
        r"blow\s+up|bomb|air[\s\-]?strike|set\s+fire\s+to|burn\s+down|attack|hurt|harm|rape|run\s+over)\s+"
        r"(?:\w+\s+){0,2}?(?:" + _PEOPLE + r"|" + _PLACES + r")\b"
        r"(?!\s+(?:an?\s+)?(?:e-?mail|mail|message|text|note|line|dm|ping|reminder|invite|update|call|quick))")),
    ("VIOLENCE", re.compile(
        r"(?i)\b(?:dissolve|dispose\s+of|get\s+rid\s+of|hide|bury|burn|dismember|chop\s+up)\s+"
        r"(?:(?:a|the|his|her|their|my|this|that)\s+)?(?:dead\s+)?(?:human\s+)?(?:body|bodies|corpse|corpses)\b"
        r"(?!\s+(?:fluids?|fat|weight|text|of\s+(?:the|an?)\s+(?:email|letter|document|text|essay)))")),
    ("WEAPONS", re.compile(
        r"(?i)\b(?:make|build|assemble|construct|create|3d[\s\-]?print|synthesi[sz]e|cook\s+up|brew|get|buy)\s+"
        r"(?:an?\s+|some\s+)?(?:\w+\s+)?(?:pipe\s*bomb|bomb|explosives?|ied|grenade|molotov|napalm|untraceable\s+gun|"
        r"ghost\s+gun|silencer|nerve\s+agent|sarin|ricin|anthrax|poison\s+gas|chemical\s+weapon|bio-?weapon|dirty\s+bomb)s?\b")),
    ("ILLEGAL_DRUGS", re.compile(
        r"(?i)\b(?:make|cook|synthesi[sz]e|produce|manufacture|extract)\s+(?:some\s+)?"
        r"(?:meth|methamphetamine|cocaine|crack|heroin|lsd|mdma|ecstasy|fentanyl|ghb)\b")),
    ("SELF_HARM", re.compile(
        r"(?i)\b(?:kill\s+myself|end\s+my\s+(?:own\s+)?life|take\s+my\s+(?:own\s+)?life|commit\s+suicide|"
        r"suicide\s+(?:method|methods|note|plan)|want\s+to\s+die|hurt\s+myself|harm\s+myself|cut\s+myself)\b")),
    # (the bare term "self-harm" was removed: it blocked safeguarding / recovery questions – context is judged
    #  by the local safety model instead)
    ("ILLEGAL_ACTIVITY", re.compile(
        r"(?i)\b(?:hack\s+into|break\s+into|get\s+into|access)\s+(?:someone(?:'s|s)?|somebody(?:'s|s)?|"
        r"(?:my|his|her|their)\s+(?:\w+(?:'s)?\s+)?)(?:\w+\s+)?(?:account|email|e-mail|phone|instagram|facebook|"
        r"whatsapp|wifi|wi-fi|bank|laptop|computer)\b")),
    ("ILLEGAL_ACTIVITY", re.compile(
        r"(?i)\b(?:launder(?:ing)?\s+(?:the\s+)?money|money\s+laundering\s+(?:scheme|plan|method)|"
        r"steal\s+(?:someone'?s?\s+|his\s+|her\s+|their\s+)?(?:identity|credit\s+cards?|money|credentials|passwords?)|"
        r"(?:write|create|build|make)\s+(?:a\s+|some\s+)?(?:ransomware|keylogger|malware|computer\s+virus|phishing\s+(?:page|site|email))|"
        r"evade\s+(?:taxes|tax|the\s+police)|bribe\s+(?:a|the)\s+(?:official|officer|judge|inspector))\b")),
]
_HARMFUL_FALSE_FRIENDS = re.compile(r"(?i)\b(?:bath\s+bomb|photo\s*bomb|bomb(?:ed)?\s+(?:the|my|an?)\s+(?:interview|exam|test|presentation))\b")

# ── L · Source code ────────────────────────────────────────────────────────
_CODE_LINE = re.compile(
    r"""^\s*(?:
        (?:def|class|import|return|elif|lambda|yield|raise)\b
        |(?:try|finally|else)\s*:|except\b|with\s.+:\s*$|async\s+def\b
        |from\s+[\w.]+\s+import\b
        |@\w+
        |(?:public|private|protected|static|void|const|let|var|function|package|interface|struct|fn|func)\b
        |\#include\b|using\s+namespace\b
        |(?:SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER)\s.+
        |.*[;{}]\s*$
        |.*=>.*
        |(?:if|for|while)\s.*[:{]\s*$
        |\w+\s*=\s*.+\(.*\)\s*$
    )""",
    re.VERBOSE,
)
_PROPRIETARY_CODE = re.compile(
    r"(?i)copyright\s*(?:\(c\)|©)?\s*(?:\d{4}\s*)?nimbus|nimbus\.internal|proprietary|@nimbus\b|com\.nimbus\."
)
SOURCE_CODE_MIN_LINES = 8


# ---------------------------------------------------------------------------
# Detector functions
# ---------------------------------------------------------------------------
def _span_of_group(m: "re.Match", group: int = 1) -> Tuple[int, int, str]:
    if group and m.lastindex and m.lastindex >= group:
        return m.start(group), m.end(group), m.group(group)
    return m.start(), m.end(), m.group(0)


def _rule_findings(text: str, source: str) -> List[Finding]:
    out: List[Finding] = []
    for ftype, rx, group, method, conf, validator in RULES:
        for m in rx.finditer(text):
            s, e, v = _span_of_group(m, group)
            v_stripped = v.rstrip(" \t,;.")
            if not v_stripped or (validator and not validator(v_stripped)):
                continue
            out.append(Finding(ftype, s, s + len(v_stripped), v_stripped, source, method=method, confidence=conf))
    # "born on 12/03/1990" / "born on 12 March 1990"
    for m in _BORN_ON.finditer(text):
        out.append(Finding("DATE_OF_BIRTH", m.start(1), m.end(1), m.group(1), source, method="pattern + keyword", confidence=0.9))
    # GPS "12.9716, 77.5946" (range-checked)
    for m in _GPS_PAIR.finditer(text):
        lat, lon = float(m.group(1)), float(m.group(2))
        if -90 <= lat <= 90 and -180 <= lon <= 180:
            out.append(Finding("GPS_COORDINATES", m.start(), m.end(), m.group(0), source, method="pattern + range check",
                               confidence=0.85))
    # IP addresses
    for m in _IPV4.finditer(text):
        before = text[max(0, m.start() - 12): m.start()].lower()
        if re.search(r"(?:version|ver\.?|v)\s*$", before):
            continue
        ip = m.group(1)
        octets = [int(x) for x in ip.split(".")]
        private = octets[0] == 10 or (octets[0] == 172 and 16 <= octets[1] <= 31) or (octets[0] == 192 and octets[1] == 168)
        out.append(Finding("INTERNAL_IP" if private else "IP_ADDRESS", m.start(1), m.end(1), ip, source,
                           method="pattern + range check", confidence=0.85))
    for m in _IPV6.finditer(text):
        if m.group(1).count(":") >= 3:
            out.append(Finding("IP_ADDRESS", m.start(1), m.end(1), m.group(1), source, method="pattern", confidence=0.8))
    return out


def _core_findings(text: str, source: str) -> List[Finding]:
    out: List[Finding] = []
    for m in RE["GENERIC_API_KEY"].finditer(text):
        key = m.group(1).lower()
        ftype = ("OAUTH_SECRET" if "client" in key else "REFRESH_TOKEN" if "refresh" in key else
                 "ACCESS_TOKEN" if "token" in key else "API_KEY")
        out.append(Finding(ftype, m.start(2), m.end(2), m.group(2), source, method="pattern + label", confidence=0.92))

    for m in RE["PASSWORD"].finditer(text):
        s, e, v = _span_of_group(m)
        sep = text[m.start():s].lower()
        bare = v.strip("'\"").lower()
        if bare in _PASSWORD_STOPWORDS or bare.startswith("[") or bare.startswith("<"):
            continue
        if (" is" in sep or " was" in sep) and not re.search(r"[\d\W_]", v) and len(v) < 8:
            continue
        out.append(Finding("PASSWORD", s, e, v, source, method="pattern + keyword", confidence=0.92))

    for m in RE["PASSWORD_LOOSE"].finditer(text):
        s, e, v = _span_of_group(m)
        bare = v.strip("'\"").lower()
        if bare in _PASSWORD_STOPWORDS or not re.search(r"[\d\W_]", v):
            continue
        out.append(Finding("PASSWORD", s, e, v, source, method="keyword context", confidence=0.85))

    for m in RE["KEYWORD_SECRET"].finditer(text):
        s, e, v = _span_of_group(m)
        v_clean = v.rstrip(".")
        if not re.search(r"\d", v_clean) or len(v_clean) < 6 or v_clean.lower().startswith(("http", "www.")):
            continue
        out.append(Finding("API_KEY", s, s + len(v_clean), v_clean, source, method="keyword context", confidence=0.8))

    for m in _UNLABELLED_ADDRESS.finditer(text):
        val = m.group(0).rstrip(" ,.")
        out.append(Finding("ADDRESS", m.start(), m.start() + len(val), val, source, detail="street address",
                           method="heuristic (street pattern)", confidence=0.7))

    for m in RE["EMAIL"].finditer(text):
        out.append(Finding("EMAIL", m.start(), m.end(), m.group(0), source, method="pattern", confidence=0.97))

    for m in RE["CREDIT_CARD"].finditer(text):
        if luhn_valid(m.group(0)):
            out.append(Finding("CREDIT_CARD", m.start(), m.end(), m.group(0), source, method="pattern + Luhn checksum",
                               confidence=0.95))

    for m in RE["AADHAAR"].finditer(text):
        window = text[max(0, m.start() - 40): m.start()].lower()
        labelled = "aadhaar" in window or "aadhar" in window or "uid" in window
        valid = verhoeff_valid(m.group(0))
        if valid or labelled:
            out.append(Finding("AADHAAR", m.start(), m.end(), m.group(0), source,
                               method="pattern + Verhoeff checksum" if valid else "pattern + label (checksum failed)",
                               confidence=0.96 if valid else 0.65, extra={"checksum_valid": valid, "labelled": labelled}))

    for m in RE["PHONE"].finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if 10 <= len(digits) <= 15:
            out.append(Finding("PHONE", m.start(), m.end(), m.group(0), source, method="pattern", confidence=0.85))

    for ftype, conf in (("PAN", 0.9), ("SSN", 0.85)):
        for m in RE[ftype].finditer(text):
            out.append(Finding(ftype, m.start(), m.end(), m.group(0), source, method="pattern", confidence=conf))

    for m in _LABELLED_PERSONAL.finditer(text):
        label = m.group(1).lower()
        ftype = next((t for key, t in _LABEL_TYPE if key in label), None)
        if not ftype:
            continue
        s = m.start(2)
        value = m.group(2)
        if ftype in ("PERSON_NAME", "CHILD_NAME"):
            cut = value.find(",")
            if cut > 0:
                value = value[:cut]
        elif ftype in ("SALARY", "DATE_OF_BIRTH"):
            mcut = re.search(r",\s+[A-Za-z]", value)  # "18,00,000, born on …" → "18,00,000"
            if mcut:
                value = value[:mcut.start()]
        stripped = value.rstrip(" .,")
        if len(stripped.strip()) >= 2:
            out.append(Finding(ftype, s, s + len(stripped), stripped, source, method="pattern + label", confidence=0.9))
    return out


def _medical_findings(text: str, source: str) -> List[Finding]:
    out: List[Finding] = []
    for rx in _MED_PERSONAL:
        for m in rx.finditer(text):
            term = m.group(1)
            base = re.sub(r"(?i)^" + _MED_MOD, "", term).lower()
            ftype = _TERM_TYPE.get(base, "MEDICAL_DIAGNOSIS")
            out.append(Finding(ftype, m.start(1), m.end(1), term, source, method="lexicon + personal context", confidence=0.85))
    for m in _MED_LABELLED.finditer(text):
        v = m.group(1).rstrip(" .,")
        out.append(Finding("MEDICAL_RECORD", m.start(1), m.start(1) + len(v), v, source, method="pattern + label", confidence=0.9))
    for m in _PRESCRIPTION.finditer(text):
        out.append(Finding("PRESCRIPTION", m.start(1), m.end(1), m.group(1), source, method="pattern (dosage)", confidence=0.85))
    return out


def _attribute_findings(text: str, source: str) -> List[Finding]:
    out: List[Finding] = []
    for ftype, rx in _ATTR_PATTERNS:
        for m in rx.finditer(text):
            t = ftype or _ATTR_TYPE.get(m.group(1).lower(), "RELIGION")
            out.append(Finding(t, m.start(1), m.end(1), m.group(1), source, method="lexicon + personal context", confidence=0.85))
    for m in _ATTR_LABELLED.finditer(text):
        label = m.group(1).lower()
        t = next((tt for k, tt in _ATTR_LABEL_TYPE if k in label), "RELIGION")
        v = m.group(2).rstrip(" .,")
        out.append(Finding(t, m.start(2), m.start(2) + len(v), v, source, method="pattern + label", confidence=0.9))
    return out


def _communication_findings(text: str, source: str) -> List[Finding]:
    out: List[Finding] = []
    chat = list(_CHAT_LINE.finditer(text))
    if len(chat) >= 2:  # a pasted conversation, not a single timestamp
        for m in chat:
            name = m.group(1).strip()
            if name:
                out.append(Finding("CHAT_PARTICIPANT", m.start(1), m.start(1) + len(m.group(1).rstrip()), name, source,
                                   method="pattern (chat export)", confidence=0.85))
    headers = list(_EMAIL_HEADER.finditer(text))
    if len(headers) >= 2 or (headers and re.search(r"(?mi)^subject\s*:", text)):
        for m in headers:
            out.append(Finding("EMAIL_CORRESPONDENT", m.start(1), m.end(1), m.group(1), source,
                               method="pattern (email header)", confidence=0.85))
    if "BEGIN:VCARD" in text.upper():
        for m in _VCARD_FN.finditer(text):
            out.append(Finding("CONTACT_ENTRY", m.start(1), m.end(1), m.group(1), source, method="pattern (vCard)", confidence=0.9))
    for m in _CHILD_NAME.finditer(text):
        if m.group(1) not in _NOT_NAMES:
            out.append(Finding("CHILD_NAME", m.start(1), m.end(1), m.group(1), source, method="pattern + relation context",
                               confidence=0.85))
    return out


def _harmful_findings(text: str, source: str) -> List[Finding]:
    out: List[Finding] = []
    for ftype, rx in _HARMFUL_PATTERNS:
        for m in rx.finditer(text):
            if _HARMFUL_FALSE_FRIENDS.search(m.group(0)):
                continue
            out.append(Finding(ftype, m.start(), m.end(), m.group(0), source, detail="harmful intent",
                               method="intent phrase lexicon", confidence=0.9))
    return out


def _tabular_findings(text: str, source: str) -> List[Finding]:
    """Detect personal data columns in CSV/TSV-like text (customer exports)."""
    lines = text.split("\n")
    if len(lines) < 2:
        return []
    out: List[Finding] = []
    offset = 0
    i = 0
    while i < len(lines) - 1:
        header = lines[i]
        delim = max([",", "\t", ";", "|"], key=lambda d: header.count(d))
        if header.count(delim) >= 1:
            cols = [re.sub(r"[\s\-]+", "_", c.strip().strip('"').lower()) for c in header.split(delim)]
            sensitive = {}
            for idx, c in enumerate(cols):
                if c in _SENSITIVE_COLUMNS:
                    sensitive[idx] = _SENSITIVE_COLUMNS[c]
                elif c.endswith("_name") and c not in ("file_name", "product_name", "company_name", "project_name"):
                    sensitive[idx] = "PERSON_NAME"
            if sensitive:
                row_offset = offset + len(header) + 1
                j = i + 1
                while j < len(lines) and lines[j].count(delim) == header.count(delim) and lines[j].strip():
                    cells = lines[j].split(delim)
                    pos = row_offset
                    for idx, cell in enumerate(cells):
                        if idx in sensitive and cell.strip().strip('"'):
                            lead = len(cell) - len(cell.lstrip())
                            val = cell.strip()
                            out.append(Finding(sensitive[idx], pos + lead, pos + lead + len(val), val, source,
                                               detail="column '%s'" % cols[idx], method="column header", confidence=0.9))
                        pos += len(cell) + 1
                    row_offset += len(lines[j]) + 1
                    j += 1
                for k in range(i, j):
                    offset += len(lines[k]) + 1
                i = j
                continue
        offset += len(header) + 1
        i += 1
    return out


def _confidential_findings(text: str, source: str) -> List[Finding]:
    low = text.lower()
    strong: List[Finding] = []
    for term in CONFIDENTIAL_STRONG + PROJECT_CODENAMES:
        for m in re.finditer(r"(?<![\w-])" + re.escape(term) + r"(?![\w-])", low):
            strong.append(Finding("CONFIDENTIAL_MARKER", m.start(), m.end(), text[m.start():m.end()], source,
                                  detail="project codename" if term in PROJECT_CODENAMES else "classification marker",
                                  method="lexicon", confidence=0.9))
    weak: List[Finding] = []
    for term in CONFIDENTIAL_WEAK:
        for m in re.finditer(r"(?<![\w-])" + re.escape(term) + r"(?![\w-])", low):
            weak.append(Finding("BUSINESS_SENSITIVE_TERM", m.start(), m.end(), text[m.start():m.end()], source,
                                detail="sensitive business topic", method="lexicon (2+ topics)", confidence=0.75))
    distinct_weak = {f.value.lower() for f in weak}
    if strong or len(distinct_weak) >= 2:
        return strong + weak
    return []


def _document_marker_findings(text: str, source: str) -> List[Finding]:
    out: List[Finding] = []
    for ftype, rx in DOC_MARKERS:
        for m in rx.finditer(text):
            out.append(Finding(ftype, m.start(), m.end(), m.group(0), source, method="lexicon", confidence=0.85))
    return out


def _source_code_findings(text: str, source: str, is_code_file: bool = False) -> List[Finding]:
    lines = [ln for ln in text.split("\n") if ln.strip()]
    code_lines = sum(1 for ln in lines if _CODE_LINE.match(ln))
    proprietary = bool(_PROPRIETARY_CODE.search(text))
    if (code_lines >= SOURCE_CODE_MIN_LINES) or (proprietary and code_lines >= 2):
        detail = "%d code lines%s" % (code_lines, ", proprietary marker" if proprietary else "")
        return [Finding("SOURCE_CODE_BLOCK", source=source, detail=detail, extra={"lines": code_lines},
                        method="code-structure heuristic", confidence=0.85)]
    return []


# ---------------------------------------------------------------------------
# Overlap handling: overlapping spans are MERGED (never left half-redacted)
# ---------------------------------------------------------------------------
def _rank(f: Finding):
    return (f.severity, CATEGORY_PRIORITY.get(f.category, 0), f.end - f.start, f.confidence)


def _merge_overlaps(text: str, findings: List[Finding]) -> List[Finding]:
    """Cluster overlapping spans; each cluster becomes ONE finding that covers the
    union of the spans, typed after its most severe member. This guarantees that
    overlapping detections never leave a fragment of a value unredacted.

    Document-level markers (confidential keywords, harmful phrases) are kept as
    separate findings – they classify the request rather than mark a value."""
    spans = sorted((f for f in findings if f.has_span and f.scope == "token"), key=lambda f: (f.start, -f.end))
    markers = [f for f in findings if f.has_span and f.scope != "token"]
    others = [f for f in findings if not f.has_span]
    clusters: List[List[Finding]] = []
    for f in spans:
        if clusters and f.start < max(x.end for x in clusters[-1]):
            clusters[-1].append(f)
        else:
            clusters.append([f])
    merged: List[Finding] = []
    for cl in clusters:
        best = max(cl, key=_rank)
        s, e = min(x.start for x in cl), max(x.end for x in cl)
        if (s, e) != (best.start, best.end):
            best.start, best.end, best.value = s, e, text[s:e]
            best.detail = (best.detail + "; " if best.detail else "") + "merged with %d overlapping detection(s)" % (len(cl) - 1)
        if len(cl) > 1:
            best.confidence = max(x.confidence for x in cl)
        merged.append(best)
    # de-duplicate identical markers
    seen = set()
    uniq_markers = []
    for f in sorted(markers, key=lambda f: (f.start, -(f.end - f.start))):
        key = (f.type, f.start, f.end)
        if key in seen or any(m.type == f.type and m.start <= f.start and f.end <= m.end for m in uniq_markers):
            continue
        seen.add(key)
        uniq_markers.append(f)
    return sorted(merged + uniq_markers, key=lambda f: f.start) + others



# ---------------------------------------------------------------------------
# Labelled identifiers in forms, tables and prose ("Account Number: …",
# "| CVV | 123", "his medical record number is …"). Added after evaluating
# against the Nemotron-PII dev sample – see dataset_audit/.
# ---------------------------------------------------------------------------
_ID_SEP = r"(?:\*\*|__)?\s*(?:\([A-Za-z]{2,6}\))?\s*(?:\*\*|__)?\s*(?:[:|=#,\-–]\s*|\s)(?:\*\*\s*)?(?:(?:is|was|of|reads|for\s+(?:this|the|your|his|her|their)\s+\w+\s+is)\s*[:\-]?\s*)?[`'\"]?"
_DATE_VALUE = (r"(?:\d{4}-\d{2}-\d{2}|\d{1,2}[/.\-]\d{1,2}[/.\-]\d{2,4}|"
               r"\d{1,2}(?:st|nd|rd|th)?\s+(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?,?\s+\d{4}|"
               r"(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?\s+\d{1,2}(?:st|nd|rd|th)?,?\s+\d{4})")
_ID_VALUE = r"([A-Z0-9][A-Z0-9 .\-/]{2,30}[A-Z0-9]|\d{3,})"
_LABELLED_IDS = [
    # (type, label regex, value regex, min digits, confidence)
    ("CREDIT_CARD", r"(?:credit|debit|credit\s*/?\s*debit|payment|bank)\s+card(?:\s+(?:number|no\.?|#))?|card\s+(?:number|no\.?)",
     r"((?:\d[ \-]?){12,18}\d)(?!\d)", 12, 0.88),
    ("CARD_CVV_PIN", r"cvv2?|cvc2?|card\s+verification\s+(?:value|code)", r"(\d{3,4})(?!\d)", 3, 0.9),
    # "pin code" is excluded: in India it is the postal code (handled as part of an address)
    ("CARD_CVV_PIN", r"(?:billing\s+|atm\s+|card\s+|secure\s+|login\s+|transaction\s+)?pin(?:\s+number)?(?!\s*code)|"
     r"personal\s+identification\s+number", r"(\d{4,8})(?![\d\-/])", 4, 0.85),
    ("BANK_ACCOUNT", r"(?:bank\s+)?account\s+(?:number|no\.?|#)|acct\.?\s*(?:number|no\.?|#)",
     r"([A-Z]{0,4}\d[\d \-]{4,32}\d)(?![\dA-Za-z])", 6, 0.88),
    ("MEDICAL_RECORD", r"medical\s+record\s+(?:number|no\.?|#|id)|mrn|patient\s+(?:id|number)", _ID_VALUE, 4, 0.88),
    ("INSURANCE_POLICY", r"health\s+plan(?:\s+beneficiary)?\s+(?:number|no\.?|id)|(?:health\s+)?insurance\s+(?:member\s+)?(?:id|number)|"
     r"member\s+id|beneficiary\s+(?:number|id)", _ID_VALUE, 4, 0.86),
    ("NATIONAL_ID", r"national\s+(?:id(?:entity)?|identification|insurance)(?:\s+(?:card\s+)?(?:number|no\.?))?|"
     r"(?:personal|citizen|resident)\s+id(?:entity)?\s+(?:number|no\.?)", _ID_VALUE, 6, 0.88),
    ("TAX_RECORD", r"tax\s+(?:id(?:entification)?|identification)(?:\s+(?:number|no\.?))?|tin|ein|itin|vat\s+(?:number|id|no\.?)",
     _ID_VALUE, 6, 0.85),
    ("EMPLOYEE_ID", r"employee\s+(?:id|number|no\.?|code)|staff\s+(?:id|number)|personnel\s+(?:id|number)",
     r"([A-Z0-9]{1,5}(?:-[A-Z0-9]{1,8}){0,3}|\d{3,10})(?![\w\-])", 3, 0.86),
    ("BIOMETRIC", r"biometric\s+(?:identifier|id|template|hash)|fingerprint\s+(?:id|hash|template)|(?:face|iris|voice)\s*(?:print\s+)?id",
     r"([A-Z0-9][A-Z0-9\-]{5,40})(?![\w\-])", 4, 0.88),
    ("DATE_OF_BIRTH", r"date\s+of\s+birth|d\.?o\.?b\.?|birth\s*date|born\s+on|born", r"(" + _DATE_VALUE + r")", 2, 0.9),
    ("SESSION_COOKIE", r"(?:http\s+)?cookie(?:\s+header)?|set-cookie",
     r"([A-Za-z_][\w.\-]{1,40}=[^\s;,]{4,}(?:;\s*[\w\-]+(?:=[^;\n]{0,40})?){0,6})", 0, 0.85),
    ("PASSWORD", r"password", r"([^\s,;'\"`]{6,64})", 0, 0.82),
    ("PHONE", r"(?:phone|mobile|cell|telephone|tel|contact|fax)(?:\s+(?:number|no\.?|#))?|(?:call|text|reach|reached|contact)\s+(?:us\s+|me\s+|him\s+|her\s+)?(?:at|on)|"
     r"(?:by|via)\s+phone\s+(?:at|on)", r"(\+?\(?\d[\d\s().\-]{6,18}\d)(?![\d\-])", 8, 0.82),
]
_POSTAL_CONTEXT = re.compile(r"(?i)address|road|\brd\b|street|nagar|layout|colony|district|city|state|cross|main|sector|"
                             r"bengaluru|bangalore|mumbai|delhi|chennai|hyderabad|pune|kolkata|india")
_LABELLED_ID_RX = [(t, re.compile(r"(?i)\b(?:" + lab + r")\b" + _ID_SEP + val), md, conf)
                   for t, lab, val, md, conf in _LABELLED_IDS]


def _labelled_id_findings(text: str, source: str) -> List[Finding]:
    out: List[Finding] = []
    for ftype, rx, min_digits, conf in _LABELLED_ID_RX:
        for m in rx.finditer(text):
            v = m.group(1).rstrip(" .-/")
            digits = sum(ch.isdigit() for ch in v)
            if digits < min_digits:
                continue
            method = "pattern + label"
            if ftype == "CREDIT_CARD" and not luhn_valid(v):
                method, c = "pattern + label (checksum not valid)", conf - 0.08
            else:
                c = conf
            if ftype == "PASSWORD" and not (_strong_password(v) or (re.search(r"\d", v) and re.search(r"[^\w]", v))):
                continue
            if ftype in ("PASSWORD", "SESSION_COOKIE") and _looks_like_reference(v):
                continue
            if ftype == "CARD_CVV_PIN" and len(v) == 6 and _POSTAL_CONTEXT.search(text[max(0, m.start() - 100): m.start()]):
                continue  # a bare "PIN: 560001" next to an address is an Indian postal PIN code
            out.append(Finding(ftype, m.start(1), m.start(1) + len(v), v, source, method=method, confidence=c))
    return out



# ---------------------------------------------------------------------------
# Secrets by key name, login pairs, Basic auth, webhook URLs, PKCS#12 blobs
# (added after evaluating against the CredDetX dev split – see dataset_audit/)
# ---------------------------------------------------------------------------
_REF_VALUE = re.compile(
    r"(?i)^(?:\$\{?|%\(|\{|<|~?\.{0,2}/[\w.\-]+/|process\.env|os\.environ|os\.getenv|getenv|env\b|ENV\[|vault:|secretsmanager|arn:|"
    r"ssm:|config\.|settings\.|secrets\.|self\.|this\.|params\.|props\.|request\.|req\.|context\.)")
_CODE_VALUE = re.compile(r"^[A-Za-z_$][\w$]{0,24}(?:\.[A-Za-z_$][\w$]{0,24})+(?:\(.*)?$|^[A-Za-z_][\w.]*\(|%[sdr]|\{\}|^\$\d?[a-z]?\$|^\$(?:2[aby]|argon2)")
_TYPE_WORDS = {"string", "str", "number", "int", "integer", "bool", "boolean", "any", "none", "null", "nil", "undefined",
               "true", "false", "required", "optional", "varchar", "text", "secret", "password", "token", "bytes", "object"}


def _looks_like_reference(value: str) -> bool:
    """A value that points at a secret instead of containing one (env var, vault path, code, type, hash)."""
    v = value.strip().strip("'\"`").rstrip(";,)")
    if not v:
        return True
    if v.lower().rstrip(";,") in _TYPE_WORDS:
        return True
    if _REF_VALUE.search(v) or _CODE_VALUE.search(v):
        return True
    if re.fullmatch(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+", v) and not re.search(r"\d", v):
        return True  # UPPER_SNAKE env-var name, e.g. DB_PASSWORD
    return False


_KEY_ASSIGN = re.compile(
    r"""(?x)
    (?<![\w.\-/:@])["']?(?P<key>[A-Za-z_][\w.\-]{1,60})["']?    # key name, optionally quoted
    (?:[ \t]*(?::=|=>|->|[:=])[ \t]*|[ \t]+(?:is[ \t]+)?set[ \t]+to[ \t]+|["'][ \t]*,[ \t]*|[ \t]+value[ \t]*=[ \t]*)  # key = v | key: v | ("key", "v")
    (?:(?P<q>["'`])(?P<qval>[^"'`\n]{4,400})(?P=q)|(?P<val>[^\s"'`,;)\]}]{4,400}))
    """)
_SPLIT_CAMEL = re.compile(r"([a-z0-9])([A-Z])")
_PW_TOKENS = {"password", "passwd", "pwd", "pass", "passphrase", "passcode", "pw", "pword"}
_SECRET_TOKENS = {"secret", "secrets", "sig", "signature", "hmac", "signing", "webhook", "credential", "credentials",
                  "secretkeybase", "keybase"}
_TOKEN_TOKENS = {"token", "apikey"}
_PUBLIC_TOKENS = {"pub", "public", "publishable"}
_CERT_TOKENS = {"cert", "certificate", "pfx", "p12", "pkcs12", "keystore", "truststore", "bundle", "certbase64"}
_NOT_SECRET_KEYS = {"id", "name", "path", "file", "filename", "dir", "url", "uri", "header", "type", "length", "len",
                    "expiry", "expires", "ttl", "algorithm", "alg", "version", "hash", "public", "pub", "policy",
                    "manager", "store", "provider", "env", "ref", "arn", "field", "prompt", "hint", "label", "rotation",
                    "required", "min", "max", "format", "mode", "enabled", "count", "region", "user", "username",
                    "login", "email", "description", "desc", "example"}


def _key_tokens(key: str) -> List[str]:
    return [t for t in re.split(r"[^a-z0-9]+", _SPLIT_CAMEL.sub(r"\1_\2", key).lower()) if t]


def _high_entropy(v: str) -> bool:
    """Long random-looking token: 20+ chars, no spaces/colons, 3+ character classes or 32+ hex digits."""
    v = v.strip("'\"`")
    if len(v) < 20 or re.search(r"[\s:]", v) or v.startswith("/"):
        return False
    return _classes(v) >= 3 or bool(re.fullmatch(r"[0-9a-fA-F]{32,}", v))


def _classes(v: str) -> int:
    return sum(bool(re.search(p, v)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))


def _key_assignments(text: str):
    """Like finditer, but a match whose "value" is really the next key ("using: SESSION_SECRET = …")
    does not swallow that next assignment: scanning resumes right after the key."""
    pos = 0
    while True:
        m = _KEY_ASSIGN.search(text, pos)
        if not m:
            return
        yield m
        pos = max(m.end("key"), pos + 1)


def _secret_assignment_findings(text: str, source: str) -> List[Finding]:
    out: List[Finding] = []
    for m in _key_assignments(text):
        toks = _key_tokens(m.group("key"))
        if not toks or toks[-1] in _NOT_SECRET_KEYS or set(toks) & _PUBLIC_TOKENS:
            continue
        quoted = m.group("qval") is not None
        val = m.group("qval") if quoted else m.group("val")
        s = m.start("qval") if quoted else m.start("val")
        tset = set(toks)
        joined = "".join(toks)
        if tset & _PW_TOKENS or "password" in joined or "passphrase" in joined:
            ftype, min_len = "PASSWORD", 4
        elif tset & _CERT_TOKENS and re.fullmatch(r"[A-Za-z0-9+/]{40,}={0,2}", val):
            ftype, min_len = "PRIVATE_KEY", 40   # PKCS#12 / PFX bundle (holds a private key)
        elif tset & _SECRET_TOKENS or joined.endswith("secret"):
            ftype, min_len = "GENERIC_SECRET", 12
        elif tset & _TOKEN_TOKENS or "apikey" in joined:
            ftype, min_len = "ACCESS_TOKEN" if "token" in tset else "API_KEY", 12
        elif toks[-1] == "key" and _high_entropy(val):
            ftype, min_len = ("ENCRYPTION_KEY" if tset & {"app", "encryption", "crypt", "aes", "cipher", "master", "data"}
                              else "API_KEY"), 20
        else:
            continue
        val = val.strip()
        if len(val) < min_len or _looks_like_reference(val) or val.endswith(":"):
            continue
        if not quoted and re.fullmatch(r"[A-Za-z_]+", val):
            continue  # an unquoted bare word is a variable name in code, not a literal secret
        if " " in val and not (ftype == "PASSWORD" and quoted):
            continue  # only quoted passphrases may contain spaces
        if ftype == "PASSWORD":
            if val.lower() in _PASSWORD_STOPWORDS or not (re.search(r"[\d\W_]", val) or len(val) >= 8 or " " in val):
                continue
        elif _classes(val) < 2 or val.lower().startswith(("http://", "https://")) and ftype != "GENERIC_SECRET":
            continue
        out.append(Finding(ftype, s, s + len(val), val, source, detail="value of '%s'" % m.group("key")[:40],
                           method="key name + value", confidence=0.88))
    return out


_LOGIN_PAIR = re.compile(
    r"(?i)\b(?:login|log\s+in(?:to)?|logged\s+in|credentials?|creds|sign\s*in|account|user(?:name)?)\b[^\n]{0,60}?"
    r"[`'\"]?(?:[A-Za-z0-9._@\-]{2,40})[`'\"]?\s+/\s+[`'\"]?([^\s`'\"]{4,64})")
_PASS_LINE = re.compile(r"(?im)^[ \t>*#-]*(?:pass|pw)[ \t]*[:=][ \t]*[`'\"]?([^\s`'\"]{4,64})")
_PW_PROSE = re.compile(
    r"(?i)\b(?:password|passwd|passphrase|pass|pwd)\b(?:[ \t]+[A-Za-z'\-]+){0,4}?[ \t]+(?:to|with|is|was|as|still|now)"
    r"(?:[ \t]+(?:still|now|is))?[ \t]*[:\-]?[ \t]*[`'\"]?([^\s`'\",;]{6,64})")
_LOGIN_PROSE = re.compile(
    r"(?i)\b(?:login|password|passphrase|credentials?|sign[\s-]?in)\b[^\n]{0,60}?(?:protected\s+with|set\s+to|changed\s+to|"
    r"rotated\s+to|reset\s+to|is\s+now|now\s+is)[ \t]*[`'\"]?([^\s`'\",;]{6,64})")
_BASIC_AUTH = re.compile(r"(?i)\bbasic\s+([A-Za-z0-9+/]{8,}={0,2})(?![A-Za-z0-9+/=])")
_CURL_USER = re.compile(r"(?:\s-u|--user)\s+['\"]?[^\s:'\"]{1,64}:([^\s'\"]{3,64})")
_WEBHOOK_URL = re.compile(
    r"https://(?:hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9/_\-]{8,}|(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w\-]+|"
    r"[\w\-]+\.webhook\.office\.com/[^\s'\"<>]+|outlook\.office(?:365)?\.com/webhook/[^\s'\"<>]+|hooks\.zapier\.com/hooks/catch/[^\s'\"<>]+|"
    r"chat\.googleapis\.com/v1/spaces/[^\s'\"<>]*key=[^\s'\"<>]+)")
_PKCS12_BLOB = re.compile(r"(?<![A-Za-z0-9+/])(MII[A-Za-z0-9+/]{60,}={0,2})(?![A-Za-z0-9+/=])")
_PKCS12_CONTEXT = re.compile(r"(?i)pfx|p12|pkcs\s*#?12|keystore|cert(?:ificate)?\s+bundle|bundle|client[_\s\-]?cert")


def _strong_password(v: str) -> bool:
    return 6 <= len(v) <= 64 and _classes(v) >= 3 and bool(re.search(r"\d", v)) and not re.search(r"[/\\]|\.\w{2,4}$|@\w+\.", v)


def _credential_phrase_findings(text: str, source: str) -> List[Finding]:
    out: List[Finding] = []

    def add(ftype, s, e, v, method, conf, detail=""):
        out.append(Finding(ftype, s, e, v, source, detail=detail, method=method, confidence=conf))

    for m in _LOGIN_PAIR.finditer(text):
        v = m.group(1).rstrip("`'\".,")
        if re.search(r"[\d\W_]", v) and not _looks_like_reference(v) and v.lower() not in _PASSWORD_STOPWORDS:
            add("PASSWORD", m.start(1), m.start(1) + len(v), v, "login pair (user / password)", 0.85)
    for m in _PASS_LINE.finditer(text):
        v = m.group(1)
        if re.fullmatch(r"[A-Za-z_]+[,;]?", v):
            continue  # "pass = adminPass," – a variable in code
        if not _looks_like_reference(v) and v.lower() not in _PASSWORD_STOPWORDS:
            add("PASSWORD", m.start(1), m.end(1), v, "pattern + keyword", 0.88)
    for rx in (_PW_PROSE, _LOGIN_PROSE):
        for m in rx.finditer(text):
            v = m.group(1).rstrip(".")
            if _strong_password(v) or (len(v) >= 6 and re.search(r"\d", v) and re.search(r"[^\w]", v)):
                if not _looks_like_reference(v) and v.lower() not in _PASSWORD_STOPWORDS:
                    add("PASSWORD", m.start(1), m.start(1) + len(v), v, "keyword context", 0.82)
    for m in _BASIC_AUTH.finditer(text):
        try:
            import base64
            decoded = base64.b64decode(m.group(1) + "=" * (-len(m.group(1)) % 4)).decode("utf-8")
        except Exception:
            continue
        if ":" in decoded and decoded.isprintable():
            add("PASSWORD", m.start(1), m.end(1), m.group(1), "HTTP Basic auth (decodes to user:password)", 0.95,
                "Basic auth credential")
    for m in _CURL_USER.finditer(text):
        add("PASSWORD", m.start(1), m.end(1), m.group(1), "curl -u user:password", 0.9)
    for m in _WEBHOOK_URL.finditer(text):
        v = m.group(0).rstrip(".,)`")
        add("GENERIC_SECRET", m.start(), m.start() + len(v), v, "pattern (incoming-webhook URL)", 0.93,
            "incoming-webhook URL – the path is the secret")
    for m in _PKCS12_BLOB.finditer(text):
        before = text[max(0, m.start() - 160): m.start()]
        if _PKCS12_CONTEXT.search(before) and "BEGIN CERTIFICATE" not in before[-80:]:
            add("PRIVATE_KEY", m.start(1), m.end(1), m.group(1), "pattern + context (PKCS#12 / PFX bundle)", 0.9,
                "certificate bundle with private key")
    return out


def _drop_references(findings: List[Finding]) -> List[Finding]:
    """Remove label/keyword-based credential findings whose value only refers to a secret
    (environment variable, vault path, code expression, type name, password hash)."""
    keep = []
    for f in findings:
        if f.category == CREDENTIALS and f.method in ("pattern + label", "keyword context", "pattern + keyword") \
                and _looks_like_reference(f.value):
            continue
        keep.append(f)
    return keep



# IFSC (Indian bank branch code – public, noted only) and login usernames
_IFSC = re.compile(r"\b([A-Z]{4}0[A-Z0-9]{6})\b")
_USERNAME = re.compile(r"(?i)\b(?:user\s*name|user\s*id|login\s*(?:id|name)|login|user)\s*(?::|=|\bis\b)\s*[`'\"]?([A-Za-z0-9][\w.@\-]{2,40})")
_USERNAME_STOP = {"required", "optional", "invalid", "incorrect", "missing", "empty", "unknown", "admin_here", "not", "the",
                  "your", "my", "page", "screen", "form", "field", "failed", "successful", "string", "none", "null"}


def _account_findings(text: str, source: str) -> List[Finding]:
    out: List[Finding] = []
    for m in _IFSC.finditer(text):
        out.append(Finding("IFSC", m.start(1), m.end(1), m.group(1), source, method="pattern (IFSC format)",
                           detail="public bank branch code – not secret on its own", confidence=0.9))
    for m in _USERNAME.finditer(text):
        v = m.group(1).rstrip(".,;")
        if v.lower() in _USERNAME_STOP or "@" in v and "." in v.split("@")[-1]:
            continue  # e-mail addresses are handled by the e-mail detector
        out.append(Finding("USERNAME", m.start(1), m.start(1) + len(v), v, source, method="pattern + label",
                           confidence=0.85))
    return out


def detect(text: str, source: str = "prompt", is_code_file: bool = False) -> List[Finding]:
    """Run every detector on `text` and return findings with overlaps merged."""
    if not text:
        return []
    findings = _harmful_findings(text, source)
    findings += _rule_findings(text, source)
    findings += _core_findings(text, source)
    findings += _medical_findings(text, source)
    findings += _attribute_findings(text, source)
    findings += _communication_findings(text, source)
    findings += _tabular_findings(text, source)
    findings += _confidential_findings(text, source)
    findings += _document_marker_findings(text, source)
    findings += _source_code_findings(text, source, is_code_file)
    findings += _secret_assignment_findings(text, source)
    findings += _credential_phrase_findings(text, source)
    findings += _labelled_id_findings(text, source)
    findings += _account_findings(text, source)
    return _merge_overlaps(text, _drop_references(findings))


def bulk_personal_finding(all_findings: Iterable[Finding]) -> Optional[Finding]:
    """Aggregate check across prompt + attachments: many identifiers = bulk records.
    LOW findings (placeholders, public contacts) do not count."""
    ids = {(f.type, f.value.strip().lower()) for f in all_findings
           if f.type in PERSONAL_IDENTIFIER_TYPES and f.level != "LOW"}
    if len(ids) >= config.BULK_PERSONAL_THRESHOLD:
        return Finding("BULK_RECORDS", source="request",
                       detail="%d distinct personal identifiers (threshold %d)" % (len(ids), config.BULK_PERSONAL_THRESHOLD),
                       extra={"count": len(ids)}, method="aggregate count", confidence=0.95)
    return None
