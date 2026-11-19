"""Lightweight, fully offline text embeddings for policy retrieval.

We use a feature-hashing embedder (unigrams + bigrams + a small security
synonym expansion) so that ChromaDB works with zero model downloads – ideal for
a hackathon laptop with no GPU and unreliable Wi-Fi. Vectors are L2-normalised,
so ChromaDB's default L2 distance ranks results exactly like cosine similarity.

Swapping in a neural model (e.g. all-MiniLM-L6-v2) only requires changing
`embed()`; the rest of the pipeline is unchanged.
"""
from __future__ import annotations

import hashlib
import math
import re
from typing import Dict, List

DIM = 512

# Concept expansion: maps surface words to a shared concept token so that
# "pwd", "api key" and "token" all land near the credentials clause.
_CONCEPTS: Dict[str, List[str]] = {
    "concept_credential": ["password", "passwords", "pwd", "passcode", "credential", "credentials", "secret",
                           "secrets", "token", "tokens", "key", "keys", "apikey", "api", "aws", "ssh",
                           "private", "login", "connection", "access"],
    "concept_personal": ["email", "emails", "phone", "mobile", "address", "aadhaar", "pan", "ssn", "dob",
                         "birth", "customer", "customers", "employee", "employees", "salary", "personal",
                         "name", "names", "card", "bank", "account", "identifier", "identifiers", "hr"],
    "concept_bulk": ["records", "dataset", "export", "spreadsheet", "csv", "list", "database", "bulk",
                     "rows", "many"],
    "concept_confidential": ["confidential", "internal", "nda", "merger", "acquisition", "board",
                             "forecast", "revenue", "earnings", "pricing", "strategy", "roadmap",
                             "layoff", "layoffs", "restructuring", "codename", "unreleased", "falcon",
                             "orion", "nebula"],
    "concept_code": ["code", "source", "function", "class", "repository", "repo", "script", "algorithm",
                     "proprietary", "copyright", "snippet", "program", "configuration", "config"],
    "concept_attachment": ["image", "images", "screenshot", "photo", "attachment", "attachments", "file",
                           "files", "pdf", "docx", "ocr", "scan", "scanned", "upload"],
    "concept_public": ["public", "general", "learning", "explain", "generic", "question", "help", "what",
                       "how", "why"],
    "concept_redact": ["redact", "redaction", "redacted", "placeholder", "sanitized", "sanitize", "mask"],
    "concept_approval": ["approval", "approve", "approved", "manager", "authorize", "pending", "hold"],
    "concept_harmful": ["violence", "violent", "kill", "murder", "attack", "weapon", "weapons", "bomb", "explosives",
                        "harm", "harmful", "illegal", "drugs", "hack", "hacking", "fraud", "suicide", "self", "body",
                        "prohibited", "airstrike", "poison", "steal"],
    "concept_audit": ["audit", "log", "logging", "monitor", "monitoring", "governance", "record"],
}
_WORD_TO_CONCEPT = {w: c for c, words in _CONCEPTS.items() for w in words}
_STOP = {"the", "a", "an", "and", "or", "of", "to", "in", "on", "for", "is", "are", "be", "with", "as",
         "by", "it", "this", "that", "at", "from", "must", "may", "such", "any", "all", "not", "can"}
_TOKEN = re.compile(r"[a-z0-9]+")


def _stem(w: str) -> str:
    for suf in ("ing", "ed", "es", "s"):
        if len(w) > 4 and w.endswith(suf):
            return w[: -len(suf)]
    return w


def _features(text: str) -> Dict[str, float]:
    words = [w for w in _TOKEN.findall(text.lower()) if w not in _STOP]
    feats: Dict[str, float] = {}
    for w in words:
        feats["u:" + _stem(w)] = feats.get("u:" + _stem(w), 0) + 1.0
        concept = _WORD_TO_CONCEPT.get(w)
        if concept:
            feats[concept] = feats.get(concept, 0) + 2.0
    for a, b in zip(words, words[1:]):
        key = "b:%s_%s" % (_stem(a), _stem(b))
        feats[key] = feats.get(key, 0) + 1.0
    return feats


def embed(text: str) -> List[float]:
    vec = [0.0] * DIM
    for feat, count in _features(text).items():
        h = hashlib.md5(feat.encode("utf-8")).digest()
        idx = int.from_bytes(h[:4], "little") % DIM
        sign = 1.0 if h[4] & 1 else -1.0
        vec[idx] += sign * (1.0 + math.log(count))
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


def cosine(a: List[float], b: List[float]) -> float:
    return sum(x * y for x, y in zip(a, b))
