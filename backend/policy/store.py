"""Policy knowledge base backed by ChromaDB.

Two retrieval paths are combined for every request:
  1. Category lookup – a ChromaDB metadata query (`where category in [...]`)
     fetches the clause that governs each detected category. The decision
     engine reads the clause's `action` from this result, so the decision is
     driven by what is stored in the policy knowledge base (admins can change it).
  2. Semantic search – the sanitized prompt is embedded and the nearest
     clauses are returned to explain context to the user.

Reference clauses (policy/reference_policies.json – the organisation policy pack
supplied with the hackathon datasets) are indexed in the same collection with
`kind = "reference"`. They are retrieved and shown next to the governing clause
(best match per detected category) but never govern a decision: the category
lookup used by the decision engine only returns `kind = "governing"` clauses, and
decision.py ignores REFERENCE clauses as a second safeguard.

If ChromaDB cannot be imported or initialised, an in-memory store with the same
interface is used and the UI shows "Policy store: in-memory fallback" so the
deviation is never hidden.
"""
from __future__ import annotations

import json
import os
import threading
from typing import Dict, Iterable, List, Optional, Tuple

from .. import config
from . import embeddings

COLLECTION = "ai_usage_policy"
_META_KEYS = ("id", "title", "category", "action", "severity", "remediation", "version", "kind", "policy", "source",
              "source_ref", "maps_to", "consistency", "consistency_note")
REFERENCE = "reference"
GOVERNING = "governing"


def _clause_doc(c: dict) -> str:
    return "%s. %s" % (c["title"], c["text"])


def _meta(c: dict) -> dict:
    return {
        "id": c["id"], "title": c["title"], "category": c["category"], "action": c["action"],
        "severity": int(c.get("severity", 0)), "remediation": c.get("remediation", ""),
        "version": int(c.get("version", 1)), "kind": c.get("kind") or GOVERNING,
        "policy": c.get("policy", ""), "source": c.get("source", ""), "source_ref": c.get("source_ref", ""),
        "maps_to": ", ".join(c.get("maps_to") or []) if isinstance(c.get("maps_to"), list) else (c.get("maps_to") or ""),
        "consistency": c.get("consistency", ""), "consistency_note": c.get("consistency_note", ""),
    }


def _from_meta(meta: dict, doc: str) -> dict:
    out = {k: meta.get(k) for k in _META_KEYS}
    out["kind"] = out.get("kind") or GOVERNING
    prefix = "%s. " % meta.get("title", "")
    out["text"] = doc[len(prefix):] if doc.startswith(prefix) else doc
    return out


class MemoryPolicyStore:
    backend = "in-memory fallback"

    def __init__(self, reason: str = "") -> None:
        self.reason = reason
        self._clauses: List[dict] = []
        self._vectors: List[List[float]] = []
        self._lock = threading.Lock()

    def index(self, clauses: Iterable[dict]) -> None:
        with self._lock:
            self._clauses = [dict(c) for c in clauses]
            self._vectors = [embeddings.embed(_clause_doc(c)) for c in self._clauses]

    def count(self) -> int:
        return len(self._clauses)

    def by_categories(self, categories: List[str], kind: str = GOVERNING) -> List[dict]:
        cats = set(categories)
        return [dict(c) for c in self._clauses if c["category"] in cats and (c.get("kind") or GOVERNING) == kind]

    def search(self, query: str, k: int = 3) -> List[Tuple[dict, float]]:
        q = embeddings.embed(query)
        scored = [(dict(c), embeddings.cosine(q, v)) for c, v in zip(self._clauses, self._vectors)]
        scored.sort(key=lambda x: -x[1])
        return scored[:k]


class ChromaPolicyStore:
    backend = "ChromaDB"

    def __init__(self, path: str) -> None:
        os.environ.setdefault("ANONYMIZED_TELEMETRY", "False")
        import chromadb
        from chromadb.config import Settings

        self.reason = ""
        self._client = chromadb.PersistentClient(path=path, settings=Settings(anonymized_telemetry=False))
        self._lock = threading.Lock()
        self._col = None

    def index(self, clauses: Iterable[dict]) -> None:
        clauses = list(clauses)
        with self._lock:
            try:
                self._client.delete_collection(COLLECTION)
            except Exception:
                pass
            # We supply our own embeddings, so no embedding function (no model download).
            self._col = self._client.create_collection(name=COLLECTION, embedding_function=None)
            self._col.add(
                ids=[c["id"] for c in clauses],
                documents=[_clause_doc(c) for c in clauses],
                metadatas=[_meta(c) for c in clauses],
                embeddings=[embeddings.embed(_clause_doc(c)) for c in clauses],
            )

    def count(self) -> int:
        return self._col.count() if self._col is not None else 0

    def by_categories(self, categories: List[str], kind: str = GOVERNING) -> List[dict]:
        if not categories:
            return []
        cat = {"category": categories[0]} if len(categories) == 1 else {"category": {"$in": list(categories)}}
        res = self._col.get(where={"$and": [cat, {"kind": kind}]}, include=["documents", "metadatas"])
        return [_from_meta(m, d) for m, d in zip(res["metadatas"], res["documents"])]

    def search(self, query: str, k: int = 3) -> List[Tuple[dict, float]]:
        n = min(k, self.count())
        if n == 0:
            return []
        res = self._col.query(query_embeddings=[embeddings.embed(query)], n_results=n,
                              include=["documents", "metadatas", "distances"])
        out = []
        for m, d, dist in zip(res["metadatas"][0], res["documents"][0], res["distances"][0]):
            # squared L2 between unit vectors: d = 2 - 2cos  ->  cos = 1 - d/2
            out.append((_from_meta(m, d), 1.0 - float(dist) / 2.0))
        return out


_store = None
_store_lock = threading.Lock()


def get_store():
    """Create the policy store once (ChromaDB if possible, else fallback)."""
    global _store
    with _store_lock:
        if _store is None:
            if config.POLICY_BACKEND == "memory":
                _store = MemoryPolicyStore("POLICY_BACKEND=memory")
            else:
                try:
                    config.ensure_data_dir()
                    _store = ChromaPolicyStore(str(config.CHROMA_DIR))
                except Exception as exc:  # chromadb missing or broken
                    _store = MemoryPolicyStore("ChromaDB unavailable: %s" % exc)
        return _store


def reset_store_for_tests(store) -> None:
    global _store
    _store = store


def load_reference_clauses() -> List[dict]:
    """The organisation policy pack (built by scripts/datasets/build_processed.py). Missing file = none."""
    path = config.POLICY_REFERENCE_FILE
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    out = []
    for c in data.get("clauses", []):
        c = dict(c)
        c["kind"] = REFERENCE
        c["action"] = "REFERENCE"  # never a decision action
        out.append(c)
    return out


def index_clauses(clauses: List[dict]) -> None:
    """(Re)build the vector index from the governing clauses (database) plus the
    reference clauses. Falls back to memory if Chroma fails at runtime."""
    global _store
    clauses = [dict(c, kind=GOVERNING) for c in clauses] + load_reference_clauses()
    store = get_store()
    try:
        store.index(clauses)
    except Exception as exc:
        if isinstance(store, ChromaPolicyStore):
            fallback = MemoryPolicyStore("ChromaDB indexing failed: %s" % exc)
            fallback.index(clauses)
            with _store_lock:
                _store = fallback
        else:
            raise


CATEGORY_QUERY_TERMS = {
    "PERSONAL_DATA": "personal information email phone customer employee identifiers",
    "BULK_PERSONAL_DATA": "bulk customer records dataset export",
    "CREDENTIALS": "credentials password api key token secret",
    "CONFIDENTIAL_BUSINESS": "confidential business information merger forecast",
    "SOURCE_CODE": "proprietary source code intellectual property",
    "UNSCANNABLE_ATTACHMENT": "attachment image scan unsupported file",
    "HARMFUL_CONTENT": "harmful violent illegal weapons self-harm prohibited use",
    "FINANCIAL_DATA": "financial bank account card cvv pin upi salary tax insurance transaction",
    "MEDICAL_DATA": "medical health diagnosis prescription patient mental genetic disability",
    "LEGAL_GOVERNMENT": "legal court case fir visa immigration classified privileged government",
    "LOCATION_DATA": "location gps live location travel vehicle tracking",
    "PRIVATE_COMMUNICATIONS": "private communications chat email messages contacts",
    "SENSITIVE_ATTRIBUTES": "religion caste political ethnicity sexual orientation gender union",
    "CHILDREN_DATA": "children minor child school records",
    "SECURITY_TECHNICAL": "internal network host ip firewall vulnerability security architecture",
}


def retrieve(query: str, categories: List[str], k: int = 3,
             extra_categories: Optional[List[str]] = None) -> List[dict]:
    """Return governing clauses for `categories` plus top-k semantic matches.

    Each result: clause fields + `score` (cosine similarity to the query) and
    `match` ("category", "semantic" or "category+semantic").
    """
    store = get_store()
    cats = list(dict.fromkeys(list(categories) + list(extra_categories or [])))
    query_text = (query or "")[:1500] + " " + " ".join(CATEGORY_QUERY_TERMS.get(c, "") for c in categories)
    results: Dict[str, dict] = {}
    q_vec = embeddings.embed(query_text)
    for clause in store.by_categories(cats):
        clause["score"] = round(embeddings.cosine(q_vec, embeddings.embed(_clause_doc(clause))), 3)
        clause["match"] = "category"
        results[clause["id"]] = clause
    # best-matching clause of the organisation policy pack for each detected category
    for cat in categories:
        best = None
        for clause in store.by_categories([cat], kind=REFERENCE):
            clause["score"] = round(embeddings.cosine(q_vec, embeddings.embed(_clause_doc(clause))), 3)
            if best is None or clause["score"] > best["score"]:
                best = clause
        if best is not None and best["id"] not in results:
            best["match"] = "reference"
            results[best["id"]] = best
    for clause, score in store.search(query_text, k):
        if clause["id"] in results:
            if results[clause["id"]]["match"] == "category":
                results[clause["id"]]["match"] = "category+semantic"
            results[clause["id"]]["score"] = round(score, 3)
        else:
            clause["score"] = round(score, 3)
            clause["match"] = "semantic"
            results[clause["id"]] = clause
    rank = {"category": 0, "category+semantic": 0, "reference": 1}
    ordered = sorted(results.values(), key=lambda c: (rank.get(c["match"], 2), -c["score"]))
    return ordered


def store_info() -> dict:
    s = get_store()
    return {"backend": s.backend, "clauses": s.count(), "note": getattr(s, "reason", "")}
