"""Evaluate the gateway's detectors and decisions against the labelled datasets.

    python scripts/datasets/evaluate.py creddetx --split test       # report numbers
    python scripts/datasets/evaluate.py creddetx --split dev --misses 30   # study errors (dev only)
    python scripts/datasets/evaluate.py nemotron --split eval [--strict]
    python scripts/datasets/evaluate.py all                          # what the test report uses

Two kinds of measurement:
  * detection – does a censoring finding (severity above LOW) overlap each labelled span?
  * outcome   – run the full text path (scripts/datasets/gateway_sim.py) and check, for every
                labelled span, whether its characters would reach the LLM: "held" (blocked or
                waiting for approval), "protected" (fully replaced by a placeholder) or
                "exposed" (forwarded, fully or partly, in clear text).

Privacy: results contain counts only. --misses prints context with every labelled value
masked to its shape (letters -> a/A, digits -> 9) and is meant for the dev splits only.
"""
from __future__ import annotations

import sys as _sys
for _s in (_sys.stdout, _sys.stderr):  # Windows consoles: never crash on a non-ASCII character
    try:
        _s.reconfigure(errors="replace")
    except Exception:
        pass

import argparse
import collections
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from gateway_sim import ROOT, screen_text, severity_policy  # noqa: E402
from paths import CREDDETX_DIR, PROCESSED  # noqa: E402

from backend.scanner.entities import ENTITIES  # noqa: E402

OUT_DIR = ROOT / "dataset_audit" / "evaluation"
SECRET_TYPES = {k for k, e in ENTITIES.items() if e.category == "CREDENTIALS"} | {
    "CRYPTO_PRIVATE_KEY", "SEED_PHRASE", "BANK_LOGIN", "CARD_CVV_PIN"}

# Nemotron label scope, judged against the gateway policy (AUP-3/5/13/14/16/18):
#   core  – the policy names it as something that must not reach the model in clear text
#   quasi – context dependent (names, attributes, network ids…): the policy asks for review
#   out   – not sensitive on its own under the policy (company, city, date, url, …)
NEMOTRON_SCOPE = {
    "core": ["email", "phone_number", "fax_number", "street_address", "date_of_birth", "ssn", "national_id",
             "tax_id", "credit_debit_card", "cvv", "pin", "account_number", "password", "api_key", "http_cookie",
             "medical_record_number", "health_plan_beneficiary_number", "biometric_identifier", "employee_id",
             "coordinate"],
    "quasi": ["first_name", "last_name", "ipv4", "ipv6", "license_plate", "certificate_license_number",
              "religious_belief", "political_view", "race_ethnicity", "sexuality", "customer_id", "user_name",
              "blood_type", "bank_routing_number"],
}
SCOPE_OF = {lab: tier for tier, labs in NEMOTRON_SCOPE.items() for lab in labs}


def shape(v: str) -> str:
    return "".join("9" if c.isdigit() else ("A" if c.isupper() else ("a" if c.isalpha() else c)) for c in v)


def coverage(start: int, end: int, intervals: list[tuple[int, int]]) -> int:
    covered = 0
    for s, e in intervals:
        lo, hi = max(s, start), min(e, end)
        if hi > lo:
            covered += hi - lo
    return covered


def trim(text: str, s: int, e: int) -> tuple[int, int]:
    while s < e and text[s].isspace():
        s += 1
    while e > s and text[e - 1].isspace():
        e -= 1
    return s, e


def outcome_for(res, text_same: bool, raw: str, s: int, e: int, mode: str) -> str:
    """held | protected | exposed | partial for one labelled span under one forwarding mode."""
    fwd = {"strict": res.forwarded_strict, "send_anyway": res.forwarded_send_anyway,
           "approved": res.released_if_approved if res.decision == "MANAGER_APPROVAL" else res.forwarded_strict}[mode]
    if fwd is None:
        return "held"
    if res.decision == "ALLOW":
        return "exposed"
    if not text_same:  # offsets moved during normalisation: fall back to a substring test
        return "exposed" if raw[s:e] in fwd else "protected"
    if mode == "send_anyway" and res.decision == "USER_REVIEW":
        include = lambda f: f.action in ("redact", "block")  # noqa: E731
    else:
        include = lambda f: f.action in ("redact", "review", "block")  # noqa: E731
    spans = [(f.start, f.end) for f in res.findings if f.redactable and include(f)]
    c = coverage(s, e, spans)
    return "protected" if c >= e - s else ("partial" if c else "exposed")


def pct(a: int, b: int) -> float:
    return round(100.0 * a / b, 1) if b else 0.0


# =========================================================================== CredDetX
def eval_creddetx(split: str, policy_name: str = "strict", strict_mode: bool = False, misses: int = 0) -> dict:
    path = CREDDETX_DIR / f"{split}.jsonl"
    pol = severity_policy(strict_mode)
    t0 = time.perf_counter()
    gold_n = found_any = found_cred = 0
    tp_pred = fp_pred_capped = 0
    by_label = collections.defaultdict(lambda: [0, 0])
    by_slice = collections.defaultdict(lambda: [0, 0])
    by_context = collections.defaultdict(lambda: [0, 0])
    neg_hit = collections.defaultdict(lambda: [0, 0])
    no_secret_texts = no_secret_flagged = 0
    decisions = collections.Counter()
    decisions_no_secret = collections.Counter()
    outcomes = {m: collections.Counter() for m in ("strict", "send_anyway", "approved")}
    texts_exposed = texts_with_secret = 0
    norm_changed = 0
    shown = 0
    n = 0
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            r = json.loads(line)
            n += 1
            raw = r["text"]
            res = screen_text(raw, pol)
            same = res.text == raw
            norm_changed += 0 if same else 1
            decisions[res.decision] += 1
            censor = [f for f in res.findings if f.has_span and f.level != "LOW"]
            cred_pred = [(f.start, f.end) for f in censor if f.type in SECRET_TYPES]
            any_pred = [(f.start, f.end) for f in censor]
            gold = []
            for s in r.get("spans") or []:
                a = s.get("attrs", {})
                if policy_name == "lenient" and (a.get("is_example") or a.get("is_test_name")):
                    continue
                gold.append(s)
            if not r.get("spans"):
                no_secret_texts += 1
                decisions_no_secret[res.decision] += 1
                if cred_pred:
                    no_secret_flagged += 1
            # detection: precision over credential-type predictions (CredDetX labels secrets only)
            fp_here = 0
            all_gold = r.get("spans") or []
            for ps, pe in cred_pred:
                if any(ps < g["end"] and g["start"] < pe for g in all_gold):
                    tp_pred += 1
                else:
                    fp_here += 1
            fp_pred_capped += min(fp_here, 5)
            text_exposed = False
            for g in gold:
                gold_n += 1
                hit_any = coverage(g["start"], g["end"], any_pred) > 0
                hit_cred = coverage(g["start"], g["end"], cred_pred) > 0
                found_any += hit_any
                found_cred += hit_cred
                by_label[g["label"]][0] += 1
                by_label[g["label"]][1] += hit_any
                for sl in g.get("slice") or []:
                    by_slice[sl][0] += 1
                    by_slice[sl][1] += hit_any
                ctx = r["meta"]["context_type"]
                by_context[ctx][0] += 1
                by_context[ctx][1] += hit_any
                s, e = trim(raw, g["start"], g["end"])
                for m in outcomes:
                    o = outcome_for(res, same, raw, s, e, m)
                    outcomes[m][o] += 1
                    if m == "strict" and o in ("exposed", "partial"):
                        text_exposed = True
                if misses and shown < misses and not hit_any:
                    shown += 1
                    lo = max(0, g["start"] - 70)
                    ctx_txt = raw[lo:g["start"]].replace("\n", "⏎")
                    print("MISS %-20s %-24s …%s[%s]" % (g["label"], ",".join(g.get("slice") or []), ctx_txt[-70:],
                                                       shape(raw[g["start"]:g["end"]])[:40]))
            if gold:
                texts_with_secret += 1
                texts_exposed += text_exposed
            for neg in r.get("negatives") or []:
                neg_hit[neg["kind"]][0] += 1
                neg_hit[neg["kind"]][1] += coverage(neg["start"], neg["end"], cred_pred) > 0
    secs = time.perf_counter() - t0
    neg_total = sum(v[0] for v in neg_hit.values())
    neg_flagged = sum(v[1] for v in neg_hit.values())
    precision = tp_pred / (tp_pred + fp_pred_capped) if tp_pred + fp_pred_capped else 0.0
    recall = found_any / gold_n if gold_n else 0.0
    return {
        "dataset": "CredDetX v0.1", "split": split, "gold_policy": policy_name, "strict_mode": strict_mode,
        "texts": n, "gold_spans": gold_n, "seconds": round(secs, 1), "texts_changed_by_normalisation": norm_changed,
        "detection": {
            "recall_any_censoring_finding": round(recall, 3),
            "recall_credential_type_finding": round(found_cred / gold_n, 3) if gold_n else 0,
            "precision_credential_findings_capped5": round(precision, 3),
            "f1": round(2 * precision * recall / (precision + recall), 3) if precision + recall else 0,
            "negatives_hit": round(neg_flagged / neg_total, 3) if neg_total else 0,
            "no_secret_texts_flagged": round(no_secret_flagged / no_secret_texts, 3) if no_secret_texts else 0,
            "recall_by_label": {k: [v[1], v[0], pct(v[1], v[0])] for k, v in sorted(by_label.items())},
            "recall_by_slice": {k: [v[1], v[0], pct(v[1], v[0])] for k, v in sorted(by_slice.items())},
            "recall_by_context": {k: [v[1], v[0], pct(v[1], v[0])] for k, v in sorted(by_context.items())},
            "negatives_hit_by_kind": {k: [v[1], v[0], pct(v[1], v[0])] for k, v in sorted(neg_hit.items())},
        },
        "outcome": {
            "decisions_all_texts": dict(decisions.most_common()),
            "decisions_no_secret_texts": dict(decisions_no_secret.most_common()),
            "secret_spans_by_outcome": {m: dict(c) for m, c in outcomes.items()},
            "texts_with_secret": texts_with_secret,
            "texts_with_any_secret_exposed_strict": texts_exposed,
            "texts_with_any_secret_exposed_pct": pct(texts_exposed, texts_with_secret),
        },
    }


# =========================================================================== Nemotron
def eval_nemotron(split: str, strict_mode: bool = False, misses: int = 0) -> dict:
    path = PROCESSED / ("nemotron_%s.jsonl" % split)
    pol = severity_policy(strict_mode)
    t0 = time.perf_counter()
    per_label = collections.defaultdict(collections.Counter)
    tier_out = {t: {m: collections.Counter() for m in ("strict", "send_anyway", "approved")}
                for t in ("core", "quasi", "out")}
    decisions = collections.Counter()
    by_locale = collections.defaultdict(collections.Counter)
    docs_core_exposed = docs_with_core = 0
    unlabelled_findings = collections.Counter()
    shown = 0
    n = 0
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            r = json.loads(line)
            n += 1
            raw = r["text"]
            res = screen_text(raw, pol)
            same = res.text == raw
            decisions[res.decision] += 1
            by_locale[r["locale"]][res.decision] += 1
            censor = [f for f in res.findings if f.has_span and f.level != "LOW"]
            any_pred = [(f.start, f.end) for f in censor]
            low_pred = [(f.start, f.end) for f in res.findings if f.has_span and f.level == "LOW"]
            core_exposed = has_core = False
            for g in r["spans"]:
                tier = SCOPE_OF.get(g["label"], "out")
                s, e = trim(raw, g["start"], g["end"])
                if e <= s:
                    continue
                c = per_label[g["label"]]
                c["n"] += 1
                hit = coverage(s, e, any_pred) > 0
                c["detected"] += hit
                if not hit and coverage(s, e, low_pred) > 0:
                    c["detected_low"] += 1
                for m in ("strict", "send_anyway", "approved"):
                    o = outcome_for(res, same, raw, s, e, m)
                    tier_out[tier][m][o] += 1
                    if m == "strict":
                        c[o] += 1
                        if tier == "core" and o in ("exposed", "partial"):
                            core_exposed = True
                has_core |= tier == "core"
                if misses and shown < misses and tier == "core" and not hit:
                    shown += 1
                    lo = max(0, s - 60)
                    print("MISS %-30s …%s[%s]" % (g["label"], raw[lo:s].replace("\n", "⏎")[-60:], shape(raw[s:e])[:40]))
            docs_with_core += has_core
            docs_core_exposed += core_exposed
            for f in censor:
                if not any(f.start < g["end"] and g["start"] < f.end for g in r["spans"]):
                    unlabelled_findings[f.type] += 1
    secs = time.perf_counter() - t0

    def tier_summary(t: str) -> dict:
        labs = [lab for lab in per_label if SCOPE_OF.get(lab, "out") == t]
        tot = sum(per_label[lab]["n"] for lab in labs)
        det_ = sum(per_label[lab]["detected"] for lab in labs)
        return {"spans": tot, "detected": det_, "recall_pct": pct(det_, tot),
                "outcome_strict": dict(tier_out[t]["strict"]), "outcome_send_anyway": dict(tier_out[t]["send_anyway"]),
                "outcome_after_approval": dict(tier_out[t]["approved"])}

    return {
        "dataset": "NVIDIA Nemotron-PII", "split": split, "strict_mode": strict_mode, "documents": n,
        "seconds": round(secs, 1),
        "tiers": {t: tier_summary(t) for t in ("core", "quasi", "out")},
        "documents_with_core_pii": docs_with_core, "documents_with_core_pii_exposed": docs_core_exposed,
        "documents_with_core_pii_exposed_pct": pct(docs_core_exposed, docs_with_core),
        "decisions": dict(decisions.most_common()),
        "decisions_by_locale": {k: dict(v) for k, v in by_locale.items()},
        "per_label": {lab: {"tier": SCOPE_OF.get(lab, "out"), **dict(c), "recall_pct": pct(c["detected"], c["n"])}
                      for lab, c in sorted(per_label.items(), key=lambda kv: (SCOPE_OF.get(kv[0], "out"), kv[0]))},
        "censoring_findings_on_unlabelled_text": dict(unlabelled_findings.most_common()),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset", choices=["creddetx", "nemotron", "all"])
    ap.add_argument("--split", default=None, help="creddetx: dev|test   nemotron: dev|eval")
    ap.add_argument("--strict", action="store_true", help="evaluate with strict mode on")
    ap.add_argument("--lenient", action="store_true", help="CredDetX: ignore example / test-named secrets")
    ap.add_argument("--misses", type=int, default=0, help="print N masked misses (dev splits only)")
    ap.add_argument("--tag", default="", help="suffix for the output file name")
    a = ap.parse_args()
    if a.misses and a.split in ("test", "eval"):
        raise SystemExit("--misses is for dev splits only (do not tune on the reporting split)")
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    jobs = []
    if a.dataset in ("creddetx", "all"):
        jobs.append(("creddetx", a.split or "test"))
    if a.dataset in ("nemotron", "all"):
        jobs.append(("nemotron", a.split or "eval"))
    for name, split in jobs:
        if name == "creddetx":
            res = eval_creddetx(split, "lenient" if a.lenient else "strict", a.strict, a.misses)
            d, o = res["detection"], res["outcome"]
            print("CredDetX %s: recall %.3f precision %.3f F1 %.3f | negatives hit %.3f | no-secret flagged %.3f | "
                  "texts with a secret exposed %s%% | %ss" % (split, d["recall_any_censoring_finding"],
                                                              d["precision_credential_findings_capped5"], d["f1"],
                                                              d["negatives_hit"], d["no_secret_texts_flagged"],
                                                              o["texts_with_any_secret_exposed_pct"], res["seconds"]))
        else:
            res = eval_nemotron(split, a.strict, a.misses)
            print("Nemotron %s: core recall %s%% quasi %s%% | docs with core PII exposed %s%% | decisions %s | %ss" % (
                split, res["tiers"]["core"]["recall_pct"], res["tiers"]["quasi"]["recall_pct"],
                res["documents_with_core_pii_exposed_pct"], res["decisions"], res["seconds"]))
        fname = "%s_%s%s%s%s.json" % (name, split, "_strict" if a.strict else "", "_lenient" if a.lenient else "",
                                      ("_" + a.tag) if a.tag else "")
        (OUT_DIR / fname).write_text(json.dumps(res, indent=2) + "\n", encoding="utf-8")
        print("  ->", (OUT_DIR / fname).relative_to(ROOT))


if __name__ == "__main__":
    main()
