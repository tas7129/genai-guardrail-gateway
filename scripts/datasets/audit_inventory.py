"""Phase 1 – inventory every member of AI_GuardRail_Datasets.zip.

Stdlib only (plus the bundled parquet_lite fallback). Reads the ORIGINAL files
and never modifies them. Writes:

  dataset_audit/dataset_inventory.csv   one row per file in the ZIP
  dataset_audit/inventory_stats.json    distributions and quality checks

Privacy rule: nothing in the outputs contains a dataset VALUE (no secret, no
PII string). Only counts, field names, label names and hashes are written.

Usage (from the project root):
    python scripts/datasets/audit_inventory.py
"""
from __future__ import annotations

import sys as _sys
for _s in (_sys.stdout, _sys.stderr):  # Windows consoles: never crash on a non-ASCII character
    try:
        _s.reconfigure(errors="replace")
    except Exception:
        pass

import ast
import collections
import csv
import hashlib
import io
import json
import os
import re
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from paths import (CREDDETX_DIR, EXTRACTED, NEMOTRON_DIR, POLICIES_DIR,  # noqa: E402
                   ROOT, ZIP_PATH)

AUDIT = ROOT / "dataset_audit"
CANARY = "7b1f3c52-9e4d-4a6b-b8f0-2d5c61e9a374"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def short_hash(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8", "replace")).hexdigest()


# --------------------------------------------------------------------------- policies
def inventory_policies() -> tuple[list[dict], dict]:
    rows, stats = [], {}
    clause_re = re.compile(r"^\s*(\d+)\.\s+", re.M)
    bullet_re = re.compile(r"^\s*-\s+", re.M)
    for p in sorted(POLICIES_DIR.glob("*.txt")):
        raw = p.read_bytes()
        text = raw.decode("utf-8")  # raises if not UTF-8 -> reported as failure
        title = text.strip().splitlines()[0].lstrip("# ").strip()
        numbered = len(clause_re.findall(text))
        bullets = len(bullet_re.findall(text))
        stats[p.name] = {"title": title, "numbered_clauses": numbered, "bullet_rules": bullets,
                         "lines": text.count("\n") + 1, "utf8": True,
                         "crlf": b"\r\n" in raw, "trailing_ws_lines": sum(1 for l in text.splitlines() if l != l.rstrip())}
        rows.append({
            "dataset": "Sample AI usage policies", "file": f"05_Sample_Policies/{p.name}", "format": "text",
            "bytes": len(raw), "sha256": sha256(p), "records": numbered or bullets,
            "record_unit": "numbered clauses" if numbered else "bullet rules",
            "fields": "title; clause text", "labels": "n/a (policy prose)", "nulls_or_empty": 0,
            "duplicates": "", "integrity_errors": 0, "contains_sensitive_values": "no",
            "licence": "not stated (supplied with the hackathon pack)", "notes": title,
        })
    return rows, stats


# --------------------------------------------------------------------------- CredDetX
def inventory_creddetx() -> tuple[list[dict], dict]:
    rows, stats = [], {}
    ids_by_split: dict[str, set] = {}
    texthash_by_split: dict[str, set] = {}
    for split in ("dev", "test"):
        path = CREDDETX_DIR / f"{split}.jsonl"
        labels = collections.Counter()
        neg_kinds = collections.Counter()
        contexts = collections.Counter()
        reviews = collections.Counter()
        attrs = collections.Counter()
        n = bad_json = empty = offset_err = no_secret_mismatch = canary_missing = 0
        span_neg_overlap = 0
        ids, dup_ids = set(), 0
        hashes, dup_text = set(), 0
        lengths = []
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    bad_json += 1
                    continue
                n += 1
                text = r.get("text") or ""
                if not text.strip():
                    empty += 1
                lengths.append(len(text))
                if r["id"] in ids:
                    dup_ids += 1
                ids.add(r["id"])
                h = short_hash(text)
                if h in hashes:
                    dup_text += 1
                hashes.add(h)
                meta = r.get("meta", {})
                contexts[meta.get("context_type")] += 1
                reviews[meta.get("review")] += 1
                if CANARY not in json.dumps(meta):
                    canary_missing += 1
                spans = r.get("spans") or []
                if bool(meta.get("no_secret")) != (len(spans) == 0):
                    no_secret_mismatch += 1
                for s in spans:
                    labels[s["label"]] += 1
                    if not (0 <= s["start"] < s["end"] <= len(text)):
                        offset_err += 1
                    a = s.get("attrs", {})
                    for k in ("is_example", "is_test_name", "is_identifier", "weak_password", "in_long_line"):
                        if a.get(k):
                            attrs[k] += 1
                    if a.get("masked", "none") != "none":
                        attrs["masked"] += 1
                    if a.get("fake_kind", "none") != "none":
                        attrs["fake"] += 1
                for g in r.get("negatives") or []:
                    neg_kinds[g["kind"]] += 1
                    if not (0 <= g["start"] < g["end"] <= len(text)):
                        offset_err += 1
                    if any(s["start"] < g["end"] and g["start"] < s["end"] for s in spans):
                        span_neg_overlap += 1
        ids_by_split[split] = ids
        texthash_by_split[split] = hashes
        lengths.sort()
        stats[split] = {
            "texts": n, "invalid_json_lines": bad_json, "empty_texts": empty, "duplicate_ids": dup_ids,
            "duplicate_texts": dup_text, "gold_spans": sum(labels.values()), "labels": dict(labels.most_common()),
            "negatives": sum(neg_kinds.values()), "negative_kinds": dict(neg_kinds.most_common()),
            "context_types": dict(contexts.most_common()), "review_verdicts": dict(reviews.most_common()),
            "span_attributes": dict(attrs.most_common()), "offset_errors": offset_err,
            "no_secret_flag_mismatches": no_secret_mismatch, "span_negative_overlaps": span_neg_overlap,
            "texts_missing_canary": canary_missing,
            "texts_without_secret": 0,  # filled below
            "median_chars": lengths[len(lengths) // 2] if lengths else 0, "max_chars": lengths[-1] if lengths else 0,
        }
        # count texts with no spans (second, cheap pass keeps the loop above readable)
        with open(path, encoding="utf-8") as fh:
            stats[split]["texts_without_secret"] = sum(1 for line in fh if line.strip() and not json.loads(line).get("spans"))
        rows.append({
            "dataset": "CredDetX v0.1", "file": f"CredDetX/{split}.jsonl", "format": "JSON Lines",
            "bytes": path.stat().st_size, "sha256": sha256(path), "records": n, "record_unit": "texts",
            "fields": "id; text; spans[start,end,label,slice,attrs]; negatives[start,end,kind,slice,attrs]; meta{context_type,file_type,domain,generator,origin,chars,no_secret,review,benchmark_version,canary}",
            "labels": f"{len(labels)} secret labels; {len(neg_kinds)} negative kinds",
            "nulls_or_empty": empty, "duplicates": f"ids {dup_ids}; texts {dup_text}",
            "integrity_errors": bad_json + offset_err + no_secret_mismatch,
            "contains_sensitive_values": "synthetic secret-shaped values (invented; do not use or publish)",
            "licence": "CC BY 4.0", "notes": "dev = study errors; test = report only (dataset authors' rule)",
        })
    stats["cross_split"] = {
        "shared_ids": len(ids_by_split["dev"] & ids_by_split["test"]),
        "shared_texts": len(texthash_by_split["dev"] & texthash_by_split["test"]),
    }
    for name in ("README (1).md", "DATASHEET.md", "labelling_guide.md"):
        p = CREDDETX_DIR / name
        rows.append({"dataset": "CredDetX v0.1", "file": f"CredDetX/{name}", "format": "markdown",
                     "bytes": p.stat().st_size, "sha256": sha256(p), "records": "", "record_unit": "documentation",
                     "fields": "", "labels": "", "nulls_or_empty": "", "duplicates": "", "integrity_errors": "",
                     "contains_sensitive_values": "no (example values are invented)", "licence": "CC BY 4.0",
                     "notes": "dataset card / datasheet / labelling rules"})
    return rows, stats


# --------------------------------------------------------------------------- Nemotron
def _parquet(path: Path):
    from parquet_lite import ParquetFile
    return ParquetFile(str(path))


def inventory_nemotron() -> tuple[list[dict], dict]:
    rows, stats = [], {}
    uids_by_file: dict[str, set] = {}
    texts_by_file: dict[str, set] = {}
    for split in ("train", "test"):
        path = NEMOTRON_DIR / f"{split}-00000-of-00001.parquet"
        pf = _parquet(path)
        desc = pf.describe()
        cols = [c["name"] for c in desc["columns"]]
        nulls = collections.Counter()
        empties = collections.Counter()
        labels = collections.Counter()
        domains = collections.Counter()
        formats = collections.Counter()
        locales = collections.Counter()
        doc_types = set()
        n = span_parse_err = offset_err = text_mismatch = overlap = 0
        no_span_rows = 0
        uids, dup_uid = set(), 0
        hashes, dup_text = set(), 0
        lengths = []
        for r in pf.iter_rows():
            n += 1
            for c in cols:
                v = r.get(c)
                if v is None:
                    nulls[c] += 1
                elif isinstance(v, str) and not v.strip():
                    empties[c] += 1
            text = r.get("text") or ""
            lengths.append(len(text))
            if r["uid"] in uids:
                dup_uid += 1
            uids.add(r["uid"])
            h = short_hash(text)
            if h in hashes:
                dup_text += 1
            hashes.add(h)
            domains[r.get("domain")] += 1
            formats[r.get("document_format")] += 1
            locales[r.get("locale")] += 1
            doc_types.add(r.get("document_type"))
            try:
                spans = ast.literal_eval(r.get("spans") or "[]")
            except (ValueError, SyntaxError):
                span_parse_err += 1
                continue
            if not spans:
                no_span_rows += 1
            prev_end = -1
            for s in sorted(spans, key=lambda s: (s["start"], s["end"])):
                labels[s["label"]] += 1
                if not (0 <= s["start"] < s["end"] <= len(text)):
                    offset_err += 1
                elif text[s["start"]:s["end"]] != s.get("text"):
                    text_mismatch += 1
                if s["start"] < prev_end:
                    overlap += 1
                prev_end = max(prev_end, s["end"])
        uids_by_file[split] = uids
        texts_by_file[split] = hashes
        lengths.sort()
        stats[split] = {
            "rows_in_footer": desc["rows"], "rows_read": n, "row_groups": desc["row_groups"], "codec": desc["codecs"],
            "columns": cols, "null_counts": dict(nulls), "empty_string_counts": dict(empties),
            "duplicate_uids": dup_uid, "duplicate_texts": dup_text, "span_parse_errors": span_parse_err,
            "span_offset_errors": offset_err, "span_text_mismatches": text_mismatch, "overlapping_spans": overlap,
            "rows_without_spans": no_span_rows, "total_spans": sum(labels.values()),
            "distinct_labels": len(labels), "labels": dict(labels.most_common()),
            "distinct_domains": len(domains), "top_domains": dict(domains.most_common(15)),
            "document_formats": dict(formats), "locales": dict(locales), "distinct_document_types": len(doc_types),
            "median_chars": lengths[len(lengths) // 2] if lengths else 0, "max_chars": lengths[-1] if lengths else 0,
        }
        rows.append({
            "dataset": "NVIDIA Nemotron-PII", "file": f"Nemotron-PII/{path.name}", "format": "Parquet (snappy)",
            "bytes": path.stat().st_size, "sha256": sha256(path), "records": n, "record_unit": "documents",
            "fields": "; ".join(cols) + " (spans = Python-literal list of {start,end,text,label})",
            "labels": f"{len(labels)} PII/PHI labels", "nulls_or_empty": sum(nulls.values()) + sum(empties.values()),
            "duplicates": f"uids {dup_uid}; texts {dup_text}", "integrity_errors": span_parse_err + offset_err + text_mismatch,
            "contains_sensitive_values": "synthetic PII (persona-generated; treat as sensitive-shaped)",
            "licence": "CC BY 4.0", "notes": f"footer rows {desc['rows']}; README states 50k/50k split",
        })
    stats["cross_file"] = {
        "shared_uids": len(uids_by_file["train"] & uids_by_file["test"]),
        "shared_texts": len(texts_by_file["train"] & texts_by_file["test"]),
    }
    p = NEMOTRON_DIR / "README.md"
    rows.append({"dataset": "NVIDIA Nemotron-PII", "file": "Nemotron-PII/README.md", "format": "markdown",
                 "bytes": p.stat().st_size, "sha256": sha256(p), "records": "", "record_unit": "documentation",
                 "fields": "", "labels": "", "nulls_or_empty": "", "duplicates": "", "integrity_errors": "",
                 "contains_sensitive_values": "no", "licence": "CC BY 4.0", "notes": "dataset card"})
    return rows, stats


# --------------------------------------------------------------------------- tool archives
DATA_EXT = (".csv", ".tsv", ".json", ".jsonl", ".parquet", ".txt", ".png", ".jpg", ".jpeg")


def inventory_archives() -> tuple[list[dict], dict]:
    rows, stats = [], {}
    outer = zipfile.ZipFile(ZIP_PATH)
    for member, name, licence in (
        ("AI_GuardRail_Datasets/EasyOCR_Tool/EasyOCR-master.zip", "EasyOCR source archive", "Apache-2.0"),
        ("AI_GuardRail_Datasets/Microsoft Presidio — PII detection and redaction/presidio-main.zip",
         "Microsoft Presidio source archive", "MIT"),
    ):
        info = outer.getinfo(member)
        inner = zipfile.ZipFile(io.BytesIO(outer.read(member)))
        names = [i.filename for i in inner.infolist() if not i.is_dir()]
        ext = collections.Counter(os.path.splitext(n)[1].lower() or "(none)" for n in names)
        weights = [n for n in names if n.endswith((".pth", ".pt", ".onnx", ".bin"))]
        data_like = [n for n in names if n.lower().endswith(DATA_EXT) and "/test" in n.lower()]
        stats[name] = {"files": len(names), "top_extensions": dict(ext.most_common(12)),
                       "model_weight_files": len(weights), "data_like_files_under_tests": len(data_like),
                       "python_files": ext.get(".py", 0)}
        rows.append({
            "dataset": name, "file": member.split("AI_GuardRail_Datasets/")[1], "format": "zip of a source repository",
            "bytes": info.file_size, "sha256": hashlib.sha256(outer.read(member)).hexdigest(), "records": len(names),
            "record_unit": "files in archive", "fields": "n/a", "labels": "none (software, not a labelled dataset)",
            "nulls_or_empty": "", "duplicates": "", "integrity_errors": 0 if inner.testzip() is None else 1,
            "contains_sensitive_values": "no", "licence": licence,
            "notes": f"{ext.get('.py', 0)} .py files; {len(weights)} model-weight files",
        })
        for doc in [m for m in outer.namelist() if m.startswith(member.rsplit("/", 1)[0] + "/") and m != member and not m.endswith("/")]:
            i = outer.getinfo(doc)
            rows.append({"dataset": name, "file": doc.split("AI_GuardRail_Datasets/")[1], "format": "text",
                         "bytes": i.file_size, "sha256": hashlib.sha256(outer.read(doc)).hexdigest(), "records": "",
                         "record_unit": "documentation", "fields": "", "labels": "", "nulls_or_empty": "",
                         "duplicates": "", "integrity_errors": "", "contains_sensitive_values": "no",
                         "licence": licence, "notes": "readme / licence"})
    return rows, stats


def main() -> None:
    AUDIT.mkdir(exist_ok=True)
    all_rows, all_stats = [], {"zip": {"path": str(ZIP_PATH.relative_to(ROOT)), "bytes": ZIP_PATH.stat().st_size,
                                       "sha256": sha256(ZIP_PATH),
                                       "crc_check": "ok" if zipfile.ZipFile(ZIP_PATH).testzip() is None else "FAILED"}}
    for fn, key in ((inventory_policies, "policies"), (inventory_creddetx, "creddetx"),
                    (inventory_nemotron, "nemotron"), (inventory_archives, "tool_archives")):
        print("inventory:", key, flush=True)
        r, s = fn()
        all_rows += r
        all_stats[key] = s
    fields = list(all_rows[0])
    with open(AUDIT / "dataset_inventory.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(all_rows)
    with open(AUDIT / "inventory_stats.json", "w", encoding="utf-8") as fh:
        json.dump(all_stats, fh, indent=2, sort_keys=False)
    print("wrote", AUDIT / "dataset_inventory.csv", "and inventory_stats.json")


if __name__ == "__main__":
    main()
