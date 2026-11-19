"""Phase 4/6 – build the cleaned, integrated subsets from the ORIGINAL files.

Stdlib only. Originals under datasets/original/ are opened read-only and never
changed. Every transformation is counted and written to
datasets/processed/MANIFEST.json (summarised in dataset_audit/cleaning_report.md).

Outputs
  policy/reference_policies.json          organisation policy pack, one clause per record
                                          (committed: short policy prose, no sensitive values)
  datasets/processed/nemotron_dev.jsonl   2,000-document stratified sample of the Nemotron TRAIN file
                                          (used to study detector errors)
  datasets/processed/nemotron_eval.jsonl  2,000-document stratified sample of the Nemotron TEST file
                                          (used only to report results)
  datasets/processed/MANIFEST.json        input/output hashes, seeds, counts, transformations

CredDetX needs no transformation (0 integrity errors, see inventory) and is read
in place by scripts/datasets/evaluate.py, so no second copy is made.

Usage (from the project root):
    python scripts/datasets/build_processed.py [--per-stratum 500] [--seed 16]
"""
from __future__ import annotations

import sys as _sys
for _s in (_sys.stdout, _sys.stderr):  # Windows consoles: never crash on a non-ASCII character
    try:
        _s.reconfigure(errors="replace")
    except Exception:
        pass

import argparse
import ast
import collections
import hashlib
import json
import random
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from paths import NEMOTRON_DIR, POLICIES_DIR, PROCESSED, ROOT  # noqa: E402

REFERENCE_OUT = ROOT / "policy" / "reference_policies.json"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


# =========================================================================== policies
# Reviewed mapping of every source clause to the gateway's categories and AUP clauses.
# consistency: consistent | partial | conflict | advisory  (explained in the relevance report)
POLICY_FILES = {
    "01_Data_Privacy_Policy.txt": ("DPP", "Data Privacy Policy"),
    "02_Source_Code_Policy.txt": ("SCP", "Source Code and Intellectual Property Policy"),
    "03_Credentials_Policy.txt": ("CRP", "Credentials and Secrets Policy"),
    "04_Confidential_Information_Policy.txt": ("CIP", "Confidential Business Information Policy"),
    "05_Image_and_Attachment_Policy.txt": ("IAP", "Image and Attachment Security Policy"),
    "06_AI_Usage_Governance_Policy.txt": ("GOV", "AI Usage Governance Policy"),
}
CLAUSE_MAP = {
    "DPP-1": ("PERSONAL_DATA", "Customer personal and financial details", ["AUP-3", "AUP-13"], "consistent",
              "Identifiers are redacted or held before anything reaches the model."),
    "DPP-2": ("PERSONAL_DATA", "Redact personal information before forwarding", ["AUP-3", "AUP-8"], "partial",
              "HIGH identifiers are always redacted. MEDIUM items can be sent unredacted by the user's choice "
              "unless strict mode is on; strict mode makes the gateway follow this clause literally."),
    "DPP-3": ("PERSONAL_DATA", "Block when safe redaction is impossible", ["AUP-4", "AUP-5"], "partial",
              "The gateway blocks when a secret cannot be safely redacted and holds bulk personal records for "
              "manager approval instead of blocking them."),
    "DPP-4": ("BULK_PERSONAL_DATA", "Only anonymised customer data for analysis", ["AUP-4"], "partial",
              "Bulk customer records are held for manager approval; identifiers stay redacted after approval."),
    "SCP-1": ("SOURCE_CODE", "Proprietary source code needs authorisation", ["AUP-7"], "consistent", ""),
    "SCP-2": ("SOURCE_CODE", "Algorithms, designs and technical documents are protected", ["AUP-7", "AUP-6"],
              "consistent", ""),
    "SCP-3": ("SOURCE_CODE", "Proprietary code is flagged for manager approval", ["AUP-7"], "consistent", ""),
    "SCP-4": ("SOURCE_CODE", "Public code may be shared subject to its licence", ["AUP-7"], "consistent", ""),
    "CRP-1": ("CREDENTIALS", "Credentials must never be shared with AI tools", ["AUP-5"], "consistent",
              "Credential values are always replaced before forwarding and never reach the model."),
    "CRP-2": ("CREDENTIALS", "Prompts containing active credentials are blocked", ["AUP-5"], "conflict",
              "The gateway's severity policy (AUP-5) replaces credentials with placeholders and forwards the rest "
              "of the prompt; it blocks only when safe redaction is impossible. An admin can set AUP-5 to BLOCK "
              "to follow this clause literally."),
    "CRP-3": ("CREDENTIALS", "Detected credentials are not forwarded", ["AUP-5", "AUP-8"], "consistent", ""),
    "CRP-4": ("CREDENTIALS", "Rotate exposed credentials", ["AUP-5"], "advisory",
              "A procedural duty for the employee; the gateway shows it as remediation advice."),
    "CIP-1": ("CONFIDENTIAL_BUSINESS", "Internal financials, strategy and plans need authorisation", ["AUP-6"],
              "consistent", ""),
    "CIP-2": ("CONFIDENTIAL_BUSINESS", "Confidential requests require manager approval", ["AUP-6", "AUP-9"],
              "consistent", ""),
    "CIP-3": ("PUBLIC", "Public company information may be used freely", ["AUP-2"], "consistent", ""),
    "CIP-4": ("UNSCANNABLE_ATTACHMENT", "Confidential attachments are scanned first", ["AUP-10"], "consistent", ""),
    "IAP-1": ("UNSCANNABLE_ATTACHMENT", "Scan every image and document", ["AUP-10"], "consistent", ""),
    "IAP-2": ("UNSCANNABLE_ATTACHMENT", "Extract image text with OCR", ["AUP-10"], "consistent", ""),
    "IAP-3": ("UNSCANNABLE_ATTACHMENT", "Check extracted text for sensitive data", ["AUP-10", "AUP-3", "AUP-5"],
              "consistent", ""),
    "IAP-4": ("UNSCANNABLE_ATTACHMENT", "Block or redact prohibited attachments", ["AUP-10", "AUP-8"], "consistent", ""),
    "GOV-1": ("GENERAL", "Purpose", ["AUP-1"], "consistent", ""),
    "GOV-2": ("GENERAL", "Employee responsibilities", ["AUP-1"], "consistent", ""),
    "GOV-3": ("APPROVAL", "Manager approval", ["AUP-9"], "consistent", ""),
    "GOV-4": ("AUDIT", "Audit and monitoring", ["AUP-11"], "consistent", ""),
    "GOV-5": ("PUBLIC", "Exceptions: public information and fictional examples", ["AUP-2", "AUP-21"], "consistent", ""),
    "GOV-6": ("GENERAL", "Enforcement", ["AUP-1"], "advisory", ""),
    "GOV-7": ("GENERAL", "Relationship to the gateway's technical rules", ["AUP-21"], "consistent",
              "States that the policy pack supplements and does not override the gateway's detection, "
              "classification and censorship rules."),
}


def _clean_text(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def parse_policies(stats: dict) -> list[dict]:
    clauses: list[dict] = []
    for fname, (prefix, policy_name) in POLICY_FILES.items():
        path = POLICIES_DIR / fname
        raw = path.read_bytes()
        text = raw.decode("utf-8")
        if "\r\n" in text:
            stats["crlf_files_normalised"] += 1
        text = text.replace("\r\n", "\n")
        parts: list[tuple[str, str]] = []
        if prefix == "GOV":
            # Markdown: "## n. Title" sections; bullets in a section are joined into one clause.
            for m in re.finditer(r"^## (\d+)\. [^\n]+\n(.*?)(?=^## |\Z)", text, re.M | re.S):
                num, section = m.group(1), m.group(2)
                paras = [p for p in re.split(r"\n\s*\n", section) if p.strip()]
                if num == "6" and len(paras) > 1:
                    # the closing paragraph after "Enforcement" is a separate statement (GOV-7)
                    parts.append(("6", _clean_text(paras[0])))
                    parts.append(("7", _clean_text(" ".join(paras[1:]))))
                    stats["closing_statement_split"] += 1
                    continue
                bullets = [b.strip() for b in re.findall(r"^-\s+(.*)$", section, re.M)]
                if bullets:
                    stats["bullet_lists_joined"] += 1
                parts.append((num, _clean_text(" ".join(bullets) if bullets else section)))
        else:
            for m in re.finditer(r"^(\d+)\.\s+(.*?)(?=^\d+\.\s|\Z)", text, re.M | re.S):
                stats["wrapped_lines_joined"] += m.group(2).strip().count("\n")
                parts.append((m.group(1), _clean_text(m.group(2))))
        for num, body in parts:
            cid = "%s-%s" % (prefix, num)
            category, title, maps_to, consistency, note = CLAUSE_MAP[cid]
            clauses.append({
                "id": cid, "title": title, "category": category, "action": "REFERENCE", "severity": 0,
                "text": body, "remediation": "", "kind": "reference", "policy": policy_name,
                "source": "AI_GuardRail_Datasets/05_Sample_Policies/" + fname,
                "source_ref": ("section %s" if prefix == "GOV" else "clause %s") % num,
                "maps_to": maps_to, "consistency": consistency, "consistency_note": note,
            })
    missing = set(CLAUSE_MAP) - {c["id"] for c in clauses}
    if missing:
        raise SystemExit("policy parse error: clauses not found: %s" % sorted(missing))
    return clauses


# =========================================================================== Nemotron
def clean_nemotron_row(r: dict, counts: collections.Counter) -> dict | None:
    text = r.get("text")
    if not isinstance(text, str) or not text.strip():
        counts["dropped_empty_text"] += 1
        return None
    try:
        spans = ast.literal_eval(r.get("spans") or "[]")  # literal_eval only: never executes code
    except (ValueError, SyntaxError):
        counts["dropped_unparseable_spans"] += 1
        return None
    if not spans:
        counts["dropped_no_spans"] += 1
        return None
    out_spans = []
    for s in spans:
        st, en = s.get("start"), s.get("end")
        if not (isinstance(st, int) and isinstance(en, int) and 0 <= st < en <= len(text)):
            counts["dropped_offset_out_of_range"] += 1
            return None
        seg = text[st:en]
        given = s.get("text")
        if isinstance(given, str) and given == seg:
            pass
        elif not isinstance(given, str) and str(given) == seg:
            counts["span_text_type_normalised"] += 1   # e.g. age stored as int 42
        elif isinstance(given, str) and given.lower() == seg.lower():
            counts["span_text_case_normalised"] += 1   # offsets right, label text re-cased
        else:
            counts["dropped_offset_mismatch_records"] += 1  # offsets point at different text
            return None
        out_spans.append({"start": st, "end": en, "label": s.get("label")})
    out_spans.sort(key=lambda s: (s["start"], s["end"]))
    return {"uid": r["uid"], "locale": r.get("locale"), "document_format": r.get("document_format"),
            "domain": r.get("domain"), "document_type": r.get("document_type"), "text": text, "spans": out_spans}


def sample_nemotron(split: str, per_stratum: int, seed: int) -> tuple[list[dict], dict]:
    from parquet_lite import ParquetFile
    path = NEMOTRON_DIR / f"{split}-00000-of-00001.parquet"
    pf = ParquetFile(str(path))
    rng = random.Random(f"{seed}-{split}")
    counts: collections.Counter = collections.Counter()
    seen_text: set[str] = set()
    reservoirs: dict[tuple, list] = collections.defaultdict(list)
    seen_per: collections.Counter = collections.Counter()
    for r in pf.iter_rows(["uid", "domain", "document_type", "document_format", "locale", "text", "spans"]):
        counts["rows_read"] += 1
        h = hashlib.sha1((r.get("text") or "").encode("utf-8", "replace")).hexdigest()
        if h in seen_text:
            counts["dropped_duplicate_text"] += 1
            continue
        seen_text.add(h)
        row = clean_nemotron_row(r, counts)
        if row is None:
            continue
        counts["clean_rows"] += 1
        key = (row["locale"], row["document_format"])
        seen_per[key] += 1
        res = reservoirs[key]
        if len(res) < per_stratum:          # reservoir sampling: uniform within each stratum
            res.append(row)
        else:
            j = rng.randrange(seen_per[key])
            if j < per_stratum:
                res[j] = row
    sample = [row for key in sorted(reservoirs) for row in reservoirs[key]]
    rng.shuffle(sample)
    labels = collections.Counter(s["label"] for row in sample for s in row["spans"])
    info = {"source": str(path.relative_to(ROOT)), "source_sha256": sha256_file(path),
            "strata": {"%s/%s" % k: len(v) for k, v in sorted(reservoirs.items())},
            "clean_rows_per_stratum": {"%s/%s" % k: v for k, v in sorted(seen_per.items())},
            "transformations": dict(counts), "sample_size": len(sample),
            "sample_spans": sum(labels.values()), "sample_labels": dict(labels.most_common())}
    return sample, info


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--per-stratum", type=int, default=500, help="documents per locale x format stratum")
    ap.add_argument("--seed", type=int, default=16)
    args = ap.parse_args()
    PROCESSED.mkdir(parents=True, exist_ok=True)
    manifest: dict = {"seed": args.seed, "per_stratum": args.per_stratum}

    pstats: collections.Counter = collections.Counter()
    clauses = parse_policies(pstats)
    doc = {"policy_name": "Organisation AI policy pack (reference)", "version": 1,
           "source": "AI_GuardRail_Datasets.zip / 05_Sample_Policies (6 files)",
           "note": "Reference clauses only (action REFERENCE): they are retrieved and shown next to the governing "
                   "AUP clause but never decide an outcome. The pack itself states it supplements, and does not "
                   "override, the gateway's technical rules (GOV-7).",
           "clauses": clauses}
    REFERENCE_OUT.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    manifest["policies"] = {"output": str(REFERENCE_OUT.relative_to(ROOT)), "clauses": len(clauses),
                            "by_consistency": dict(collections.Counter(c["consistency"] for c in clauses)),
                            "transformations": dict(pstats),
                            "inputs": {f: sha256_file(POLICIES_DIR / f) for f in POLICY_FILES}}
    print("policies:", len(clauses), "reference clauses ->", REFERENCE_OUT.relative_to(ROOT), flush=True)

    for split, name in (("train", "nemotron_dev.jsonl"), ("test", "nemotron_eval.jsonl")):
        sample, info = sample_nemotron(split, args.per_stratum, args.seed)
        out = PROCESSED / name
        write_jsonl(out, sample)
        info["output"] = str(out.relative_to(ROOT))
        info["output_sha256"] = sha256_file(out)
        manifest["nemotron_" + split] = info
        print("nemotron", split, "->", out.relative_to(ROOT), len(sample), "docs", flush=True)

    (PROCESSED / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print("manifest written")


if __name__ == "__main__":
    main()
