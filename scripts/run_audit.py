"""Run the complete automated test suite and write the audit report.

    python scripts/run_audit.py

Writes audit_report/AUDIT_REPORT.md and audit_report/audit_results.csv:
  * every data-driven audit case (tests/audit/cases.py) with section, category,
    expected decision, actual decision, whether anything reached the assistant
    model, PASS/FAIL and the reason for a failure;
  * every other test (workflow, access control, approvals, policy hierarchy,
    concurrency, audit log/dashboard, detectors, datasets, OCR) with PASS/FAIL/SKIP.

The suite uses a recording mock in place of Ollama (both the assistant and the
safety model), so it proves the gateway's enforcement logic – not the judgement
quality of the real models. Run scripts/verify_safety_model.py for that.
"""
import sys as _sys
for _s in (_sys.stdout, _sys.stderr):
    try:
        _s.reconfigure(errors="replace")
    except Exception:
        pass

import collections
import csv
import json
import os
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "audit_report"

FILE_SECTION = {
    "test_security_workflow.py": "6/7 Workflow, access control, audit & dashboard",
    "test_pipeline.py": "6 Pipeline & workflow (regression)",
    "test_api.py": "6 HTTP API & roles (regression)",
    "test_detectors.py": "3 Detectors (regression)",
    "test_severity.py": "3 Severity & censorship (regression)",
    "test_attachments_and_policy.py": "4/5 Attachments & policy store (regression)",
    "test_datasets.py": "3 Dataset benchmarks & policy pack (regression)",
}


def main() -> int:
    OUT.mkdir(exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="gg_audit_"))
    results_path, junit = tmp / "cases.jsonl", tmp / "junit.xml"
    env = dict(os.environ, AUDIT_RESULTS=str(results_path), PYTHONIOENCODING="utf-8")
    t0 = time.time()
    proc = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests",
                           "--junitxml", str(junit)], cwd=ROOT, env=env, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    secs = time.time() - t0
    tail = [l for l in proc.stdout.splitlines() if l.strip()][-1:] or ["(no pytest output)"]

    cases = [json.loads(l) for l in results_path.read_text(encoding="utf-8").splitlines()] if results_path.exists() else []
    others = []
    param_no = collections.defaultdict(int)  # parametrised test ids embed the synthetic inputs: number them instead
    for tc in ET.parse(junit).getroot().iter("testcase"):
        file = (tc.get("file") or tc.get("classname", "").replace(".", "/") + ".py").split("/")[-1]
        if "test_audit_cases" in file or "test_audit_cases" in (tc.get("classname") or ""):
            continue
        status = "PASS"
        reason = ""
        for tag in ("failure", "error"):
            el = tc.find(tag)
            if el is not None:
                status, reason = "FAIL", (el.get("message") or "")[:200]
        if tc.find("skipped") is not None:
            status, reason = "SKIP", (tc.find("skipped").get("message") or "")[:200]
        name = tc.get("name") or ""
        if "[" in name:
            base = name.split("[", 1)[0]
            param_no[base] += 1
            name = "%s[case %d]" % (base, param_no[base])
        others.append({"section": FILE_SECTION.get(file, file), "test": name, "result": status, "reason": reason})

    with open(OUT / "audit_results.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["kind", "id_or_test", "section", "category", "expected", "actual", "reached_assistant", "result", "reason"])
        for c in cases:
            w.writerow(["case", c["id"], c["section"], c["category"], c["expected"], c["actual"], c["forwarded"], c["result"], c["reason"]])
        for o in others:
            w.writerow(["test", o["test"], o["section"], "", "", "", "", o["result"], o["reason"]])

    by_sec = collections.defaultdict(collections.Counter)
    for c in cases:
        by_sec[c["section"]][c["result"]] += 1
    for o in others:
        by_sec[o["section"]][o["result"]] += 1
    total = collections.Counter()
    for v in by_sec.values():
        total.update(v)

    lines = ["# Security & functionality audit – automated results", "",
             "Generated %s by `python scripts/run_audit.py` (%.0f s). pytest: `%s`" % (time.strftime("%Y-%m-%d %H:%M"), secs, tail[0]), "",
             "The suite runs the real gateway code with a recording mock in place of Ollama (assistant + safety model). "
             "It proves enforcement: what is blocked, held, redacted or forwarded, and that nothing unsafe or unapproved "
             "reaches the assistant. It does not measure how well the real Llama Guard judges real prompts – run "
             "`python scripts/verify_safety_model.py` on a machine with the models installed.", "",
             "## Totals", "", "| Section | Passed | Failed | Skipped |", "|---|---|---|---|"]
    for sec in sorted(by_sec):
        c = by_sec[sec]
        lines.append("| %s | %d | %d | %d |" % (sec, c["PASS"], c["FAIL"], c["SKIP"]))
    lines.append("| **All** | **%d** | **%d** | **%d** |" % (total["PASS"], total["FAIL"], total["SKIP"]))
    lines += ["", "## Data-driven audit cases", "", "| ID | Section | Category | Expected | Actual | Reached assistant | Result |",
              "|---|---|---|---|---|---|---|"]
    for c in cases:
        lines.append("| %s | %s | %s | %s | %s | %s | %s%s |" % (
            c["id"], c["section"], c["category"].replace("|", "/"), c["expected"], c["actual"],
            "yes" if c["forwarded"] else "no", c["result"], (" – " + c["reason"]) if c["reason"] else ""))
    fails = [o for o in others if o["result"] != "PASS"]
    lines += ["", "## Other tests", "", "%d tests in workflow, access-control, policy, OCR, detector, dataset and regression "
              "suites; %d passed. Non-passing tests:" % (len(others), sum(o["result"] == "PASS" for o in others)), ""]
    lines += ["- %s · %s · %s %s" % (o["result"], o["section"], o["test"], o["reason"]) for o in fails] or ["- none"]
    (OUT / "AUDIT_REPORT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(tail[0])
    print("Report: %s  (cases: %d, other tests: %d)" % (OUT / "AUDIT_REPORT.md", len(cases), len(others)))
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())
