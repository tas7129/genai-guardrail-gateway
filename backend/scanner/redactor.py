"""Replace sensitive spans with descriptive placeholders such as [EMAIL REDACTED].

* Only the sensitive span is replaced; the rest of the sentence is untouched.
* The same value always gets the same placeholder within one request.
* When a request holds several DIFFERENT values of the same kind they are
  numbered so the model can still tell them apart: [EMAIL 1 REDACTED], [EMAIL 2 REDACTED].
"""
from __future__ import annotations

import re
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from .detectors import Finding

PLACEHOLDER_RE = re.compile(r"\[[A-Z0-9/' ]+? REDACTED\]")


def _norm(v: str) -> str:
    v = v.strip().lower()
    return re.sub(r"[\s\-]", "", v) if re.fullmatch(r"[\d\s\-+()]+", v) else v


class Redactor:
    def __init__(self, findings: Optional[Iterable[Finding]] = None) -> None:
        self._mapping: Dict[Tuple[str, str], str] = {}
        self._counters: Dict[str, int] = {}
        self._distinct: Dict[str, int] = {}
        if findings is not None:
            self.prepare(findings)

    def prepare(self, findings: Iterable[Finding]) -> None:
        """Count distinct values per placeholder over everything that may be redacted."""
        seen: Dict[str, set] = {}
        for f in findings:
            if f.redactable and f.level != "LOW":
                seen.setdefault(f.placeholder_prefix, set()).add(_norm(f.value))
        self._distinct = {k: len(v) for k, v in seen.items()}

    def placeholder_for(self, f: Finding) -> str:
        prefix = f.placeholder_prefix
        key = (prefix, _norm(f.value))
        if key not in self._mapping:
            if self._distinct.get(prefix, 1) <= 1:
                self._mapping[key] = "[%s REDACTED]" % prefix
            else:
                n = self._counters.get(prefix, 0) + 1
                self._counters[prefix] = n
                self._mapping[key] = "[%s %d REDACTED]" % (prefix, n)
        return self._mapping[key]

    def redact(self, text: str, findings: Iterable[Finding],
               include: Optional[Callable[[Finding], bool]] = None) -> Tuple[str, List[dict]]:
        """Return (sanitized_text, replacements). `include` selects which findings to
        replace (default: every redactable finding that is not LOW)."""
        include = include or (lambda f: f.level != "LOW")
        spans = sorted((f for f in findings if f.redactable and include(f)), key=lambda f: (f.start, -f.end))
        out, last, replacements = [], 0, []
        for f in spans:
            if f.start < last:  # overlaps were merged by the detector; never emit a partial value
                continue
            ph = self.placeholder_for(f)
            out.append(text[last:f.start])
            out.append(ph)
            last = f.end
            replacements.append({"placeholder": ph, "type": f.type, "label": f.label, "category": f.category,
                                 "severity": f.level, "masked": f.masked(), "source": f.source})
        out.append(text[last:])
        return "".join(out), replacements


def highlight_segments(text: str, findings: Iterable[Finding], max_chars: int = 4000) -> List[dict]:
    """Split text into plain / sensitive segments for UI highlighting.
    Sensitive segments carry a masked value, never the raw value."""
    text = text[:max_chars]
    spans = sorted((f for f in findings if f.has_span and f.start < len(text)), key=lambda f: (f.start, -f.end))
    segs, last = [], 0
    for f in spans:
        if f.start < last:
            continue
        if f.start > last:
            segs.append({"text": text[last:f.start]})
        segs.append({"text": f.masked(), "type": f.type, "label": f.label, "category": f.category, "severity": f.level})
        last = min(f.end, len(text))
    if last < len(text):
        segs.append({"text": text[last:]})
    return segs
