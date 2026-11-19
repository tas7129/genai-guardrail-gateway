"""Attachment inspection: type checks and text extraction (fail closed).

Every attachment ends in one of two states:
  ok=True  -> its text was extracted and will be screened like the prompt
  ok=False -> it could not be scanned; the gateway BLOCKS the request
"""
from __future__ import annotations

import io
from dataclasses import dataclass, field
from pathlib import PurePath
from typing import Optional

from .. import config
from .ocr import OCRError, ocr_image

TEXT_EXT = {".txt", ".md", ".csv", ".tsv", ".json", ".log", ".xml", ".yaml", ".yml",
            ".ini", ".cfg", ".conf", ".env", ".html", ".htm", ".sql", ".properties", ".toml"}
CODE_EXT = {".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".c", ".cpp", ".h", ".hpp", ".cs",
            ".go", ".rb", ".php", ".kt", ".swift", ".rs", ".sh", ".scala", ".r", ".m"}
IMAGE_EXT = {".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff", ".webp", ".gif"}
DOC_EXT = {".pdf", ".docx"}

SUPPORTED_DESCRIPTION = "text, markdown, CSV, JSON, source code, PDF (with text layer), DOCX, PNG/JPG/WEBP images"


@dataclass
class AttachmentResult:
    name: str
    size: int
    kind: str = "unsupported"
    ok: bool = False
    text: str = ""
    error: str = ""
    method: str = ""
    ocr_confidence: Optional[float] = None
    ocr_words: int = 0
    is_code: bool = False
    pages: int = 0
    notes: list = field(default_factory=list)

    def public(self) -> dict:
        return {
            "name": self.name, "size": self.size, "kind": self.kind, "ok": self.ok,
            "error": self.error, "method": self.method, "chars": len(self.text),
            "ocr_confidence": self.ocr_confidence, "ocr_words": self.ocr_words,
            "pages": self.pages, "notes": self.notes,
        }


def _kind_for(name: str) -> str:
    lower = name.lower()
    ext = PurePath(lower).suffix
    if lower in (".env", "dockerfile", "makefile") or ext in TEXT_EXT:
        return "text"
    if ext in CODE_EXT:
        return "code"
    if ext in IMAGE_EXT:
        return "image"
    if ext == ".pdf":
        return "pdf"
    if ext == ".docx":
        return "docx"
    return "unsupported"


def _decode_text(data: bytes) -> str:
    if b"\x00" in data[:4096]:
        raise ValueError("file looks binary although it has a text extension")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def inspect_attachment(name: str, data: bytes) -> AttachmentResult:
    safe_name = PurePath(name or "attachment").name[:120]
    res = AttachmentResult(name=safe_name, size=len(data))
    res.kind = _kind_for(safe_name)

    if len(data) == 0:
        res.error = "file is empty"
        return res
    if len(data) > config.MAX_FILE_MB * 1024 * 1024:
        res.error = "file exceeds %.0f MB limit" % config.MAX_FILE_MB
        return res
    if res.kind == "unsupported":
        res.error = "unsupported file type – supported: %s" % SUPPORTED_DESCRIPTION
        return res

    try:
        if res.kind in ("text", "code"):
            res.text = _decode_text(data)
            res.method = "utf-8 text extraction"
            res.is_code = res.kind == "code"
        elif res.kind == "image":
            ocr = ocr_image(data)
            res.text = ocr.text
            res.method = "Tesseract OCR"
            res.ocr_confidence = ocr.confidence
            res.ocr_words = ocr.words
            if ocr.method != "standard":
                res.notes.append("text read after %s pass" % ocr.method)
            if not ocr.text.strip():
                res.notes.append("no readable text found – nothing from this image is sent to the assistant (pixels are never forwarded)")
            elif ocr.confidence < 60:
                res.notes.append("moderate OCR confidence (%.0f%%)" % ocr.confidence)
        elif res.kind == "pdf":
            res.text, res.pages = _extract_pdf(data)
            res.method = "PDF text-layer extraction"
        elif res.kind == "docx":
            res.text = _extract_docx(data)
            res.method = "DOCX text extraction"
    except OCRError as exc:
        res.error = "OCR failed: %s" % exc
        return res
    except Exception as exc:
        res.error = "could not be read: %s" % exc
        return res

    res.ok = True
    return res


def _extract_pdf(data: bytes):
    from pypdf import PdfReader

    reader = PdfReader(io.BytesIO(data))
    if reader.is_encrypted:
        try:
            if not reader.decrypt(""):
                raise ValueError("PDF is password-protected")
        except Exception:
            raise ValueError("PDF is password-protected")
    pages = reader.pages
    if len(pages) > 50:
        raise ValueError("PDF has more than 50 pages")
    text = "\n".join((p.extract_text() or "") for p in pages)
    if not text.strip():
        raise ValueError("PDF has no text layer (scanned PDF) – export as image or paste text")
    return text, len(pages)


def _extract_docx(data: bytes) -> str:
    import docx  # python-docx

    document = docx.Document(io.BytesIO(data))
    parts = [p.text for p in document.paragraphs]
    for table in document.tables:
        for row in table.rows:
            parts.append(", ".join(cell.text for cell in row.cells))
    return "\n".join(parts)
