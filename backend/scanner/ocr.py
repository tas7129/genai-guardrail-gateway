"""OCR for uploaded images using Tesseract (via pytesseract)."""
from __future__ import annotations

import io
import re
from dataclasses import dataclass, field
from typing import List, Tuple


class OCRError(Exception):
    pass


_CONFIGURED = False


def _configure_tesseract() -> None:
    """Find tesseract.exe on Windows when it is not on PATH (the installer does not add it by default).
    TESSERACT_CMD in .env / the environment always wins."""
    global _CONFIGURED
    if _CONFIGURED:
        return
    _CONFIGURED = True
    import os
    import shutil
    try:
        import pytesseract
    except ImportError:
        return
    cmd = os.environ.get("TESSERACT_CMD", "").strip().strip('"')
    if not cmd and os.name == "nt" and not shutil.which("tesseract"):
        for cand in (r"C:\Program Files\Tesseract-OCR\tesseract.exe", r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
                     os.path.expandvars(r"%LOCALAPPDATA%\Programs\Tesseract-OCR\tesseract.exe")):
            if os.path.exists(cand):
                cmd = cand
                break
    if cmd:
        pytesseract.pytesseract.tesseract_cmd = cmd


@dataclass
class OCRResult:
    text: str
    confidence: float  # mean word confidence 0..100
    words: int
    width: int
    height: int
    method: str = "standard"
    passes: List[str] = field(default_factory=list)


def ocr_status() -> Tuple[bool, str]:
    """(available, version-or-error) – used by the health endpoint."""
    try:
        _configure_tesseract()
        import pytesseract
        return True, str(pytesseract.get_tesseract_version()).split("\n")[0]
    except Exception as exc:  # pragma: no cover - depends on host
        return False, "Tesseract not available: %s" % exc


def ocr_image(data: bytes) -> OCRResult:
    _configure_tesseract()
    try:
        import pytesseract
        from PIL import Image, ImageOps
    except ImportError as exc:
        raise OCRError("OCR libraries not installed (%s)" % exc)

    try:
        img = Image.open(io.BytesIO(data))
        img.load()
    except Exception as exc:
        raise OCRError("image could not be decoded (%s)" % exc.__class__.__name__)

    if getattr(img, "is_animated", False):
        img.seek(0)
    width, height = img.size
    if width * height > 40_000_000:
        raise OCRError("image too large to scan safely")

    gray = ImageOps.grayscale(img.convert("RGB"))
    if width < 1400:  # upscale small screenshots – improves Tesseract accuracy
        factor = 1400 / float(width)
        gray = gray.resize((int(width * factor), int(height * factor)))
    gray = ImageOps.autocontrast(gray)

    best = _run(gray, "standard")
    passes = [best.method]
    if best.weak:
        # 1) rotated scans: ask Tesseract's orientation detector, else try all three rotations
        angle = _osd_rotation(gray)
        candidates = [angle] if angle else [90, 180, 270]
        for a in candidates:
            r = _run(gray.rotate(-a, expand=True, fillcolor=255), "rotated %d°" % a)
            passes.append(r.method)
            if r.score > best.score:
                best = r
        # 2) small / blurry text: upscale ×2 and sharpen;  3) faint text: equalise + binarise
        if best.weak:
            from PIL import ImageFilter
            base = gray.rotate(-best.rotation, expand=True, fillcolor=255) if best.rotation else gray
            big = base.resize((base.width * 2, base.height * 2)).filter(ImageFilter.UnsharpMask(radius=2, percent=180))
            for img2, name in ((big, "upscaled + sharpened"),
                               (ImageOps.equalize(base).point(lambda v: 255 if v > 160 else 0), "contrast-enhanced")):
                r = _run(img2, name, best.rotation)
                passes.append(r.method)
                if r.score > best.score:
                    best = r
    if best.words and best.confidence < NOISE_CONFIDENCE:
        # Only noise-level "words" (photo texture, patterns): no text to screen. Image pixels are never
        # forwarded, so nothing from this image reaches the model; the UI says so explicitly.
        return OCRResult(text="", confidence=round(best.confidence, 1), words=0, width=width, height=height,
                         method=best.method, passes=passes)
    if best.words and best.confidence < MIN_RELIABLE_CONFIDENCE:
        raise OCRError("text in the image could not be read reliably (confidence %.0f%% after %d passes) – "
                       "upload a clearer image or paste the text" % (best.confidence, len(passes)))
    return OCRResult(text=best.text, confidence=round(best.confidence, 1), words=best.words, width=width, height=height,
                     method=best.method, passes=passes)


# Below this mean word confidence, OCR output is treated as unreadable and the
# attachment fails closed (a partly-read secret must not slip through as noise).
MIN_RELIABLE_CONFIDENCE = 45.0
NOISE_CONFIDENCE = 30.0


class _Pass:
    def __init__(self, text: str, confidence: float, words: int, method: str, rotation: int = 0):
        self.text, self.confidence, self.words, self.method, self.rotation = text, confidence, words, method, rotation

    @property
    def score(self) -> float:
        return self.confidence * min(self.words, 60)

    @property
    def weak(self) -> bool:
        return self.confidence < 70 or self.words < 3


def _osd_rotation(gray) -> int:
    try:
        import pytesseract
        osd = pytesseract.image_to_osd(gray, config="--psm 0")
        m = re.search(r"Rotate:\s*(\d+)", osd)
        return int(m.group(1)) % 360 if m else 0
    except Exception:
        return 0  # OSD data missing or too little text – fall back to trying rotations


def _run(gray, method: str, rotation: int = 0) -> "_Pass":
    import pytesseract
    if rotation is None:
        rotation = 0
    rot = int(re.search(r"(\d+)°", method).group(1)) if "rotated" in method else rotation
    try:
        data_dict = pytesseract.image_to_data(gray, output_type=pytesseract.Output.DICT, config="--psm 3")
    except Exception as exc:
        raise OCRError("Tesseract failed: %s" % exc)
    lines = {}
    confs = []
    for i, word in enumerate(data_dict["text"]):
        word = (word or "").strip()
        try:
            conf = float(data_dict["conf"][i])
        except (TypeError, ValueError):
            conf = -1
        if not word or conf < 0:
            continue
        key = (data_dict["block_num"][i], data_dict["par_num"][i], data_dict["line_num"][i])
        lines.setdefault(key, []).append(word)
        confs.append(conf)
    text = "\n".join(" ".join(ws) for _, ws in sorted(lines.items()))
    mean_conf = sum(confs) / len(confs) if confs else 0.0
    return _Pass(text, mean_conf, len(confs), method, rot)
