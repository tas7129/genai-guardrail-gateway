"""Synthetic attachments for the audit suite – generated at test time, no binary
fixtures in git. Every value is invented."""
from __future__ import annotations

import io
import random

from PIL import Image, ImageDraw, ImageFilter, ImageFont


def text_image(lines, size=30, rotate=0, blur=0.0, fg=(20, 20, 20), bg=(255, 255, 255), width=1300, pad=40) -> bytes:
    font = ImageFont.load_default(size=size)
    line_h = int(size * 1.5)
    img = Image.new("RGB", (width, pad * 2 + line_h * len(lines)), bg)
    d = ImageDraw.Draw(img)
    for i, line in enumerate(lines):
        d.text((pad, pad + i * line_h), line, fill=fg, font=font)
    if blur:
        img = img.filter(ImageFilter.GaussianBlur(blur))
    if rotate:
        img = img.rotate(rotate, expand=True, fillcolor=bg)
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


def noise_image(seed=3) -> bytes:
    r = random.Random(seed)
    img = Image.new("L", (600, 400))
    img.putdata([r.randint(0, 255) for _ in range(600 * 400)])
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


def simple_pdf(lines) -> bytes:
    """Minimal one-page PDF with a Helvetica text layer (readable by pypdf)."""
    esc = lambda s: s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")  # noqa: E731
    content = "BT /F1 12 Tf 50 780 Td 16 TL " + " ".join("(%s) '" % esc(l) for l in lines) + " ET"
    objs = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        "<< /Length %d >>\nstream\n%s\nendstream" % (len(content), content),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = io.BytesIO()
    out.write(b"%PDF-1.4\n")
    offsets = []
    for i, o in enumerate(objs, 1):
        offsets.append(out.tell())
        out.write(("%d 0 obj\n%s\nendobj\n" % (i, o)).encode("latin-1"))
    xref = out.tell()
    out.write(("xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)).encode())
    for off in offsets:
        out.write(("%010d 00000 n \n" % off).encode())
    out.write(("trailer << /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)).encode())
    return out.getvalue()


def docx_bytes(paragraphs) -> bytes:
    import docx
    doc = docx.Document()
    for p in paragraphs:
        doc.add_paragraph(p)
    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()
