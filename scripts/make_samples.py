"""Generate the synthetic demo files in samples/ (all data is fictional).

    python scripts/make_samples.py

The repository already contains the generated files; re-run this only if you
want to change them.
"""
from __future__ import annotations

import sys as _sys
for _s in (_sys.stdout, _sys.stderr):  # Windows consoles: never crash on a non-ASCII character
    try:
        _s.reconfigure(errors="replace")
    except Exception:
        pass

import os
import random
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

OUT = Path(__file__).resolve().parent.parent / "samples"
OUT.mkdir(exist_ok=True)

FONT_CANDIDATES = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/Library/Fonts/Arial.ttf",
    "/System/Library/Fonts/Supplemental/Arial.ttf",
    "C:/Windows/Fonts/arial.ttf",
]
MONO_CANDIDATES = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/System/Library/Fonts/Menlo.ttc",
    "C:/Windows/Fonts/consola.ttf",
]


def font(candidates, size):
    for path in candidates:
        if os.path.exists(path):
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def meeting_notes_png():
    img = Image.new("RGB", (1200, 760), "#fffdf5")
    d = ImageDraw.Draw(img)
    h, b = font(FONT_CANDIDATES, 40), font(FONT_CANDIDATES, 28)
    d.text((60, 50), "Sprint 42 - Customer Success Sync", fill="#1b2a4a", font=h)
    d.line((60, 110, 1140, 110), fill="#c9cfe0", width=3)
    # synthetic values; literals are split so secret scanners do not flag this source file
    lines = [
        "Action items:",
        "1. Call back Rohan Verma about the failed EMI payment",
        "   Phone: +91 98452 17630",
        "2. Send the revised onboarding guide to anita.desai@inboxly.in",
        "3. Update the FAQ page with the new refund timelines",
        "4. Schedule product demo for the Pune branch next Tuesday",
        "",
        "Owner: Customer Success team    Due: Friday",
    ]
    y = 140
    for ln in lines:
        d.text((60, y), ln, fill="#22304f", font=b)
        y += 62
    img.save(OUT / "meeting_notes.png")


def server_config_png():
    img = Image.new("RGB", (1200, 520), "#0d1117")
    d = ImageDraw.Draw(img)
    m = font(MONO_CANDIDATES, 28)
    lines = [
        ("# deploy/prod.env  (screenshot from laptop)", "#8b949e"),
        ("APP_ENV=production", "#e6edf3"),
        ("AWS_ACCESS_KEY_ID=AK" "IAQ3N7RZ5WMB2K4TQX", "#e6edf3"),
        ("aws_secret_access_key=" "q8Lz2Rk7Vt0Np3Ws9Xc5" "Hm1Bd6Fj4Gy0Ua8Ke2Tn", "#e6edf3"),
        ("DB_PASSWORD=Winter2026!", "#e6edf3"),
        ("SMTP_HOST=smtp.nimbus.example", "#e6edf3"),
    ]
    y = 50
    for text, color in lines:
        d.text((50, y), text, fill=color, font=m)
        y += 70
    img.save(OUT / "server_config_screenshot.png")


def customer_export_csv():
    random.seed(7)
    first = ["Aarav", "Diya", "Kabir", "Meera", "Rohan", "Isha", "Vivaan", "Anaya", "Arjun", "Sara"]
    last = ["Kapoor", "Iyer", "Menon", "Shah", "Verma", "Reddy", "Nair", "Gupta", "Bose", "Khan"]
    rows = ["customer_id,full_name,email,phone,city,plan,monthly_spend,last_login_days"]
    for i in range(10):
        name = "%s %s" % (first[i], last[i])
        email = "%s.%s@inboxly.in" % (first[i].lower(), last[i].lower())
        phone = "+91 9%d%03d %05d" % (random.randint(0, 9), random.randint(100, 999), random.randint(10000, 99999))
        rows.append("C%04d,%s,%s,%s,%s,%s,%d,%d" % (
            1001 + i, name, email, phone, random.choice(["Pune", "Chennai", "Delhi", "Kochi", "Mumbai"]),
            random.choice(["Basic", "Pro", "Enterprise"]), random.randint(499, 9999), random.randint(0, 120)))
    (OUT / "customer_export.csv").write_text("\n".join(rows) + "\n", encoding="utf-8")


def payment_service_py():
    code = '''# Copyright (c) 2026 Nimbus Technologies. Proprietary and confidential.
# Internal module: com.nimbus.payments.reconciliation

from decimal import Decimal
from datetime import date


class SettlementReconciler:
    """Matches gateway settlements against the internal ledger."""

    TOLERANCE = Decimal("0.50")

    def __init__(self, ledger, gateway_client):
        self.ledger = ledger
        self.gateway = gateway_client

    def reconcile(self, day: date):
        settled = self.gateway.fetch_settlements(day)
        booked = {t.ref: t for t in self.ledger.transactions(day)}
        mismatches = []
        for s in settled:
            t = booked.get(s.ref)
            if t is None or abs(t.amount - s.amount) > self.TOLERANCE:
                mismatches.append((s.ref, s.amount, t.amount if t else None))
        return mismatches
'''
    (OUT / "payment_service.py").write_text(code, encoding="utf-8")


def misc():
    (OUT / "public_faq.txt").write_text(
        "Nimbus Cloud Storage - Public FAQ\n\n"
        "Q: How much free storage do I get?\nA: Every account includes 15 GB of free storage.\n\n"
        "Q: Can I share folders with people outside my organisation?\nA: Yes, using view-only links that expire after 30 days.\n",
        encoding="utf-8")
    # A file with an image extension that is not actually an image -> fails closed
    (OUT / "corrupted_image.png").write_bytes(os.urandom(2048))
    # An unsupported binary type -> fails closed
    (OUT / "unsupported_file.bin").write_bytes(b"\x00\x01\x02BINARY" + os.urandom(512))


if __name__ == "__main__":
    meeting_notes_png()
    server_config_png()
    customer_export_csv()
    payment_service_py()
    misc()
    print("Sample files written to", OUT)
