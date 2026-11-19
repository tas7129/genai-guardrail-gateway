"""Optional PIN sign-in with signed session cookies (GG_AUTH_MODE=pin).

The default "demo" mode lets presenters switch identity from the sidebar (the
browser sends X-Demo-User). That is convenient for a hackathon demo but anyone
can claim any identity. In "pin" mode:

* every demo user has a 6-digit PIN, generated randomly on first start, stored
  only as a salted PBKDF2 hash in data/demo_pins.json; the plain PINs are written
  once to data/DEMO_PINS.txt (git-ignored) for the presenter;
* POST /api/login checks the PIN and sets an HttpOnly, SameSite=Strict cookie
  holding "user.expiry.HMAC" signed with data/session.key;
* the X-Demo-User header and ?as= parameter are ignored, so identity cannot be
  spoofed from the browser;
* 5 wrong PINs for a user lock that user out for 5 minutes.

Production would replace this with SSO (OIDC/SAML).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import time
from typing import Optional

from . import config
from .auth import USERS

SESSION_COOKIE = "gg_session"
SESSION_TTL_S = 8 * 3600
_FAILS: dict = {}
_lock = threading.Lock()


def _key() -> bytes:
    config.ensure_data_dir()
    if not config.SESSION_KEY_PATH.exists():
        config.SESSION_KEY_PATH.write_bytes(secrets.token_bytes(32))
    return config.SESSION_KEY_PATH.read_bytes()


def _hash(pin: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", pin.encode("utf-8"), bytes.fromhex(salt), 200_000).hex()


def ensure_pins() -> bool:
    """Create PINs on first start in pin mode. Returns True if new PINs were written."""
    config.ensure_data_dir()
    if config.PIN_FILE.exists():
        data = json.loads(config.PIN_FILE.read_text(encoding="utf-8"))
        if set(data) >= set(USERS):
            return False
    plain, stored = {}, {}
    for uid in USERS:
        pin = "%06d" % secrets.randbelow(1_000_000)
        salt = secrets.token_hex(16)
        plain[uid] = pin
        stored[uid] = {"salt": salt, "hash": _hash(pin, salt)}
    config.PIN_FILE.write_text(json.dumps(stored, indent=2), encoding="utf-8")
    lines = ["Demo sign-in PINs (generated %s). Keep this file private; delete it after noting the PINs." % time.strftime("%Y-%m-%d %H:%M")]
    lines += ["%-8s %s" % (uid, pin) for uid, pin in plain.items()]
    config.PIN_PLAINTEXT_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return True


def check_pin(user_id: str, pin: str) -> str:
    """'' on success, otherwise an error message."""
    uid = (user_id or "").strip().lower()
    if uid not in USERS:
        return "unknown user"
    with _lock:
        fails = [t for t in _FAILS.get(uid, []) if time.time() - t < 300]
        _FAILS[uid] = fails
        if len(fails) >= 5:
            return "too many wrong PINs – try again in 5 minutes"
    data = json.loads(config.PIN_FILE.read_text(encoding="utf-8"))
    rec = data.get(uid)
    if not rec or not hmac.compare_digest(_hash(str(pin or ""), rec["salt"]), rec["hash"]):
        with _lock:
            _FAILS.setdefault(uid, []).append(time.time())
        return "wrong PIN"
    with _lock:
        _FAILS.pop(uid, None)
    return ""


def issue(user_id: str) -> str:
    exp = str(int(time.time()) + SESSION_TTL_S)
    msg = "%s.%s" % (user_id, exp)
    return msg + "." + hmac.new(_key(), msg.encode(), hashlib.sha256).hexdigest()


def verify(token: Optional[str]) -> Optional[str]:
    try:
        uid, exp, sig = (token or "").split(".")
    except ValueError:
        return None
    msg = "%s.%s" % (uid, exp)
    if not hmac.compare_digest(sig, hmac.new(_key(), msg.encode(), hashlib.sha256).hexdigest()):
        return None
    if int(exp) < time.time() or uid not in USERS:
        return None
    return uid
