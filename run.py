"""Start the Guardrail Gateway:  python run.py

Then open http://127.0.0.1:8000 in your browser.
"""

import sys as _sys
for _s in (_sys.stdout, _sys.stderr):  # Windows consoles: never crash on a non-ASCII character
    try:
        _s.reconfigure(errors="replace")
    except Exception:
        pass
import logging

import uvicorn

from backend import config

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    print("\n  GenAI Guardrail Gateway  →  http://%s:%d\n" % (config.HOST, config.PORT))
    uvicorn.run("backend.main:app", host=config.HOST, port=config.PORT, log_level="info")
