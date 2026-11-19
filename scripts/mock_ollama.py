"""A tiny stand-in for Ollama, FOR AUTOMATED TESTS ONLY.

It implements /api/tags and /api/chat (streaming NDJSON) and records every
request body it receives, so tests can prove exactly what reached the "LLM".
Replies are prefixed with "[MOCK LLM]" so they can never be mistaken for a
real model in a demo.

It also plays the local SAFETY model (any model name starting with
"llama-guard"). The mock does not judge real content: it reacts only to neutral
test markers, so the test-suite never needs harmful text:
    [[GUARD:S2]]       -> "unsafe\nS2"   (any category code)
    [[GUARD:GARBAGE]]  -> an unreadable verdict
    [[GUARD:ERROR]]    -> HTTP 500
    [[GUARD:SLOW]]     -> answers after 3 s (timeout tests)
    [[CTX-A]] in an earlier turn + [[CTX-B]] in the last turn -> "unsafe\nS2"
    anything else      -> "safe"
Unknown model names get HTTP 404 "model not found", like Ollama.

    python scripts/mock_ollama.py --port 11500 --log /tmp/mock_llm.jsonl
"""
from __future__ import annotations

import argparse
import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


import os

KNOWN_MODELS = ["qwen2.5:3b", "llama-guard3:1b", "llama-guard3:8b"]
# Launcher / setup tests: models listed in MOCK_MISSING start "not downloaded" until /api/pull is called
INSTALLED = [m for m in KNOWN_MODELS if m not in os.environ.get("MOCK_MISSING", "").split(",")]


def guard_reply(messages) -> tuple:
    """(http_status, verdict_text) for the safety-model role."""
    last = (messages or [{}])[-1].get("content", "")
    earlier = " ".join(m.get("content", "") for m in (messages or [])[:-1])
    if "[[GUARD:ERROR]]" in last:
        return 500, ""
    if "[[GUARD:SLOW]]" in last:
        time.sleep(3)
    if "[[GUARD:GARBAGE]]" in last:
        return 200, "I am not sure about this one."
    m = re.search(r"\[\[GUARD:(S\d{1,2}(?:,S\d{1,2})*)\]\]", last)
    if m:
        return 200, "unsafe\n" + m.group(1)
    if "[[CTX-A]]" in earlier and "[[CTX-B]]" in last:
        return 200, "unsafe\nS2"
    return 200, "safe"


def make_handler(log_path: str):
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # silence
            pass

        def do_GET(self):
            if self.path == "/api/tags":
                body = json.dumps({"models": [{"name": n} for n in INSTALLED]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.end_headers()

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length) or b"{}")
            if log_path:
                with lock, open(log_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(payload) + "\n")
            model = payload.get("model", "")
            if self.path == "/api/pull":
                self.send_response(200)
                self.send_header("Content-Type", "application/x-ndjson")
                self.end_headers()
                total = 1_000_000
                for done in (0, 250_000, 500_000, 1_000_000):
                    self.wfile.write((json.dumps({"status": "pulling mock", "total": total, "completed": done}) + "\n").encode())
                    self.wfile.flush()
                    time.sleep(0.05)
                self.wfile.write(b'{"status":"success"}\n')
                if model in KNOWN_MODELS and model not in INSTALLED:
                    INSTALLED.append(model)
                return
            if model not in INSTALLED:
                body = json.dumps({"error": "model '%s' not found" % model}).encode()
                self.send_response(404)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if model.startswith("llama-guard"):
                code, verdict = guard_reply(payload.get("messages"))
                body = json.dumps({"model": model, "message": {"role": "assistant", "content": verdict},
                                   "done": True}).encode() if code == 200 else b'{"error":"mock failure"}'
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            last = payload.get("messages", [{}])[-1].get("content", "")
            reply = ("[MOCK LLM] I received %d characters. First line: %s"
                     % (len(last), last.split("\n")[0][:120]))
            self.send_response(200)
            self.send_header("Content-Type", "application/x-ndjson")
            self.end_headers()
            for word in reply.split(" "):
                chunk = {"message": {"role": "assistant", "content": word + " "}, "done": False}
                self.wfile.write((json.dumps(chunk) + "\n").encode())
                self.wfile.flush()
                time.sleep(0.01)
            self.wfile.write((json.dumps({"message": {"role": "assistant", "content": ""}, "done": True}) + "\n").encode())

    return Handler


def serve(port: int, log_path: str) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(log_path))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=11500)
    ap.add_argument("--log", default="")
    args = ap.parse_args()
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(args.log))
    print("Mock Ollama on http://127.0.0.1:%d (tests only)" % args.port)
    srv.serve_forever()
