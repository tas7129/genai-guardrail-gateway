#!/bin/bash
# macOS: double-click to start the GenAI Guardrail Gateway (opens the browser when ready).
# First time only: if macOS says it cannot be opened, right-click the file → Open → Open.
cd "$(dirname "$0")" || exit 1
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
for py in python3.12 python3.11 python3.10 python3; do
  if command -v "$py" >/dev/null 2>&1 && "$py" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
    exec "$py" launcher.py "$@"
  fi
done
echo "Python 3.10 or newer is required."
echo "Install Python 3.12 from https://www.python.org/downloads/ (or: brew install python@3.12), then double-click this file again."
read -r -p "Press Enter to close…"
