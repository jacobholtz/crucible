#!/bin/bash
# Runs the CRUCIBLE SIGINT FastAPI server in the foreground (launchd keeps
# it alive). Binds to 127.0.0.1 only; port defaults to 8000 with automatic
# fallback to 8080/8888/9000/9090 if occupied (see crucible_app.py __main__).

set -euo pipefail

REPO_DIR="/Users/jacob/Projects/crucible"
cd "$REPO_DIR"

exec "$REPO_DIR/venv/bin/python3" "$REPO_DIR/src/crucible_app.py"
