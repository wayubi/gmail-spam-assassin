#!/bin/sh
# Run from anywhere; the scripts use their own repo-root path.
set -eu
cd "$(dirname "$0")/.."
python3 tests/test_app.py
python3 tests/test_runner.py
python3 tests/test_idle.py
