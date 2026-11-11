#!/bin/sh
set -eu
cd "$(dirname "$0")"
if [ ! -f .venv/bin/python ]; then python3 -m venv .venv; fi
if [ ! -f .venv/installed.ok ]; then .venv/bin/python -m pip install -r requirements.txt; touch .venv/installed.ok; fi
.venv/bin/python launcher.py "${1:-operasional}"
