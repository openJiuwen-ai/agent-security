#!/usr/bin/env bash
# Run from management/hypershell. Pass Python and optionally a wheel directory.
set -euo pipefail
PYTHON=${1:-python3}
"$PYTHON" -m venv .test-venv
if [[ -n ${2:-} ]]; then
  .test-venv/bin/python -m pip install --no-index --find-links="$2" -r requirements-test.txt
else
  .test-venv/bin/python -m pip install -r requirements-test.txt
fi
.test-venv/bin/python -m pytest tests -q -ra --basetemp=.test-tmp/pytest -p no:cacheprovider
