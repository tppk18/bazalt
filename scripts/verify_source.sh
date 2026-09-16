#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

cleanup() { rm -rf scripts/__pycache__; }
trap cleanup EXIT

python3 -m py_compile scripts/generate_fixture.py scripts/verify_fixture.py scripts/static_verify.py
python3 scripts/generate_fixture.py
python3 scripts/verify_fixture.py
python3 scripts/static_verify.py
python3 scripts/verify_v04_hotpath.py
node --check frontend/app.js
bash -n scripts/smoke.sh
python3 - <<'PY'
import yaml
for path in ('docker-compose.yml', 'docker-compose.smoke.yml'):
    with open(path, 'r', encoding='utf-8') as f:
        yaml.safe_load(f)
print('YAML PASS')
PY

if command -v cargo >/dev/null 2>&1; then
  cargo fmt --check
  cargo clippy --all-features --all-targets -- -D warnings
  cargo test --all-features
else
  echo 'NOTE: cargo unavailable; Rust fmt/clippy/unit-test gate skipped.' >&2
fi
