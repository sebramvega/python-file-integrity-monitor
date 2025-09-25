# File Integrity Monitor (FIM)

[![CI](https://github.com/sebramvega/python-file-integrity-monitor/actions/workflows/ci.yml/badge.svg)](https://github.com/sebramvega/python-file-integrity-monitor/actions/workflows/ci.yml)

A lightweight, practical file integrity monitor that detects **additions, removals, and modifications** by hashing files and comparing against a saved baseline.

- ✅ Hash algorithms: `sha256` (default), `sha512`, etc.
- ✅ `.fimignore` with **gitignore-style** patterns (via `pathspec`)
- ✅ Colored console output (via `colorama`)
- ✅ Logging to `monitor.log`
- ✅ Unit tests + GitHub Actions CI
- ✅ Dockerized (optional)

---

## Quick start

### 1) Clone & install

```bash
git clone https://github.com/sebramvega/python-file-integrity-monitor.git
cd python-file-integrity-monitor

# Python 3.12 recommended (3.10+ should work)
python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 2) (Optional) Create `.fimignore` in the watched folder
```bash
# example .fimignore
*.log
*.tmp
__pycache__/
*.pyc
node_modules/
```

Put `.fimignore` inside the directory you’re monitoring.
Patterns support gitignore semantics when `pathspec` is installed (already in `requirements.txt`).

### 3) Initialize a baseline
```bash
python file_integrity_monitor.py /path/to/watched --hash sha256 --init
```

### 4) Monitor (Ctrl+C to stop)
```bash
python file_integrity_monitor.py /path/to/watched -i 5 --hash sha256
```

## CLI
usage: file_integrity_monitor.py [-h] [-i INTERVAL] [--hash HASH] [--init] directory

positional arguments:
  directory             Directory to monitor

options:
  -h, --help            Show help and exit
  -i, --interval        Interval in seconds (default: 10)
  --hash                Hash algorithm (default: sha256)
  --init                Initialize baseline and exit

- `--init` creates/updates `file_hashes.json` (the baseline) and exits.
- During monitoring, the tool prints and logs any files that were Added/Removed/Modified.

## How it works
1. Scan: walk the directory, hash each file (`sha256` by default).
2. Compare: diff current hashes against those saved in `file_hashes.json`.
3. Report: print/log Added / Removed / Modified paths.
4. Update: write the new baseline back to `file_hashes.json`.

Baseline stores absolute paths. If you switch environments (e.g., WSL path `/mnt/c/...` vs Docker path `/watched/...`), re-baseline so paths match.

## Docker

### Build
```bash
docker build -t fim:latest .
```

### Initialize baseline (persist state/logs)
Mount the watched folder to `/watched` and your repo to `/app` so `file_hashes.json/monitor.log` are saved on your host:
```bash
docker run --rm \
  -v "/absolute/path/to/watched:/watched" \
  -v "$PWD:/app" \
  fim:latest /watched --hash sha256 --init
```

### Monitor
```bash
docker run --rm \
  -v "/absolute/path/to/watched:/watched" \
  -v "$PWD:/app" \
  fim:latest /watched -i 5 --hash sha256

```

### Tests
```bash
pytest -q
```
CI runs the tests automatically on every push/PR (see badge at the top).


## Project structure
```bash
python-file-integrity-monitor/
├─ file_integrity_monitor.py   # main tool (CLI)
├─ requirements.txt            # deps: colorama, pathspec
├─ tests/
│  ├─ conftest.py              # ensures project root is importable
│  └─ test_fim.py              # unit tests (hashing + scan/compare lifecycle)
├─ .github/workflows/ci.yml    # GitHub Actions: run tests on push/PR
├─ Dockerfile                  # containerized runner
├─ .dockerignore               # trims image build context
├─ .gitignore                  # keeps repo clean
├─ file_hashes.json            # (generated) baseline state  ← not committed
└─ monitor.log                 # (generated) log file        ← not committed
```

## Troubleshooting
* I see “/watched removed, /mnt/c added”

You switched between Docker and WSL. Re-baseline in the environment you're using:
```bash
# WSL
python file_integrity_monitor.py /mnt/c/Users/... --hash sha256 --init

# Docker
docker run --rm -v "/mnt/c/Users/...:/watched" -v "$PWD:/app" fim:latest /watched --hash sha256 --init

```
* VS Code shows “Import `‘pathspec’` could not be resolved”

Select your venv interpreter: Ctrl+Shift+P → Python: Select Interpreter → .venv/bin/python.
(It’s only an editor warning; the code falls back if `pathspec` isn’t installed.)

* Too many false positives

Add/adjust patterns in `.fimignore` (lives in the watched folder).


## License
MIT License © 2025 [sebramvega]
