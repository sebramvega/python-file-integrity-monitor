# File Integrity Monitor (FIM)
![CI](https://github.com/sebramvega/python-file-integrity-monitor/actions/workflows/ci.yml/badge.svg)


Simple Python tool that detects file **additions, removals, and modifications** by comparing cryptographic hashes (SHA-256 by default). Includes baseline mode, colored console output, logging, and tests with CI.

## Quickstart
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Initialize baseline
```bash
python file_integrity_monitor.py /path/to/watched --hash sha256 --init
```

## Monitor (Ctrl+C to stop)
```bash
python file_integrity_monitor.py /path/to/watched -i 5 --hash sha256
```

## Run tests
```bash
pytest -q
```

## Notes
- Baseline and logs are written to the project directory (file_hashes.json, monitor.log)
- Change hash with --hash sha512; re-baseline after intentional bulk edits.
