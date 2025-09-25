"""
conftest.py
-----------
Pytest auto-loads this file to configure the test environment.

Purpose:
- Ensure the project root (the folder that contains `file_integrity_monitor.py`)
  is on `sys.path` so tests can do:
      from file_integrity_monitor import hash_file, ...
- This is handy when tests are executed from the `tests/` directory or in CI,
  where the working directory might not be the repo root.

Notes:
- If you always run `pytest` from the repo root, Python would already find the
  module, but this shim makes test imports robust in all contexts.
"""

import os
import sys

# Absolute path to repository root (parent of this `tests/` directory)
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Prepend once to avoid duplicates and to give precedence over site-packages.
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
