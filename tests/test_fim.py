# --- Imports ---------------------------------------------------------------
# Use pathlib-friendly pytest fixtures and your public API.
import pytest
from file_integrity_monitor import (
    hash_file,
    scan_directory,
    compare_states,
)

# --- Helpers ---------------------------------------------------------------
def _is_hex(s: str) -> bool:
    """
    Return True if `s` is a valid hexadecimal string (case-insensitive).
    Used to sanity-check hash outputs.
    """
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


# --- Unit tests ------------------------------------------------------------
def test_hash_file_sha256_is_64_hex(tmp_path):
    """
    Create a file *relative to a pytest-managed temp directory* and verify:
      - `hash_file(..., 'sha256')` returns a value
      - The digest is 64 hex chars (SHA-256)
    Notes:
      - `tmp_path` is a per-test temporary folder (auto-cleaned by pytest).
      - We use pathlib operations for clarity.
    """
    p = tmp_path / "sample.txt"
    p.write_bytes(b"hello\n")  # write a small payload

    h = hash_file(str(p), "sha256")
    assert h is not None
    assert len(h) == 64
    assert _is_hex(h)


def test_hash_file_invalid_algorithm(tmp_path):
    """
    Using an unsupported hash algorithm should raise `ValueError`.
    This ensures your CLI validation bubbles up clearly for bad inputs.
    """
    p = tmp_path / "x.txt"
    p.write_text("x")

    with pytest.raises(ValueError):
        hash_file(str(p), "notahash")


def test_scan_compare_add_modify_remove(tmp_path):
    """
    End-to-end lifecycle within a temp directory:
      1) Start with empty baseline (no files)
      2) Add a file  -> shows up in `added`
      3) Modify file -> shows up in `modified`
      4) Delete file -> shows up in `removed`
    This exercises `scan_directory` and `compare_states` together.
    """
    root = str(tmp_path)

    # 1) empty baseline
    old = scan_directory(root, "sha256")

    # 2) add a file
    p = tmp_path / "a.txt"
    p.write_text("A")
    new = scan_directory(root, "sha256")
    added, removed, modified = compare_states(old, new)
    assert str(p) in added
    assert removed == []
    assert modified == []

    # 3) modify the file
    p.write_text("B")
    newer = scan_directory(root, "sha256")
    added, removed, modified = compare_states(new, newer)
    assert added == []
    assert removed == []
    assert modified == [str(p)]

    # 4) remove the file
    p.unlink()
    newest = scan_directory(root, "sha256")
    added, removed, modified = compare_states(newer, newest)
    assert added == []
    assert modified == []
    assert removed == [str(p)]
