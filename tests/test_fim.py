import os
import tempfile
import pytest

from file_integrity_monitor import (
    hash_file,
    scan_directory,
    compare_states,
)

def _is_hex(s: str) -> bool:
    try:
        int(s, 16)
        return True
    except ValueError:
        return False

def test_hash_file_sha256_is_64_hex():
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "hello.txt")
        with open(p, "wb") as f:
            f.write(b"hello\n")

        h = hash_file(p, "sha256")
        assert h is not None
        assert len(h) == 64
        assert _is_hex(h)

def test_hash_file_invalid_algorithm():
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "x.txt")
        with open(p, "w") as f:
            f.write("x")
        with pytest.raises(ValueError):
            hash_file(p, "notahash")

def test_scan_compare_add_modify_remove():
    with tempfile.TemporaryDirectory() as tmp:
        # baseline = empty
        old = scan_directory(tmp, "sha256")

        # add a file
        p = os.path.join(tmp, "a.txt")
        with open(p, "w") as f:
            f.write("A")
        new = scan_directory(tmp, "sha256")
        added, removed, modified = compare_states(old, new)
        assert p in added and removed == [] and modified == []

        # modify the file
        with open(p, "w") as f:
            f.write("B")
        newer = scan_directory(tmp, "sha256")
        added, removed, modified = compare_states(new, newer)
        assert added == [] and removed == [] and modified == [p]

        # remove the file
        os.remove(p)
        newest = scan_directory(tmp, "sha256")
        added, removed, modified = compare_states(newer, newest)
        assert added == [] and modified == [] and removed == [p]
