"""
File Integrity Monitor (FIM)
----------------------------

Watches a directory tree and reports when files are **added, removed, or modified**
by comparing cryptographic hashes across scans. Designed to be simple, readable,
and portable (works on Linux/WSL/macOS/Windows; also runs fine inside Docker).

Key behaviors & notes
- Baseline/state is stored in JSON (`file_hashes.json`) in the current working dir.
  The state maps **absolute paths -> hex digest**. If you switch environments
  (e.g., WSL path /mnt/c/... vs Docker path /watched/...), re-initialize with `--init`
  so paths match the environment you use.
- `.fimignore` inside the **watched directory** controls which paths are skipped.
  It accepts gitignore-style patterns when `pathspec` is available, and falls
  back to simple `fnmatch` patterns otherwise. The ignore file itself is *not*
  hashed or reported.
- Colored output uses `colorama` if installed; otherwise plain text is printed.
- Press **Ctrl+C** to stop; you will see a `KeyboardInterrupt` traceback by default.

Typical usage
-------------
Initialize a baseline (hashes only, no monitoring):
    python file_integrity_monitor.py /path/to/dir --hash sha256 --init

Monitor with a 5-second interval (Ctrl+C to stop):
    python file_integrity_monitor.py /path/to/dir -i 5 --hash sha256
"""

import os
import hashlib
import json
import time
import argparse
import logging
from datetime import datetime
import fnmatch  # used by the fallback ignore engine when pathspec isn't installed

# --- Optional color support ---------------------------------------------------
# If colorama is present, we print colored messages for Added/Removed/Modified.
try:
    from colorama import Fore, Style, init
    init(autoreset=True)  # ensure colors reset after each print
    COLOR_SUPPORT = True
except ImportError:
    COLOR_SUPPORT = False  # graceful fallback to plain text

# --- Optional gitignore-style pattern support --------------------------------
# If pathspec is present, we get full gitignore semantics for `.fimignore`.
# Otherwise we gracefully fall back to simple fnmatch/glob behavior.
try:
    from pathspec import PathSpec
    from pathspec.patterns.gitwildmatch import GitWildMatchPattern
    PATHSPEC_AVAILABLE = True
except Exception:
    PATHSPEC_AVAILABLE = False

# --- Files written next to where you run the script ---------------------------
STATE_FILE = "file_hashes.json"  # baseline of absolute_path -> hex_digest
LOG_FILE = "monitor.log"         # human-readable event log
IGNORE_FILE = ".fimignore"       # lives inside the *watched* directory (not here)


# -----------------------------------------------------------------------------
# Hashing
# -----------------------------------------------------------------------------
def hash_file(filepath, algorithm="sha256"):
    """
    Compute the cryptographic digest of a file in chunks (memory-friendly).

    Parameters
    ----------
    filepath : str
        Absolute path to the file to hash.
    algorithm : str
        Any algorithm supported by hashlib on your platform (e.g., "sha256", "sha512").

    Returns
    -------
    str | None
        Hex-encoded digest string if successful, else None for unreadable/missing files.

    Raises
    ------
    ValueError
        If the requested algorithm is not supported by hashlib.
    """
    try:
        h = hashlib.new(algorithm)
    except ValueError:
        # Surface a clear error for invalid algorithm names
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")

    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        return h.hexdigest()
    except (FileNotFoundError, PermissionError):
        # Skip files that are deleted between listing & open, or that we can't read.
        return None


# -----------------------------------------------------------------------------
# Ignore (.fimignore)
# -----------------------------------------------------------------------------
def load_ignore_spec(directory):
    """
    Load ignore patterns from `<directory>/.fimignore`.

    Returns
    -------
    (spec, found) : (PathSpec | list[str] | None, bool)
        - If pathspec is available: a PathSpec instance and True.
        - If not: a list of patterns (strings) and True.
        - If the file doesn't exist or has no rules: (None, False).
    """
    ignore_path = os.path.join(directory, IGNORE_FILE)
    if not os.path.exists(ignore_path):
        return None, False

    with open(ignore_path, "r", encoding="utf-8") as f:
        # Keep non-empty, non-comment lines
        lines = [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]

    if not lines:
        return None, False

    if PATHSPEC_AVAILABLE:
        spec = PathSpec.from_lines(GitWildMatchPattern, lines)
        return spec, True

    # Fallback: plain fnmatch strings
    return lines, True


def is_ignored(path_abs, root_dir, ignore, is_dir=False):
    """
    Decide if an absolute path should be ignored by the rules in `.fimignore`.

    Parameters
    ----------
    path_abs : str
        Absolute path to test.
    root_dir : str
        The directory being monitored (the root for relative matching).
    ignore : PathSpec | list[str] | None
        The compiled ignore rules (or None if no rules).
    is_dir : bool
        True if `path_abs` is a directory (affects directory pattern handling).

    Returns
    -------
    bool : True if the path is ignored, False otherwise.
    """
    if not ignore:
        return False

    # Normalize to a POSIX-style path **relative to the root**
    rel = os.path.relpath(path_abs, root_dir).replace(os.sep, "/")
    if rel == ".":
        rel = ""  # safety for edge cases

    # Preferred pathspec engine (gitignore semantics)
    if PATHSPEC_AVAILABLE and not isinstance(ignore, list):
        if ignore.match_file(rel):          # match file/dir directly
            return True
        if is_dir and ignore.match_file(rel + "/"):  # ensure dir patterns match
            return True
        return False

    # Fallback: simple fnmatch matching against each pattern
    for pat in ignore:
        # Directory pattern (convention: trailing slash)
        if pat.endswith("/"):
            base = pat[:-1]
            if is_dir and (fnmatch.fnmatch(rel, base) or rel.startswith(base + "/")):
                return True
            # skip any files under that dir
            if rel.startswith(base + "/"):
                return True

        # File pattern: try against full relative path and basename
        if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(os.path.basename(rel), pat):
            return True

    return False


# -----------------------------------------------------------------------------
# Scanning
# -----------------------------------------------------------------------------
def scan_directory(directory, algorithm):
    """
    Walk the directory tree and build a mapping of absolute file paths to hashes.
    Honors `.fimignore` if present in the *watched* directory.

    Notes
    -----
    - We prune ignored directories in-place (faster than descending and skipping later).
    - The ignore file itself (`.fimignore`) is never hashed/reported.
    """
    ignore_spec, _found = load_ignore_spec(directory)

    file_hashes = {}
    for root, dirs, files in os.walk(directory):
        # Prune ignored subdirectories to avoid unnecessary descent
        pruned = []
        for d in dirs:
            dir_abs = os.path.join(root, d)
            if not is_ignored(dir_abs, directory, ignore_spec, is_dir=True):
                pruned.append(d)
        dirs[:] = pruned  # in-place modification controls traversal

        # Hash files that are not ignored
        for filename in files:
            filepath = os.path.join(root, filename)

            # Never include the ignore file itself in the baseline/events
            if os.path.basename(filepath) == IGNORE_FILE:
                continue

            if is_ignored(filepath, directory, ignore_spec, is_dir=False):
                continue

            file_hash = hash_file(filepath, algorithm)
            if file_hash:
                file_hashes[filepath] = file_hash

    return file_hashes


# -----------------------------------------------------------------------------
# State management
# -----------------------------------------------------------------------------
def save_state(file_hashes):
    """
    Persist the current snapshot to disk as JSON.

    The file lives in the current working directory (not the watched directory).
    """
    with open(STATE_FILE, "w") as f:
        json.dump(file_hashes, f, indent=4)


def load_state():
    """
    Load the last snapshot from disk, or return an empty mapping if none exists.
    """
    if not os.path.exists(STATE_FILE):
        return {}
    with open(STATE_FILE, "r") as f:
        return json.load(f)


def compare_states(old, new):
    """
    Compute *added*, *removed*, and *modified* sets from two hash dictionaries.

    Returns
    -------
    (added, removed, modified) : (list[str], list[str], list[str])
        Lists contain **absolute paths** (the keys of the dictionaries).
    """
    added = [f for f in new if f not in old]
    removed = [f for f in old if f not in new]
    modified = [f for f in new if f in old and new[f] != old[f]]
    return added, removed, modified


# -----------------------------------------------------------------------------
# Logging & output
# -----------------------------------------------------------------------------
def setup_logging():
    """
    Configure a simple file logger writing to `monitor.log`.
    """
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )


def log_and_print(msg, color=None):
    """
    Write a line to the log file and mirror it to stdout.
    If `color` (from colorama.Fore) is provided and colorama is installed,
    print in color for quick visual scanning.
    """
    logging.info(msg)
    if COLOR_SUPPORT and color:
        print(color + msg + Style.RESET_ALL)
    else:
        print(msg)


# -----------------------------------------------------------------------------
# Monitoring loop
# -----------------------------------------------------------------------------
def monitor(directory, interval, algorithm):
    """
    Continuously rescan the directory and report differences since the last scan.

    Parameters
    ----------
    directory : str
        Root of the tree to monitor.
    interval : int
        Seconds to sleep between scans.
    algorithm : str
        Hash algorithm name (e.g., 'sha256').

    Notes
    -----
    - Ctrl+C will raise KeyboardInterrupt and exit the loop (you'll see a traceback).
      You can wrap the call to `monitor(...)` in a try/except if you prefer a silent exit.
    """
    print(f"[*] Monitoring {directory} every {interval}s using {algorithm.upper()}...")
    previous_state = load_state()

    while True:
        current_state = scan_directory(directory, algorithm)
        added, removed, modified = compare_states(previous_state, current_state)

        if added or removed or modified:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"\n[{timestamp}] Changes detected:")

            # NOTE: We print absolute paths for precision. If you prefer shorter output,
            # you can display relative paths with:
            #   rel = lambda p: os.path.relpath(p, directory)
            # and join those instead.
            if added:
                log_and_print("  [+] Added: " + ", ".join(added), color=(Fore.GREEN if COLOR_SUPPORT else None))
            if removed:
                log_and_print("  [-] Removed: " + ", ".join(removed), color=(Fore.RED if COLOR_SUPPORT else None))
            if modified:
                log_and_print("  [!] Modified: " + ", ".join(modified), color=(Fore.YELLOW if COLOR_SUPPORT else None))

        save_state(current_state)
        previous_state = current_state
        time.sleep(interval)


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------
def main():
    """
    Command-line entry point.

    Examples
    --------
    Initialize baseline only:
        python file_integrity_monitor.py /path/to/dir --hash sha256 --init

    Monitor continuously (5-second interval):
        python file_integrity_monitor.py /path/to/dir -i 5 --hash sha256
    """
    parser = argparse.ArgumentParser(description="Simple File Integrity Monitor (Extended)")
    parser.add_argument("directory", help="Directory to monitor")
    parser.add_argument("-i", "--interval", type=int, default=10, help="Interval in seconds")
    parser.add_argument(
        "--hash",
        choices=hashlib.algorithms_available,
        default="sha256",
        help="Hash algorithm (default: sha256)"
    )
    parser.add_argument(
        "--init",
        action="store_true",
        help="Initialize baseline and exit"
    )
    args = parser.parse_args()

    if not os.path.isdir(args.directory):
        print("Error: Provided path is not a directory.")
        return

    setup_logging()

    if args.init:
        # One-time baseline creation: compute and save hashes, then exit.
        print(f"[*] Initializing baseline for {args.directory} using {args.hash.upper()}...")
        state = scan_directory(args.directory, args.hash)
        save_state(state)
        logging.info(f"Baseline initialized with {len(state)} files")
        print("[*] Baseline created and saved.")
    else:
        monitor(args.directory, args.interval, args.hash)


if __name__ == "__main__":
    main()
