import os
import hashlib
import json
import time
import argparse
import logging
from datetime import datetime

# Try to import colorama for colored output (optional)
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLOR_SUPPORT = True
except ImportError:
    COLOR_SUPPORT = False

STATE_FILE = "file_hashes.json"
LOG_FILE = "monitor.log"

# --- Hashing ---
def hash_file(filepath, algorithm="sha256"):
    """Compute cryptographic hash of a file."""
    try:
        h = hashlib.new(algorithm)
    except ValueError:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")

    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        return h.hexdigest()
    except (FileNotFoundError, PermissionError):
        return None

def scan_directory(directory, algorithm):
    """Return dictionary of {filepath: hash} for all files in directory."""
    file_hashes = {}
    for root, _, files in os.walk(directory):
        for filename in files:
            filepath = os.path.join(root, filename)
            file_hash = hash_file(filepath, algorithm)
            if file_hash:
                file_hashes[filepath] = file_hash
    return file_hashes

# --- State Management ---
def save_state(file_hashes):
    with open(STATE_FILE, "w") as f:
        json.dump(file_hashes, f, indent=4)

def load_state():
    if not os.path.exists(STATE_FILE):
        return {}
    with open(STATE_FILE, "r") as f:
        return json.load(f)

def compare_states(old, new):
    """Compare old vs new hashes and return changes."""
    added = [f for f in new if f not in old]
    removed = [f for f in old if f not in new]
    modified = [f for f in new if f in old and new[f] != old[f]]
    return added, removed, modified

# --- Logging & Output ---
def setup_logging():
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )

def log_and_print(msg, color=None):
    """Log to file and print to console (with optional color)."""
    logging.info(msg)
    if COLOR_SUPPORT and color:
        print(color + msg + Style.RESET_ALL)
    else:
        print(msg)

# --- Monitor ---
def monitor(directory, interval, algorithm):
    """Continuously monitor a directory for file changes."""
    print(f"[*] Monitoring {directory} every {interval}s using {algorithm.upper()}...")
    previous_state = load_state()

    while True:
        current_state = scan_directory(directory, algorithm)
        added, removed, modified = compare_states(previous_state, current_state)

        if added or removed or modified:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"\n[{timestamp}] Changes detected:")
            if added:
                log_and_print("  [+] Added: " + ", ".join(added), Fore.GREEN)
            if removed:
                log_and_print("  [-] Removed: " + ", ".join(removed), Fore.RED)
            if modified:
                log_and_print("  [!] Modified: " + ", ".join(modified), Fore.YELLOW)

        save_state(current_state)
        previous_state = current_state
        time.sleep(interval)

# --- Main CLI ---
def main():
    parser = argparse.ArgumentParser(description="Simple File Integrity Monitor (Extended)")
    parser.add_argument("directory", help="Directory to monitor")
    parser.add_argument("-i", "--interval", type=int, default=10, help="Interval in seconds")
    parser.add_argument("--hash", choices=hashlib.algorithms_available, default="sha256",
                        help="Hash algorithm (default: sha256)")
    parser.add_argument("--init", action="store_true",
                        help="Initialize baseline and exit")
    args = parser.parse_args()

    if not os.path.isdir(args.directory):
        print("Error: Provided path is not a directory.")
        return

    setup_logging()

    if args.init:
        # Just create baseline hashes
        print(f"[*] Initializing baseline for {args.directory} using {args.hash.upper()}...")
        state = scan_directory(args.directory, args.hash)
        save_state(state)
        logging.info(f"Baseline initialized with {len(state)} files")
        print("[*] Baseline created and saved.")
    else:
        monitor(args.directory, args.interval, args.hash)

if __name__ == "__main__":
    main()
