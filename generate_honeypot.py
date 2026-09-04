"""
honeypot/generate_honeypot.py

Generates a nested decoy filesystem under honeypot/ for the monitor and
simulator to operate on. detector/monitor.py already watches recursively
(Observer(..., recursive=True)) and walks the honeypot tree with os.walk()
when scanning entropy, so a flat 3-file honeypot under-tests that recursive
path. This script builds a multi-level directory tree of small decoy files
so the recursive watch, nested-rename handling, and directory-aware entropy
scan are all exercised the way they would be against a real filesystem.

Usage:
    python honeypot/generate_honeypot.py --files 40 --min-depth 2 --max-depth 4

Safe by design: it only ever creates plain .txt files with filler text
under the target honeypot directory. It does not touch, read, or modify
anything outside that directory.
"""
import os
import random
import argparse

DEFAULT_DIR_NAMES = [
    "Documents", "Photos", "Projects", "Invoices", "Backups", "Notes",
    "Downloads", "Reports", "Archive", "Personal", "Work", "Misc",
]

FILLER_LINE = "This is a decoy file used to test ransomware detection.\n"


def _random_subpath(base_dir: str, min_depth: int, max_depth: int) -> str:
    depth = random.randint(min_depth, max_depth)
    parts = [base_dir]
    for _ in range(depth):
        parts.append(random.choice(DEFAULT_DIR_NAMES))
    return os.path.join(*parts)


def generate_honeypot(base_dir: str, num_files: int, min_depth: int, max_depth: int) -> list[str]:
    """
    Builds a nested decoy filesystem under base_dir and returns the list of
    created file paths. Existing files are left untouched; re-running this
    is safe and additive.
    """
    created = []
    os.makedirs(base_dir, exist_ok=True)

    for i in range(1, num_files + 1):
        target_dir = _random_subpath(base_dir, min_depth, max_depth)
        os.makedirs(target_dir, exist_ok=True)
        file_path = os.path.join(target_dir, f"file{i}.txt")
        if not os.path.exists(file_path):
            with open(file_path, "w") as f:
                f.write(FILLER_LINE * random.randint(20, 120))
            created.append(file_path)

    return created


def main():
    parser = argparse.ArgumentParser(
        description="Generate a nested honeypot decoy filesystem for RansomShield."
    )
    parser.add_argument("--honeypot", default="honeypot",
                         help="Target honeypot directory (default: honeypot)")
    parser.add_argument("--files", type=int, default=40,
                         help="Number of decoy files to create (default: 40)")
    parser.add_argument("--min-depth", type=int, default=2,
                         help="Minimum nesting depth for generated files (default: 2)")
    parser.add_argument("--max-depth", type=int, default=4,
                         help="Maximum nesting depth for generated files (default: 4)")
    parser.add_argument("--seed", type=int, default=None,
                         help="Optional random seed for reproducible layouts")
    args = parser.parse_args()

    if args.min_depth < 1 or args.max_depth < args.min_depth:
        parser.error("Require 1 <= min-depth <= max-depth")

    if args.seed is not None:
        random.seed(args.seed)

    created = generate_honeypot(args.honeypot, args.files, args.min_depth, args.max_depth)

    print("=" * 62)
    print("  Honeypot filesystem generated")
    print("=" * 62)
    print(f"  Target dir : {os.path.abspath(args.honeypot)}")
    print(f"  Files made : {len(created)} (requested {args.files})")
    print(f"  Depth range: {args.min_depth}-{args.max_depth}")
    print()
    print("  Start the monitor with:")
    print(f"    python detector/monitor.py --folder {args.honeypot}")


if __name__ == "__main__":
    main()
