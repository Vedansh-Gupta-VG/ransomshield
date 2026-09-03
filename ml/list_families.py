"""
ml/list_families.py
====================
Run this FIRST, before preprocessing. It only lists the unique sample/family
folder names inside the RanSAP zip — takes seconds, doesn't read any CSV data.

We need this because RanSAP's benign-application folder names are not
documented anywhere obvious, and guessing them wrong is what caused the
mislabeling bug in the previous preprocessing script (everything not matching
a ransomware keyword silently defaulted to label=1).

Usage:
    python ml/list_families.py --zip ransap-2022-ransomware-behavioral-features.zip
"""
import argparse
import zipfile
import os
from collections import Counter

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--zip", required=True)
    args = parser.parse_args()

    counts = Counter()
    with zipfile.ZipFile(args.zip, "r") as zf:
        for name in zf.namelist():
            if name.endswith(".csv"):
                # folder immediately containing the csv = one "sample run" folder
                sample_dir = os.path.basename(os.path.dirname(name))
                counts[sample_dir] += 1

    print(f"Total unique sample folders: {len(counts)}\n")
    for name, n in sorted(counts.items()):
        print(f"{n:5d}  {name}")

if __name__ == "__main__":
    main()
