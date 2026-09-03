import argparse
import zipfile
import os
import re
from collections import Counter

def base_type(folder_name: str) -> str:
    # Strip trailing timestamp-like suffixes (YYYYMMDD_HH-MM-SS or similar)
    # so we group "Zip-20200420_15-10-33" and "Zip-20200427_17-46-52" together as "Zip"
    name = re.sub(r'[-_]?\d{8}[-_]\d{2}[-_]\d{2}[-_]\d{2}.*$', '', folder_name)
    name = re.sub(r'[-_]?\d{4,}.*$', '', name)  # catch any other trailing numeric run
    return name.strip('-_') or folder_name

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--zip", required=True)
    args = parser.parse_args()

    raw_counts = Counter()
    with zipfile.ZipFile(args.zip, "r") as zf:
        for name in zf.namelist():
            if name.endswith(".csv"):
                sample_dir = os.path.basename(os.path.dirname(name))
                raw_counts[sample_dir] += 1

    grouped = Counter()
    examples = {}
    for folder, n in raw_counts.items():
        bt = base_type(folder)
        grouped[bt] += n
        examples.setdefault(bt, folder)

    print(f"Total raw folders: {len(raw_counts)}")
    print(f"Total distinct sample TYPES: {len(grouped)}\n")
    print(f"{'TYPE':<25} {'FOLDER COUNT':<15} EXAMPLE FOLDER NAME")
    for bt, n in sorted(grouped.items(), key=lambda x: -x[1]):
        print(f"{bt:<25} {n:<15} {examples[bt]}")

if __name__ == "__main__":
    main()
