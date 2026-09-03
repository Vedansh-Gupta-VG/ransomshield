"""
ml/preprocess_ransap.py
========================
Preprocesses RanSAP into a clean, honestly-labeled CSV for ML training.

FIXES vs. the previous version:
  1. Labeling is now an EXPLICIT WHITELIST. Any folder name that doesn't
     match a known ransomware or benign sample is EXCLUDED and logged —
     never silently defaulted to a label. The old version defaulted
     unmatched folders to label=1 (ransomware), which mislabeled most
     benign application samples and produced a fake 92.6%/7.4% imbalance.
  2. Only features genuinely present in the raw storage trace are kept.
     cpu_percent, io_read_rate_mb, and files_with_entropy_gt7 are DROPPED
     here because they were fabricated from entropy/write-rate formulas,
     not measured — that made the model's "feature importance" circular
     (multiple columns encoding the same entropy signal). Real CPU/IO
     telemetry will come from the live agent (psutil) instead.

RAW FORMAT (RanSAP ata_write.csv, confirmed from the official README):
  unix_sec, unix_ns, LBA, size_bytes, entropy_1, entropy_2 (entropy_2 unused)
  ata_read.csv has no entropy column: unix_sec, unix_ns, LBA, size_bytes

Run list_families.py FIRST to get real folder names before editing the
FAMILY_LABELS dict below.

Usage:
  python ml/preprocess_ransap.py --raw-dir path/to.zip
"""

import os
import glob
import argparse
import zipfile
import numpy as np
import pandas as pd

WINDOW_SEC = 30
OUTPUT_CSV = "data/dataset.csv"
UNMATCHED_LOG = "data/unmatched_folders.txt"

# ── EXPLICIT LABEL WHITELIST ──────────────────────────────────────────────
# Fill in / correct after running list_families.py. Matching is substring,
# case-insensitive, checked against the sample folder name.
RANSOMWARE_NAMES = [
    "sodinokibi", "ryuk", "wannacry", "teslacrypt", "cerber",
    "darkside", "gandcrab4",
]

# Confirmed via list_types.py against the actual zip contents (1495 folders,
# 12 distinct base types, totals match the RanSAP paper's 7 ransomware / 5
# benign sample counts exactly). AESCrypt and SDelete are intentional hard
# negatives: both legitimately produce high-entropy / repeated-overwrite
# patterns without being ransomware.
BENIGN_NAMES = [
    "excel", "aescrypt", "firefox", "sdelete", "zip",
]


def classify(folder_name: str) -> int | None:
    name = folder_name.lower()
    if any(kw in name for kw in RANSOMWARE_NAMES):
        return 1
    if any(kw in name for kw in BENIGN_NAMES):
        return 0
    return None  # unmatched -> excluded, not guessed


def aggregate_window(write_group: pd.DataFrame, read_count: int, label: int) -> dict:
    ent = write_group["entropy_1"].values
    n = len(write_group)

    if n < 2:
        slope = 0.0
    else:
        xs = np.arange(n, dtype=float)
        slope = float(np.polyfit(xs, ent, 1)[0])

    total_bytes = write_group["size_bytes"].sum()
    write_mb_s = (total_bytes / 1_048_576) / WINDOW_SEC

    lba_var = float(write_group["lba"].var()) if n > 1 else 0.0

    # write event rate — a real proxy for file-modification intensity,
    # not derived from entropy
    write_events_per_sec = n / WINDOW_SEC
    read_events_per_sec = read_count / WINDOW_SEC

    return {
        "entropy_mean":        round(float(np.mean(ent)), 6),
        "entropy_slope":       round(slope, 8),
        "entropy_max":         round(float(np.max(ent)), 6),
        "entropy_std":         round(float(np.std(ent)), 6),
        "write_rate_mb_s":     round(write_mb_s, 4),
        "write_events_per_s":  round(write_events_per_sec, 4),
        "read_events_per_s":   round(read_events_per_sec, 4),
        "lba_variance":        round(lba_var, 2),
        "label": label,
    }


def process_sample(write_df: pd.DataFrame, read_df: pd.DataFrame, family: str, label: int) -> pd.DataFrame:
    if write_df.empty or len(write_df) < 5:
        return pd.DataFrame()

    t0 = write_df["unix_sec"].iloc[0]
    write_df["window_id"] = ((write_df["unix_sec"] - t0) // WINDOW_SEC).astype(int)

    if not read_df.empty:
        read_df["window_id"] = ((read_df["unix_sec"] - t0) // WINDOW_SEC).astype(int)
        read_counts = read_df.groupby("window_id").size()
    else:
        read_counts = pd.Series(dtype=int)

    rows = []
    for wid, group in write_df.groupby("window_id"):
        if len(group) < 3:
            continue
        rc = int(read_counts.get(wid, 0))
        row = aggregate_window(group, rc, label)
        row["family"] = family
        rows.append(row)

    return pd.DataFrame(rows) if rows else pd.DataFrame()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-dir", required=True, help="Path to RanSAP zip or extracted dir")
    parser.add_argument("--output", default=OUTPUT_CSV)
    parser.add_argument("--max-rows", type=int, default=6000)
    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)

    unmatched = set()
    frames = []
    processed = 0

    def load_csv(file_obj, is_write: bool) -> pd.DataFrame:
        try:
            if is_write:
                df = pd.read_csv(file_obj, header=None, usecols=[0, 2, 3, 4],
                                  names=["unix_sec", "lba", "size_bytes", "entropy_1"],
                                  on_bad_lines="skip")
            else:
                df = pd.read_csv(file_obj, header=None, usecols=[0],
                                  names=["unix_sec"], on_bad_lines="skip")
            return df
        except Exception:
            return pd.DataFrame()

    if args.raw_dir.endswith(".zip"):
        with zipfile.ZipFile(args.raw_dir, "r") as zf:
            # group files by sample folder
            by_folder = {}
            for name in zf.namelist():
                if name.endswith("ata_write.csv") or name.endswith("ata_read.csv"):
                    folder = os.path.basename(os.path.dirname(name))
                    by_folder.setdefault(folder, {})[
                        "write" if "write" in name else "read"] = name

            print(f"Found {len(by_folder)} sample folders.")
            for folder, files in by_folder.items():
                label = classify(folder)
                if label is None:
                    unmatched.add(folder)
                    continue
                write_df = pd.DataFrame()
                read_df = pd.DataFrame()
                if "write" in files:
                    with zf.open(files["write"]) as f:
                        write_df = load_csv(f, is_write=True)
                if "read" in files:
                    with zf.open(files["read"]) as f:
                        read_df = load_csv(f, is_write=False)
                df = process_sample(write_df, read_df, folder, label)
                if not df.empty:
                    frames.append(df)
                    processed += 1
                    if processed % 50 == 0:
                        print(f"  Processed {processed} labeled folders...")
    else:
        all_write = glob.glob(os.path.join(args.raw_dir, "**", "ata_write.csv"), recursive=True)
        print(f"Found {len(all_write)} write CSVs.")
        for write_path in all_write:
            folder = os.path.basename(os.path.dirname(write_path))
            label = classify(folder)
            if label is None:
                unmatched.add(folder)
                continue
            read_path = write_path.replace("ata_write.csv", "ata_read.csv")
            write_df = load_csv(write_path, is_write=True)
            read_df = load_csv(read_path, is_write=False) if os.path.exists(read_path) else pd.DataFrame()
            df = process_sample(write_df, read_df, folder, label)
            if not df.empty:
                frames.append(df)
                processed += 1
                if processed % 50 == 0:
                    print(f"  Processed {processed} labeled folders...")

    with open(UNMATCHED_LOG, "w") as f:
        f.write("\n".join(sorted(unmatched)))
    print(f"\n{len(unmatched)} folders did NOT match the whitelist and were EXCLUDED.")
    print(f"  -> full list written to {UNMATCHED_LOG} (review before assuming this is fine)")

    if not frames:
        print("No labeled data extracted. Update RANSOMWARE_NAMES / BENIGN_NAMES and retry.")
        return

    combined = pd.concat(frames, ignore_index=True)

    n_benign = (combined["label"] == 0).sum()
    n_ransom = (combined["label"] == 1).sum()
    print(f"\nBefore balancing -> benign: {n_benign:,}  ransomware: {n_ransom:,}")

    cap_each = min(n_benign, n_ransom, args.max_rows // 2)
    if cap_each == 0:
        print("WARNING: one class has zero samples — check BENIGN_NAMES whitelist.")
        combined.to_csv(args.output, index=False)
        return

    benign = combined[combined["label"] == 0].sample(cap_each, random_state=42)
    ransom = combined[combined["label"] == 1].sample(cap_each, random_state=42)
    final = pd.concat([benign, ransom]).sample(frac=1, random_state=42).reset_index(drop=True)

    final.to_csv(args.output, index=False)
    print(f"\n✓ Dataset saved: {args.output}")
    print(f"  Rows: {len(final):,}  (balanced {cap_each:,}/{cap_each:,})")
    print(f"  Columns: {list(final.columns)}")


if __name__ == "__main__":
    np.random.seed(42)
    main()
