"""
ml/generate_timeline.py
========================
Regenerate the demo timeline by scoring the dataset and selecting 20 representative 
rows spanning the risk score spectrum in ascending order.
"""
import os
import json
import joblib
import numpy as np
import pandas as pd
import warnings
warnings.filterwarnings("ignore")

FEATURE_COLS = [
    "entropy_mean", "entropy_slope", "entropy_max", "entropy_std",
    "write_rate_mb_s", "write_events_per_s", "read_events_per_s", "lba_variance",
]

MODEL_PATH = "ml/model.pkl"
DATASET_PATH = "data/dataset.csv"
OUT_PATH = "backend/data/demo_timeline.json"

def main():
    if not os.path.exists(MODEL_PATH) or not os.path.exists(DATASET_PATH):
        print(f"Error: Required files not found. Check {MODEL_PATH} and {DATASET_PATH}.")
        return

    print("Loading model and dataset...")
    bundle = joblib.load(MODEL_PATH)
    model = bundle["rf"]
    iso = bundle["iso"]
    scaler = bundle["scaler"]
    
    df = pd.read_csv(DATASET_PATH)
    
    print(f"Scoring {len(df)} rows...")
    X = df[FEATURE_COLS].values.astype(float)
    X_scaled = scaler.transform(X)
    
    # We use [:, 1] for RandomForest probability of class 1
    model_prob = model.predict_proba(X_scaled)[:, 1]
    
    # IsolationForest score_samples
    iso_raw = iso.score_samples(X_scaled)
    # Replicate the normalization used in backend/ml_inference.py
    # Note: Phase 1 identified this as fragile (iso_norm = clip(iso_raw + 0.5, 0, 1)). 
    # We use the current behavior to stay consistent until we fix it.
    iso_norm = np.clip(iso_raw + 0.5, 0, 1)
    
    risk_scores = 0.70 * model_prob + 0.30 * (1.0 - iso_norm)
    risk_scores = np.clip(risk_scores, 0, 1)
    
    df["risk_score"] = risk_scores
    
    # Sort dataset by risk score
    df_sorted = df.sort_values(by="risk_score").reset_index(drop=True)
    
    # Sample 20 evenly spaced percentiles
    indices = np.linspace(0, len(df_sorted) - 1, 20).astype(int)
    sampled = df_sorted.iloc[indices]
    
    timeline = []
    for _, row in sampled.iterrows():
        point = {col: round(float(row[col]), 4) for col in FEATURE_COLS}
        timeline.append(point)
        
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w") as f:
        json.dump(timeline, f, indent=2)
        
    print(f"Generated {len(timeline)} steps for the demo timeline.")
    print(f"Scores range from {df_sorted['risk_score'].min():.4f} to {df_sorted['risk_score'].max():.4f}.")
    print(f"Saved to {OUT_PATH}")

if __name__ == "__main__":
    main()
