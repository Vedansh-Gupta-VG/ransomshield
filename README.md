# RansomShield

An interactive demonstration of behavioral machine learning for ransomware detection.

**Live demo:** [https://ransomshield-ten.vercel.app/](https://ransomshield-ten.vercel.app/)

## What this is

This is a **demonstration project** illustrating how machine learning can be used to score storage behavior for ransomware-like anomalies. It features a data engineering pipeline, a trained ML ensemble model, and a deployed system architecture.

**Key capabilities:**
- The model is trained on [RanSAP](https://www.kaggle.com/datasets/hiranomanabu/ransap-2022-ransomware-behavioral-features)
  (Hirano et al., 2022) - real low-level storage access traces captured
  from 7 actual ransomware families (Sodinokibi, Ryuk, WannaCry,
  TeslaCrypt, Cerber, Darkside, GandCrab4) and 5 benign applications.
- Every metric shown in the live demonstration - entropy, write rate, risk score,
  and feature importance - is sourced from real dataset rows evaluated by the trained model.
- The backend serves a pre-scored, synthetic timeline of 20 escalating dataset samples to demonstrate the model's sensitivity range.

**Limitations:**
- This is not a production endpoint security tool. It has not been evaluated against in-the-wild or novel ransomware variants outside the training dataset.
- This is a stateless demonstration service, not a live filesystem filter driver.

## Architecture & Technology Stack

1. **ML Pipeline (Python/scikit-learn/XGBoost)**: 
   - `ml/preprocess_ransap.py` turns RanSAP's raw per-sector I/O traces into windowed behavioral features (entropy mean/max/std, write throughput, read/write event rates, LBA variance).
   - `ml/train_model.py` trains a Random Forest and XGBoost model against an Isolation Forest anomaly detector. It uses GroupKFold cross-validation (grouped by malware family) to prevent data leakage.
2. **Backend (Python/FastAPI)**: 
   - `backend/main.py` is a stateless FastAPI service deployed on Render. Its primary endpoint (`/demo/start`) loads the serialized model and pre-scored synthetic timeline.
3. **Frontend (React/Next.js)**: 
   - `frontend/app/demo/page.jsx` animates the timeline client-side, charting risk progression, feature importance, and storage metrics using Recharts.

## Repository Layout

```text
/backend    FastAPI service (Python) - deploys to Render
/frontend   Next.js app (React)      - deploys to Vercel
/ml         Model training pipeline (preprocessing, train_model.py)
/data       dataset.csv (output of preprocessing) + model artifacts
```

## Local Development

```bash
# Backend
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# Frontend (separate terminal)
cd frontend
npm install
echo "NEXT_PUBLIC_API_BASE=http://localhost:8000" > .env.local
npm run dev
```

## Retraining the model

If you modify the ML pipeline, you can retrain the model and regenerate the demo timeline:

```bash
cd ml
python preprocess_ransap.py --raw-dir path/to/ransap.zip
python train_model.py
python generate_timeline.py
```

This overwrites `model.pkl` in the `ml/` directory and updates `demo_timeline.json` in `backend/data/`.

## Deployment

**Backend (Render)**
- Build command: `pip install -r backend/requirements.txt`
- Start command: `uvicorn backend.main:app --host 0.0.0.0 --port $PORT`
- Required Environment variables: `ALLOWED_ORIGINS` (e.g., `https://ransomshield-ten.vercel.app`)

**Frontend (Vercel)**
- Root Directory: `frontend`
- Required Environment variables: `NEXT_PUBLIC_API_BASE` (e.g., `https://ransomshield-yw4q.onrender.com`)

## Credits

Trained on [RanSAP](https://doi.org/10.1016/j.fsidi.2022.301338)
(Hirano, Hodota & Kobayashi, 2022), Forensic Science International:
Digital Investigation.
