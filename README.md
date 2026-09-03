# RansomShield

A live, interactive demo of a behavioral ransomware-detection model —
trained on real ransomware storage traces, deployed as a real service, and
scored live in the browser. No signup, no accounts, no fabricated data.

**Live demo:** _add your deployed URL here once live_

## What this actually is

This is a **demonstration project**, not a commercial security product. It
exists to show real, defensible work: honest data engineering, a real
trained ML model, and a real deployed system — not a mockup. Read this
section before judging the metrics below; the scope is intentionally
narrow and stated plainly rather than oversold.

**What's real:**
- The model is trained on [RanSAP](https://www.kaggle.com/datasets/hiranomanabu/ransap-2022-ransomware-behavioral-features)
  (Hirano et al., 2022) — real low-level storage access traces captured
  from 7 actual ransomware families (Sodinokibi, Ryuk, WannaCry,
  TeslaCrypt, Cerber, Darkside, GandCrab4) and 5 benign applications
  (Excel, AESCrypt, Firefox, SDelete, Zip) running in an instrumented VM.
- Every number shown in the live demo — entropy, write rate, risk score,
  feature importance — is either a real row from that dataset or a real
  output of the trained model scoring it. Nothing is scripted or faked for
  effect.
- The backend is a real deployed FastAPI service; the frontend is a real
  deployed Next.js app.

**What this is NOT, on purpose:**
- Not a production security tool. It hasn't been evaluated against
  real-world, novel, or evasive ransomware — only the 7 families in the
  training set.
- Not multi-tenant, no accounts, no "protect my real machine" agent. That
  direction was explored and deliberately cut in favor of a focused,
  honest demo that does one thing well.
- The 95.75% F1 / 0.988 ROC-AUC the model achieves is real and
  cross-validated, but it's measured on a few thousand rows from one lab's
  controlled captures, not a broad or adversarial benchmark. Treat it as
  "this approach genuinely works," not "this catches everything."

## How it works

1. **Data**: `ml/preprocess_ransap.py` turns RanSAP's raw per-sector I/O
   traces into windowed behavioral features (entropy mean/max/std, write
   throughput, read/write event rates, LBA variance) with an explicit,
   verified label whitelist — no folder-name guessing, no silent
   mislabeling. Unmatched samples are excluded and logged, not assumed.
2. **Model**: `ml/train_model.py` trains a Random Forest + XGBoost
   ensemble against an IsolationForest anomaly detector, with grouped
   train/test splitting (by malware sample, not by row) to prevent data
   leakage.
3. **Backend**: `backend/main.py` is a stateless FastAPI service. Its one
   real endpoint, `/demo/start`, scores a pre-selected set of real dataset
   rows (spanning the actual risk-score range the model produces) through
   the live model and returns the full timeline plus real feature
   importance in one response.
4. **Frontend**: `frontend/app/demo/page.jsx` animates that real timeline
   client-side — risk score, entropy breakdown, storage activity, feature
   importance, and a narrated detection log — all sourced from the one API
   response, no per-step network calls.

## Repo layout

```
/backend    FastAPI service (Python) — deploys to Render
/frontend   Next.js app (React)      — deploys to Vercel
/ml         Model training pipeline (preprocessing, train_model.py)
/data       dataset.csv (output of preprocessing) + model artifacts
```

No database, no auth provider — deliberately, since there are no accounts.

## Deploying the backend (Render)

1. New Web Service → connect this repo.
2. Root Directory: leave blank (repo root).
3. Build command: `pip install -r backend/requirements.txt`
4. Start command: `uvicorn backend.main:app --host 0.0.0.0 --port $PORT`
5. Environment variables:
   - `ALLOWED_ORIGINS` — your frontend's deployed URL (comma-separated if
     more than one), e.g. `https://ransomshield.vercel.app`
   - `MODEL_PATH` — optional, defaults to `ml/model.pkl` relative to the
     backend folder.

## Deploying the frontend (Vercel)

1. New Project → import this repo.
2. **Root Directory**: set to `frontend` (Project Settings → General). This
   is the setting that makes the monorepo work.
3. Framework preset: Next.js (auto-detected).
4. Environment variables:
   - `NEXT_PUBLIC_API_BASE` — your deployed Render backend URL.

## Local development

```bash
# Backend
cd backend
pip install -r requirements.txt --break-system-packages
uvicorn main:app --reload --port 8000

# Frontend (separate terminal)
cd frontend
npm install
echo "NEXT_PUBLIC_API_BASE=http://localhost:8000" > .env.local
npm run dev
```

## Retraining the model

```bash
cd ml
python preprocess_ransap.py --raw-dir path/to/ransap.zip
python train_model.py
```

Outputs `model.pkl` in the `ml/` folder, which is where
the backend already looks for it by default.

## Credits

Trained on [RanSAP](https://doi.org/10.1016/j.fsidi.2022.301338)
(Hirano, Hodota & Kobayashi, 2022), Forensic Science International:
Digital Investigation.
