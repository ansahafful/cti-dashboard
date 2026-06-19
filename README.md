# 🛰️ Cyber Threat Intelligence & Predictive Exploitation Dashboard

A production-grade, end-to-end CTI platform that **harvests live vulnerability
and threat-actor feeds asynchronously**, **enriches** them with reputation and
geolocation data, **predicts the likelihood of imminent exploitation** with a
supervised ML model, and surfaces it all in an **executive-ready dark-mode
dashboard**.

> Given a freshly disclosed CVE, *how likely is it to be weaponised and added
> to CISA's Known Exploited Vulnerabilities catalogue?* This project answers
> that question with a calibrated probability — before the exploit lands.

---

## ✨ Highlights

| Capability | Implementation |
|---|---|
| Async multi-source harvest | `httpx` + `asyncio`, per-host concurrency + token-bucket rate limiting |
| Resilience | Exponential backoff w/ jitter, `Retry-After` aware, graceful per-source degradation |
| Ground truth | CISA KEV catalogue used as the supervised label (`1` = actively exploited) |
| Feature engineering | Text weak-signals, CVSS vector decomposition, CWE/CPE structural features, TF-IDF |
| Model | Random Forest / Gradient Boosting, **recall-optimised** for minimal false negatives |
| Presentation | Streamlit + Plotly, unified dark theme, predictive watchlist, threat geomap, distributions |

---

## 🏗️ Architecture

```
                ┌──────────────────────────────────────────────┐
                │            ingest_engine.py (async)            │
   NVD  ───────▶│  AsyncFetcher (semaphore + token bucket +     │
   CISA KEV ───▶│   exponential backoff)  →  normalised schemas │
   OTX  ───────▶│  + AbuseIPDB reputation + ip-api GeoIP        │
                └───────────────┬──────────────────────────────┘
                                │  parquet artefacts (data/)
                                ▼
                ┌──────────────────────────────────────────────┐
                │           predictive_engine.py                 │
                │  engineer_features → attach_labels (KEV) →     │
                │  ColumnTransformer(OneHot + TF-IDF + numeric)  │
                │  → RandomForest → exploit_probability          │
                └───────────────┬──────────────────────────────┘
                                │  cves_scored.parquet + model + metrics.json
                                ▼
                ┌──────────────────────────────────────────────┐
                │                  app.py                        │
                │  Streamlit dark dashboard:                     │
                │   • Predictive high-risk watchlist             │
                │   • Geographic threat-actor map                │
                │   • Attack-vector / severity distributions     │
                └──────────────────────────────────────────────┘
```

The three tiers are **decoupled**: ingestion writes parquet, the engine reads
parquet and writes a model + scored parquet, and the UI reads those artefacts.
Each tier can be run, tested and scaled independently.

### Source feeds

| Source | Role | Auth |
|---|---|---|
| **NVD CVE API 2.0** | Vulnerability metadata + CVSS vectors | Optional key (raises rate limit 5→50 req/30s) |
| **CISA KEV catalogue** | Ground-truth exploitation labels | None |
| **AlienVault OTX** | Community IOCs (IP indicators from pulses) | Key required |
| **AbuseIPDB** | IP reputation / confidence score | Key optional |
| **ip-api.com** | Batch GeoIP → map coordinates | None (45 req/min) |

Missing keys never crash the run — that source simply yields an empty,
correctly-typed frame and the pipeline continues.

---

## 🧠 Feature Engineering Methodology

Only signals **knowable at disclosure time** are used (no leakage from KEV
`date_added`). Three families:

1. **Lexical weak-signals** — binary flags for ~20 weaponisation phrases
   (`remote code execution`, `unauthenticated`, `deserialization`, …) plus a
   300-feature TF-IDF (1–2 gram) projection of the description.
2. **CVSS vector decomposition** — `attack_vector`, `attack_complexity`,
   `privileges_required`, `user_interaction`, `scope`, `severity` one-hot
   encoded; `cvss_score` median-imputed.
3. **Structural breadth** — CWE count and CPE product breadth (a vuln hitting
   many products is a juicier target), plus reference count.

All transforms live in a single pure `engineer_features()` function, applied
identically at train and inference time to guarantee parity.

---

## 📈 Model & Performance

**Target:** binary — `1` if the CVE is in the CISA KEV catalogue, else `0`.

Exploited CVEs are a **rare minority** (typically 5–10% of any sample), so:

- The classifier uses `class_weight="balanced"`.
- We evaluate with **Precision, Recall, F1, PR-AUC and the confusion matrix**
  — never raw accuracy.
- The decision threshold (default `0.35`) is deliberately set **below 0.5 to
  favour recall**: in CTI a *false negative* (missing a vuln that gets
  exploited) is far costlier than a false positive (an analyst double-checks a
  benign CVE). The dashboard reports false-negative count explicitly.

`models/metrics.json` (regenerated each run) holds the live numbers, e.g.:

```json
{
  "algorithm": "RandomForestClassifier",
  "precision": 0.94,
  "recall": 1.0,
  "f1": 0.97,
  "false_negatives": 0,
  "pr_auc": 1.0,
  "decision_threshold": 0.35
}
```

> Numbers above are from the offline synthetic demo (intentionally separable).
> On live NVD/KEV data expect lower-but-realistic figures; the **recall-first**
> framing and metric choices are what matter for the portfolio narrative.

---

## 🚀 Setup

```bash
# 1. Install
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. (Optional) add API keys for richer live data
cp .env.example .env      # then edit

# 3a. Zero-config demo (no keys, no network) — recommended first run
python generate_demo_data.py

#   ...or 3b. live harvest + train + score
python run_pipeline.py                  # full live run
python run_pipeline.py --use-cache      # retrain on last harvest
python run_pipeline.py --algorithm gradient_boosting

# 4. Launch the dashboard
streamlit run app.py
```

---

## 📁 Project Layout

```
CTI/
├── config.py                 # endpoints, rate limits, retry policy, theme, hyper-params
├── run_pipeline.py           # orchestrator: harvest → train → score → persist
├── generate_demo_data.py     # offline synthetic dataset for keyless demos
├── app.py                    # Streamlit dark-mode dashboard
├── requirements.txt
├── .env.example
└── src/
    ├── schemas.py            # typed dataclass data contracts
    ├── http_client.py        # AsyncFetcher: rate limiting + backoff + logging
    ├── ingest_engine.py      # NVD / CISA / OTX / AbuseIPDB / GeoIP async clients
    └── predictive_engine.py  # feature engineering + ML training + scoring
```

---

## 🔭 Dashboard Tour

- **🎯 High-Risk Watchlist** — every CVE sorted by ML exploitation likelihood,
  with a progress-bar probability column, severity, attack vector, and free-text
  search across CVE id / description / vendor.
- **🌍 Threat Map** — Plotly `scatter_geo` of malicious IP indicators, sized by
  report volume and coloured by reputation score, on a custom dark projection.
- **📊 Distributions** — severity donut, attack-vector bar, attack-complexity
  vs. predicted-risk grouped bars, and a weekly disclosure-volume trend.

---

## 🛡️ Notes & Disclaimers

- For **authorised research, education and defensive** use. Respect each API's
  terms of service and rate limits.
- Secrets are read from the environment only; `.env` is git-ignored.
- The predictive score is a **prioritisation aid**, not a guarantee of
  exploitation — treat it as one input to triage.

---

*Built as a portfolio demonstration of async data engineering, applied ML, and
threat-intelligence analytics.*
