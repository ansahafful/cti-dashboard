# Deploying to Streamlit Community Cloud

> **Why not Vercel?** Streamlit runs a persistent, stateful WebSocket server —
> Vercel only hosts static files and short-lived serverless functions (and the
> `pandas`+`scikit-learn` bundle exceeds Vercel's 250 MB function limit).
> Streamlit Community Cloud is free and purpose-built for this app.

The app is **deploy-ready as-is**: on first load it self-bootstraps the
synthetic demo dataset and trains the model (see `bootstrap_data()` in
[app.py](app.py)), so it works with **zero secrets and zero manual steps**.

---

## 1. Push to GitHub

```bash
cd /Users/andrewansah/Downloads/CTI
git init
git add .
git commit -m "CTI predictive exploitation dashboard"
git branch -M main
git remote add origin https://github.com/<you>/cti-dashboard.git
git push -u origin main
```

`data/` and `models/` are git-ignored — that's intentional. The app regenerates
them on boot, so nothing binary needs committing.

## 2. Deploy

1. Go to **[share.streamlit.io](https://share.streamlit.io)** and sign in with GitHub.
2. **Create app** → **Deploy a public app from a repo**.
3. Set:
   - **Repository:** `<you>/cti-dashboard`
   - **Branch:** `main`
   - **Main file path:** `app.py`
4. (Optional) **Advanced settings → Python version:** `3.11`.
5. Click **Deploy**. First build installs `requirements.txt` (~2–3 min), then
   the app cold-starts and bootstraps its dataset.

Your app goes live at `https://<app-name>.streamlit.app`.

## 3. (Optional) Secrets

Not required for the demo. Only needed if you later add a live-harvest button.
In **Manage app → Settings → Secrets**, paste TOML (see
[.streamlit/secrets.toml.example](.streamlit/secrets.toml.example)):

```toml
NVD_API_KEY = "your-key"
OTX_API_KEY = "your-key"
ABUSEIPDB_API_KEY = "your-key"
```

`app.py` copies these into the environment before importing `config`, so the
ingestion engine picks them up automatically.

---

## Notes & gotchas

- **Ephemeral filesystem.** Generated parquet/model files do **not** persist
  across restarts — that's fine, `bootstrap_data()` recreates them. Resource
  caching keeps it to once per server boot.
- **Live data.** Community Cloud has no scheduler, so it won't run
  `run_pipeline.py` on a cron. For continuously-refreshed live data, deploy on
  a container host (Render/Railway/Fly) with a scheduled job instead — ping me
  and I'll add a `Dockerfile` + cron config.
- **Resource limits.** The free tier gives ~1 GB RAM; the demo corpus (1,500
  CVEs) trains in ~1s and fits comfortably. If you bump `max_cves` for a live
  run, watch memory.
- **Python version.** Code targets 3.10+. Pin 3.11 in advanced settings for a
  stable, well-supported runtime.
```
