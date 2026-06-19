"""End-to-end batch pipeline: harvest -> train -> score -> persist.

This is the single command an operator runs to refresh the dashboard's data::

    python run_pipeline.py                # full live harvest + train + score
    python run_pipeline.py --use-cache    # reuse last harvest, just retrain
    python run_pipeline.py --algorithm gradient_boosting

Artefacts produced (consumed by ``app.py``):
    data/cves_scored.parquet   scored CVE watchlist
    data/indicators.parquet    enriched IOC geomap data
    models/exploit_predictor.joblib + models/metrics.json
"""

from __future__ import annotations

import argparse
import asyncio
import logging

import pandas as pd

import config
from src import ingest_engine, predictive_engine

logger = logging.getLogger("cti.pipeline")


def _load_cached() -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Reload the most recent harvest from disk (for --use-cache runs)."""
    cves = pd.read_parquet(config.RAW_CVE_PATH)
    kev = pd.read_parquet(config.DATA_DIR / "kev.parquet")
    indicators = (
        pd.read_parquet(config.INDICATORS_PATH)
        if config.INDICATORS_PATH.exists()
        else pd.DataFrame()
    )
    logger.info("Loaded cached harvest: %d CVEs, %d KEV", len(cves), len(kev))
    return cves, kev, indicators


def run(*, use_cache: bool, algorithm: str) -> None:
    """Execute the full pipeline."""
    if use_cache and config.RAW_CVE_PATH.exists():
        cves, kev, indicators = _load_cached()
    else:
        cves, kev, indicators = asyncio.run(ingest_engine.harvest_all())
        ingest_engine._persist(cves, kev, indicators)

    if cves.empty:
        logger.error("No CVEs harvested — aborting. Check network / API keys.")
        return

    artifacts = predictive_engine.train_model(cves, kev, algorithm=algorithm)
    predictive_engine.save_artifacts(artifacts)

    scored = predictive_engine.score_cves(artifacts.pipeline, cves)
    scored.to_parquet(config.SCORED_CVE_PATH, index=False)
    logger.info(
        "Pipeline complete. %d CVEs scored, %d flagged high-risk.",
        len(scored),
        int(scored["high_risk"].sum()),
    )
    logger.info("Model metrics: %s", artifacts.metrics)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CTI predictive pipeline")
    parser.add_argument(
        "--use-cache",
        action="store_true",
        help="Reuse the last harvest instead of hitting live APIs.",
    )
    parser.add_argument(
        "--algorithm",
        choices=["random_forest", "gradient_boosting"],
        default="random_forest",
        help="Classifier to train.",
    )
    return parser.parse_args()


def main() -> None:
    logging.basicConfig(level=config.LOG_LEVEL, format=config.LOG_FORMAT)
    args = _parse_args()
    run(use_cache=args.use_cache, algorithm=args.algorithm)


if __name__ == "__main__":
    main()
