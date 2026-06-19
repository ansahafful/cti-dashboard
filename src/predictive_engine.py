"""Predictive exploitability engine.

Transforms raw CVE metadata into model-ready features, trains a supervised
classifier to recognise the signature of vulnerabilities that end up in the
CISA KEV catalogue, and emits a continuous **Likelihood of Imminent
Exploitation** score for every CVE.

Design notes
------------
* **Target.** ``label = 1`` iff the CVE appears in the CISA KEV catalogue,
  else ``0``. KEV membership is the analyst-grade ground truth for "actively
  exploited in the wild".
* **Class imbalance.** Exploited CVEs are a small minority. We use
  ``class_weight='balanced'`` and evaluate with Precision/Recall/PR-AUC
  rather than accuracy, explicitly prioritising **recall** (minimising false
  negatives) — a missed exploitable CVE is the costly error in CTI.
* **Leakage control.** Only features knowable at disclosure time are used
  (text, CVSS vector, CWE, CPE). KEV ``date_added`` is never a feature.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

import config
from config import EXPLOIT_KEYWORDS, MODEL

logger = logging.getLogger("cti.predict")

def _kw_column(keyword: str) -> str:
    """Map an exploit keyword to a safe, collision-free feature column name."""
    return "kw_" + keyword.replace(" ", "_").replace("-", "_")


# Group keyword variants that sanitise to the same column (e.g. "zero-day" /
# "zero day") so each feature column is built exactly once from an OR of its
# source phrases. Preserves first-seen order for deterministic columns.
_KEYWORD_GROUPS: dict[str, list[str]] = {}
for _kw in EXPLOIT_KEYWORDS:
    _KEYWORD_GROUPS.setdefault(_kw_column(_kw), []).append(_kw)

# Columns produced by feature engineering (unique, ordered).
_KEYWORD_COLUMNS = list(_KEYWORD_GROUPS.keys())
_CATEGORICAL = [
    "attack_vector",
    "attack_complexity",
    "privileges_required",
    "user_interaction",
    "scope",
    "cvss_severity",
]
_NUMERIC = ["cvss_score", "reference_count", "cwe_count", "cpe_breadth"] + _KEYWORD_COLUMNS
_TEXT = "description"


@dataclass
class ModelArtifacts:
    """Bundle returned by :func:`train_model` for persistence and reuse."""

    pipeline: Pipeline
    metrics: dict


# --------------------------------------------------------------------------- #
# Feature engineering
# --------------------------------------------------------------------------- #
def engineer_features(cves: pd.DataFrame) -> pd.DataFrame:
    """Derive model-ready feature columns from raw CVE metadata.

    The transformation is pure (no fitting) so it can be applied identically
    to training data and to freshly ingested CVEs at inference time.

    Parameters
    ----------
    cves:
        Raw CVE frame matching :class:`schemas.CVERecord`.

    Returns
    -------
    pandas.DataFrame
        ``cves`` augmented with engineered feature columns.
    """
    df = cves.copy()

    # Normalise description text once.
    desc = df["description"].fillna("").str.lower()
    df["description"] = desc

    # Binary keyword presence features (cheap, interpretable weak signals).
    # Variants that share a column (e.g. "zero-day"/"zero day") are OR'd.
    for col, variants in _KEYWORD_GROUPS.items():
        present = desc.str.contains(variants[0], regex=False)
        for extra in variants[1:]:
            present = present | desc.str.contains(extra, regex=False)
        df[col] = present.astype(int)

    # Structural counts.
    df["cwe_count"] = df["cwe_ids"].apply(
        lambda v: len(v) if isinstance(v, (list, np.ndarray)) else 0
    )
    df["cpe_breadth"] = df["cpe_products"].apply(
        lambda v: len(v) if isinstance(v, (list, np.ndarray)) else 0
    )

    # CVSS score: impute missing with the median so the model still sees a row.
    df["cvss_score"] = pd.to_numeric(df["cvss_score"], errors="coerce")
    median_score = df["cvss_score"].median()
    df["cvss_score"] = df["cvss_score"].fillna(
        median_score if not np.isnan(median_score) else 0.0
    )

    df["reference_count"] = (
        pd.to_numeric(df["reference_count"], errors="coerce").fillna(0).astype(int)
    )

    # Ensure categorical columns are strings with an explicit unknown bucket.
    for col in _CATEGORICAL:
        df[col] = df[col].fillna("UNKNOWN").replace("", "UNKNOWN").astype(str)

    return df


def attach_labels(cves: pd.DataFrame, kev: pd.DataFrame) -> pd.DataFrame:
    """Add a binary ``label`` column: 1 if the CVE is in the KEV catalogue."""
    df = cves.copy()
    kev_ids = set(kev["cve_id"].astype(str)) if not kev.empty else set()
    df["label"] = df["cve_id"].astype(str).isin(kev_ids).astype(int)
    logger.info(
        "Labelling: %d/%d CVEs are KEV-positive (%.2f%%)",
        int(df["label"].sum()),
        len(df),
        100.0 * df["label"].mean() if len(df) else 0.0,
    )
    return df


# --------------------------------------------------------------------------- #
# Model construction
# --------------------------------------------------------------------------- #
def _build_pipeline(algorithm: str = "random_forest") -> Pipeline:
    """Assemble the preprocessing + classifier scikit-learn pipeline."""
    preprocessor = ColumnTransformer(
        transformers=[
            (
                "categorical",
                OneHotEncoder(handle_unknown="ignore"),
                _CATEGORICAL,
            ),
            ("numeric", "passthrough", _NUMERIC),
            (
                "text",
                TfidfVectorizer(
                    max_features=300,
                    ngram_range=(1, 2),
                    stop_words="english",
                    sublinear_tf=True,
                ),
                _TEXT,
            ),
        ],
        remainder="drop",
        sparse_threshold=0.3,
    )

    if algorithm == "gradient_boosting":
        classifier = GradientBoostingClassifier(
            n_estimators=MODEL.n_estimators,
            random_state=MODEL.random_state,
        )
    else:
        classifier = RandomForestClassifier(
            n_estimators=MODEL.n_estimators,
            max_depth=MODEL.max_depth,
            class_weight=MODEL.class_weight,
            random_state=MODEL.random_state,
            n_jobs=-1,
        )

    return Pipeline(
        steps=[("features", preprocessor), ("classifier", classifier)]
    )


def _evaluate(
    pipeline: Pipeline,
    x_test: pd.DataFrame,
    y_test: pd.Series,
) -> dict:
    """Compute CTI-relevant metrics, emphasising recall / false negatives."""
    proba = pipeline.predict_proba(x_test)[:, 1]
    preds = (proba >= MODEL.decision_threshold).astype(int)

    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test, preds, average="binary", zero_division=0
    )
    tn, fp, fn, tp = confusion_matrix(y_test, preds, labels=[0, 1]).ravel()

    metrics = {
        "algorithm": pipeline.named_steps["classifier"].__class__.__name__,
        "decision_threshold": MODEL.decision_threshold,
        "support_positive": int(y_test.sum()),
        "support_total": int(len(y_test)),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1": round(float(f1), 4),
        "false_negatives": int(fn),
        "false_positives": int(fp),
        "true_positives": int(tp),
        "true_negatives": int(tn),
    }

    # Threshold-independent ranking quality (robust under class imbalance).
    if y_test.nunique() > 1:
        metrics["roc_auc"] = round(float(roc_auc_score(y_test, proba)), 4)
        metrics["pr_auc"] = round(
            float(average_precision_score(y_test, proba)), 4
        )

    logger.info(
        "Eval — precision=%.3f recall=%.3f f1=%.3f FN=%d (threshold=%.2f)",
        precision,
        recall,
        f1,
        fn,
        MODEL.decision_threshold,
    )
    logger.debug(
        "Full report:\n%s",
        classification_report(y_test, preds, zero_division=0),
    )
    return metrics


def train_model(
    cves: pd.DataFrame,
    kev: pd.DataFrame,
    *,
    algorithm: str = "random_forest",
) -> ModelArtifacts:
    """Engineer features, train the classifier and return fitted artefacts.

    Raises
    ------
    ValueError
        If there are too few positive (KEV) examples to train responsibly.
    """
    labelled = attach_labels(engineer_features(cves), kev)

    positives = int(labelled["label"].sum())
    if positives < MODEL.min_positive_samples:
        raise ValueError(
            f"Only {positives} KEV-positive samples found "
            f"(need >= {MODEL.min_positive_samples}). Widen the CVE lookback "
            "window in config.INGEST or harvest more data before training."
        )

    feature_cols = _CATEGORICAL + _NUMERIC + [_TEXT]
    x = labelled[feature_cols]
    y = labelled["label"]

    x_train, x_test, y_train, y_test = train_test_split(
        x,
        y,
        test_size=MODEL.test_size,
        random_state=MODEL.random_state,
        stratify=y,
    )

    pipeline = _build_pipeline(algorithm)
    logger.info("Training %s on %d samples", algorithm, len(x_train))
    pipeline.fit(x_train, y_train)

    metrics = _evaluate(pipeline, x_test, y_test)
    return ModelArtifacts(pipeline=pipeline, metrics=metrics)


# --------------------------------------------------------------------------- #
# Inference
# --------------------------------------------------------------------------- #
def score_cves(pipeline: Pipeline, cves: pd.DataFrame) -> pd.DataFrame:
    """Attach an ``exploit_probability`` column to a CVE frame.

    The frame is run through identical feature engineering before prediction,
    guaranteeing train/inference parity.
    """
    if cves.empty:
        out = cves.copy()
        out["exploit_probability"] = pd.Series(dtype=float)
        out["high_risk"] = pd.Series(dtype=bool)
        return out

    features = engineer_features(cves)
    feature_cols = _CATEGORICAL + _NUMERIC + [_TEXT]
    proba = pipeline.predict_proba(features[feature_cols])[:, 1]

    out = cves.copy()
    out["exploit_probability"] = proba
    out["high_risk"] = out["exploit_probability"] >= MODEL.decision_threshold
    return out.sort_values("exploit_probability", ascending=False).reset_index(
        drop=True
    )


# --------------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------------- #
def save_artifacts(artifacts: ModelArtifacts) -> None:
    """Persist the fitted pipeline (joblib) and metrics (JSON)."""
    import joblib

    joblib.dump(artifacts.pipeline, config.MODEL_PATH)
    config.METRICS_PATH.write_text(json.dumps(artifacts.metrics, indent=2))
    logger.info("Saved model to %s", config.MODEL_PATH)


def load_pipeline() -> Pipeline:
    """Load a previously trained pipeline from disk."""
    import joblib

    return joblib.load(config.MODEL_PATH)
