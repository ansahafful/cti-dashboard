"""Generate realistic synthetic data so the dashboard runs with zero API keys.

This is purely for demos / portfolio review: it fabricates a plausible CVE
corpus, a KEV label set and a geolocated indicator set, then runs the *real*
predictive engine over them. The ML training, scoring and UI code paths are
identical to a live run — only the data origin differs.

    python generate_demo_data.py
    streamlit run app.py
"""

from __future__ import annotations

import logging
import random
from datetime import datetime, timedelta

import numpy as np
import pandas as pd

import config
from src import predictive_engine
from src.schemas import CVE_COLUMNS, INDICATOR_COLUMNS, KEV_COLUMNS

logger = logging.getLogger("cti.demo")

RNG = random.Random(42)
np.random.seed(42)

_VENDORS = ["microsoft", "apache", "cisco", "fortinet", "vmware", "oracle",
            "adobe", "atlassian", "citrix", "ivanti", "progress", "linux"]
_PRODUCTS = ["windows", "struts", "ios_xe", "fortios", "vcenter", "weblogic",
             "acrobat", "confluence", "netscaler", "connect_secure", "moveit"]
_VECTORS = ["NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"]
_COMPLEX = ["LOW", "HIGH"]
_PRIV = ["NONE", "LOW", "HIGH"]
_UI = ["NONE", "REQUIRED"]
_SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

# Phrases that the model should learn correlate with exploitation.
_HOT = ["remote code execution", "unauthenticated", "buffer overflow",
        "deserialization", "authentication bypass", "command injection",
        "use-after-free", "privilege escalation", "path traversal"]
_COLD = ["information disclosure", "denial of service", "cross-site scripting",
         "improper input validation", "memory leak", "missing authorization"]


def _make_cve(i: int, exploited: bool) -> dict:
    """Fabricate one CVE row; exploited ones get hotter text / higher CVSS."""
    year = RNG.choice([2023, 2024, 2025])
    cve_id = f"CVE-{year}-{10000 + i}"
    if exploited:
        phrases = RNG.sample(_HOT, k=RNG.randint(1, 3))
        score = round(RNG.uniform(7.5, 10.0), 1)
        vector = "NETWORK"
        complexity = "LOW"
        priv = RNG.choice(["NONE", "LOW"])
    else:
        pool = _COLD + (_HOT if RNG.random() < 0.15 else [])
        phrases = RNG.sample(pool, k=RNG.randint(1, 2))
        score = round(RNG.uniform(2.0, 9.0), 1)
        vector = RNG.choice(_VECTORS)
        complexity = RNG.choice(_COMPLEX)
        priv = RNG.choice(_PRIV)

    severity = ("CRITICAL" if score >= 9 else "HIGH" if score >= 7
                else "MEDIUM" if score >= 4 else "LOW")
    published = datetime.utcnow() - timedelta(days=RNG.randint(0, 540))

    return {
        "cve_id": cve_id,
        "published": published.isoformat(),
        "last_modified": published.isoformat(),
        "description": f"A {' and '.join(phrases)} vulnerability in "
                       f"{RNG.choice(_VENDORS)} {RNG.choice(_PRODUCTS)} allows attackers to compromise the host.",
        "cvss_version": "3.1",
        "cvss_score": score,
        "cvss_severity": severity,
        "attack_vector": vector,
        "attack_complexity": complexity,
        "privileges_required": priv,
        "user_interaction": RNG.choice(_UI),
        "scope": RNG.choice(["UNCHANGED", "CHANGED"]),
        "cwe_ids": RNG.sample(["CWE-79", "CWE-89", "CWE-787", "CWE-416", "CWE-22"],
                              k=RNG.randint(1, 2)),
        "cpe_vendors": RNG.sample(_VENDORS, k=RNG.randint(1, 2)),
        "cpe_products": RNG.sample(_PRODUCTS, k=RNG.randint(1, 3)),
        "reference_count": RNG.randint(1, 25),
        "source": "synthetic",
    }


def build_cves(n: int = 1500, exploited_rate: float = 0.08) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Return (cves, kev) synthetic frames with a realistic positive rate."""
    rows, kev_rows = [], []
    for i in range(n):
        exploited = RNG.random() < exploited_rate
        row = _make_cve(i, exploited)
        rows.append(row)
        if exploited:
            kev_rows.append({
                "cve_id": row["cve_id"],
                "vendor_project": row["cpe_vendors"][0],
                "product": row["cpe_products"][0],
                "vulnerability_name": f"{row['cpe_products'][0]} RCE",
                "date_added": datetime.utcnow().date().isoformat(),
                "due_date": (datetime.utcnow() + timedelta(days=21)).date().isoformat(),
                "known_ransomware": RNG.choice(["Known", "Unknown"]),
                "notes": "",
            })
    cves = pd.DataFrame(rows, columns=CVE_COLUMNS)
    kev = pd.DataFrame(kev_rows, columns=KEV_COLUMNS)
    return cves, kev


def build_indicators(n: int = 200) -> pd.DataFrame:
    """Fabricate geolocated, reputation-scored IP indicators."""
    hotspots = [
        ("Russia", "RU", 55.75, 37.62), ("China", "CN", 39.90, 116.40),
        ("United States", "US", 38.0, -97.0), ("Brazil", "BR", -15.79, -47.88),
        ("Netherlands", "NL", 52.37, 4.90), ("India", "IN", 28.61, 77.21),
        ("Nigeria", "NG", 9.08, 8.68), ("Iran", "IR", 35.69, 51.39),
    ]
    rows = []
    for i in range(n):
        country, cc, lat, lon = RNG.choice(hotspots)
        rows.append({
            "indicator": f"{RNG.randint(1,223)}.{RNG.randint(0,255)}.{RNG.randint(0,255)}.{RNG.randint(1,254)}",
            "indicator_type": "IPv4",
            "pulse_name": RNG.choice(["APT cluster", "Botnet C2", "Phishing infra",
                                      "Ransomware staging", "Scanner pool"]),
            "threat_score": round(RNG.uniform(20, 100), 0),
            "total_reports": RNG.randint(1, 500),
            "country": country,
            "country_code": cc,
            "city": "",
            "latitude": lat + RNG.uniform(-4, 4),
            "longitude": lon + RNG.uniform(-4, 4),
            "isp": RNG.choice(["Hosting Ltd", "CloudCorp", "TelecomNet", "VPS Provider"]),
            "last_seen": datetime.utcnow().isoformat(),
            "source": "synthetic",
        })
    return pd.DataFrame(rows, columns=INDICATOR_COLUMNS)


def main() -> None:
    logging.basicConfig(level=config.LOG_LEVEL, format=config.LOG_FORMAT)
    logger.info("Generating synthetic CTI dataset...")
    cves, kev = build_cves()
    indicators = build_indicators()

    cves.to_parquet(config.RAW_CVE_PATH, index=False)
    kev.to_parquet(config.DATA_DIR / "kev.parquet", index=False)
    indicators.to_parquet(config.INDICATORS_PATH, index=False)

    artifacts = predictive_engine.train_model(cves, kev)
    predictive_engine.save_artifacts(artifacts)
    scored = predictive_engine.score_cves(artifacts.pipeline, cves)
    scored.to_parquet(config.SCORED_CVE_PATH, index=False)

    logger.info("Demo data ready. Metrics: %s", artifacts.metrics)
    logger.info("Now run:  streamlit run app.py")


if __name__ == "__main__":
    main()
