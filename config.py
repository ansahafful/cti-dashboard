"""Central configuration for the Cyber Threat Intelligence dashboard.

All tunable runtime parameters — API endpoints, rate limits, retry policy,
file paths and model hyper-parameters — live here so that the ingestion,
analytics and presentation tiers stay decoupled and environment-driven.

Secrets are read from the process environment (optionally hydrated from a
local ``.env`` file via :mod:`python-dotenv`). Nothing sensitive is hard
coded.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

try:  # Optional convenience: load .env if python-dotenv is installed.
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # pragma: no cover - dotenv is an optional dependency.
    pass


# --------------------------------------------------------------------------- #
# Filesystem layout
# --------------------------------------------------------------------------- #
BASE_DIR: Path = Path(__file__).resolve().parent
DATA_DIR: Path = BASE_DIR / "data"
MODEL_DIR: Path = BASE_DIR / "models"

DATA_DIR.mkdir(exist_ok=True)
MODEL_DIR.mkdir(exist_ok=True)

# Canonical artefacts produced by the pipeline and consumed by the dashboard.
RAW_CVE_PATH: Path = DATA_DIR / "cves_raw.parquet"
ENRICHED_CVE_PATH: Path = DATA_DIR / "cves_enriched.parquet"
SCORED_CVE_PATH: Path = DATA_DIR / "cves_scored.parquet"
INDICATORS_PATH: Path = DATA_DIR / "indicators.parquet"
MODEL_PATH: Path = MODEL_DIR / "exploit_predictor.joblib"
METRICS_PATH: Path = MODEL_DIR / "metrics.json"


# --------------------------------------------------------------------------- #
# API credentials (read from the environment; never commit real values)
# --------------------------------------------------------------------------- #
NVD_API_KEY: str | None = os.getenv("NVD_API_KEY")
OTX_API_KEY: str | None = os.getenv("OTX_API_KEY")
ABUSEIPDB_API_KEY: str | None = os.getenv("ABUSEIPDB_API_KEY")


@dataclass(frozen=True)
class EndpointConfig:
    """Static metadata describing a single upstream data source."""

    name: str
    base_url: str
    #: Maximum number of in-flight requests allowed against this host.
    max_concurrency: int = 4
    #: Minimum seconds between successive requests (token-bucket spacing).
    min_interval: float = 0.6
    #: Default page size where the API supports pagination.
    page_size: int = 2000


# --------------------------------------------------------------------------- #
# Source endpoints
# --------------------------------------------------------------------------- #
# NVD enforces 5 req/30s without a key and 50 req/30s with one. We space
# requests conservatively and let the key (if present) relax the interval.
NVD = EndpointConfig(
    name="nvd",
    base_url="https://services.nvd.nist.gov/rest/json/cves/2.0",
    max_concurrency=1 if NVD_API_KEY is None else 4,
    min_interval=6.0 if NVD_API_KEY is None else 0.7,
    page_size=2000,
)

CISA_KEV = EndpointConfig(
    name="cisa_kev",
    base_url=(
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    ),
    max_concurrency=1,
    min_interval=1.0,
)

OTX = EndpointConfig(
    name="otx",
    base_url="https://otx.alienvault.com/api/v1",
    max_concurrency=4,
    min_interval=0.4,
)

ABUSEIPDB = EndpointConfig(
    name="abuseipdb",
    base_url="https://api.abuseipdb.com/api/v2",
    max_concurrency=2,
    min_interval=1.5,
)

# Keyless batch GeoIP resolver (45 req/min). Used to map IOC IPs to coords.
GEOIP = EndpointConfig(
    name="ip-api",
    base_url="http://ip-api.com/batch",
    max_concurrency=1,
    min_interval=1.4,
    page_size=100,
)


# --------------------------------------------------------------------------- #
# Resilience / retry policy
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class RetryPolicy:
    """Exponential-backoff parameters shared by all async clients."""

    max_attempts: int = 5
    base_delay: float = 1.0
    max_delay: float = 30.0
    #: Jitter fraction applied to each computed delay to avoid thundering herd.
    jitter: float = 0.25
    #: HTTP status codes that should trigger a retry.
    retry_statuses: tuple[int, ...] = (408, 429, 500, 502, 503, 504)


RETRY_POLICY = RetryPolicy()
REQUEST_TIMEOUT: float = 30.0


# --------------------------------------------------------------------------- #
# Ingestion volume controls
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class IngestConfig:
    """How much data to pull on a given run."""

    #: Trailing window of CVEs to harvest from NVD (NVD caps at 120 days).
    cve_lookback_days: int = 90
    #: Hard ceiling on harvested CVEs to keep portfolio runs snappy.
    max_cves: int = 6000
    #: OTX pulses to scan for IP indicators.
    otx_pulse_pages: int = 3
    #: Cap on indicator IPs sent for GeoIP/reputation enrichment.
    max_indicators: int = 400


INGEST = IngestConfig()


# --------------------------------------------------------------------------- #
# Feature engineering vocabulary
# --------------------------------------------------------------------------- #
# Presence of these phrases in a CVE description is a strong weak-signal of
# weaponisability. Order is irrelevant; each becomes a binary feature column.
EXPLOIT_KEYWORDS: tuple[str, ...] = (
    "remote code execution",
    "arbitrary code",
    "buffer overflow",
    "heap overflow",
    "stack overflow",
    "use after free",
    "use-after-free",
    "privilege escalation",
    "authentication bypass",
    "sql injection",
    "command injection",
    "deserialization",
    "path traversal",
    "directory traversal",
    "zero-day",
    "zero day",
    "wormable",
    "unauthenticated",
    "memory corruption",
    "type confusion",
)


@dataclass(frozen=True)
class ModelConfig:
    """Hyper-parameters and training controls for the exploit predictor."""

    test_size: float = 0.25
    random_state: int = 42
    n_estimators: int = 400
    max_depth: int | None = None
    #: Up-weight the rare positive (KEV) class to bias toward recall.
    class_weight: str = "balanced"
    #: Probability threshold for the binary "high risk" flag in the UI.
    decision_threshold: float = 0.35
    #: Features fall back to zero when a source (e.g. OTX) is unavailable.
    min_positive_samples: int = 25


MODEL = ModelConfig()


# --------------------------------------------------------------------------- #
# Presentation theme (kept here so UI and any generated charts stay in sync)
# --------------------------------------------------------------------------- #
THEME: dict[str, str] = {
    "bg": "#0f172a",
    "surface": "#1e293b",
    "surface_alt": "#334155",
    "text": "#e2e8f0",
    "muted": "#94a3b8",
    "accent": "#38bdf8",      # neon cyan
    "accent_alt": "#a855f7",  # neon violet
    "danger": "#f43f5e",      # neon rose
    "warning": "#fbbf24",
    "success": "#34d399",
}

# Ordered severity bands used consistently across charts and tables.
SEVERITY_ORDER: list[str] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "#f43f5e",
    "HIGH": "#fb923c",
    "MEDIUM": "#fbbf24",
    "LOW": "#38bdf8",
    "NONE": "#64748b",
}

# Structured logging format reused by every module.
LOG_FORMAT: str = "%(asctime)s | %(levelname)-8s | %(name)-18s | %(message)s"
LOG_LEVEL: str = os.getenv("CTI_LOG_LEVEL", "INFO")
