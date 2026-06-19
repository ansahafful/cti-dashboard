"""Typed data contracts shared across the ingestion, analytics and UI tiers.

Using lightweight dataclasses (rather than passing bare dicts around) gives us
self-documenting column names, IDE autocompletion and a single place to evolve
the schema. Each model also exposes a ``columns`` helper so the analytics tier
can build empty, correctly-typed DataFrames when a source is offline.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from datetime import datetime


@dataclass
class CVERecord:
    """A single normalised vulnerability harvested from NVD.

    Attributes
    ----------
    cve_id:
        Canonical identifier, e.g. ``CVE-2024-12345``.
    published / last_modified:
        ISO-8601 timestamps as reported by NVD.
    description:
        English description text (used heavily in feature engineering).
    cvss_score:
        Base score on the 0-10 scale; ``NaN`` when no metric is published.
    cvss_severity:
        Qualitative band (CRITICAL/HIGH/MEDIUM/LOW/NONE).
    attack_vector / attack_complexity / privileges_required /
    user_interaction:
        Decomposed CVSS v3.x vector components used as categorical features.
    cwe_ids:
        Associated weakness identifiers (e.g. ``CWE-79``).
    cpe_vendors / cpe_products:
        Parsed vendor/product strings from affected-configuration CPEs.
    """

    cve_id: str
    published: str | None = None
    last_modified: str | None = None
    description: str = ""
    cvss_version: str | None = None
    cvss_score: float = float("nan")
    cvss_severity: str = "NONE"
    attack_vector: str = "UNKNOWN"
    attack_complexity: str = "UNKNOWN"
    privileges_required: str = "UNKNOWN"
    user_interaction: str = "UNKNOWN"
    scope: str = "UNKNOWN"
    cwe_ids: list[str] = field(default_factory=list)
    cpe_vendors: list[str] = field(default_factory=list)
    cpe_products: list[str] = field(default_factory=list)
    reference_count: int = 0
    source: str = "nvd"

    @classmethod
    def columns(cls) -> list[str]:
        """Return the ordered field names for DataFrame construction."""
        return [f.name for f in fields(cls)]

    def to_dict(self) -> dict:
        """Serialise to a plain dict (safe for DataFrame / parquet)."""
        return asdict(self)


@dataclass
class KEVRecord:
    """A CISA Known-Exploited-Vulnerability catalogue entry (ground truth)."""

    cve_id: str
    vendor_project: str = ""
    product: str = ""
    vulnerability_name: str = ""
    date_added: str | None = None
    due_date: str | None = None
    known_ransomware: str = "Unknown"
    notes: str = ""

    @classmethod
    def columns(cls) -> list[str]:
        return [f.name for f in fields(cls)]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class IndicatorRecord:
    """A network IOC (IP) with reputation and geolocation enrichment."""

    indicator: str
    indicator_type: str = "IPv4"
    pulse_name: str = ""
    threat_score: float = float("nan")  # 0-100 (AbuseIPDB confidence)
    total_reports: int = 0
    country: str = ""
    country_code: str = ""
    city: str = ""
    latitude: float = float("nan")
    longitude: float = float("nan")
    isp: str = ""
    last_seen: str | None = None
    source: str = "otx"

    @classmethod
    def columns(cls) -> list[str]:
        return [f.name for f in fields(cls)]

    def to_dict(self) -> dict:
        return asdict(self)


# Convenience aliases for callers that prefer explicit column lists.
CVE_COLUMNS: list[str] = CVERecord.columns()
KEV_COLUMNS: list[str] = KEVRecord.columns()
INDICATOR_COLUMNS: list[str] = IndicatorRecord.columns()


def utcnow_iso() -> str:
    """Return the current UTC time as an ISO-8601 string (no microseconds)."""
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
