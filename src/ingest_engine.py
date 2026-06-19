"""Asynchronous multi-source ingestion & enrichment engine.

Harvests, normalises and joins four live threat-intelligence feeds:

1. **NVD CVE API (2.0)** — vulnerability metadata + CVSS vectors.
2. **CISA KEV catalogue** — ground-truth registry of exploited CVEs.
3. **AlienVault OTX** — community IOCs (IP indicators from pulses).
4. **AbuseIPDB + ip-api** — IP reputation and GeoIP enrichment.

The engine is fully async (``httpx`` + ``asyncio``), rate-limit-aware and
resilient (see :mod:`src.http_client`). Every public coroutine degrades
gracefully: a dead or key-less source yields an empty, correctly-typed
DataFrame rather than aborting the run, so the dashboard always has data.

Run as a script to execute the whole harvest and persist parquet artefacts::

    python -m src.ingest_engine
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta

import pandas as pd

import config
from src.http_client import AsyncFetcher
from src.schemas import (
    CVE_COLUMNS,
    INDICATOR_COLUMNS,
    KEV_COLUMNS,
    CVERecord,
    IndicatorRecord,
    KEVRecord,
)

logger = logging.getLogger("cti.ingest")


# --------------------------------------------------------------------------- #
# NVD CVE harvesting
# --------------------------------------------------------------------------- #
def _parse_cve_item(vuln: dict) -> CVERecord | None:
    """Normalise a single NVD ``vulnerabilities[]`` entry into a CVERecord."""
    cve = vuln.get("cve")
    if not cve or "id" not in cve:
        return None

    cve_id = cve["id"]

    # English description (NVD returns a list of localised descriptions).
    description = ""
    for entry in cve.get("descriptions", []):
        if entry.get("lang") == "en":
            description = entry.get("value", "")
            break

    record = CVERecord(
        cve_id=cve_id,
        published=cve.get("published"),
        last_modified=cve.get("lastModified"),
        description=description,
        reference_count=len(cve.get("references", [])),
    )

    # --- CVSS metrics: prefer v3.1 > v3.0 > v2 -------------------------- #
    metrics = cve.get("metrics", {})
    metric_block = None
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if metrics.get(key):
            metric_block = metrics[key][0]
            record.cvss_version = "3.1" if key.endswith("31") else "3.0"
            break

    if metric_block is not None:
        data = metric_block.get("cvssData", {})
        record.cvss_score = float(data.get("baseScore", float("nan")))
        record.cvss_severity = (
            metric_block.get("baseSeverity")
            or data.get("baseSeverity")
            or "NONE"
        ).upper()
        record.attack_vector = data.get("attackVector", "UNKNOWN")
        record.attack_complexity = data.get("attackComplexity", "UNKNOWN")
        record.privileges_required = data.get("privilegesRequired", "UNKNOWN")
        record.user_interaction = data.get("userInteraction", "UNKNOWN")
        record.scope = data.get("scope", "UNKNOWN")
    elif metrics.get("cvssMetricV2"):
        block = metrics["cvssMetricV2"][0]
        data = block.get("cvssData", {})
        record.cvss_version = "2.0"
        record.cvss_score = float(data.get("baseScore", float("nan")))
        record.cvss_severity = block.get("baseSeverity", "NONE").upper()
        record.attack_vector = data.get("accessVector", "UNKNOWN")
        record.attack_complexity = data.get("accessComplexity", "UNKNOWN")
        record.privileges_required = data.get("authentication", "UNKNOWN")

    # --- CWE weakness identifiers --------------------------------------- #
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            value = desc.get("value", "")
            if value.startswith("CWE-") and value not in record.cwe_ids:
                record.cwe_ids.append(value)

    # --- CPE vendor/product parsing ------------------------------------- #
    vendors: set[str] = set()
    products: set[str] = set()
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                # CPE 2.3: cpe:2.3:a:vendor:product:version:...
                parts = match.get("criteria", "").split(":")
                if len(parts) >= 5:
                    if parts[3] not in ("*", "-"):
                        vendors.add(parts[3])
                    if parts[4] not in ("*", "-"):
                        products.add(parts[4])
    record.cpe_vendors = sorted(vendors)
    record.cpe_products = sorted(products)

    return record


async def fetch_cves(
    *,
    lookback_days: int = config.INGEST.cve_lookback_days,
    max_cves: int = config.INGEST.max_cves,
) -> pd.DataFrame:
    """Harvest recent CVEs from the NVD 2.0 API with cursor pagination.

    Parameters
    ----------
    lookback_days:
        Size of the trailing publication window (NVD allows up to 120 days
        per ``pubStartDate``/``pubEndDate`` query).
    max_cves:
        Upper bound on harvested records to keep runtimes reasonable.

    Returns
    -------
    pandas.DataFrame
        One row per CVE, columns matching :class:`schemas.CVERecord`.
    """
    headers = {"apiKey": config.NVD_API_KEY} if config.NVD_API_KEY else {}
    end = datetime.utcnow()
    start = end - timedelta(days=min(lookback_days, 120))

    params_base = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": config.NVD.page_size,
    }

    records: list[CVERecord] = []
    start_index = 0

    async with AsyncFetcher(config.NVD, headers=headers) as fetcher:
        while len(records) < max_cves:
            params = {**params_base, "startIndex": start_index}
            payload = await fetcher.get_json(config.NVD.base_url, params=params)
            if not payload or "vulnerabilities" not in payload:
                break

            page = payload["vulnerabilities"]
            for vuln in page:
                parsed = _parse_cve_item(vuln)
                if parsed is not None:
                    records.append(parsed)

            total = payload.get("totalResults", 0)
            start_index += len(page)
            logger.info(
                "NVD: harvested %d/%d (total available %d)",
                len(records),
                max_cves,
                total,
            )
            if not page or start_index >= total:
                break

    logger.info("NVD: finished with %d CVE records", len(records))
    if not records:
        return pd.DataFrame(columns=CVE_COLUMNS)
    return pd.DataFrame([r.to_dict() for r in records], columns=CVE_COLUMNS)


# --------------------------------------------------------------------------- #
# CISA KEV catalogue (ground-truth labels)
# --------------------------------------------------------------------------- #
async def fetch_kev() -> pd.DataFrame:
    """Download the full CISA Known-Exploited-Vulnerabilities catalogue."""
    async with AsyncFetcher(config.CISA_KEV) as fetcher:
        payload = await fetcher.get_json(config.CISA_KEV.base_url)

    if not payload or "vulnerabilities" not in payload:
        logger.warning("CISA KEV: no data returned")
        return pd.DataFrame(columns=KEV_COLUMNS)

    records = [
        KEVRecord(
            cve_id=item.get("cveID", ""),
            vendor_project=item.get("vendorProject", ""),
            product=item.get("product", ""),
            vulnerability_name=item.get("vulnerabilityName", ""),
            date_added=item.get("dateAdded"),
            due_date=item.get("dueDate"),
            known_ransomware=item.get("knownRansomwareCampaignUse", "Unknown"),
            notes=item.get("notes", ""),
        )
        for item in payload["vulnerabilities"]
        if item.get("cveID")
    ]
    logger.info("CISA KEV: %d known-exploited CVEs", len(records))
    return pd.DataFrame([r.to_dict() for r in records], columns=KEV_COLUMNS)


# --------------------------------------------------------------------------- #
# OTX indicator harvesting
# --------------------------------------------------------------------------- #
async def fetch_otx_indicators(
    *,
    pages: int = config.INGEST.otx_pulse_pages,
    max_indicators: int = config.INGEST.max_indicators,
) -> pd.DataFrame:
    """Pull recent IPv4 indicators from subscribed AlienVault OTX pulses.

    Requires ``OTX_API_KEY``; returns an empty frame (logged) if absent so the
    pipeline still completes for users without OTX access.
    """
    if not config.OTX_API_KEY:
        logger.warning("OTX: OTX_API_KEY not set — skipping indicator harvest")
        return pd.DataFrame(columns=INDICATOR_COLUMNS)

    headers = {"X-OTX-API-KEY": config.OTX_API_KEY}
    records: list[IndicatorRecord] = []

    async with AsyncFetcher(config.OTX, headers=headers) as fetcher:
        for page in range(1, pages + 1):
            url = f"{config.OTX.base_url}/pulses/subscribed"
            payload = await fetcher.get_json(
                url, params={"page": page, "limit": 20}
            )
            if not payload or "results" not in payload:
                break

            for pulse in payload["results"]:
                pulse_name = pulse.get("name", "")
                for ind in pulse.get("indicators", []):
                    if ind.get("type") not in ("IPv4", "IPv6"):
                        continue
                    records.append(
                        IndicatorRecord(
                            indicator=ind.get("indicator", ""),
                            indicator_type=ind.get("type", "IPv4"),
                            pulse_name=pulse_name,
                            last_seen=ind.get("created"),
                            source="otx",
                        )
                    )
                    if len(records) >= max_indicators:
                        break
                if len(records) >= max_indicators:
                    break
            if len(records) >= max_indicators:
                break

    logger.info("OTX: collected %d IP indicators", len(records))
    if not records:
        return pd.DataFrame(columns=INDICATOR_COLUMNS)
    # De-duplicate on the indicator value, keeping first occurrence.
    df = pd.DataFrame([r.to_dict() for r in records], columns=INDICATOR_COLUMNS)
    return df.drop_duplicates(subset="indicator").reset_index(drop=True)


# --------------------------------------------------------------------------- #
# Reputation + GeoIP enrichment
# --------------------------------------------------------------------------- #
async def _enrich_abuseipdb(
    df: pd.DataFrame, fetcher: AsyncFetcher
) -> pd.DataFrame:
    """Annotate indicators with AbuseIPDB confidence scores (in place)."""
    url = f"{config.ABUSEIPDB.base_url}/check"

    async def _check(ip: str) -> tuple[str, float, int]:
        payload = await fetcher.get_json(
            url, params={"ipAddress": ip, "maxAgeInDays": 90}
        )
        if payload and "data" in payload:
            data = payload["data"]
            return (
                ip,
                float(data.get("abuseConfidenceScore", 0)),
                int(data.get("totalReports", 0)),
            )
        return ip, float("nan"), 0

    results = await asyncio.gather(*(_check(ip) for ip in df["indicator"]))
    scores = {ip: (score, reports) for ip, score, reports in results}
    df["threat_score"] = df["indicator"].map(lambda x: scores.get(x, (float("nan"), 0))[0])
    df["total_reports"] = df["indicator"].map(lambda x: scores.get(x, (float("nan"), 0))[1])
    return df


async def _enrich_geoip(df: pd.DataFrame) -> pd.DataFrame:
    """Resolve indicator IPs to coordinates via the ip-api batch endpoint."""
    ips = df["indicator"].tolist()
    fields = "status,country,countryCode,city,lat,lon,isp,query"
    geo: dict[str, dict] = {}

    async with AsyncFetcher(config.GEOIP) as fetcher:
        # ip-api batch accepts up to 100 IPs per POST.
        for i in range(0, len(ips), config.GEOIP.page_size):
            chunk = ips[i : i + config.GEOIP.page_size]
            payload = await fetcher.post_json(
                config.GEOIP.base_url,
                json=[{"query": ip, "fields": fields} for ip in chunk],
            )
            if not isinstance(payload, list):
                continue
            for entry in payload:
                if entry.get("status") == "success":
                    geo[entry["query"]] = entry

    df["country"] = df["indicator"].map(lambda x: geo.get(x, {}).get("country", ""))
    df["country_code"] = df["indicator"].map(
        lambda x: geo.get(x, {}).get("countryCode", "")
    )
    df["city"] = df["indicator"].map(lambda x: geo.get(x, {}).get("city", ""))
    df["latitude"] = df["indicator"].map(
        lambda x: geo.get(x, {}).get("lat", float("nan"))
    )
    df["longitude"] = df["indicator"].map(
        lambda x: geo.get(x, {}).get("lon", float("nan"))
    )
    df["isp"] = df["indicator"].map(lambda x: geo.get(x, {}).get("isp", ""))
    return df


async def enrich_indicators(df: pd.DataFrame) -> pd.DataFrame:
    """Run reputation and GeoIP enrichment over an indicator frame."""
    if df.empty:
        return df

    # GeoIP first (keyless, always available).
    df = await _enrich_geoip(df)

    if config.ABUSEIPDB_API_KEY:
        headers = {
            "Key": config.ABUSEIPDB_API_KEY,
            "Accept": "application/json",
        }
        async with AsyncFetcher(config.ABUSEIPDB, headers=headers) as fetcher:
            df = await _enrich_abuseipdb(df, fetcher)
    else:
        logger.warning("AbuseIPDB: key not set — reputation scores left as NaN")

    return df


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
async def harvest_all() -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Concurrently harvest CVEs, KEV labels and enriched indicators.

    Returns
    -------
    (cves, kev, indicators):
        Three DataFrames ready for the analytics tier.
    """
    logger.info("Starting concurrent harvest of all sources")
    cves, kev, raw_indicators = await asyncio.gather(
        fetch_cves(),
        fetch_kev(),
        fetch_otx_indicators(),
    )
    indicators = await enrich_indicators(raw_indicators)
    logger.info(
        "Harvest complete: %d CVEs, %d KEV, %d indicators",
        len(cves),
        len(kev),
        len(indicators),
    )
    return cves, kev, indicators


def _persist(
    cves: pd.DataFrame, kev: pd.DataFrame, indicators: pd.DataFrame
) -> None:
    """Write harvested frames to parquet for downstream tiers."""
    cves.to_parquet(config.RAW_CVE_PATH, index=False)
    kev.to_parquet(config.DATA_DIR / "kev.parquet", index=False)
    indicators.to_parquet(config.INDICATORS_PATH, index=False)
    logger.info("Persisted raw artefacts to %s", config.DATA_DIR)


def main() -> None:
    """CLI entry point: harvest everything and persist to disk."""
    logging.basicConfig(level=config.LOG_LEVEL, format=config.LOG_FORMAT)
    cves, kev, indicators = asyncio.run(harvest_all())
    _persist(cves, kev, indicators)


if __name__ == "__main__":
    main()
