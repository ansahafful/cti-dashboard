"""Cyber Threat Intelligence & Predictive Exploitation Dashboard (Streamlit).

A dark-mode, executive-ready interface over the artefacts produced by
``run_pipeline.py``. Three pillars:

1. Predictive high-risk vulnerability watchlist (sortable / searchable).
2. Geographic threat-actor activity map (Plotly scatter-geo).
3. Attack-vector & severity distributions + disclosure volume trend.

Launch with::

    streamlit run app.py

The app reads pre-computed parquet artefacts so the UI stays responsive; it
never calls live APIs itself.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import streamlit as st

# --- Secrets hydration (must run before `import config`) ------------------- #
# On Streamlit Community Cloud, API keys are provided via the Secrets UI and
# exposed through ``st.secrets``. config.py reads them from the environment, so
# we copy any top-level string secrets into os.environ first. Wrapped in a
# try/except so local runs without a secrets.toml are unaffected.
try:
    for _key, _value in st.secrets.items():
        if isinstance(_value, str):
            os.environ.setdefault(_key, _value)
except Exception:  # pragma: no cover - no secrets file locally
    pass

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

import config

# --------------------------------------------------------------------------- #
# Page + theme setup
# --------------------------------------------------------------------------- #
T = config.THEME

st.set_page_config(
    page_title="CTI · Predictive Exploitation Dashboard",
    page_icon="🛰️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Inject the unified dark-mode aesthetic.
st.markdown(
    f"""
    <style>
        .stApp {{ background-color: {T['bg']}; color: {T['text']}; }}
        section[data-testid="stSidebar"] {{ background-color: {T['surface']}; }}
        h1, h2, h3, h4 {{ color: {T['text']}; }}
        div[data-testid="stMetric"] {{
            background-color: {T['surface']};
            border: 1px solid {T['surface_alt']};
            border-radius: 12px;
            padding: 16px;
        }}
        div[data-testid="stMetricValue"] {{ color: {T['accent']}; }}
        .stDataFrame {{ border: 1px solid {T['surface_alt']}; }}
    </style>
    """,
    unsafe_allow_html=True,
)


PLOTLY_LAYOUT = dict(
    paper_bgcolor=T["surface"],
    plot_bgcolor=T["surface"],
    font=dict(color=T["text"]),
    margin=dict(l=20, r=20, t=50, b=20),
)


# --------------------------------------------------------------------------- #
# Data loading (cached)
# --------------------------------------------------------------------------- #
@st.cache_resource(show_spinner="Bootstrapping dataset (first run)…")
def bootstrap_data() -> bool:
    """Ensure scored artefacts exist before the UI renders.

    Streamlit Community Cloud has an ephemeral filesystem and only runs
    ``app.py`` — the offline pipeline never executes there. So on first load
    (or after a cold restart) we generate the synthetic demo dataset and train
    the real model, guaranteeing the dashboard always has data to show.

    Cached as a resource so it runs at most once per server boot. Returns True
    when artefacts are present/created.
    """
    if Path(config.SCORED_CVE_PATH).exists():
        return True
    try:
        import generate_demo_data

        generate_demo_data.main()
    except Exception as exc:  # pragma: no cover - surfaced in the UI
        st.error(f"Failed to bootstrap demo data: {exc}")
        return False
    return Path(config.SCORED_CVE_PATH).exists()


@st.cache_data(show_spinner=False)
def load_scored_cves() -> pd.DataFrame:
    """Load the scored CVE watchlist, or an empty frame if not yet built."""
    if not Path(config.SCORED_CVE_PATH).exists():
        return pd.DataFrame()
    df = pd.read_parquet(config.SCORED_CVE_PATH)
    df["published_dt"] = pd.to_datetime(df["published"], errors="coerce", utc=True)
    return df


@st.cache_data(show_spinner=False)
def load_indicators() -> pd.DataFrame:
    if not Path(config.INDICATORS_PATH).exists():
        return pd.DataFrame()
    return pd.read_parquet(config.INDICATORS_PATH)


@st.cache_data(show_spinner=False)
def load_metrics() -> dict:
    if not Path(config.METRICS_PATH).exists():
        return {}
    return json.loads(Path(config.METRICS_PATH).read_text())


# --------------------------------------------------------------------------- #
# Chart builders
# --------------------------------------------------------------------------- #
def severity_donut(df: pd.DataFrame) -> go.Figure:
    """Donut chart of CVE counts by severity band."""
    counts = (
        df["cvss_severity"]
        .value_counts()
        .reindex(config.SEVERITY_ORDER)
        .dropna()
    )
    fig = go.Figure(
        go.Pie(
            labels=counts.index,
            values=counts.values,
            hole=0.6,
            marker=dict(
                colors=[config.SEVERITY_COLORS.get(s, T["muted"]) for s in counts.index]
            ),
            textinfo="label+percent",
        )
    )
    fig.update_layout(title="Severity Distribution", **PLOTLY_LAYOUT)
    return fig


def attack_vector_bar(df: pd.DataFrame) -> go.Figure:
    """Horizontal bar of CVE counts by CVSS attack vector."""
    counts = df["attack_vector"].value_counts().sort_values()
    fig = go.Figure(
        go.Bar(
            x=counts.values,
            y=counts.index,
            orientation="h",
            marker=dict(color=T["accent"]),
        )
    )
    fig.update_layout(
        title="Attack Vector Breakdown",
        xaxis_title="CVE count",
        **PLOTLY_LAYOUT,
    )
    return fig


def complexity_bar(df: pd.DataFrame) -> go.Figure:
    """Grouped bar of attack complexity split by high-risk flag."""
    grouped = (
        df.groupby(["attack_complexity", "high_risk"]).size().reset_index(name="count")
    )
    fig = px.bar(
        grouped,
        x="attack_complexity",
        y="count",
        color="high_risk",
        barmode="group",
        color_discrete_map={True: T["danger"], False: T["accent_alt"]},
    )
    fig.update_layout(title="Attack Complexity vs. Predicted Risk", **PLOTLY_LAYOUT)
    return fig


def disclosure_trend(df: pd.DataFrame) -> go.Figure:
    """Line chart of weekly CVE disclosure volume."""
    valid = df.dropna(subset=["published_dt"])
    if valid.empty:
        return go.Figure(layout=PLOTLY_LAYOUT)
    weekly = (
        valid.set_index("published_dt")
        .resample("W")
        .size()
        .reset_index(name="count")
    )
    fig = px.area(weekly, x="published_dt", y="count")
    fig.update_traces(line_color=T["accent"], fillcolor="rgba(56,189,248,0.2)")
    fig.update_layout(
        title="Disclosure Volume Trend (weekly)",
        xaxis_title="",
        yaxis_title="CVEs published",
        **PLOTLY_LAYOUT,
    )
    return fig


def threat_map(df: pd.DataFrame) -> go.Figure:
    """Scatter-geo map of malicious indicator IPs."""
    geo = df.dropna(subset=["latitude", "longitude"])
    if geo.empty:
        fig = go.Figure(layout=PLOTLY_LAYOUT)
        fig.update_layout(title="Threat Actor Activity (no geolocated indicators)")
        return fig

    size = geo["total_reports"].fillna(1).clip(lower=1)
    fig = px.scatter_geo(
        geo,
        lat="latitude",
        lon="longitude",
        color="threat_score",
        size=size,
        hover_name="indicator",
        hover_data={
            "country": True,
            "isp": True,
            "threat_score": True,
            "latitude": False,
            "longitude": False,
        },
        color_continuous_scale=["#38bdf8", "#fbbf24", "#f43f5e"],
        projection="natural earth",
    )
    fig.update_geos(
        bgcolor=T["surface"],
        landcolor=T["surface_alt"],
        oceancolor=T["bg"],
        showocean=True,
        showcountries=True,
        countrycolor=T["muted"],
    )
    fig.update_layout(title="Geographic Threat Actor Activity", **PLOTLY_LAYOUT)
    return fig


# --------------------------------------------------------------------------- #
# Sidebar
# --------------------------------------------------------------------------- #
def render_sidebar(cves: pd.DataFrame, metrics: dict) -> dict:
    """Render sidebar controls and return the selected filter state."""
    st.sidebar.title("🛰️ CTI Console")
    st.sidebar.caption("Predictive Exploitation Dashboard")

    if metrics:
        st.sidebar.markdown("### Model performance")
        st.sidebar.metric("Recall (↓ false negatives)", metrics.get("recall", "—"))
        st.sidebar.metric("Precision", metrics.get("precision", "—"))
        st.sidebar.metric("PR-AUC", metrics.get("pr_auc", "—"))
        st.sidebar.caption(
            f"{metrics.get('algorithm', 'model')} · "
            f"threshold {metrics.get('decision_threshold', '—')} · "
            f"FN={metrics.get('false_negatives', '—')}"
        )
    else:
        st.sidebar.warning("No trained model found. Run `python run_pipeline.py`.")

    st.sidebar.markdown("### Filters")
    min_prob = st.sidebar.slider(
        "Min. exploitation probability", 0.0, 1.0, 0.0, 0.05
    )
    severities = st.sidebar.multiselect(
        "Severity",
        options=config.SEVERITY_ORDER,
        default=config.SEVERITY_ORDER,
    )
    search = st.sidebar.text_input("Search (CVE id / keyword / vendor)")
    return {"min_prob": min_prob, "severities": severities, "search": search}


def apply_filters(df: pd.DataFrame, state: dict) -> pd.DataFrame:
    """Filter the CVE frame according to sidebar state."""
    out = df[df["exploit_probability"] >= state["min_prob"]]
    if state["severities"]:
        out = out[out["cvss_severity"].isin(state["severities"])]
    term = state["search"].strip().lower()
    if term:
        mask = (
            out["cve_id"].str.lower().str.contains(term, na=False)
            | out["description"].str.lower().str.contains(term, na=False)
            | out["cpe_vendors"].astype(str).str.lower().str.contains(term, na=False)
        )
        out = out[mask]
    return out


# --------------------------------------------------------------------------- #
# Main layout
# --------------------------------------------------------------------------- #
def main() -> None:
    bootstrap_data()
    cves = load_scored_cves()
    indicators = load_indicators()
    metrics = load_metrics()

    st.title("Cyber Threat Intelligence & Predictive Exploitation")

    if cves.empty:
        st.error(
            "No scored data found. Build the dataset first:\n\n"
            "```bash\npython run_pipeline.py\n```"
        )
        st.stop()

    state = render_sidebar(cves, metrics)
    filtered = apply_filters(cves, state)

    # --- KPI row -------------------------------------------------------- #
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("CVEs ingested", f"{len(cves):,}")
    c2.metric("High-risk (predicted)", f"{int(cves['high_risk'].sum()):,}")
    c3.metric("Critical severity", f"{int((cves['cvss_severity'] == 'CRITICAL').sum()):,}")
    c4.metric("Geolocated IOCs", f"{len(indicators.dropna(subset=['latitude'])) if not indicators.empty else 0:,}")

    tab_watch, tab_map, tab_dist = st.tabs(
        ["🎯 High-Risk Watchlist", "🌍 Threat Map", "📊 Distributions"]
    )

    # --- Tab 1: predictive watchlist ----------------------------------- #
    with tab_watch:
        st.subheader("Predictive High-Risk Vulnerability Watchlist")
        st.caption(
            f"{len(filtered):,} CVEs match filters · sorted by ML exploitation likelihood"
        )
        display = filtered.assign(
            exploit_probability=(filtered["exploit_probability"] * 100).round(1)
        )[
            [
                "cve_id",
                "exploit_probability",
                "cvss_score",
                "cvss_severity",
                "attack_vector",
                "high_risk",
                "published",
                "description",
            ]
        ].rename(columns={"exploit_probability": "exploit_%"})

        st.dataframe(
            display,
            use_container_width=True,
            height=520,
            column_config={
                "exploit_%": st.column_config.ProgressColumn(
                    "Exploit likelihood",
                    min_value=0,
                    max_value=100,
                    format="%.1f%%",
                ),
                "description": st.column_config.TextColumn(width="large"),
            },
            hide_index=True,
        )

    # --- Tab 2: geographic map ----------------------------------------- #
    with tab_map:
        st.subheader("Geographic Threat Actor Activity")
        if indicators.empty:
            st.info(
                "No enriched indicators available. Set `OTX_API_KEY` "
                "(and optionally `ABUSEIPDB_API_KEY`) and re-run the pipeline."
            )
        else:
            st.plotly_chart(threat_map(indicators), use_container_width=True)
            top = indicators.sort_values("threat_score", ascending=False).head(15)
            st.dataframe(
                top[
                    ["indicator", "country", "city", "isp", "threat_score", "total_reports"]
                ],
                use_container_width=True,
                hide_index=True,
            )

    # --- Tab 3: distributions ------------------------------------------ #
    with tab_dist:
        st.subheader("Attack Vector & Severity Analytics")
        col_a, col_b = st.columns(2)
        col_a.plotly_chart(severity_donut(filtered), use_container_width=True)
        col_b.plotly_chart(attack_vector_bar(filtered), use_container_width=True)
        st.plotly_chart(complexity_bar(filtered), use_container_width=True)
        st.plotly_chart(disclosure_trend(filtered), use_container_width=True)


if __name__ == "__main__":
    main()
