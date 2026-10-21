#!/usr/bin/env python3
"""
app.py
======
GARUDA SENTINEL — Local Tactical Interface (Streamlit SOC).

Jalankan:
    python -m streamlit run app.py
"""
from __future__ import annotations

import logging
import time
from pathlib import Path

import streamlit as st

from engine.detectors import DetectorConfig
from engine.pipeline import GarudaPipeline, PipelineConfig
from ui.components import (
    render_footer,
    render_header,
    render_metrics,
    render_recent_actions,
    render_system_panel,
    render_threat_card,
)
from ui.theme import inject_theme


# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
)
LOGGER = logging.getLogger("garuda.app")


# --------------------------------------------------------------------------- #
# Konstanta
# --------------------------------------------------------------------------- #
DEFAULT_MODEL_DIR = "models"
DEFAULT_STREAM_CSV = "data/processed/simulation_stream.csv"
DEFAULT_DELAY_MS = 200
SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


# --------------------------------------------------------------------------- #
# Page config
# --------------------------------------------------------------------------- #
st.set_page_config(
    page_title="GARUDA SENTINEL · Tactical SOC",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded",
)
inject_theme()


# --------------------------------------------------------------------------- #
# Pipeline singleton
# --------------------------------------------------------------------------- #
@st.cache_resource(show_spinner="Menginisialisasi GARUDA SENTINEL...")
def _build_pipeline(model_dir: str, stream_csv: str, delay_ms: int) -> GarudaPipeline:
    cfg = PipelineConfig(
        model_dir=Path(model_dir),
        stream_csv=Path(stream_csv),
        delay_ms=delay_ms,
        detector_config=DetectorConfig(
            model_dir=Path(model_dir),
            strict_ips=False,
            xgb_threshold=0.5,
            enable_layer2=True,
            explain_on_attack=True,
            iso_threshold_override=0.037,
        ),
    )
    return GarudaPipeline.build(cfg)


# --------------------------------------------------------------------------- #
# Session state
# --------------------------------------------------------------------------- #
def _init_state() -> None:
    defaults = {
        "auto_refresh": True,
        "refresh_interval_s": 2,
        "severity_filter": "SEMUA",
        "operator_id": "SOC_OFFICER_01",
        "auto_started": False,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


# --------------------------------------------------------------------------- #
# Sidebar
# --------------------------------------------------------------------------- #
def _render_sidebar(pipeline: GarudaPipeline) -> None:
    with st.sidebar:
        # ---- Status ----
        st.markdown("### ⚙️ KONTROL SISTEM")
        if pipeline.is_running:
            if pipeline.is_paused:
                st.warning("⏸ **PAUSED**")
            else:
                st.success("🟢 **OPERASIONAL**")
        else:
            st.error("🔴 **TERHENTI**")

        # ---- Start/Stop ----
        c1, c2 = st.columns(2)
        with c1:
            if not pipeline.is_running:
                if st.button("▶ MULAI", use_container_width=True, type="primary"):
                    pipeline.start()
                    st.rerun()
            else:
                if st.button("⏹ STOP", use_container_width=True):
                    pipeline.stop()
                    st.rerun()
        with c2:
            if pipeline.is_running:
                if pipeline.is_paused:
                    if st.button("▶ LANJUT", use_container_width=True, type="primary"):
                        pipeline.resume()
                        st.rerun()
                else:
                    if st.button("⏸ PAUSE", use_container_width=True):
                        pipeline.pause()
                        st.rerun()
            else:
                st.button("⏸ PAUSE", use_container_width=True, disabled=True)

        # ---- Operator ----
        with st.expander("👤 Operator", expanded=False):
            st.text_input("Operator ID", key="operator_id", max_chars=32)

        # ---- Refresh ----
        with st.expander("📊 Refresh", expanded=False):
            st.toggle("Auto-refresh", key="auto_refresh")
            st.slider("Interval (detik)", 1, 10, key="refresh_interval_s")
            if st.button("🔄 Refresh Sekarang", use_container_width=True):
                st.rerun()

        # ---- Filter ----
        st.selectbox(
            "🔍 Severity minimum",
            ["SEMUA", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
            key="severity_filter",
        )

        # ---- Reset ----
        st.divider()
        with st.expander("🧨 EMERGENCY", expanded=False):
            if st.button("🔁 Reset Sistem", use_container_width=True):
                try:
                    pipeline.stop()
                finally:
                    st.cache_resource.clear()
                    st.session_state["auto_started"] = False
                    st.rerun()

        # ---- Brand ----
        st.divider()
        st.caption("**GARUDA SENTINEL** v1.0")
        st.caption("Kartika Cyber Hackathon 2026")
        st.caption("TNI AD · Air-Gapped Edge SOC")


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _filter_by_severity(cards: list[dict], minimum: str) -> list[dict]:
    if minimum == "SEMUA":
        return cards
    try:
        cutoff = SEVERITY_ORDER.index(minimum)
    except ValueError:
        return cards
    out = []
    for c in cards:
        try:
            if SEVERITY_ORDER.index(c["severity"]) >= cutoff:
                out.append(c)
        except ValueError:
            out.append(c)
    return out


def _handle_action(pipeline: GarudaPipeline, result: dict, card: dict) -> None:
    action = result["action"]
    cid = result["card_id"]
    operator = st.session_state["operator_id"]
    if action == "ISOLATE":
        pipeline.isolate(cid, operator=operator)
        st.toast(f"🚨 Aset {card['dst_ip']} DIISOLASI oleh {operator}", icon="🚨")
    elif action == "ACK":
        pipeline.acknowledge(cid, operator=operator)
        st.toast(f"✓ Kartu {cid} di-acknowledge", icon="✓")
    st.rerun()


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main() -> None:
    _init_state()

    try:
        pipeline = _build_pipeline(
            DEFAULT_MODEL_DIR, DEFAULT_STREAM_CSV, DEFAULT_DELAY_MS
        )
    except Exception as exc:  # noqa: BLE001
        st.error(f"❌ Gagal inisialisasi pipeline: {exc}")
        st.info(
            "Pastikan artefak model tersedia di `models/` dan "
            "`data/processed/simulation_stream.csv` sudah dibuat."
        )
        with st.expander("Detail error"):
            st.exception(exc)
        return

    if not st.session_state["auto_started"]:
        if not pipeline.is_running:
            pipeline.start()
        st.session_state["auto_started"] = True

    _render_sidebar(pipeline)

    # ---- Dashboard ----
    snapshot = pipeline.snapshot()
    render_header(snapshot)
    render_metrics(snapshot)

    col_main, col_side = st.columns([2.5, 1], gap="medium")

    with col_main:
        st.markdown("#### 🚨 THREAT CARDS")
        active = _filter_by_severity(
            pipeline.get_active_cards(),
            st.session_state["severity_filter"],
        )
        if not active:
            st.info("✅ Tidak ada ancaman aktif. Sistem dalam kondisi siaga penuh.")
        else:
            for card in active:
                result = render_threat_card(card, key_prefix="live")
                if result:
                    _handle_action(pipeline, result, card)

    with col_side:
        render_system_panel(snapshot)
        st.divider()
        render_recent_actions(snapshot["recent_actions"])

    render_footer()

    # ---- Auto-refresh ----
    if st.session_state["auto_refresh"] and pipeline.is_running:
        time.sleep(st.session_state["refresh_interval_s"])
        st.rerun()


if __name__ == "__main__":
    main()