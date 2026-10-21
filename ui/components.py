#!/usr/bin/env python3
"""ui/components.py — Komponen visual GARUDA SENTINEL."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

import streamlit as st

from ui.theme import PALETTE, severity_style


# --------------------------------------------------------------------------- #
# Header banner
# --------------------------------------------------------------------------- #
def render_header(snapshot: Dict[str, Any]) -> None:
    running = snapshot["running"]
    paused = snapshot["paused"]
    if paused:
        status, color, dot = "PAUSED", PALETTE["warning"], "⏸"
    elif running:
        status, color, dot = "OPERASIONAL", PALETTE["success"], "●"
    else:
        status, color, dot = "TERHENTI", PALETTE["danger"], "●"

    st.markdown(
        f"""
        <div class="gs-header">
          <div>
            <div class="gs-header-title">🛡 GARUDA SENTINEL</div>
            <div class="gs-header-sub">
              Tactical AI Defense · TNI AD · Kartika Cyber Hackathon 2026
            </div>
          </div>
          <div class="gs-header-status" style="color:{color};">{dot} {status}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# --------------------------------------------------------------------------- #
# Metrics — custom HTML grid (responsif 5→3→2 kolom)
# --------------------------------------------------------------------------- #
def render_metrics(snapshot: Dict[str, Any]) -> None:
    stats = snapshot["stats"]
    triage = snapshot["triage"]
    cards = [
        ("📊 Throughput", f"{snapshot['throughput_pps']:.1f}", "pkt/s"),
        ("📦 Paket", f"{stats['records_processed']:,}", ""),
        ("⚡ Alert", f"{stats['alerts_generated']:,}",
         f"L1:{stats['alerts_l1']} · L2:{stats['alerts_l2']}"),
        ("🚨 Kartu Aktif", str(triage["active_cards"]), ""),
        ("🛡 Diisolasi", str(triage["isolated_cards"]), ""),
    ]
    html = '<div class="gs-metrics-grid">'
    for label, value, sub in cards:
        html += (
            f'<div class="gs-metric-card">'
            f'<div class="gs-metric-label">{label}</div>'
            f'<div class="gs-metric-value">{value}</div>'
            f'<div class="gs-metric-sub">{sub or "&nbsp;"}</div>'
            f'</div>'
        )
    html += '</div>'
    st.markdown(html, unsafe_allow_html=True)


# --------------------------------------------------------------------------- #
# Threat Card
# --------------------------------------------------------------------------- #
def render_threat_card(
    card: Dict[str, Any], key_prefix: str
) -> Optional[Dict[str, str]]:
    """
    Render satu Threat Card. Return aksi bila tombol ditekan:
        {"action": "ISOLATE" | "ACK", "card_id": ...}
    """
    severity = card["severity"]
    style = severity_style(severity)

    with st.container(border=True):
        # ---- Header row: badge + asset | count ----
        c1, c2 = st.columns([3, 1])
        with c1:
            st.markdown(
                f'<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">'
                f'<span class="gs-badge" style="background:{style["bg"]};color:{style["fg"]};">'
                f'{style["icon"]} {severity}</span>'
                f'<span style="font-weight:600;color:{PALETTE["text"]};">{card["dst_asset"]}</span>'
                f'<code style="font-size:0.8em;color:{PALETTE["text_muted"]};">{card["dst_ip"]}</code>'
                f'</div>',
                unsafe_allow_html=True,
            )
        with c2:
            st.markdown(
                f'<div style="text-align:right;line-height:1.2;">'
                f'<div class="gs-mono" style="font-size:1.4em;font-weight:700;color:{PALETTE["accent"]};">'
                f'{card["alert_count"]}×</div>'
                f'<div style="font-size:0.7em;color:{PALETTE["text_muted"]};">'
                f'{card["duration_s"]}s · {card["unique_src_count"]} src</div>'
                f'</div>',
                unsafe_allow_html=True,
            )

        # ---- MITRE badges ----
        mitre = card.get("mitre_techniques", [])
        if mitre:
            badges = "".join(
                f'<span class="gs-mitre-badge" title="{t.get("name", "")} · '
                f'{t.get("tactic", "")}">{t["id"]}</span>'
                for t in mitre[:6]
            )
            st.markdown(f"<div>{badges}</div>", unsafe_allow_html=True)

        # ---- Kategori anomali (jika ada) ----
        cats = card.get("anomaly_categories", {})
        if cats:
            cat_str = " · ".join(f"{k} ×{v}" for k, v in cats.items())
            st.caption(f"Kategori: {cat_str}")

        # ---- Explanation (blockquote native) ----
        samples = card.get("sample_alerts", [])
        last_alert = samples[-1] if samples else None
        explanation = ""
        if last_alert:
            explanation = last_alert.get("features", {}).get("explanation", "") or ""
        if not explanation:
            explanation = "Anomali terdeteksi; menunggu analisis lanjutan dari pipeline."
        st.markdown(f"> {explanation}")

        # ---- Top features (SHAP) ----
        if last_alert:
            top_feats = last_alert.get("features", {}).get("top_features", {}) or {}
            if top_feats:
                chips = "".join(
                    f'<span class="gs-feature-chip">{name} = {value:+.4f}</span>'
                    for name, value in list(top_feats.items())[:3]
                )
                st.markdown(f"<div>{chips}</div>", unsafe_allow_html=True)

        # ---- Action buttons ----
        b1, b2 = st.columns(2)
        action: Optional[Dict[str, str]] = None
        with b1:
            if st.button(
                "🚨 ISOLASI ASET",
                key=f"{key_prefix}_iso_{card['card_id']}",
                type="primary",
                use_container_width=True,
            ):
                action = {"action": "ISOLATE", "card_id": card["card_id"]}
        with b2:
            if st.button(
                "✓ ACK",
                key=f"{key_prefix}_ack_{card['card_id']}",
                use_container_width=True,
            ):
                action = {"action": "ACK", "card_id": card["card_id"]}
        return action


# --------------------------------------------------------------------------- #
# System panel (sidebar kanan)
# --------------------------------------------------------------------------- #
def render_system_panel(snapshot: Dict[str, Any]) -> None:
    st.markdown("#### 📡 STATUS SISTEM")
    stats = snapshot["stats"]
    triage = snapshot["triage"]
    duration = snapshot["duration_s"]
    duration_str = f"{int(duration // 60)}m {int(duration % 60)}s"

    rows = [
        ("Uptime", duration_str),
        ("Throughput", f"{snapshot['throughput_pps']:.2f} pkt/s"),
        ("Total alert", f"{stats['alerts_generated']:,}"),
        ("Kartu dibuat", str(triage["total_cards_created"])),
        ("Auto-close", str(triage["auto_closed_cards"])),
        ("Aset terlacak", str(triage["tracked_assets"])),
        ("Error", str(stats["errors"])),
    ]
    for label, value in rows:
        st.markdown(
            f'<div style="display:flex;justify-content:space-between;'
            f'padding:6px 0;border-bottom:1px solid {PALETTE["border_subtle"]};">'
            f'<span style="color:{PALETTE["text_muted"]};font-size:0.75em;'
            f'letter-spacing:0.5px;text-transform:uppercase;">{label}</span>'
            f'<span class="gs-mono" style="font-size:0.85em;'
            f'color:{PALETTE["text"]};">{value}</span>'
            f'</div>',
            unsafe_allow_html=True,
        )


# --------------------------------------------------------------------------- #
# Recent actions (audit log)
# --------------------------------------------------------------------------- #
def render_recent_actions(actions: List[Dict[str, Any]]) -> None:
    st.markdown("#### 🧾 AUDIT LOG")
    if not actions:
        st.caption("Belum ada aksi isolasi.")
        return

    for a in reversed(actions):
        ts = datetime.fromtimestamp(a["ts"]).strftime("%H:%M:%S")
        st.markdown(
            f'<div class="gs-log-entry">'
            f'<div class="gs-log-ts">{ts} · {a.get("operator", "?")}</div>'
            f'<div class="gs-log-body">🚨 <b style="color:{PALETTE["danger"]};">ISOLASI</b> '
            f'· {a["dst_asset"]}</div>'
            f'<div style="color:{PALETTE["text_muted"]};font-size:0.7em;'
            f'font-family:monospace;">{a["dst_ip"]} · sev={a["severity"]} · card={a["card_id"]}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )


# --------------------------------------------------------------------------- #
# Footer
# --------------------------------------------------------------------------- #
def render_footer() -> None:
    st.markdown(
        '<div class="gs-footer">GARUDA SENTINEL v1.0 · '
        'XGBoost L1 + Isolation Forest L2 + SHAP Explainer · AIR-GAPPED MODE</div>',
        unsafe_allow_html=True,
    )