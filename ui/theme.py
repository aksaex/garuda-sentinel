#!/usr/bin/env python3
"""ui/theme.py — Palet warna & CSS injeksi untuk GARUDA SENTINEL."""
from __future__ import annotations

import streamlit as st


PALETTE: dict[str, str] = {
    "bg":           "#0A0E14",
    "bg_card":      "#111820",
    "bg_card_alt":  "#0D1117",
    "border":       "#1F2A36",
    "text":         "#E6EDF3",
    "text_muted":   "#8B949E",
    "success":      "#00C853",
    "warning":      "#FFB300",
    "danger":       "#FF1744",
    "critical":     "#D50000",
    "medium":       "#FF6D00",
    "low":          "#FFB300",
    "accent":       "#00E5FF",
    "header_bg":    "#0D1117",
}


SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": PALETTE["critical"],
    "HIGH":     PALETTE["danger"],
    "MEDIUM":   PALETTE["medium"],
    "LOW":      PALETTE["low"],
}


def severity_color(severity: str) -> str:
    return SEVERITY_COLORS.get(str(severity).upper(), PALETTE["warning"])


_CSS = f"""
<style>
  /* ---------- Global ---------- */
  .stApp {{
      background-color: {PALETTE['bg']};
      color: {PALETTE['text']};
      font-family: 'Inter', 'Segoe UI', sans-serif;
  }}
  section[data-testid="stSidebar"] {{
      background-color: {PALETTE['header_bg']};
      border-right: 1px solid {PALETTE['border']};
  }}
  h1, h2, h3, h4, h5 {{ color: {PALETTE['text']}; }}

  /* ---------- Header ---------- */
  .gs-header {{
      background: linear-gradient(90deg, {PALETTE['header_bg']} 0%, {PALETTE['bg_card']} 100%);
      border-left: 4px solid {PALETTE['success']};
      padding: 16px 24px;
      border-radius: 6px;
      margin-bottom: 18px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
  }}
  .gs-title {{
      font-family: 'JetBrains Mono', 'Consolas', monospace;
      font-size: 26px;
      font-weight: 700;
      color: {PALETTE['success']};
      letter-spacing: 3px;
  }}
  .gs-subtitle {{
      color: {PALETTE['text_muted']};
      font-size: 10px;
      letter-spacing: 2px;
      text-transform: uppercase;
      margin-top: 4px;
  }}
  .gs-status {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 13px;
      font-weight: 600;
      padding: 4px 12px;
      border: 1px solid currentColor;
      border-radius: 3px;
  }}

  /* ---------- Metric card ---------- */
  .gs-metric {{
      background: {PALETTE['bg_card']};
      border: 1px solid {PALETTE['border']};
      border-radius: 6px;
      padding: 12px 16px;
      text-align: left;
  }}
  .gs-metric-label {{
      color: {PALETTE['text_muted']};
      font-size: 10px;
      letter-spacing: 1.5px;
      text-transform: uppercase;
  }}
  .gs-metric-value {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 22px;
      font-weight: 700;
      color: {PALETTE['text']};
      margin-top: 4px;
  }}

  /* ---------- Threat Card ---------- */
  .gs-sev {{
      display: inline-block;
      padding: 2px 10px;
      color: #fff;
      font-weight: 700;
      font-size: 10px;
      border-radius: 3px;
      letter-spacing: 1.5px;
      margin-right: 10px;
  }}
  .gs-asset {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 14px;
      color: {PALETTE['text']};
  }}
  .gs-card-count {{
      text-align: right;
      font-family: 'JetBrains Mono', monospace;
      font-size: 18px;
      color: {PALETTE['accent']};
      line-height: 1.2;
  }}
  .gs-card-count small {{
      color: {PALETTE['text_muted']};
      font-size: 10px;
  }}
  .gs-card-meta {{
      color: {PALETTE['text_muted']};
      font-size: 11px;
      font-family: 'JetBrains Mono', monospace;
      margin: 4px 0 8px 0;
  }}
  .gs-explanation {{
      background: {PALETTE['bg_card_alt']};
      border-left: 3px solid {PALETTE['accent']};
      padding: 10px 14px;
      font-size: 12px;
      font-family: 'JetBrains Mono', monospace;
      line-height: 1.55;
      color: {PALETTE['text']};
      margin: 8px 0;
      border-radius: 3px;
  }}
  .gs-mitre {{
      display: inline-block;
      background: {PALETTE['border']};
      color: {PALETTE['accent']};
      padding: 2px 8px;
      border-radius: 3px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 10px;
      margin-right: 4px;
      margin-bottom: 2px;
      border: 1px solid {PALETTE['accent']}33;
      letter-spacing: 0.5px;
  }}
  .gs-feat {{
      display: inline-block;
      background: {PALETTE['border']};
      color: {PALETTE['warning']};
      padding: 1px 8px;
      border-radius: 2px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 10px;
      margin-right: 4px;
      margin-top: 2px;
  }}

  /* ---------- Action log ---------- */
  .gs-log-entry {{
      background: {PALETTE['bg_card_alt']};
      border-left: 2px solid {PALETTE['danger']};
      padding: 8px 10px;
      margin-bottom: 6px;
      font-size: 11px;
      font-family: 'JetBrains Mono', monospace;
      border-radius: 2px;
  }}
  .gs-log-ts {{
      color: {PALETTE['text_muted']};
      font-size: 10px;
  }}

  /* ---------- Footer ---------- */
  .gs-footer {{
      color: {PALETTE['text_muted']};
      font-size: 10px;
      text-align: center;
      padding: 12px;
      border-top: 1px solid {PALETTE['border']};
      margin-top: 20px;
      font-family: 'JetBrains Mono', monospace;
      letter-spacing: 1px;
  }}

  /* ---------- Button primary override ---------- */
  .stButton > button[kind="primary"] {{
      background: {PALETTE['danger']};
      color: #fff;
      border: none;
      font-weight: 700;
      letter-spacing: 1px;
  }}
  .stButton > button[kind="primary"]:hover {{
      background: {PALETTE['critical']};
  }}
</style>
"""


def inject_theme() -> None:
    """Suntikkan CSS dark-mode militer ke halaman Streamlit."""
    st.markdown(_CSS, unsafe_allow_html=True)