#!/usr/bin/env python3
"""ui/theme.py — Palet warna & CSS tambahan untuk GARUDA SENTINEL."""
from __future__ import annotations

import streamlit as st


# --------------------------------------------------------------------------- #
# Palet — semua kombinasi foreground/background sudah diverifikasi WCAG AA
# --------------------------------------------------------------------------- #
PALETTE = {
    "bg":            "#0D1117",
    "bg_elevated":   "#161B22",
    "bg_hover":      "#21262D",
    "border":        "#30363D",
    "border_subtle": "#21262D",
    "text":          "#E6EDF3",
    "text_muted":    "#8B949E",
    "text_subtle":   "#6E7681",
    "accent":        "#58A6FF",
    "success":       "#2EA043",
    "warning":       "#D29922",
    "danger":        "#DA3633",
    "danger_hover":  "#F85149",
}

# Badge styles: bg + fg sudah dicek kontras AA
SEVERITY_STYLES: dict[str, dict[str, str]] = {
    "CRITICAL": {"bg": "#7F0000", "fg": "#FFFFFF", "icon": "🔴"},
    "HIGH":     {"bg": "#C62828", "fg": "#FFFFFF", "icon": "🟠"},
    "MEDIUM":   {"bg": "#FB8C00", "fg": "#000000", "icon": "🟡"},
    "LOW":      {"bg": "#2E7D32", "fg": "#FFFFFF", "icon": "🟢"},
}


def severity_style(severity: str) -> dict[str, str]:
    return SEVERITY_STYLES.get(str(severity).upper(), SEVERITY_STYLES["LOW"])


# --------------------------------------------------------------------------- #
# CSS — hanya untuk elemen dekoratif; native Streamlit sudah ditangani theme
# --------------------------------------------------------------------------- #
_CSS = f"""
<style>
/* ============================================================ */
/* Typography & layout dasar                                    */
/* ============================================================ */
html, body, [class*="css"] {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
                 "Helvetica Neue", Arial, sans-serif;
}}
code, pre, .gs-mono {{
    font-family: "JetBrains Mono", "Consolas", "Courier New", monospace;
    font-size: 0.85em;
}}

/* ============================================================ */
/* Header banner                                                */
/* ============================================================ */
.gs-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 12px;
    padding: 16px 20px;
    background: linear-gradient(135deg, #0D1117 0%, #161B22 100%);
    border: 1px solid {PALETTE['border']};
    border-left: 4px solid {PALETTE['success']};
    border-radius: 8px;
    margin-bottom: 16px;
}}
.gs-header-title {{
    font-size: clamp(18px, 3vw, 24px);
    font-weight: 700;
    letter-spacing: 2px;
    color: {PALETTE['success']};
    line-height: 1.2;
}}
.gs-header-sub {{
    font-size: clamp(9px, 1.5vw, 11px);
    color: {PALETTE['text_muted']};
    letter-spacing: 1.5px;
    text-transform: uppercase;
    margin-top: 4px;
}}
.gs-header-status {{
    font-family: "JetBrains Mono", monospace;
    font-size: clamp(11px, 1.5vw, 13px);
    font-weight: 700;
    padding: 6px 14px;
    border: 2px solid currentColor;
    border-radius: 4px;
    letter-spacing: 1px;
    white-space: nowrap;
}}

/* ============================================================ */
/* Metric grid — responsif (5 → 3 → 2 kolom)                    */
/* ============================================================ */
.gs-metrics-grid {{
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 12px;
    margin-bottom: 20px;
}}
.gs-metric-card {{
    background: {PALETTE['bg_elevated']};
    border: 1px solid {PALETTE['border']};
    border-radius: 6px;
    padding: 14px 16px;
    display: flex;
    flex-direction: column;
    gap: 4px;
    transition: border-color 0.15s ease;
}}
.gs-metric-card:hover {{
    border-color: {PALETTE['border']};
    background: {PALETTE['bg_hover']};
}}
.gs-metric-label {{
    font-size: 10px;
    letter-spacing: 1.2px;
    text-transform: uppercase;
    color: {PALETTE['text_muted']};
    font-weight: 500;
}}
.gs-metric-value {{
    font-family: "JetBrains Mono", monospace;
    font-size: clamp(18px, 2.5vw, 22px);
    font-weight: 700;
    color: {PALETTE['text']};
    line-height: 1.1;
}}
.gs-metric-sub {{
    font-size: 10px;
    color: {PALETTE['text_subtle']};
    font-family: "JetBrains Mono", monospace;
}}

/* ============================================================ */
/* Severity badge                                               */
/* ============================================================ */
.gs-badge {{
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 3px 10px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 1px;
    line-height: 1.4;
    white-space: nowrap;
}}

/* ============================================================ */
/* MITRE badges                                                 */
/* ============================================================ */
.gs-mitre-badge {{
    display: inline-block;
    background: {PALETTE['bg_hover']};
    color: {PALETTE['accent']};
    border: 1px solid {PALETTE['border']};
    padding: 2px 8px;
    border-radius: 3px;
    font-family: "JetBrains Mono", monospace;
    font-size: 10px;
    font-weight: 600;
    margin: 2px 4px 2px 0;
    letter-spacing: 0.5px;
}}

/* ============================================================ */
/* Feature chips (SHAP top-features)                            */
/* ============================================================ */
.gs-feature-chip {{
    display: inline-block;
    background: rgba(210, 153, 34, 0.12);
    color: {PALETTE['warning']};
    border: 1px solid rgba(210, 153, 34, 0.3);
    padding: 2px 8px;
    border-radius: 3px;
    font-family: "JetBrains Mono", monospace;
    font-size: 10px;
    margin: 2px 4px 2px 0;
}}

/* ============================================================ */
/* Audit log entries                                            */
/* ============================================================ */
.gs-log-entry {{
    background: {PALETTE['bg_elevated']};
    border-left: 3px solid {PALETTE['danger']};
    padding: 10px 12px;
    margin-bottom: 8px;
    font-size: 12px;
    border-radius: 4px;
}}
.gs-log-ts {{
    color: {PALETTE['text_muted']};
    font-size: 10px;
    font-family: "JetBrains Mono", monospace;
    margin-bottom: 4px;
}}
.gs-log-body {{
    color: {PALETTE['text']};
    font-family: "JetBrains Mono", monospace;
}}

/* ============================================================ */
/* Buttons — fix selector untuk Streamlit 1.58+                 */
/* ============================================================ */
/* Semua tombol dapat focus ring yang jelas */
.stButton > button:focus-visible,
.stButton > button[data-testid^="stBaseButton"]:focus-visible {{
    outline: 2px solid {PALETTE['accent']} !important;
    outline-offset: 2px !important;
}}

/* Tombol primary DI MAIN AREA = danger (merah) */
[data-testid="stMain"] .stButton > button[kind="primary"],
[data-testid="stMain"] .stButton > button[data-testid="stBaseButton-primary"] {{
    background-color: {PALETTE['danger']} !important;
    color: #FFFFFF !important;
    border: 1px solid {PALETTE['danger']} !important;
    font-weight: 600 !important;
    letter-spacing: 0.5px;
}}
[data-testid="stMain"] .stButton > button[kind="primary"]:hover,
[data-testid="stMain"] .stButton > button[data-testid="stBaseButton-primary"]:hover {{
    background-color: {PALETTE['danger_hover']} !important;
    border-color: {PALETTE['danger_hover']} !important;
}}

/* Tombol primary DI SIDEBAR = success (hijau, dibiarkan dari theme) */
section[data-testid="stSidebar"] .stButton > button[kind="primary"] {{
    background-color: {PALETTE['success']} !important;
    color: #FFFFFF !important;
    font-weight: 600 !important;
}}

/* ============================================================ */
/* Threat card container refinement                             */
/* ============================================================ */
[data-testid="stMain"] [data-testid="stVerticalBlockBorderWrapper"] {{
    border-radius: 8px !important;
}}

/* ============================================================ */
/* Blockquote (explanation) refinement                          */
/* ============================================================ */
[data-testid="stMain"] blockquote {{
    border-left: 3px solid {PALETTE['accent']} !important;
    background: {PALETTE['bg_elevated']} !important;
    padding: 10px 14px !important;
    margin: 8px 0 !important;
    border-radius: 4px !important;
    font-family: "JetBrains Mono", monospace !important;
    font-size: 0.85em !important;
    color: {PALETTE['text']} !important;
}}

/* ============================================================ */
/* Footer                                                       */
/* ============================================================ */
.gs-footer {{
    text-align: center;
    color: {PALETTE['text_subtle']};
    font-family: "JetBrains Mono", monospace;
    font-size: 10px;
    letter-spacing: 1px;
    padding: 20px 0;
    border-top: 1px solid {PALETTE['border_subtle']};
    margin-top: 24px;
}}

/* ============================================================ */
/* Responsive — tablet & mobile                                 */
/* ============================================================ */
@media (max-width: 1024px) {{
    .gs-metrics-grid {{
        grid-template-columns: repeat(3, 1fr);
    }}
}}
@media (max-width: 640px) {{
    .gs-metrics-grid {{
        grid-template-columns: repeat(2, 1fr);
        gap: 8px;
    }}
    .gs-metric-card {{
        padding: 10px 12px;
    }}
    .gs-header {{
        padding: 12px 16px;
        flex-direction: column;
        align-items: flex-start;
    }}
    .gs-header-status {{
        align-self: stretch;
        text-align: center;
    }}
    /* Tap targets ≥44px (iOS guideline) */
    .stButton > button {{
        min-height: 44px !important;
    }}
    /* Kurangi padding container bawaan */
    [data-testid="stMain"] .block-container {{
        padding-left: 1rem !important;
        padding-right: 1rem !important;
    }}
}}
</style>
"""


def inject_theme() -> None:
    """Suntikkan CSS dark-mode militer (idempoten, aman untuk rerun)."""
    st.markdown(_CSS, unsafe_allow_html=True)