"""GARUDA SENTINEL — UI package."""
from .theme import PALETTE, SEVERITY_STYLES, inject_theme, severity_style
from .components import (
    render_footer,
    render_header,
    render_metrics,
    render_recent_actions,
    render_system_panel,
    render_threat_card,
)

__all__ = [
    "PALETTE",
    "SEVERITY_STYLES",
    "inject_theme",
    "severity_style",
    "render_footer",
    "render_header",
    "render_metrics",
    "render_recent_actions",
    "render_system_panel",
    "render_threat_card",
]