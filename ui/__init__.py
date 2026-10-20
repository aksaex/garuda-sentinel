"""GARUDA SENTINEL — UI package."""
from .theme import PALETTE, inject_theme, severity_color
from .components import (
    render_header,
    render_metrics,
    render_threat_card,
    render_system_panel,
    render_recent_actions,
    render_footer,
)

__all__ = [
    "PALETTE", "inject_theme", "severity_color",
    "render_header", "render_metrics", "render_threat_card",
    "render_system_panel", "render_recent_actions", "render_footer",
]