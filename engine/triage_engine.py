#!/usr/bin/env python3
"""
engine/triage_engine.py
=======================
Contextual Triage Engine untuk GARUDA SENTINEL.

Mengubah banjir alarm per-paket menjadi Threat Card teragregasi
per aset (dst_ip) dalam sliding window, dengan mapping ke
MITRE ATT&CK for ICS.

Thread-safe: seluruh mutasi state dilindungi RLock.
"""
from __future__ import annotations

import logging
import threading
import time
import uuid
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Any, Callable, Deque, Dict, List, Optional

LOGGER = logging.getLogger("garuda.triage")

# --------------------------------------------------------------------------- #
# Severity
# --------------------------------------------------------------------------- #
SEVERITY_RANK: Dict[str, int] = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
RANK_SEVERITY: Dict[int, str] = {v: k for k, v in SEVERITY_RANK.items()}

# --------------------------------------------------------------------------- #
# MITRE ATT&CK for ICS — subset relevan untuk trafik jaringan RT-IoT2022
# --------------------------------------------------------------------------- #
MITRE_ICS_TECHNIQUES: Dict[str, Dict[str, str]] = {
    "T0800": {"name": "Activate Firmware Update Mode", "tactic": "Inhibit Response Function"},
    "T0801": {"name": "Monitor Process State", "tactic": "Collection"},
    "T0811": {"name": "Data from Information Repositories", "tactic": "Collection"},
    "T0812": {"name": "Default Credentials", "tactic": "Lateral Movement"},
    "T0813": {"name": "Denial of Control", "tactic": "Impact"},
    "T0814": {"name": "Denial of Service", "tactic": "Impact"},
    "T0815": {"name": "Denial of View", "tactic": "Impact"},
    "T0816": {"name": "Device Restart/Shutdown", "tactic": "Inhibit Response Function"},
    "T0830": {"name": "Adversary-in-the-Middle", "tactic": "Collection"},
    "T0831": {"name": "Manipulation of Control", "tactic": "Impair Process Control"},
    "T0832": {"name": "Manipulation of View", "tactic": "Impair Process Control"},
    "T0836": {"name": "Modify Parameter", "tactic": "Impair Process Control"},
    "T0842": {"name": "Network Sniffing", "tactic": "Discovery"},
    "T0843": {"name": "Program Download", "tactic": "Lateral Movement"},
    "T0846": {"name": "Remote System Discovery", "tactic": "Discovery"},
    "T0855": {"name": "Unauthorized Command Message", "tactic": "Impair Process Control"},
    "T0856": {"name": "Spoof Reporting Message", "tactic": "Impair Process Control"},
    "T0859": {"name": "Valid Accounts", "tactic": "Lateral Movement"},
    "T0869": {"name": "Standard Application Layer Protocol", "tactic": "Command and Control"},
    "T0879": {"name": "Damage to Property", "tactic": "Impact"},
    "T0881": {"name": "Service Stop", "tactic": "Inhibit Response Function"},
    "T0882": {"name": "Theft of Operational Information", "tactic": "Collection"},
    "T0885": {"name": "Commonly Used Port", "tactic": "Command and Control"},
    "T0886": {"name": "Remote Services", "tactic": "Lateral Movement"},
    "T0888": {"name": "Remote System Information Discovery", "tactic": "Discovery"},
    "T0890": {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    "T0891": {"name": "Hardcoded Credentials", "tactic": "Lateral Movement"},
}

ANOMALY_TO_MITRE: Dict[str, List[str]] = {
    "dos": ["T0814", "T0813"],
    "ddos": ["T0814", "T0813"],
    "flood": ["T0814", "T0813"],
    "rate_anomaly": ["T0814", "T0836"],
    "scan": ["T0846", "T0842", "T0888"],
    "recon": ["T0846", "T0842", "T0888"],
    "discovery": ["T0846", "T0888"],
    "brute_force": ["T0812", "T0859", "T0891"],
    "credential": ["T0812", "T0859"],
    "mitm": ["T0830", "T0856"],
    "spoof": ["T0830", "T0856"],
    "unauthorized_command": ["T0855", "T0831"],
    "command_injection": ["T0855", "T0831"],
    "parameter_tampering": ["T0836", "T0831"],
    "modbus": ["T0855", "T0836"],
    "mqtt": ["T0869", "T0885"],
    "protocol_anomaly": ["T0869", "T0885"],
    "unusual_protocol": ["T0869", "T0885"],
    "data_exfiltration": ["T0811", "T0882"],
    "exfiltration": ["T0811", "T0882"],
    "firmware": ["T0800", "T0816"],
    "zero_day": ["T0836", "T0814"],
    "unknown": ["T0836", "T0814"],
    "default": ["T0836", "T0814"],
}


def resolve_mitre(categories: Counter) -> List[Dict[str, str]]:
    """Petakan kategori anomali → daftar teknik ATT&CK for ICS (unik, terurut)."""
    found: set[str] = set()
    for raw_cat in categories:
        key = str(raw_cat).strip().lower().replace("-", "_").replace(" ", "_")
        if not key:
            continue
        if key in ANOMALY_TO_MITRE:
            found.update(ANOMALY_TO_MITRE[key])
            continue
        for alias, ids in ANOMALY_TO_MITRE.items():
            if alias in key or key in alias:
                found.update(ids)
                break
    return [
        {"id": tid, **MITRE_ICS_TECHNIQUES.get(tid, {"name": "Unknown", "tactic": "Unknown"})}
        for tid in sorted(found)
    ]


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class Alert:
    """Satu alarm anomali dari Layer-1 (XGBoost) atau Layer-2 (Isolation Forest)."""
    timestamp: float
    src_ip: str
    dst_ip: str
    anomaly_type: str
    severity: str = "MEDIUM"
    layer: int = 1
    score: float = 0.0
    features: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.severity = str(self.severity).upper()
        if self.severity not in SEVERITY_RANK:
            self.severity = "MEDIUM"
        self.anomaly_type = str(self.anomaly_type or "unknown").strip().lower()

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "anomaly_type": self.anomaly_type,
            "severity": self.severity,
            "layer": self.layer,
            "score": self.score,
            "features": self.features,
            "tags": list(self.tags),
        }


@dataclass
class ThreatCard:
    """Kartu ancaman teragregasi untuk satu aset (dst_ip)."""
    card_id: str
    dst_ip: str
    dst_asset: str
    first_seen: float
    last_seen: float
    status: str = "OPEN"  # OPEN | ISOLATED | AUTO_CLOSED | ACKNOWLEDGED
    severity: str = "LOW"
    alert_count: int = 0
    src_ips: set = field(default_factory=set)
    anomaly_categories: Counter = field(default_factory=Counter)
    layer_counts: Counter = field(default_factory=Counter)
    mitre_techniques: List[Dict[str, str]] = field(default_factory=list)
    sample_alerts: Deque[Alert] = field(default_factory=lambda: deque(maxlen=10))
    explanation: str = ""
    top_features: Dict[str, float] = field(default_factory=dict)
    actions: List[Dict[str, Any]] = field(default_factory=list)
    closed_at: Optional[float] = None
    base_severity_rank: int = 0

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "card_id": self.card_id,
            "dst_ip": self.dst_ip,
            "dst_asset": self.dst_asset,
            "status": self.status,
            "severity": self.severity,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration_s": round(max(0.0, self.last_seen - self.first_seen), 2),
            "alert_count": self.alert_count,
            "unique_src_count": len(self.src_ips),
            "src_ips": sorted(self.src_ips)[:20],
            "anomaly_categories": dict(self.anomaly_categories),
            "layer_counts": dict(self.layer_counts),
            "mitre_techniques": list(self.mitre_techniques),
            "sample_alerts": [a.to_public_dict() for a in list(self.sample_alerts)[:5]],
            "explanation": self.explanation,
            "top_features": dict(self.top_features),
            "actions": list(self.actions),
            "closed_at": self.closed_at,
        }


@dataclass
class TriageConfig:
    window_seconds: float = 3.0
    threshold: int = 5            # kartu dibuat jika len(window) > threshold
    card_idle_timeout: float = 30.0
    high_count: int = 10
    critical_count: int = 25
    max_sample_alerts: int = 10
    max_cards_in_memory: int = 500

    def __post_init__(self) -> None:
        if self.window_seconds <= 0:
            raise ValueError("window_seconds harus > 0")
        if self.threshold < 1:
            raise ValueError("threshold harus >= 1")
        if self.card_idle_timeout <= self.window_seconds:
            LOGGER.warning("card_idle_timeout <= window_seconds; kartu bisa cepat tertutup")


@dataclass
class _AssetWindow:
    alerts: Deque[Alert] = field(default_factory=deque)
    active_card_id: Optional[str] = None


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #
class TriageEngine:
    """Contextual Triage Engine — agregasi alarm → Threat Card."""

    def __init__(
        self,
        config: Optional[TriageConfig] = None,
        asset_resolver: Optional[Callable[[str], str]] = None,
    ) -> None:
        self.config = config or TriageConfig()
        self._asset_resolver = asset_resolver or (lambda ip: ip)
        self._lock = threading.RLock()
        self._windows: Dict[str, _AssetWindow] = {}
        self._cards: Dict[str, ThreatCard] = {}
        self._isolation_handlers: List[Callable[[ThreatCard, Dict[str, Any]], None]] = []
        self._total_alerts = 0
        self._total_cards = 0

    # ------------------------------------------------------------------ #
    # Registrasi handler
    # ------------------------------------------------------------------ #
    def register_isolation_handler(
        self, handler: Callable[[ThreatCard, Dict[str, Any]], None]
    ) -> None:
        """Daftarkan callback yang dipanggil saat kartu diisolasi."""
        with self._lock:
            self._isolation_handlers.append(handler)

    # ------------------------------------------------------------------ #
    # Ingest
    # ------------------------------------------------------------------ #
    def ingest(self, alert: Alert) -> Optional[ThreatCard]:
        """
        Masukkan satu alarm. Kembalikan Threat Card aktif jika ada
        (baik yang baru dibuat maupun yang diperbarui), else None.
        """
        if not alert.dst_ip:
            raise ValueError("Alert.dst_ip wajib diisi")

        with self._lock:
            self._total_alerts += 1
            window = self._windows.setdefault(alert.dst_ip, _AssetWindow())

            cutoff = alert.timestamp - self.config.window_seconds
            window.alerts.append(alert)
            self._prune_window(window, cutoff)

            card = self._get_active_card(window)
            if card is not None:
                self._apply_alert_to_card(card, alert)
                return card

            # Syarat: LEBIH DARI threshold (mis. >5 berarti minimal 6)
            if len(window.alerts) > self.config.threshold:
                card = self._create_card(alert.dst_ip, window)
                window.active_card_id = card.card_id
                self._cards[card.card_id] = card
                self._total_cards += 1
                self._enforce_card_limit()
                LOGGER.warning(
                    "THREAT CARD dibuat | id=%s dst=%s count=%d sev=%s",
                    card.card_id, card.dst_ip, card.alert_count, card.severity,
                )
                return card
            return None

    def ingest_batch(self, alerts: List[Alert]) -> List[ThreatCard]:
        results: List[ThreatCard] = []
        for alert in alerts:
            card = self.ingest(alert)
            if card is not None:
                results.append(card)
        return results

    # ------------------------------------------------------------------ #
    # Internal helpers (dipanggil dengan lock aktif)
    # ------------------------------------------------------------------ #
    @staticmethod
    def _prune_window(window: _AssetWindow, cutoff: float) -> None:
        while window.alerts and window.alerts[0].timestamp < cutoff:
            window.alerts.popleft()

    def _get_active_card(self, window: _AssetWindow) -> Optional[ThreatCard]:
        if not window.active_card_id:
            return None
        card = self._cards.get(window.active_card_id)
        if card is not None and card.status == "OPEN":
            return card
        window.active_card_id = None
        return None

    def _create_card(self, dst_ip: str, window: _AssetWindow) -> ThreatCard:
        alerts = list(window.alerts)
        card = ThreatCard(
            card_id=uuid.uuid4().hex[:12],
            dst_ip=dst_ip,
            dst_asset=self._asset_resolver(dst_ip),
            first_seen=min(a.timestamp for a in alerts),
            last_seen=max(a.timestamp for a in alerts),
        )
        for a in alerts:
            self._apply_alert_to_card(card, a, refresh=False)
        self._refresh_card(card)
        return card

    def _apply_alert_to_card(
        self, card: ThreatCard, alert: Alert, refresh: bool = True
    ) -> None:
        card.alert_count += 1
        card.last_seen = max(card.last_seen, alert.timestamp)
        card.src_ips.add(alert.src_ip)
        card.anomaly_categories[alert.anomaly_type] += 1
        card.layer_counts[f"L{alert.layer}"] += 1
        card.base_severity_rank = max(
            card.base_severity_rank, SEVERITY_RANK.get(alert.severity, 1)
        )
        card.sample_alerts.append(alert)
        if refresh:
            self._refresh_card(card)

    def _refresh_card(self, card: ThreatCard) -> None:
        rank = card.base_severity_rank
        if card.alert_count >= self.config.critical_count:
            rank = max(rank, SEVERITY_RANK["CRITICAL"])
        elif card.alert_count >= self.config.high_count:
            rank = max(rank, SEVERITY_RANK["HIGH"])

        # Zero-day (Layer-2) menaikkan satu level, capped CRITICAL
        if card.layer_counts.get("L2", 0) > 0:
            rank = min(SEVERITY_RANK["CRITICAL"], rank + 1)

        card.severity = RANK_SEVERITY[rank]
        card.mitre_techniques = resolve_mitre(card.anomaly_categories)

    # ------------------------------------------------------------------ #
    # Lifecycle kartu
    # ------------------------------------------------------------------ #
    def flush_expired(self, now: Optional[float] = None) -> List[ThreatCard]:
        """Tutup kartu yang idle > card_idle_timeout. Kembalikan kartu yang ditutup."""
        now = now if now is not None else time.time()
        closed: List[ThreatCard] = []
        with self._lock:
            for dst_ip, window in list(self._windows.items()):
                cutoff = now - self.config.window_seconds
                self._prune_window(window, cutoff)

                if window.active_card_id:
                    card = self._cards.get(window.active_card_id)
                    if card is not None and card.status == "OPEN":
                        if (now - card.last_seen) >= self.config.card_idle_timeout:
                            card.status = "AUTO_CLOSED"
                            card.closed_at = now
                            closed.append(card)
                            window.active_card_id = None
                            LOGGER.info("Kartu auto-closed | id=%s dst=%s", card.card_id, dst_ip)

                if not window.alerts and not window.active_card_id:
                    self._windows.pop(dst_ip, None)

            self._enforce_card_limit()
        return closed

    def isolate(
        self,
        card_id: str,
        operator: str = "SOC_OPERATOR",
        note: str = "",
    ) -> ThreatCard:
        """Eksekusi isolasi aset untuk kartu tertentu."""
        with self._lock:
            card = self._cards.get(card_id)
            if card is None:
                raise KeyError(f"Threat Card tidak ditemukan: {card_id}")
            if card.status != "OPEN":
                return card

            action: Dict[str, Any] = {
                "ts": time.time(),
                "action": "ISOLATE_ASSET",
                "operator": operator,
                "note": note or "Isolasi manual oleh operator SOC",
            }
            card.actions.append(action)
            card.status = "ISOLATED"
            card.closed_at = action["ts"]

            # lepaskan dari window
            window = self._windows.get(card.dst_ip)
            if window and window.active_card_id == card.card_id:
                window.active_card_id = None

            handlers = list(self._isolation_handlers)

        # panggil handler di luar lock untuk menghindari deadlock/reentrancy
        for handler in handlers:
            try:
                handler(card, action)
            except Exception:  # noqa: BLE001
                LOGGER.exception("Isolation handler gagal untuk card=%s", card_id)
        return card

    def acknowledge(self, card_id: str, operator: str = "SOC_OPERATOR") -> ThreatCard:
        with self._lock:
            card = self._cards.get(card_id)
            if card is None:
                raise KeyError(f"Threat Card tidak ditemukan: {card_id}")
            if card.status == "OPEN":
                card.status = "ACKNOWLEDGED"
                card.actions.append({
                    "ts": time.time(),
                    "action": "ACKNOWLEDGE",
                    "operator": operator,
                    "note": "Kartu di-acknowledge oleh operator",
                })
            return card

    def _enforce_card_limit(self) -> None:
        if len(self._cards) <= self.config.max_cards_in_memory:
            return
        closed_cards = [c for c in self._cards.values() if c.status != "OPEN"]
        closed_cards.sort(key=lambda c: c.closed_at or c.last_seen)
        excess = len(self._cards) - self.config.max_cards_in_memory
        for card in closed_cards[:excess]:
            self._cards.pop(card.card_id, None)

    # ------------------------------------------------------------------ #
    # Query
    # ------------------------------------------------------------------ #
    def get_card(self, card_id: str) -> Optional[ThreatCard]:
        with self._lock:
            return self._cards.get(card_id)

    def get_active_cards(self) -> List[ThreatCard]:
        with self._lock:
            cards = [c for c in self._cards.values() if c.status == "OPEN"]
        cards.sort(key=lambda c: c.last_seen, reverse=True)
        return cards

    def get_all_cards(self) -> List[ThreatCard]:
        with self._lock:
            cards = list(self._cards.values())
        cards.sort(key=lambda c: c.last_seen, reverse=True)
        return cards

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "total_alerts_ingested": self._total_alerts,
                "total_cards_created": self._total_cards,
                "active_cards": sum(1 for c in self._cards.values() if c.status == "OPEN"),
                "isolated_cards": sum(1 for c in self._cards.values() if c.status == "ISOLATED"),
                "auto_closed_cards": sum(1 for c in self._cards.values() if c.status == "AUTO_CLOSED"),
                "tracked_assets": len(self._windows),
                "cards_in_memory": len(self._cards),
            }

    def reset(self) -> None:
        with self._lock:
            self._windows.clear()
            self._cards.clear()
            self._total_alerts = 0
            self._total_cards = 0