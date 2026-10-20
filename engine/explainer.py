#!/usr/bin/env python3
"""
engine/explainer.py
===================
Tactical Explainer untuk GARUDA SENTINEL.

Menerjemahkan 2 (default) fitur penyumbang anomali tertinggi — dihitung
via SHAP TreeExplainer — menjadi kalimat brief taktis berbahasa Indonesia.

Mendukung dua mode:
    - Known threat (XGBoost, layer-1)
    - Zero-day (Isolation Forest, layer-2) dengan fallback z-score
      dari StandardScaler bila SHAP gagal.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
import shap

LOGGER = logging.getLogger("garuda.explainer")


# --------------------------------------------------------------------------- #
# Dictionary taktis: feature -> template arah (up/down)
# --------------------------------------------------------------------------- #
FEATURE_TEMPLATES: Dict[str, Dict[str, str]] = {
    "flow_duration":    {"up": "lonjakan abnormal pada durasi flow",
                         "down": "penurunan abnormal pada durasi flow"},
    "header_length":    {"up": "panjang header melampaui baseline normal",
                         "down": "panjang header lebih pendek dari baseline"},
    "duration":         {"up": "koneksi berlangsung lebih lama dari normal",
                         "down": "koneksi terlalu singkat (indikasi probe)"},
    "rate":             {"up": "lonjakan laju paket total",
                         "down": "penurunan laju paket total"},
    "srate":            {"up": "lonjakan laju pengiriman dari sumber",
                         "down": "penurunan laju pengiriman dari sumber"},
    "drate":            {"up": "lonjakan laju penerimaan ke tujuan",
                         "down": "penurunan laju penerimaan ke tujuan"},
    "syn_flag_number":  {"up": "lonjakan flag SYN (indikasi SYN flood atau port scan)",
                         "down": "anomali rendahnya flag SYN"},
    "ack_flag_number":  {"up": "lonjakan flag ACK",
                         "down": "anomali rendahnya flag ACK"},
    "fin_flag_number":  {"up": "lonjakan flag FIN (koneksi diputus paksa)",
                         "down": "anomali rendahnya flag FIN"},
    "rst_flag_number":  {"up": "lonjakan flag RST (reset koneksi masif)",
                         "down": "anomali rendahnya flag RST"},
    "psh_flag_number":  {"up": "lonjakan flag PSH",
                         "down": "anomali rendahnya flag PSH"},
    "ece_flag_number":  {"up": "lonjakan flag ECE",
                         "down": "anomali rendahnya flag ECE"},
    "cwr_flag_number":  {"up": "lonjakan flag CWR",
                         "down": "anomali rendahnya flag CWR"},
    "syn_count":        {"up": "lonjakan jumlah paket SYN",
                         "down": "penurunan jumlah paket SYN"},
    "ack_count":        {"up": "lonjakan jumlah paket ACK",
                         "down": "penurunan jumlah paket ACK"},
    "fin_count":        {"up": "lonjakan jumlah paket FIN",
                         "down": "penurunan jumlah paket FIN"},
    "rst_count":        {"up": "lonjakan jumlah paket RST",
                         "down": "penurunan jumlah paket RST"},
    "http":             {"up": "eskalasi trafik protokol HTTP",
                         "down": "penurunan trafik HTTP"},
    "https":            {"up": "eskalasi trafik protokol HTTPS",
                         "down": "penurunan trafik HTTPS"},
    "dns":              {"up": "lonjakan trafik DNS (potensi DNS tunneling)",
                         "down": "penurunan trafik DNS"},
    "ssh":              {"up": "lonjakan trafik SSH (potensi brute-force)",
                         "down": "penurunan trafik SSH"},
    "telnet":           {"up": "eskalasi trafik Telnet (protokol tidak aman)",
                         "down": "penurunan trafik Telnet"},
    "smtp":             {"up": "lonjakan trafik SMTP",
                         "down": "penurunan trafik SMTP"},
    "irc":              {"up": "lonjakan trafik IRC (potensi C2)",
                         "down": "penurunan trafik IRC"},
    "tcp":              {"up": "eskalasi trafik TCP",
                         "down": "penurunan trafik TCP"},
    "udp":              {"up": "eskalasi trafik UDP",
                         "down": "penurunan trafik UDP"},
    "dhcp":             {"up": "lonjakan trafik DHCP",
                         "down": "penurunan trafik DHCP"},
    "arp":              {"up": "lonjakan trafik ARP (potensi ARP spoofing)",
                         "down": "penurunan trafik ARP"},
    "icmp":             {"up": "lonjakan trafik ICMP (potensi ICMP flood)",
                         "down": "penurunan trafik ICMP"},
    "igmp":             {"up": "lonjakan trafik IGMP",
                         "down": "penurunan trafik IGMP"},
    "llc":              {"up": "lonjakan trafik LLC",
                         "down": "penurunan trafik LLC"},
    "ipv":              {"up": "lonjakan trafik IPv",
                         "down": "penurunan trafik IPv"},
    "tot_size":         {"up": "lonjakan ukuran total paket",
                         "down": "penurunan ukuran total paket"},
    "tot_sum":          {"up": "lonjakan agregat ukuran paket",
                         "down": "penurunan agregat ukuran paket"},
    "min":              {"up": "lonjakan nilai minimum ukuran paket",
                         "down": "penurunan nilai minimum ukuran paket"},
    "max":              {"up": "lonjakan nilai maksimum ukuran paket",
                         "down": "penurunan nilai maksimum ukuran paket"},
    "avg":              {"up": "lonjakan rata-rata ukuran paket",
                         "down": "penurunan rata-rata ukuran paket"},
    "std":              {"up": "lonjakan deviasi standar ukuran paket",
                         "down": "penurunan deviasi standar ukuran paket"},
    "variance":         {"up": "lonjakan variansi ukuran paket",
                         "down": "penurunan variansi ukuran paket"},
    "iat":              {"up": "lonjakan interval antar paket (IAT)",
                         "down": "interval antar paket terlalu rapat (indikasi flood)"},
    "number":           {"up": "lonjakan jumlah paket dalam flow",
                         "down": "penurunan jumlah paket dalam flow"},
    "protocol_type":    {"up": "pergeseran tipe protokol pada flow",
                         "down": "pergeseran tipe protokol pada flow"},
}

RECOMMENDATIONS: Dict[str, str] = {
    "CRITICAL": "Rekomendasi: isolasi aset segera dan aktifkan protokol containment level-3.",
    "HIGH":     "Rekomendasi: verifikasi aset dan pertimbangkan isolasi jaringan.",
    "MEDIUM":   "Rekomendasi: monitor intensif dan validasi log aset terkait.",
    "LOW":      "Rekomendasi: catat dan lanjutkan monitoring berkala.",
}

CONFIDENCE_BANDS: List[Tuple[float, str]] = [
    (0.95, "SANGAT TINGGI"),
    (0.85, "TINGGI"),
    (0.65, "SEDANG"),
    (0.00, "RENDAH"),
]


# --------------------------------------------------------------------------- #
# Konfigurasi
# --------------------------------------------------------------------------- #
@dataclass
class ExplainerConfig:
    top_k: int = 2
    style: str = "full"  # "short" | "full"
    include_recommendation: bool = True
    max_phrase_chars: int = 400
    shap_fallback_to_zscore: bool = True


# --------------------------------------------------------------------------- #
# Tactical Explainer
# --------------------------------------------------------------------------- #
class TacticalExplainer:
    """
    Membungkus SHAP TreeExplainer untuk XGBoost (layer-1) dan
    Isolation Forest (layer-2, dengan fallback z-score).
    """

    def __init__(
        self,
        *,
        xgb_model: Any,
        iso_model: Optional[Any],
        iso_scaler: Optional[Any],
        feature_columns: List[str],
        config: Optional[ExplainerConfig] = None,
    ) -> None:
        self.config = config or ExplainerConfig()
        self.feature_columns = list(feature_columns)
        self.iso_scaler = iso_scaler

        self._xgb_explainer = shap.TreeExplainer(xgb_model, feature_perturbation="tree_path_dependent")
        self._iso_explainer: Optional[shap.TreeExplainer] = None
        if iso_model is not None:
            try:
                self._iso_explainer = shap.TreeExplainer(iso_model)
                LOGGER.info("TreeExplainer untuk Isolation Forest berhasil dimuat")
            except Exception:  # noqa: BLE001
                LOGGER.warning(
                    "TreeExplainer gagal untuk Isolation Forest; fallback z-score aktif",
                    exc_info=True,
                )
                self._iso_explainer = None

        # cache lookup lowercase
        self._lower_lookup: Dict[str, str] = {c.lower(): c for c in self.feature_columns}

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def explain_known_threat(
        self,
        X_row: pd.DataFrame,
        *,
        severity: str,
        probability: float,
        anomaly_type: str = "known_threat",
    ) -> Tuple[str, Dict[str, float]]:
        """Layer-1: XGBoost. Return (kalimat, top_features{name: shap_value})."""
        top = self._shap_top_contributions(
            self._xgb_explainer, X_row, model_type="xgboost"
        )
        sentence = self._compose(
            top,
            severity=severity,
            confidence=probability,
            anomaly_type=anomaly_type,
            source="XGBoost (Layer-1 / Known Threat)",
        )
        return sentence, dict(top)

    def explain_zero_day(
        self,
        X_row: pd.DataFrame,
        *,
        severity: str,
        decision_score: float,
        score_threshold: float,
        anomaly_type: str = "zero_day",
    ) -> Tuple[str, Dict[str, float]]:
        """Layer-2: Isolation Forest. Return (kalimat, top_features{name: shap_value})."""
        top = self._iso_top_contributions(X_row, score_threshold, decision_score)
        # konversi decision_score menjadi pseudo-probability untuk confidence band
        pseudo_conf = self._iso_confidence(decision_score, score_threshold)
        sentence = self._compose(
            top,
            severity=severity,
            confidence=pseudo_conf,
            anomaly_type=anomaly_type,
            source="Isolation Forest (Layer-2 / Zero-Day)",
        )
        return sentence, dict(top)

    # ------------------------------------------------------------------ #
    # Top contribution extraction
    # ------------------------------------------------------------------ #
    def _shap_top_contributions(
        self,
        explainer: shap.TreeExplainer,
        X_row: pd.DataFrame,
        *,
        model_type: str,
    ) -> List[Tuple[str, float]]:
        try:
            shap_values = explainer.shap_values(X_row)
            attack_shap = self._extract_attack_shap(shap_values, model_type)
        except Exception:  # noqa: BLE001
            LOGGER.exception("SHAP gagal pada %s; mengembalikan list kosong", model_type)
            return []

        if attack_shap is None or attack_shap.size == 0:
            return []

        n = min(self.config.top_k, attack_shap.shape[0])
        top_idx = np.argsort(-np.abs(attack_shap))[:n]
        return [
            (self.feature_columns[int(i)], float(attack_shap[int(i)]))
            for i in top_idx
        ]

    def _extract_attack_shap(self, shap_values: Any, model_type: str) -> Optional[np.ndarray]:
        """
        Normalisasi output SHAP ke vektor 1-D dengan arah positif = menuju attack/anomaly.
        """
        if isinstance(shap_values, list):
            # XGBoost binary: [class0_shap, class1_shap]
            arr = np.asarray(shap_values[1])
        else:
            arr = np.asarray(shap_values)

        if arr.ndim == 3:                 # (n, features, classes)
            arr = arr[:, :, 1]
        if arr.ndim == 2:                 # (n, features)
            arr = arr[0]
        arr = np.asarray(arr, dtype=float).ravel()

        if model_type == "isolation_forest":
            # decision_function negatif = anomali; kita balik agar positif = anomali
            arr = -arr
        return arr

    def _iso_top_contributions(
        self,
        X_row: pd.DataFrame,
        score_threshold: float,
        decision_score: float,
    ) -> List[Tuple[str, float]]:
        # 1) Coba SHAP
        if self._iso_explainer is not None and self.iso_scaler is not None:
            try:
                X_scaled = self.iso_scaler.transform(X_row.values)
                shap_values = self._iso_explainer.shap_values(X_scaled)
                attack_shap = self._extract_attack_shap(shap_values, "isolation_forest")
                if attack_shap is not None and attack_shap.size == len(self.feature_columns):
                    n = min(self.config.top_k, attack_shap.shape[0])
                    top_idx = np.argsort(-np.abs(attack_shap))[:n]
                    return [
                        (self.feature_columns[int(i)], float(attack_shap[int(i)]))
                        for i in top_idx
                    ]
            except Exception:  # noqa: BLE001
                LOGGER.warning("SHAP Isolation Forest gagal; beralih ke z-score", exc_info=True)

        # 2) Fallback: z-score dari scaler
        if self.config.shap_fallback_to_zscore and self.iso_scaler is not None:
            try:
                X_scaled = self.iso_scaler.transform(X_row.values)[0]
                n = min(self.config.top_k, X_scaled.shape[0])
                top_idx = np.argsort(-np.abs(X_scaled))[:n]
                return [
                    (self.feature_columns[int(i)], float(X_scaled[int(i)]))
                    for i in top_idx
                ]
            except Exception:  # noqa: BLE001
                LOGGER.exception("Fallback z-score juga gagal")

        return []

    @staticmethod
    def _iso_confidence(decision_score: float, score_threshold: float) -> float:
        """Heuristik: makin jauh di bawah threshold, makin tinggi confidence."""
        if score_threshold <= 0:
            return 0.5
        ratio = (score_threshold - decision_score) / abs(score_threshold)
        return float(np.clip(0.5 + ratio, 0.0, 1.0))

    # ------------------------------------------------------------------ #
    # Komposisi kalimat taktis
    # ------------------------------------------------------------------ #
    def _compose(
        self,
        top: List[Tuple[str, float]],
        *,
        severity: str,
        confidence: float,
        anomaly_type: str,
        source: str,
    ) -> str:
        severity = str(severity).upper()
        conf_label = self._confidence_label(confidence)
        attack_label = self._humanize_type(anomaly_type)

        if not top:
            text = (
                f"Anomali {attack_label} terdeteksi dengan tingkat keyakinan "
                f"{conf_label} ({(confidence * 100):.0f}%). "
                "Tidak ada fitur dominan yang dapat diidentifikasi secara otomatis."
            )
        else:
            phrases = [
                f"({i + 1}) {self._phrase_for_feature(name, value)}"
                for i, (name, value) in enumerate(top)
            ]
            detail = " dan ".join(phrases) if len(phrases) == 2 else ", ".join(phrases)
            text = (
                f"Analisis forensik {source} mengungkap vektor dominan: {detail}. "
                f"Tingkat keyakinan: {conf_label} ({(confidence * 100):.0f}%)."
            )

        if self.config.style == "full" and self.config.include_recommendation:
            text = f"{text} {RECOMMENDATIONS.get(severity, RECOMMENDATIONS['LOW'])}"

        if len(text) > self.config.max_phrase_chars:
            text = text[: self.config.max_phrase_chars - 3].rstrip() + "..."
        return text

    @staticmethod
    def _confidence_label(prob: float) -> str:
        for threshold, label in CONFIDENCE_BANDS:
            if prob >= threshold:
                return label
        return "RENDAH"

    @staticmethod
    def _humanize_type(anomaly_type: str) -> str:
        return {
            "known_threat": "serangan yang dikenal (known threat)",
            "zero_day": "anomali nol-hari (zero-day)",
            "scan": "pemindaian jaringan (network scanning)",
            "flood": "banjir trafik (flooding)",
            "protocol_anomaly": "anomali protokol",
            "duration_anomaly": "anomali durasi koneksi",
            "unknown": "anomali tak terklasifikasi",
        }.get(str(anomaly_type).lower(), str(anomaly_type))

    # ------------------------------------------------------------------ #
    # Fitur → frasa taktis
    # ------------------------------------------------------------------ #
    def _phrase_for_feature(self, feature: str, shap_value: float) -> str:
        f_low = feature.lower()
        direction = "up" if shap_value > 0 else "down"

        # 1) Exact match
        if f_low in FEATURE_TEMPLATES:
            return FEATURE_TEMPLATES[f_low][direction]

        # 2) proto_xxx
        if f_low.startswith("proto_"):
            name = feature.split("_", 1)[1].upper()
            return (
                f"eskalasi trafik protokol {name}"
                if direction == "up"
                else f"penurunan trafik protokol {name}"
            )

        # 3) service_xxx
        if f_low.startswith("service_"):
            name = feature.split("_", 1)[1].upper()
            return (
                f"aktivitas abnormal layanan {name}"
                if direction == "up"
                else f"penurunan aktivitas layanan {name}"
            )

        # 4) *_flag_number
        if f_low.endswith("_flag_number"):
            flag = feature[: -len("_flag_number")].upper()
            return (
                f"lonjakan flag {flag} yang tidak wajar"
                if direction == "up"
                else f"anomali rendahnya flag {flag}"
            )

        # 5) *_count
        if f_low.endswith("_count"):
            entity = feature[: -len("_count")].upper()
            return (
                f"lonjakan jumlah paket {entity}"
                if direction == "up"
                else f"penurunan jumlah paket {entity}"
            )

        # 6) rate-like
        if any(k in f_low for k in ("rate", "srate", "drate")):
            return (
                f"lonjakan laju paket ({feature})"
                if direction == "up"
                else f"penurunan laju paket ({feature})"
            )

        # 7) duration-like
        if "duration" in f_low or "iat" in f_low:
            return (
                f"lonjakan durasi ({feature})"
                if direction == "up"
                else f"penurunan durasi ({feature})"
            )

        # 8) size/stat
        if any(k in f_low for k in ("size", "length", "tot_sum", "min", "max", "avg", "std", "variance")):
            return f"anomali ukuran/statistik ({feature})"

        # 9) Generic
        return f"pergeseran pola pada fitur '{feature}'"