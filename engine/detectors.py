#!/usr/bin/env python3
"""
engine/detectors.py
===================
Dual-Layer AI Detector — XGBoost (Layer-1) + Isolation Forest (Layer-2).

Production notes:
- Feature contract enforcement: 94 fitur OHE, urutan sesuai
  `feature_columns.json` yang dipakai XGBoost saat training.
- Layer-2 feature parity: `id.orig_p` dan `id.resp_p` di-zero-kan
  SEBELUM scaler.transform (konsisten dengan train_layer2.py).
- Version compatibility: sklearn 1.6.1 + xgboost 2.1.4 (dipin di
  requirements.txt) — model disimpan sebagai JSON untuk portabilitas.
- Thread-safe: SHAP explainer internal state dilindungi lock di
  TacticalExplainer; detector sendiri stateless.
- Batch inference: `predict_batch()` menggunakan vectorized
  preprocessing untuk throughput tinggi (diagnostic & replay).
- Graceful degradation: Layer-2 opsional — jika artefak tidak lengkap,
  Layer-1 tetap berjalan penuh.
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
import xgboost as xgb
# Panggil secara dinamis hanya saat dibutuhkan
# from catboost import CatBoostClassifier 

from engine.triage_engine import Alert

LOGGER = logging.getLogger("garuda.detector")


# --------------------------------------------------------------------------- #
# Konstanta — fitur yang HARUS di-zero untuk Layer-2
# --------------------------------------------------------------------------- #
# Port sumber (id.orig_p) adalah ephemeral → zero.
# Port tujuan (id.resp_p) DIPERTAHANKAN karena sangat diskriminatif (1883 MQTT vs 22 SSH).
NON_INFORMATIVE_FEATURES: frozenset[str] = frozenset({
    "id.orig_p",
    "unnamed: 0", "unnamed:0", "index",
    "src_ip", "dst_ip", "src_port", "dst_port", "id",
})


# --------------------------------------------------------------------------- #
# Konfigurasi
# --------------------------------------------------------------------------- #
@dataclass
class DetectorConfig:
    model_dir: Path = Path("models")

    # Multi-kandidat: cari yang pertama ada
    xgb_filenames: List[str] = field(default_factory=lambda: [
        "xgb_known_threats.json",
        "xgb_known_threats.ubj",
        "xgb_known_threats.pkl",
        "xgboost_best.json",
        "xgboost_best.ubj",
        "xgboost_best.pkl",
        "model.json",
        "model.pkl",
    ])
    iso_filename: str = "isolation_forest.pkl"
    iso_scaler_filename: str = "isolation_scaler.pkl"
    iso_metadata_filename: str = "isolation_metadata.json"
    feature_columns_filename: str = "feature_columns.json"
    categorical_categories_filename: str = "isolation_categorical_categories.json"

    # Decision thresholds
    xgb_threshold: float = 0.5
    iso_threshold_override: Optional[float] = None  # None → pakai metadata

    # Fitur Layer-2
    enable_layer2: bool = True
    explain_on_attack: bool = False # MATIKAN SECARA DEFAULT UNTUK EDGE INFERENCE

    # Severity dari probabilitas XGB
    sev_critical: float = 0.95
    sev_high: float = 0.85
    sev_medium: float = 0.65

    # Fallback IP jika record tidak punya src/dst
    fallback_src_ip: str = "0.0.0.0"
    fallback_dst_ip: str = "0.0.0.0"
    strict_ips: bool = False


@dataclass
class ModelArtifacts:
    xgb_model: Any  # Tipe Any untuk support CatBoost/XGBoost dinamis
    iso_model: Optional[Any]
    iso_scaler: Optional[Any]
    feature_columns: List[str]
    categorical_categories: Dict[str, List[str]]
    iso_metadata: Dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Detector
# --------------------------------------------------------------------------- #
class DualLayerDetector:
    """Layer-1 (XGBoost/CatBoost) + Layer-2 (Isolation Forest) inference wrapper."""

    METADATA_KEYS = ("_stream_ts", "_row_index", "_loop_index")

    def __init__(
        self,
        artifacts: ModelArtifacts,
        config: DetectorConfig,
        explainer: Optional[Any] = None,
    ) -> None:
        self.artifacts = artifacts
        self.config = config
        self.explainer = explainer

        self._feature_columns: List[str] = list(artifacts.feature_columns)
        self._lower_to_actual: Dict[str, str] = {c.lower(): c for c in self._feature_columns}
        self._categorical: Dict[str, List[str]] = artifacts.categorical_categories

        # Validasi kontrak fitur
        self._validate_feature_contract()

        # Threshold Layer-2
        iso_thr = config.iso_threshold_override
        if iso_thr is None:
            iso_thr = artifacts.iso_metadata.get("score_threshold", 0.0)
        self._iso_threshold: float = float(iso_thr)
        LOGGER.info("Isolation Forest threshold = %+.6f", self._iso_threshold)

    # ------------------------------------------------------------------ #
    # Factory
    # ------------------------------------------------------------------ #
    @classmethod
    def load(
        cls,
        config: Optional[DetectorConfig] = None,
        *,
        with_explainer: bool = False, # DEFAULT DIMATIKAN
    ) -> "DualLayerDetector":
        config = config or DetectorConfig()
        model_dir = Path(config.model_dir)

        # ---- Feature contract ----
        feat_path = model_dir / config.feature_columns_filename
        if not feat_path.exists():
            raise FileNotFoundError(
                f"{feat_path} tidak ada. Pastikan direktori models/ valid.",
            )
        feature_columns: List[str] = json.loads(feat_path.read_text(encoding="utf-8"))
        LOGGER.info("Feature contract: %d kolom", len(feature_columns))

        # ---- Layer-1 (XGBoost/CatBoost) ----
        xgb_path = cls._resolve_xgb_path(model_dir, config.xgb_filenames)
        xgb_model = cls._load_xgb(xgb_path, expected_n_features=len(feature_columns))

        # ---- Layer-2 (opsional) ----
        iso_model, iso_scaler, iso_metadata = cls._load_layer2(model_dir, config)

        # ---- Categorical categories ----
        cat_path = model_dir / config.categorical_categories_filename
        categorical_categories: Dict[str, List[str]] = {}
        if cat_path.exists():
            categorical_categories = json.loads(cat_path.read_text(encoding="utf-8"))
            LOGGER.info(
                "Kategori kategorikal: %s",
                {k: len(v) for k, v in categorical_categories.items()},
            )
        else:
            LOGGER.warning(
                "%s tidak ada — fitur OHE akan diisi 0 untuk semua record",
                cat_path.name,
            )

        artifacts = ModelArtifacts(
            xgb_model=xgb_model,
            iso_model=iso_model,
            iso_scaler=iso_scaler,
            feature_columns=feature_columns,
            categorical_categories=categorical_categories,
            iso_metadata=iso_metadata,
        )

        # ---- Explainer ----
        explainer: Optional[Any] = None
        if with_explainer and config.explain_on_attack:
            try:
                from engine.explainer import TacticalExplainer
                explainer = TacticalExplainer(
                    xgb_model=xgb_model,
                    iso_model=iso_model,
                    iso_scaler=iso_scaler,
                    feature_columns=feature_columns,
                )
                LOGGER.info("TacticalExplainer aktif")
            except Exception:  # noqa: BLE001
                LOGGER.exception("Gagal inisialisasi TacticalExplainer; deteksi tetap jalan")

        return cls(artifacts=artifacts, config=config, explainer=explainer)

    # ------------------------------------------------------------------ #
    # Loader helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _resolve_xgb_path(model_dir: Path, filenames: List[str]) -> Path:
        for fname in filenames:
            p = model_dir / fname
            if p.exists():
                return p
        raise FileNotFoundError(
            f"Model XGBoost tidak ditemukan di {model_dir}. Dicari: {filenames}",
        )

    @staticmethod
    def _load_xgb(path: Path, expected_n_features: int) -> Any:
        suffix = path.suffix.lower()
        
        if suffix == ".cbm":
            from catboost import CatBoostClassifier
            model = CatBoostClassifier()
            model.load_model(str(path))
            LOGGER.info("Model CatBoost dimuat: %s", path.name)
            return model
            
        elif suffix in {".json", ".ubj", ".model"}:
            model = xgb.XGBClassifier()
            model.load_model(str(path))
        elif suffix in {".pkl", ".joblib"}:
            obj = joblib.load(path)
            if isinstance(obj, xgb.XGBClassifier):
                model = obj
            elif isinstance(obj, xgb.Booster):
                model = xgb.XGBClassifier()
                model._Booster = obj
            else:
                raise TypeError(f"{path} berisi {type(obj)}, bukan XGBClassifier")
        else:
            raise ValueError(f"Format tidak dikenal: {suffix}")

        n_model = getattr(model, "n_features_in_", None)
        if n_model is not None and n_model != expected_n_features:
            raise ValueError(
                f"Mismatch: model dilatih dengan {n_model} fitur, "
                f"tapi metadata berisi {expected_n_features}",
            )
        LOGGER.info(
            "XGBoost dimuat: %s | n_features=%d",
            path.name, expected_n_features,
        )
        return model

    @staticmethod
    def _load_layer2(
        model_dir: Path, config: DetectorConfig,
    ) -> Tuple[Optional[Any], Optional[Any], Dict[str, Any]]:
        if not config.enable_layer2:
            LOGGER.info("Layer-2 dinonaktifkan oleh konfigurasi")
            return None, None, {}

        iso_path = model_dir / config.iso_filename
        scaler_path = model_dir / config.iso_scaler_filename
        meta_path = model_dir / config.iso_metadata_filename

        if not (iso_path.exists() and scaler_path.exists()):
            LOGGER.warning(
                "Layer-2 aktif tapi artefak tidak lengkap di %s", model_dir
            )
            return None, None, {}

        iso_model = joblib.load(iso_path)
        iso_scaler = joblib.load(scaler_path)
        iso_metadata: Dict[str, Any] = {}
        if meta_path.exists():
            iso_metadata = json.loads(meta_path.read_text(encoding="utf-8"))

        LOGGER.info(
            "Isolation Forest dimuat: contamination=%.3f",
            getattr(iso_model, "contamination", 0.0),
        )
        return iso_model, iso_scaler, iso_metadata

    # ------------------------------------------------------------------ #
    # Feature contract validation
    # ------------------------------------------------------------------ #
    def _validate_feature_contract(self) -> None:
        """Pastikan kategori OHE sesuai dengan feature_columns."""
        missing: List[str] = []
        for cat_col, cats in self._categorical.items():
            for c in cats:
                target = f"{cat_col.lower()}_{str(c).lower()}"
                if target not in self._lower_to_actual:
                    missing.append(target)
        if missing:
            LOGGER.warning(
                "Kolom OHE tidak ada di feature_columns (diabaikan): %s", missing[:5]
            )

    # ------------------------------------------------------------------ #
    # Preprocessing
    # ------------------------------------------------------------------ #
    @staticmethod
    def _normalize_record(record: Dict[str, Any]) -> Dict[str, Any]:
        return {str(k).strip().lower(): v for k, v in record.items() if k is not None}

    def preprocess(self, record: Dict[str, Any]) -> pd.DataFrame:
        rec_low = self._normalize_record(record)
        row: Dict[str, float] = {}

        for col in self._feature_columns:
            key = col.lower()
            if key in rec_low:
                val = rec_low[key]
                try:
                    row[col] = float(val) if val is not None else 0.0
                except (TypeError, ValueError):
                    row[col] = 0.0

        for cat_col, categories in self._categorical.items():
            val = rec_low.get(cat_col.lower())
            val_str = "" if val is None else str(val).strip().lower()
            for cat in categories:
                target_low = f"{cat_col.lower()}_{str(cat).lower()}"
                actual = self._lower_to_actual.get(target_low)
                if actual is None:
                    continue
                row[actual] = 1.0 if val_str == str(cat).lower() else 0.0

        df = pd.DataFrame([row], columns=self._feature_columns).fillna(0.0)
        return df.astype(np.float32)

    def preprocess_batch(self, records: List[Dict[str, Any]]) -> pd.DataFrame:
        normalized = [self._normalize_record(r) for r in records]
        n = len(normalized)
        data: Dict[str, np.ndarray] = {}
        for col in self._feature_columns:
            key = col.lower()
            values = np.empty(n, dtype=np.float32)
            for i, rec in enumerate(normalized):
                v = rec.get(key)
                try:
                    values[i] = float(v) if v is not None else 0.0
                except (TypeError, ValueError):
                    values[i] = 0.0
            data[col] = values

        for cat_col, categories in self._categorical.items():
            key = cat_col.lower()
            for cat in categories:
                target_low = f"{cat_col.lower()}_{str(cat).lower()}"
                actual = self._lower_to_actual.get(target_low)
                if actual is None:
                    continue
                cat_low = str(cat).lower()
                data[actual] = np.array(
                    [1.0 if str(r.get(key, "")).strip().lower() == cat_low else 0.0
                     for r in normalized],
                    dtype=np.float32,
                )

        return pd.DataFrame(data, columns=self._feature_columns)

    def _zero_non_informative(self, X: pd.DataFrame) -> pd.DataFrame:
        cols = [c for c in X.columns if c.lower() in NON_INFORMATIVE_FEATURES]
        if not cols:
            return X
        X = X.copy()
        X[cols] = 0.0
        return X

    # ------------------------------------------------------------------ #
    # Inference (single record)
    # ------------------------------------------------------------------ #
    def predict(
        self,
        record: Dict[str, Any],
        *,
        stream_ts: Optional[float] = None,
    ) -> Optional[Alert]:
        timestamp = float(stream_ts) if stream_ts is not None else time.time()
        X = self.preprocess(record)

        prob_attack, is_l1 = self._run_layer1(X)
        iso_score, is_l2 = self._run_layer2(X)

        if not is_l1 and not is_l2:
            return None

        src_ip, dst_ip = self._extract_ips(record)
        stream_meta = {k: record.get(k) for k in self.METADATA_KEYS if k in record}

        if is_l1:
            return self._build_l1_alert(
                X, timestamp, src_ip, dst_ip, prob_attack, iso_score, is_l2, stream_meta, record,
            )
        return self._build_l2_alert(
            X, timestamp, src_ip, dst_ip, prob_attack, iso_score, stream_meta, record,
        )

    # ------------------------------------------------------------------ #
    # Inference (batch)
    # ------------------------------------------------------------------ #
    def predict_batch(
        self,
        records: List[Dict[str, Any]],
        *,
        include_normal: bool = False,
    ) -> List[Optional[Alert]]:
        if not records:
            return []

        X_all = self.preprocess_batch(records)

        # XGBoost/CatBoost batch
        try:
            proba_arr = self.artifacts.xgb_model.predict_proba(X_all)
            prob_attack_all = proba_arr[:, 1] if proba_arr.ndim == 2 else proba_arr
        except Exception:  # noqa: BLE001
            LOGGER.exception("Batch predict_proba gagal")
            prob_attack_all = np.zeros(len(records), dtype=np.float32)

        # Isolation Forest batch
        iso_score_all = np.zeros(len(records), dtype=np.float32)
        if self.artifacts.iso_model is not None and self.artifacts.iso_scaler is not None:
            try:
                X_iso = self._zero_non_informative(X_all)
                X_scaled = self.artifacts.iso_scaler.transform(X_iso.values)
                iso_score_all = self.artifacts.iso_model.decision_function(X_scaled)
            except Exception:  # noqa: BLE001
                LOGGER.exception("Isolation Forest batch gagal")

        results: List[Optional[Alert]] = []
        for i, record in enumerate(records):
            prob = float(prob_attack_all[i])
            iso = float(iso_score_all[i])
            is_l1 = prob >= self.config.xgb_threshold
            is_l2 = iso < self._iso_threshold

            if not is_l1 and not is_l2 and not include_normal:
                results.append(None)
                continue

            X_row = X_all.iloc[[i]]
            timestamp = record.get("_stream_ts", time.time())
            src_ip, dst_ip = self._extract_ips(record)
            stream_meta = {k: record.get(k) for k in self.METADATA_KEYS if k in record}

            if is_l1:
                results.append(self._build_l1_alert(
                    X_row, float(timestamp), src_ip, dst_ip, prob, iso, is_l2,
                    stream_meta, record,
                ))
            elif is_l2:
                results.append(self._build_l2_alert(
                    X_row, float(timestamp), src_ip, dst_ip, prob, iso,
                    stream_meta, record,
                ))
            else:
                results.append(None)
        return results

    # ------------------------------------------------------------------ #
    # Layer runners
    # ------------------------------------------------------------------ #
    def _run_layer1(self, X: pd.DataFrame) -> Tuple[float, bool]:
        try:
            proba_arr = self.artifacts.xgb_model.predict_proba(X)
            prob = (
                float(proba_arr[0, 1])
                if proba_arr.shape[1] > 1
                else float(proba_arr[0, 0])
            )
        except Exception:  # noqa: BLE001
            LOGGER.exception("Model predict_proba gagal")
            prob = 0.0
        return prob, prob >= self.config.xgb_threshold

    def _run_layer2(self, X: pd.DataFrame) -> Tuple[float, bool]:
        if self.artifacts.iso_model is None or self.artifacts.iso_scaler is None:
            return 0.0, False
        try:
            X_iso = self._zero_non_informative(X)
            X_scaled = self.artifacts.iso_scaler.transform(X_iso.values)
            score = float(self.artifacts.iso_model.decision_function(X_scaled)[0])
            return score, score < self._iso_threshold
        except Exception:  # noqa: BLE001
            LOGGER.exception("Isolation Forest gagal; lewati layer-2")
            return 0.0, False

    # ------------------------------------------------------------------ #
    # Alert builders
    # ------------------------------------------------------------------ #
    def _build_l1_alert(
        self,
        X: pd.DataFrame,
        timestamp: float,
        src_ip: str,
        dst_ip: str,
        prob_attack: float,
        iso_score: float,
        is_l2: bool,
        stream_meta: Dict[str, Any],
        record: Dict[str, Any],
    ) -> Alert:
        severity = self._severity_from_probability(prob_attack)
        tags: List[str] = ["ZERO_DAY_CORROBORATED"] if is_l2 else []
        anomaly_type = self._infer_attack_type(X)

        alert = Alert(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            anomaly_type=anomaly_type,
            severity=severity,
            layer=1,
            score=prob_attack,
            features={
                "model_prob": prob_attack,
                "iso_score": iso_score,
                **stream_meta,
            },
            tags=tags,
            raw=record,
        )
        return alert

    def _build_l2_alert(
        self,
        X: pd.DataFrame,
        timestamp: float,
        src_ip: str,
        dst_ip: str,
        prob_attack: float,
        iso_score: float,
        stream_meta: Dict[str, Any],
        record: Dict[str, Any],
    ) -> Alert:
        severity = self._severity_from_iso(iso_score, self._iso_threshold)
        alert = Alert(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            anomaly_type="zero_day",
            severity=severity,
            layer=2,
            score=iso_score,
            features={
                "iso_score": iso_score,
                "iso_threshold": self._iso_threshold,
                "model_prob": prob_attack,
                **stream_meta,
            },
            tags=["ZERO_DAY"],
            raw=record,
        )
        return alert

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _extract_ips(self, record: Dict[str, Any]) -> Tuple[str, str]:
        rec_low = self._normalize_record(record)
        src = rec_low.get("src_ip") or rec_low.get("source_ip") or rec_low.get("src")
        dst = rec_low.get("dst_ip") or rec_low.get("destination_ip") or rec_low.get("dst")
        if self.config.strict_ips and (src is None or dst is None):
            raise ValueError(
                f"Record tidak punya src_ip/dst_ip; contoh key: {list(rec_low)[:10]}",
            )
        return (
            str(src) if src is not None else self.config.fallback_src_ip,
            str(dst) if dst is not None else self.config.fallback_dst_ip,
        )

    def _severity_from_probability(self, prob: float) -> str:
        c = self.config
        if prob >= c.sev_critical:
            return "CRITICAL"
        if prob >= c.sev_high:
            return "HIGH"
        if prob >= c.sev_medium:
            return "MEDIUM"
        return "LOW"

    def _severity_from_iso(self, score: float, threshold: float) -> str:
        if score >= threshold:
            return "LOW"

        if abs(threshold) < 1e-9:
            m = abs(score)
            if m >= 0.15:
                return "CRITICAL"
            if m >= 0.08:
                return "HIGH"
            if m >= 0.03:
                return "MEDIUM"
            return "LOW"

        ratio = (threshold - score) / abs(threshold)
        if ratio >= 2.0:
            return "CRITICAL"
        if ratio >= 1.0:
            return "HIGH"
        if ratio >= 0.3:
            return "MEDIUM"
        return "LOW"

    def _infer_attack_type(self, X: pd.DataFrame) -> str:
        if self.artifacts.iso_scaler is None:
            return "known_threat"
        try:
            z = self.artifacts.iso_scaler.transform(X.values)[0]
            top_idx = np.argsort(-np.abs(z))[:3]
            top_names = " ".join(self._feature_columns[int(i)].lower() for i in top_idx)
        except Exception:  # noqa: BLE001
            return "known_threat"

        if "syn" in top_names and "flag" in top_names:
            return "scan"
        if any(k in top_names for k in ("rate", "srate", "drate", "syn_count")):
            return "flood"
        if "duration" in top_names or "iat" in top_names:
            return "duration_anomaly"
        if "proto_" in top_names or "service_" in top_names:
            return "protocol_anomaly"
        return "known_threat"