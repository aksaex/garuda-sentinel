#!/usr/bin/env python3
"""
engine/detectors.py
===================
Dual-Layer Detector untuk GARUDA SENTINEL.

Layer-1 : XGBoost (known threats)       — supervisi, biner Normal/Attack
Layer-2 : Isolation Forest (zero-day)   — semi-supervisi, Normal-only

Preprocessing __wajib__ align dengan `feature_columns.json` yang
dipakai saat training XGBoost. Categorical `proto` & `service`
di-encode manual via `categorical_categories.json` agar tidak
bergantung pada objek sklearn yang mungkin berbeda versi.

Patch penting:
- `xgb_filenames`: auto-detect xgb_known_threats.json atau xgboost_best.pkl
- `_zero_non_informative()`: zero-kan id.orig_p/id.resp_p KHUSUS Layer-2
  agar Isolation Forest tidak false-positive pada port ephemeral.
- `_severity_from_iso()`: hitung severity dari magnitude decision_function
  saat threshold == 0.0 (default sklearn IsolationForest offset).
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

from engine.explainer import TacticalExplainer
from engine.triage_engine import Alert

LOGGER = logging.getLogger("garuda.detector")


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

    xgb_threshold: float = 0.5
    iso_threshold_override: Optional[float] = None
    enable_layer2: bool = True
    explain_on_attack: bool = True

    # severity dari probabilitas XGB
    sev_critical: float = 0.95
    sev_high: float = 0.85
    sev_medium: float = 0.65

    # fallback bila stream CSV tidak punya src_ip / dst_ip
    fallback_src_ip: str = "0.0.0.0"
    fallback_dst_ip: str = "0.0.0.0"
    strict_ips: bool = False


@dataclass
class ModelArtifacts:
    xgb_model: xgb.XGBClassifier
    iso_model: Any
    iso_scaler: Any
    feature_columns: List[str]
    categorical_categories: Dict[str, List[str]]
    iso_metadata: Dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Detector
# --------------------------------------------------------------------------- #
class DualLayerDetector:
    """Layer-1 (XGBoost) + Layer-2 (Isolation Forest) inference wrapper."""

    METADATA_KEYS = ("_stream_ts", "_row_index", "_loop_index")

    # Fitur yang zero-kan KHUSUS untuk Layer-2 (bukan Layer-1).
    NON_INFORMATIVE = {
        "id.orig_p", "id.resp_p",
        "unnamed: 0", "unnamed:0", "index",
        "src_ip", "dst_ip", "src_port", "dst_port", "id",
    }

    def __init__(
        self,
        artifacts: ModelArtifacts,
        config: DetectorConfig,
        explainer: Optional[TacticalExplainer] = None,
    ) -> None:
        self.artifacts = artifacts
        self.config = config
        self.explainer = explainer

        self._feature_columns = list(artifacts.feature_columns)
        self._lower_to_actual: Dict[str, str] = {c.lower(): c for c in self._feature_columns}
        self._categorical = artifacts.categorical_categories

        iso_thr = config.iso_threshold_override
        if iso_thr is None:
            iso_thr = artifacts.iso_metadata.get("score_threshold", 0.0)
        self._iso_threshold = float(iso_thr)
        LOGGER.info("Isolation Forest threshold = %.6f", self._iso_threshold)

        self._validate_category_columns()

    # ------------------------------------------------------------------ #
    # Factory
    # ------------------------------------------------------------------ #
    @classmethod
    def load(
        cls,
        config: Optional[DetectorConfig] = None,
        *,
        with_explainer: bool = True,
    ) -> "DualLayerDetector":
        config = config or DetectorConfig()
        model_dir = Path(config.model_dir)

        # --- cari XGBoost (multi-kandidat) ---
        xgb_path: Optional[Path] = None
        for fname in config.xgb_filenames:
            p = model_dir / fname
            if p.exists():
                xgb_path = p
                break
        if xgb_path is None:
            raise FileNotFoundError(
                f"Model XGBoost tidak ditemukan di {model_dir}. "
                f"Dicari: {config.xgb_filenames}\n"
                f"Jalankan: python scripts/migrate_xgb_model.py"
            )

        # --- feature columns ---
        feat_path = model_dir / config.feature_columns_filename
        if not feat_path.exists():
            raise FileNotFoundError(
                f"{feat_path} tidak ada. Jalankan: "
                f"python scripts/migrate_xgb_model.py"
            )
        feature_columns: List[str] = json.loads(feat_path.read_text(encoding="utf-8"))

        # --- load XGBoost (json / ubj / pkl) ---
        suffix = xgb_path.suffix.lower()
        if suffix in {".json", ".ubj", ".model"}:
            xgb_model = xgb.XGBClassifier()
            xgb_model.load_model(str(xgb_path))
        elif suffix in {".pkl", ".joblib"}:
            obj = joblib.load(xgb_path)
            if isinstance(obj, xgb.XGBClassifier):
                xgb_model = obj
            elif isinstance(obj, xgb.Booster):
                xgb_model = xgb.XGBClassifier()
                xgb_model._Booster = obj
            else:
                raise TypeError(f"{xgb_path} berisi {type(obj)}, bukan XGBClassifier")
        else:
            raise ValueError(f"Format tidak dikenal: {suffix}")

        # validasi konsistensi
        n_model = getattr(xgb_model, "n_features_in_", None)
        if n_model is not None and n_model != len(feature_columns):
            raise ValueError(
                f"Mismatch: XGBoost dilatih dengan {n_model} fitur "
                f"tapi feature_columns.json berisi {len(feature_columns)}"
            )
        LOGGER.info(
            "XGBoost dimuat dari %s (%s) | n_features=%d | classes=%s",
            xgb_path, suffix, len(feature_columns),
            getattr(xgb_model, "classes_", "?"),
        )

        # --- Layer-2 (opsional) ---
        iso_path = model_dir / config.iso_filename
        scaler_path = model_dir / config.iso_scaler_filename
        meta_path = model_dir / config.iso_metadata_filename

        iso_model = None
        iso_scaler = None
        iso_metadata: Dict[str, Any] = {}
        if config.enable_layer2:
            if iso_path.exists() and scaler_path.exists():
                iso_model = joblib.load(iso_path)
                iso_scaler = joblib.load(scaler_path)
                LOGGER.info("Isolation Forest dimuat dari %s", iso_path)
            else:
                LOGGER.warning(
                    "Layer-2 diminta tapi artefak tidak lengkap. "
                    "Jalankan: python train_layer2.py --input data/raw/train.csv --label-column label"
                )
            if meta_path.exists():
                iso_metadata = json.loads(meta_path.read_text(encoding="utf-8"))

        # --- categorical categories ---
        cat_path = model_dir / config.categorical_categories_filename
        categorical_categories: Dict[str, List[str]] = {}
        if cat_path.exists():
            categorical_categories = json.loads(cat_path.read_text(encoding="utf-8"))
            LOGGER.info(
                "Kategori kategorikal dimuat: %s",
                {k: len(v) for k, v in categorical_categories.items()},
            )

        artifacts = ModelArtifacts(
            xgb_model=xgb_model,
            iso_model=iso_model,
            iso_scaler=iso_scaler,
            feature_columns=feature_columns,
            categorical_categories=categorical_categories,
            iso_metadata=iso_metadata,
        )

        # --- explainer (opsional) ---
        explainer = None
        if with_explainer and config.explain_on_attack:
            try:
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
    # Preprocessing
    # ------------------------------------------------------------------ #
    def _normalize_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        return {str(k).strip().lower(): v for k, v in record.items() if k is not None}

    def preprocess(self, record: Dict[str, Any]) -> pd.DataFrame:
        """Konversi satu record stream menjadi DataFrame 1 baris align ke feature_columns."""
        rec_low = self._normalize_record(record)
        row: Dict[str, Any] = {}

        # 1) numerik & fitur non-kategorikal
        for col in self._feature_columns:
            key = col.lower()
            if key in rec_low:
                row[col] = rec_low[key]

        # 2) kategorikal -> OHE manual
        for cat_col, categories in self._categorical.items():
            val = rec_low.get(cat_col.lower())
            val = "" if val is None else str(val).strip().lower()
            for cat in categories:
                target_low = f"{cat_col.lower()}_{str(cat).lower()}"
                actual = self._lower_to_actual.get(target_low)
                if actual is None:
                    continue
                row[actual] = 1.0 if val == str(cat).lower() else 0.0

        df = pd.DataFrame([row]).reindex(columns=self._feature_columns, fill_value=0.0)
        df = df.apply(pd.to_numeric, errors="coerce").fillna(0.0).astype(np.float32)
        return df

    def _validate_category_columns(self) -> None:
        missing = []
        for cat_col, cats in self._categorical.items():
            for c in cats:
                if f"{cat_col.lower()}_{str(c).lower()}" not in self._lower_to_actual:
                    missing.append(f"{cat_col}_{c}")
        if missing:
            LOGGER.warning(
                "Kolom OHE tidak ditemukan di feature_columns (akan diabaikan): %s "
                "(total %d)",
                missing[:5], len(missing),
            )

    def _zero_non_informative(self, X: pd.DataFrame) -> pd.DataFrame:
        """Zero-kan fitur identitas/port KHUSUS untuk Layer-2.

        Konsisten dengan train_layer2.py yang zero-kan kolom ini SEBELUM
        fit scaler. Isolation Forest tidak pernah melihat variasi port,
        sehingga tidak false-positive pada port ephemeral.
        """
        cols = [c for c in X.columns if c.lower() in self.NON_INFORMATIVE]
        if not cols:
            return X
        X = X.copy()
        X[cols] = 0.0
        return X

    # ------------------------------------------------------------------ #
    # Inference
    # ------------------------------------------------------------------ #
    def predict(
        self,
        record: Dict[str, Any],
        *,
        stream_ts: Optional[float] = None,
    ) -> Optional[Alert]:
        """Return Alert bila attack/zero-day, else None."""
        timestamp = float(stream_ts) if stream_ts is not None else time.time()
        X = self.preprocess(record)

        # ---- Layer-1: XGBoost ----
        try:
            proba_arr = self.artifacts.xgb_model.predict_proba(X)
            prob_attack = (
                float(proba_arr[0, 1])
                if proba_arr.shape[1] > 1
                else float(proba_arr[0, 0])
            )
        except Exception:  # noqa: BLE001
            LOGGER.exception("XGBoost predict_proba gagal")
            prob_attack = 0.0
        is_l1 = prob_attack >= self.config.xgb_threshold

        # ---- Layer-2: Isolation Forest (dengan zero non-informative) ----
        iso_score = 0.0
        is_l2 = False
        if self.artifacts.iso_model is not None and self.artifacts.iso_scaler is not None:
            try:
                X_iso = self._zero_non_informative(X)       # ← PATCH PENTING
                X_scaled = self.artifacts.iso_scaler.transform(X_iso.values)
                iso_score = float(self.artifacts.iso_model.decision_function(X_scaled)[0])
                is_l2 = iso_score < self._iso_threshold
            except Exception:  # noqa: BLE001
                LOGGER.exception("Isolation Forest gagal; lewati layer-2")

        if not is_l1 and not is_l2:
            return None

        # ---- Metadata IP ----
        src_ip, dst_ip = self._extract_ips(record)
        stream_meta = {k: record.get(k) for k in self.METADATA_KEYS if k in record}

        # ---- Alert L1 ----
        if is_l1:
            severity = self._severity_from_probability(prob_attack)
            tags: List[str] = []
            if is_l2:
                tags.append("ZERO_DAY_CORROBORATED")
            alert = Alert(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                anomaly_type=self._infer_attack_type(X) if self.explainer else "known_threat",
                severity=severity,
                layer=1,
                score=prob_attack,
                features={"xgb_prob": prob_attack, "iso_score": iso_score, **stream_meta},
                tags=tags,
                raw=record,
            )
            if self.explainer is not None and self.config.explain_on_attack:
                try:
                    sentence, top = self.explainer.explain_known_threat(
                        X,
                        severity=severity,
                        probability=prob_attack,
                        anomaly_type=alert.anomaly_type,
                    )
                    alert.features["explanation"] = sentence
                    alert.features["top_features"] = top
                except Exception:  # noqa: BLE001
                    LOGGER.exception("Explainer L1 gagal")
            return alert

        # ---- Alert L2 (zero-day) ----
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
                "xgb_prob": prob_attack,
                **stream_meta,
            },
            tags=["ZERO_DAY"],
            raw=record,
        )
        if self.explainer is not None and self.config.explain_on_attack:
            try:
                sentence, top = self.explainer.explain_zero_day(
                    X,
                    severity=severity,
                    decision_score=iso_score,
                    score_threshold=self._iso_threshold,
                )
                alert.features["explanation"] = sentence
                alert.features["top_features"] = top
            except Exception:  # noqa: BLE001
                LOGGER.exception("Explainer L2 gagal")
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
                f"Record tidak punya src_ip/dst_ip; contoh key: {list(rec_low)[:10]}"
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
        """Hitung severity dari Isolation Forest decision score.

        Catatan penting:
        sklearn.IsolationForest.decision_function() menghasilkan:
            - skor POSITIF  = normal  (di atas threshold)
            - skor NEGATIF  = anomali (di bawah threshold)
        Threshold standar = 0.0 karena `offset_` internal sudah dikalibrasi
        dengan `contamination` saat fit().

        Skala empiris pada dataset RT-IoT (94 fitur, 10k normal):
            Normal  : +0.02 .. +0.15
            Mild    : -0.01 .. -0.05
            Anomali : -0.05 .. -0.15
            Severe  : -0.15 .. -0.30+
        """
        # Bukan anomali — tidak akan dipanggil sebenarnya, tapi jaga-jaga
        if score >= threshold:
            return "LOW"

        # Kasus standar sklearn: threshold == 0.0 → pakai magnitude absolut
        if abs(threshold) < 1e-9:
            magnitude = abs(score)
            if magnitude >= 0.15:
                return "CRITICAL"
            if magnitude >= 0.08:
                return "HIGH"
            if magnitude >= 0.03:
                return "MEDIUM"
            return "LOW"

        # Kasus threshold negatif (mis. di-override) → pakai rasio relatif
        ratio = (threshold - score) / abs(threshold)
        if ratio >= 2.0:
            return "CRITICAL"
        if ratio >= 1.0:
            return "HIGH"
        if ratio >= 0.3:
            return "MEDIUM"
        return "LOW"

    def _infer_attack_type(self, X: pd.DataFrame) -> str:
        """Heuristik tipe serangan dari top-3 |z-score| terhadap baseline."""
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