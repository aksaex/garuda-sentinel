#!/usr/bin/env python3
"""
train_layer2.py
================
Pelatihan Layer-2 GARUDA SENTINEL: Isolation Forest (Zero-Day Detector).

Aturan keras:
- Hanya dilatih dengan data NORMAL (semi-supervised anomaly detection).
- Feature space harus identik dengan Layer-1 XGBoost (83 kolom OHE).
  Bila `models/feature_columns.json` tersedia, skrip akan align kolom
  secara case-insensitive lalu reindex (kolom hilang diisi 0.0).

Usage:
    python train_layer2.py \
        --input data/raw/RT_IoT2022.csv \
        --label-column Attack_label \
        --model-dir models \
        --contamination 0.01
"""
from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

LOGGER = logging.getLogger("garuda.train_layer2")

NORMAL_LABELS = {"normal", "benign", "0", "false", "no", "n", "nrm", "none"}
LABEL_CANDIDATES = ("Attack_label", "attack_label", "label", "Label", "class", "target")
CATEGORICAL_COLUMNS = ("proto", "service")
NON_FEATURE_ALIASES = {
    "id", "timestamp", "ts", "time", "flow_id",
    "attack_type", "attacktype", "attack_label_type", "label_type",
    "src_ip", "dst_ip", "src_port", "dst_port", "asset_id",
    "src_mac", "dst_mac", "label", "attack_label",
}


# --------------------------------------------------------------------------- #
# 1. Deteksi & filter label
# --------------------------------------------------------------------------- #
def detect_label_column(df: pd.DataFrame, preferred: Optional[str] = None) -> str:
    if preferred and preferred in df.columns:
        return preferred
    for cand in LABEL_CANDIDATES:
        if cand in df.columns:
            return cand
    lower_map = {c.lower(): c for c in df.columns}
    for cand in LABEL_CANDIDATES:
        if cand.lower() in lower_map:
            return lower_map[cand.lower()]
    raise ValueError(
        f"Kolom label tidak ditemukan. Kandidat: {LABEL_CANDIDATES}. "
        f"Kolom tersedia: {list(df.columns)[:20]}..."
    )


def filter_normal(df: pd.DataFrame, label_col: str) -> pd.DataFrame:
    labels = df[label_col].astype(str).str.strip().str.lower()
    mask = labels.isin(NORMAL_LABELS)
    n_normal = int(mask.sum())
    if n_normal == 0:
        raise ValueError(
            f"Tidak ada baris Normal pada kolom '{label_col}'. "
            f"Nilai unik: {labels.unique()[:10]}"
        )
    LOGGER.info("Filter Normal: %d / %d baris", n_normal, len(df))
    return df.loc[mask].reset_index(drop=True)


# --------------------------------------------------------------------------- #
# 2. Feature engineering & alignment
# --------------------------------------------------------------------------- #
def _load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def align_to_feature_columns(X: pd.DataFrame, feature_columns: List[str]) -> pd.DataFrame:
    """Samakan nama kolom secara case-insensitive, lalu reindex ke urutan XGBoost."""
    lower_map = {str(c).lower(): str(c) for c in feature_columns}
    rename = {c: lower_map[c.lower()] for c in X.columns if c.lower() in lower_map}
    X = X.rename(columns=rename)
    if X.columns.duplicated().any():
        X = X.loc[:, ~X.columns.duplicated()]
    X = X.reindex(columns=list(feature_columns), fill_value=0.0)
    return X.astype(np.float32)


def prepare_features(
    df: pd.DataFrame,
    *,
    label_col: str,
    categories: Optional[Dict[str, List[str]]] = None,
    feature_columns: Optional[List[str]] = None,
) -> Tuple[pd.DataFrame, List[str], Dict[str, List[str]]]:
    """Bangun matriks fitur numerik dari dataframe mentah."""
    work = df.copy()

    drop_cols = {label_col}
    for c in work.columns:
        if c.lower() in NON_FEATURE_ALIASES:
            drop_cols.add(c)

    cat_cols = [c for c in CATEGORICAL_COLUMNS if c in work.columns]
    detected_categories: Dict[str, List[str]] = {}

    for col in cat_cols:
        series = work[col].astype(str).str.strip().str.lower()
        if categories and col in categories:
            series = pd.Categorical(series, categories=categories[col])
        else:
            series = pd.Categorical(series, categories=sorted(series.dropna().unique().tolist()))
        work[col] = series
        detected_categories[col] = [str(x) for x in series.cat.categories]

    X = pd.get_dummies(
        work.drop(columns=[c for c in drop_cols if c in work.columns]),
        columns=cat_cols,
        dtype=np.int8,
    )
    X = X.apply(pd.to_numeric, errors="coerce").fillna(0.0).astype(np.float32)

    if feature_columns:
        X = align_to_feature_columns(X, feature_columns)
        feature_columns = list(feature_columns)
    else:
        feature_columns = list(X.columns)

    return X, feature_columns, detected_categories


# --------------------------------------------------------------------------- #
# 3. Training
# --------------------------------------------------------------------------- #
def train(
    input_csv: Path,
    label_column: Optional[str],
    model_dir: Path,
    contamination: float,
    n_estimators: int,
    random_state: int,
    feature_columns_path: Optional[Path],
) -> Dict[str, object]:
    model_dir = Path(model_dir)
    model_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(input_csv, low_memory=False)
    label_col = detect_label_column(df, label_column)
    normal_df = filter_normal(df, label_col)

    # --- muat konteks alignment (jika ada) ---
    categories: Optional[Dict[str, List[str]]] = None
    cat_path = model_dir / "isolation_categorical_categories.json"
    if cat_path.exists():
        categories = _load_json(cat_path)  # type: ignore[assignment]

    feature_columns: Optional[List[str]] = None
    feat_source: Optional[Path] = None
    if feature_columns_path and Path(feature_columns_path).exists():
        feature_columns = _load_json(Path(feature_columns_path))  # type: ignore[assignment]
        feat_source = Path(feature_columns_path)
    elif (model_dir / "feature_columns.json").exists():
        feature_columns = _load_json(model_dir / "feature_columns.json")  # type: ignore[assignment]
        feat_source = model_dir / "feature_columns.json"

    if feature_columns:
        LOGGER.info("Alignment ke %d kolom dari %s", len(feature_columns), feat_source)
    else:
        LOGGER.warning(
            "feature_columns.json tidak ditemukan. Layer-2 akan memakai kolom "
            "hasil OHE dari data Normal saja. Pastikan urutan fitur sama dengan XGBoost!"
        )

    X, feature_columns, detected_categories = prepare_features(
        normal_df,
        label_col=label_col,
        categories=categories,
        feature_columns=feature_columns,
    )

    LOGGER.info("Matriks latih: shape=%s", X.shape)

    # --- scaling ---
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X.values)

    # --- Isolation Forest ---
    model = IsolationForest(
        n_estimators=n_estimators,
        max_samples="auto",
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1,
        verbose=0,
    )
    model.fit(X_scaled)

    scores = model.decision_function(X_scaled)
    threshold = float(np.quantile(scores, contamination))

    # --- simpan artefak ---
    joblib.dump(model, model_dir / "isolation_forest.pkl", compress=3)
    joblib.dump(scaler, model_dir / "isolation_scaler.pkl", compress=3)

    (model_dir / "isolation_feature_columns.json").write_text(
        json.dumps(feature_columns, indent=2), encoding="utf-8"
    )
    (model_dir / "isolation_categorical_categories.json").write_text(
        json.dumps(detected_categories, indent=2), encoding="utf-8"
    )

    # Jika belum ada shared feature_columns, simpan sebagai kontrak bersama.
    shared_path = model_dir / "feature_columns.json"
    if not shared_path.exists():
        shared_path.write_text(json.dumps(feature_columns, indent=2), encoding="utf-8")

    metadata: Dict[str, object] = {
        "model": "IsolationForest",
        "trained_at_utc": datetime.now(timezone.utc).isoformat(),
        "input_csv": str(Path(input_csv).resolve()),
        "label_column": label_col,
        "normal_samples": int(len(normal_df)),
        "n_features": int(len(feature_columns)),
        "contamination": float(contamination),
        "n_estimators": int(n_estimators),
        "random_state": int(random_state),
        "score_threshold": threshold,
        "sklearn_version": sklearn.__version__,
        "feature_columns_source": str(feat_source) if feat_source else "derived_from_normal_data",
        "categorical_categories": detected_categories,
    }
    (model_dir / "isolation_metadata.json").write_text(
        json.dumps(metadata, indent=2), encoding="utf-8"
    )

    LOGGER.info(
        "Selesai. Artefak tersimpan di %s | n_features=%d | threshold=%.6f",
        model_dir, len(feature_columns), threshold,
    )
    return metadata


# --------------------------------------------------------------------------- #
# 4. CLI
# --------------------------------------------------------------------------- #
def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Latih Isolation Forest Layer-2 GARUDA SENTINEL")
    parser.add_argument("--input", required=True, help="Path CSV RT-IoT2022")
    parser.add_argument("--label-column", default=None, help="Nama kolom label (auto-detect jika kosong)")
    parser.add_argument("--model-dir", default="models", help="Direktori output artefak")
    parser.add_argument("--contamination", type=float, default=0.01,
                        help="Proporsi outlier yang diasumsikan (default 1%%)")
    parser.add_argument("--n-estimators", type=int, default=200)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--feature-columns", default=None,
                        help="Path feature_columns.json milik XGBoost (opsional)")
    parser.add_argument("--log-level", default="INFO")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    )
    train(
        input_csv=Path(args.input),
        label_column=args.label_column,
        model_dir=Path(args.model_dir),
        contamination=args.contamination,
        n_estimators=args.n_estimators,
        random_state=args.random_state,
        feature_columns_path=Path(args.feature_columns) if args.feature_columns else None,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())