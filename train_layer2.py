#!/usr/bin/env python3
"""
train_layer2.py
================
Pelatihan Layer-2 GARUDA SENTINEL: Isolation Forest (Zero-Day Detector).

Aturan keras:
- Hanya dilatih dengan data NORMAL (semi-supervised anomaly detection).
- Feature space identik dengan Layer-1 XGBoost (feature_columns.json).
- Fitur identitas/port di-zero-kan SEBELUM scaler di-fit — konsisten
  dengan detectors._zero_non_informative() saat inferensi.

Multi-strategy Normal filter (untuk dataset tanpa kelas Normal eksplisit):
    1. label           — cari literal 'Normal'/'Benign'/'0'
    2. benign_subclass — pakai subclass benign seperti 'mqtt_publish'
    3. auto            — coba semua urutan di atas

Usage:
    # RT-IoT2022 varian attack-only (CSV Anda)
    python train_layer2.py --input data/raw/RT_IoT2022.csv ^
        --normal-strategy benign_subclass --benign-classes mqtt_publish

    # Dataset dengan kelas Normal eksplisit
    python train_layer2.py --input data/raw/RT_IoT2022.csv
"""
from __future__ import annotations

import argparse
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

LOGGER = logging.getLogger("garuda.train_layer2")


# --------------------------------------------------------------------------- #
# Konstanta
# --------------------------------------------------------------------------- #
NORMAL_LABELS = {"normal", "benign", "0", "false", "no", "n", "nrm", "none"}

# Subclass yang secara semantik adalah operasi benign.
BENIGN_SUBCLASSES = {
    "benign", "benigntraffic", "benign_traffic",
    "normal", "normal_traffic", "normaltraffic",
    "mqtt_publish",         # RT-IoT2022: publish = operasi MQTT legitimate
    "mqttpublish",
}

LABEL_CANDIDATES = (
    "Attack_label", "attack_label",
    "Attack_type", "attack_type",
    "label", "Label", "class", "Class", "target",
    "category", "subcategory",
    "malicious", "anomaly", "is_attack",
)

CATEGORICAL_COLUMNS = ("proto", "service")

NON_FEATURE_ALIASES = {
    "id", "timestamp", "ts", "time", "flow_id",
    "attack_type", "attacktype", "attack_label_type", "label_type",
    "attack_label",
    "src_ip", "dst_ip", "src_port", "dst_port", "asset_id",
    "src_mac", "dst_mac",
    "label", "class", "target", "category", "subcategory",
    "malicious", "anomaly", "is_attack",
    "unnamed: 0", "unnamed:0", "index",
}

NON_INFORMATIVE = {
    "id.orig_p", "id.resp_p",
    "unnamed: 0", "unnamed:0", "index",
    "src_ip", "dst_ip", "src_port", "dst_port", "id",
}


# --------------------------------------------------------------------------- #
# 1. Deteksi label
# --------------------------------------------------------------------------- #
def detect_label_column(df: pd.DataFrame, preferred: Optional[str] = None) -> str:
    df.columns = [str(c).strip() for c in df.columns]

    if preferred and preferred in df.columns:
        return preferred

    for cand in LABEL_CANDIDATES:
        if cand in df.columns:
            return cand

    lower_map = {c.lower(): c for c in df.columns}
    for cand in LABEL_CANDIDATES:
        if cand.lower() in lower_map:
            return lower_map[cand.lower()]

    pat = re.compile(r"(label|attack|class|target|category|malicious|anomaly)", re.I)
    hits = [c for c in df.columns if pat.search(c)]
    if hits:
        hits.sort(key=lambda c: df[c].nunique())
        return hits[0]

    for col in df.columns:
        try:
            vals = set(df[col].dropna().astype(str).str.strip().unique())
        except Exception:
            continue
        if vals and vals.issubset({"0", "1", "0.0", "1.0", "true", "false"}):
            return col

    raise ValueError(
        f"Kolom label tidak ditemukan.\n"
        f"SEMUA kolom ({len(df.columns)}):\n  {list(df.columns)}\n"
        f"Tip: jalankan dengan --label-column <NAMA_KOLOM>."
    )


# --------------------------------------------------------------------------- #
# 2. Filter Normal (multi-strategy)
# --------------------------------------------------------------------------- #
def filter_normal(
    df: pd.DataFrame,
    label_col: str,
    *,
    strategy: str = "auto",
    benign_classes: Optional[Set[str]] = None,
    min_samples: int = 50,
) -> Tuple[pd.DataFrame, str]:
    """
    Filter baris Normal dengan multi-strategi.

    Return:
        (df_normal, nama_strategi_yang_dipakai)
    """
    labels = df[label_col].astype(str).str.strip().str.lower()
    n_total = len(df)

    # --- Strategy 1: explicit Normal/Benign labels ---
    if strategy in ("auto", "label"):
        mask = labels.isin(NORMAL_LABELS)
        n = int(mask.sum())
        LOGGER.info("[strategy=label] %d / %d baris cocok", n, n_total)
        if n >= min_samples:
            return df.loc[mask].reset_index(drop=True), "label"

    # --- Strategy 2: benign subclasses (mqtt_publish, dll.) ---
    if strategy in ("auto", "benign_subclass"):
        candidates = set(BENIGN_SUBCLASSES)
        if benign_classes:
            candidates |= {c.lower().strip() for c in benign_classes}
        mask = labels.isin(candidates)
        n = int(mask.sum())
        LOGGER.info(
            "[strategy=benign_subclass] %d / %d baris cocok (kandidat: %s)",
            n, n_total, sorted(candidates),
        )
        if n >= min_samples:
            return df.loc[mask].reset_index(drop=True), "benign_subclass"

    # --- Gagal semua ---
    dist_str = labels.value_counts().to_string()
    raise ValueError(
        f"Filter Normal gagal (min_samples={min_samples}).\n"
        f"Distribusi label ({n_total} baris):\n{dist_str}\n\n"
        f"Strategi dicoba: {strategy}\n"
        f"Kandidat benign: {sorted(benign_classes or BENIGN_SUBCLASSES)}\n\n"
        f"Tip:\n"
        f"  - Lihat distribusi di atas, cari kelas benign (mis. 'mqtt_publish')\n"
        f"  - Jalankan: --normal-strategy benign_subclass --benign-classes <nama_kelas>"
    )


# --------------------------------------------------------------------------- #
# 3. Feature engineering & alignment
# --------------------------------------------------------------------------- #
def _load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def align_to_feature_columns(
    X: pd.DataFrame, feature_columns: List[str]
) -> pd.DataFrame:
    lower_map = {str(c).lower(): str(c) for c in feature_columns}
    rename = {c: lower_map[c.lower()] for c in X.columns if c.lower() in lower_map}
    X = X.rename(columns=rename)
    if X.columns.duplicated().any():
        X = X.loc[:, ~X.columns.duplicated()]
    X = X.reindex(columns=list(feature_columns), fill_value=0.0)

    # Zero-kan fitur identitas/port — KONSISTEN dengan detectors._zero_non_informative
    for col in X.columns:
        if col.lower() in NON_INFORMATIVE:
            X[col] = 0.0

    return X.astype(np.float32)


def prepare_features(
    df: pd.DataFrame,
    *,
    label_col: str,
    categories: Optional[Dict[str, List[str]]] = None,
    feature_columns: Optional[List[str]] = None,
) -> Tuple[pd.DataFrame, List[str], Dict[str, List[str]]]:
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
            series = pd.Categorical(
                series, categories=sorted(series.dropna().unique().tolist())
            )
        work[col] = series
        detected_categories[col] = [str(x) for x in series.categories]

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
        for col in X.columns:
            if col.lower() in NON_INFORMATIVE:
                X[col] = 0.0
        feature_columns = list(X.columns)

    return X, feature_columns, detected_categories


# --------------------------------------------------------------------------- #
# 4. Training
# --------------------------------------------------------------------------- #
def train(
    input_csv: Path,
    label_column: Optional[str],
    model_dir: Path,
    contamination: float,
    n_estimators: int,
    random_state: int,
    feature_columns_path: Optional[Path],
    normal_strategy: str = "auto",
    benign_classes: Optional[Set[str]] = None,
) -> Dict[str, object]:
    model_dir = Path(model_dir)
    model_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(input_csv, low_memory=False)
    LOGGER.info("Loaded CSV: %d baris × %d kolom", len(df), len(df.columns))

    label_col = detect_label_column(df, label_column)
    LOGGER.info("Kolom label terdeteksi: '%s'", label_col)

    # ---- DIAGNOSTIC: distribusi label ----
    labels_series = df[label_col].astype(str).str.strip().str.lower()
    dist = labels_series.value_counts()
    LOGGER.info("Distribusi label (%d kelas, %d baris):", len(dist), len(df))
    for cls, cnt in dist.items():
        LOGGER.info("  %-30s %6d (%.1f%%)", cls, cnt, 100.0 * cnt / len(df))

    # ---- Filter Normal ----
    normal_df, strategy_used = filter_normal(
        df, label_col,
        strategy=normal_strategy,
        benign_classes=benign_classes,
        min_samples=50,
    )
    LOGGER.info(
        "✅ Filter Normal via '%s': %d / %d baris",
        strategy_used, len(normal_df), len(df),
    )
    if strategy_used == "benign_subclass":
        LOGGER.info(
            "   Justifikasi: kelas benign dipakai sebagai baseline Normal "
            "(mis. mqtt_publish = operasi MQTT legitimate IoT sensor)."
        )

    # ---- Alignment context ----
    cat_path = model_dir / "isolation_categorical_categories.json"
    categories: Optional[Dict[str, List[str]]] = None
    if cat_path.exists():
        categories = _load_json(cat_path)  # type: ignore[assignment]
        LOGGER.info(
            "Kategori kategorikal dari %s: %s",
            cat_path, {k: len(v) for k, v in categories.items()},
        )

    feature_columns: Optional[List[str]] = None
    feat_source: Optional[Path] = None
    if feature_columns_path and Path(feature_columns_path).exists():
        feature_columns = _load_json(Path(feature_columns_path))  # type: ignore
        feat_source = Path(feature_columns_path)
    elif (model_dir / "feature_columns.json").exists():
        feature_columns = _load_json(model_dir / "feature_columns.json")  # type: ignore
        feat_source = model_dir / "feature_columns.json"

    if feature_columns:
        LOGGER.info("Alignment ke %d kolom dari %s", len(feature_columns), feat_source)
    else:
        LOGGER.warning(
            "feature_columns.json tidak ditemukan. Layer-2 akan memakai kolom "
            "hasil OHE dari data Normal saja. Jalankan migrate_xgb_model.py dulu."
        )

    X, feature_columns, detected_categories = prepare_features(
        normal_df,
        label_col=label_col,
        categories=categories,
        feature_columns=feature_columns,
    )

    LOGGER.info(
        "Matriks latih: shape=%s | NON_INFORMATIVE zeroed: %s",
        X.shape,
        [c for c in X.columns if c.lower() in NON_INFORMATIVE],
    )

    # ---- Scaling ----
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X.values)

    # ---- Isolation Forest ----
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

    # ---- Simpan artefak ----
    joblib.dump(model, model_dir / "isolation_forest.pkl", compress=3)
    joblib.dump(scaler, model_dir / "isolation_scaler.pkl", compress=3)

    (model_dir / "isolation_feature_columns.json").write_text(
        json.dumps(feature_columns, indent=2), encoding="utf-8"
    )

    # MERGE kategori (jangan overwrite yang dari migration)
    merged_categories = dict(categories or {})
    merged_categories.update(detected_categories)
    cat_path.write_text(
        json.dumps(merged_categories, indent=2), encoding="utf-8"
    )

    shared_path = model_dir / "feature_columns.json"
    if not shared_path.exists():
        shared_path.write_text(json.dumps(feature_columns, indent=2), encoding="utf-8")

    metadata: Dict[str, object] = {
        "model": "IsolationForest",
        "trained_at_utc": datetime.now(timezone.utc).isoformat(),
        "input_csv": str(Path(input_csv).resolve()),
        "label_column": label_col,
        "normal_strategy": strategy_used,
        "benign_classes_used": sorted(benign_classes or []) if strategy_used == "benign_subclass" else [],
        "normal_samples": int(len(normal_df)),
        "n_features": int(len(feature_columns)),
        "contamination": float(contamination),
        "n_estimators": int(n_estimators),
        "random_state": int(random_state),
        "score_threshold": threshold,
        "sklearn_version": sklearn.__version__,
        "feature_columns_source": str(feat_source) if feat_source else "derived_from_normal_data",
        "non_informative_zeroed": sorted(
            [c for c in feature_columns if c.lower() in NON_INFORMATIVE]
        ),
        "categorical_categories": merged_categories,
    }
    (model_dir / "isolation_metadata.json").write_text(
        json.dumps(metadata, indent=2), encoding="utf-8"
    )

    LOGGER.info(
        "Selesai. Artefak tersimpan di %s | n_features=%d | threshold=%.6f | "
        "strategy=%s | normal_samples=%d",
        model_dir, len(feature_columns), threshold,
        strategy_used, len(normal_df),
    )
    return metadata


# --------------------------------------------------------------------------- #
# 5. CLI
# --------------------------------------------------------------------------- #
def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Latih Isolation Forest Layer-2 GARUDA SENTINEL"
    )
    parser.add_argument("--input", required=True, help="Path CSV RT-IoT2022")
    parser.add_argument("--label-column", default=None)
    parser.add_argument("--model-dir", default="models")
    parser.add_argument("--contamination", type=float, default=0.01)
    parser.add_argument("--n-estimators", type=int, default=200)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--feature-columns", default=None)
    parser.add_argument("--log-level", default="INFO")

    # Multi-strategy filter
    parser.add_argument(
        "--normal-strategy",
        choices=["auto", "label", "benign_subclass"],
        default="auto",
        help="Strategi filter Normal: "
             "'label' (cari Normal/Benign), "
             "'benign_subclass' (mqtt_publish dkk), "
             "'auto' (coba keduanya)",
    )
    parser.add_argument(
        "--benign-classes",
        default="mqtt_publish",
        help="Comma-separated kelas yang dianggap benign "
             "(default: mqtt_publish untuk RT-IoT2022)",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    )

    benign_set: Set[str] = set()
    if args.benign_classes:
        benign_set = {s.strip().lower() for s in args.benign_classes.split(",") if s.strip()}

    train(
        input_csv=Path(args.input),
        label_column=args.label_column,
        model_dir=Path(args.model_dir),
        contamination=args.contamination,
        n_estimators=args.n_estimators,
        random_state=args.random_state,
        feature_columns_path=Path(args.feature_columns) if args.feature_columns else None,
        normal_strategy=args.normal_strategy,
        benign_classes=benign_set,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())