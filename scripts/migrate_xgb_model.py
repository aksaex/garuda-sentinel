#!/usr/bin/env python3
"""
scripts/migrate_xgb_model.py
============================
Migrasi model skripsi -> format GARUDA.

Mendukung 3 tipe pickle:
  1. sklearn Pipeline (ColumnTransformer + XGBClassifier)  ← kasus Anda
  2. XGBClassifier langsung
  3. xgboost.Booster langsung

Output:
  models/xgb_known_threats.json                  (classifier)
  models/feature_columns.json                    (urutan fitur output preprocessor)
  models/isolation_categorical_categories.json    (OHE categories, jika ada)

Jalankan:
  python scripts/migrate_xgb_model.py --source models/xgboost_best.pkl
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import warnings
from pathlib import Path

import joblib
import xgboost as xgb

warnings.filterwarnings("ignore", category=UserWarning)


def load_artifact(path: Path):
    suffix = path.suffix.lower()
    if suffix in {".json", ".ubj", ".model"}:
        m = xgb.XGBClassifier()
        m.load_model(str(path))
        return m
    if suffix in {".pkl", ".joblib"}:
        return joblib.load(path)
    raise ValueError(f"Format tidak didukung: {suffix}")


def extract_from_pipeline(pipe) -> tuple:
    """Kembalikan (classifier, feature_names, ohe_categories)."""
    from sklearn.pipeline import Pipeline

    steps = dict(pipe.named_steps)
    print(f"  Pipeline steps: {list(steps.keys())}")

    # 1) cari classifier (step terakhir yang punya predict_proba)
    clf_name, clf = None, None
    for name, step in steps.items():
        if hasattr(step, "predict_proba"):
            clf_name, clf = name, step
    if clf is None:
        raise ValueError("Pipeline tidak punya step dengan predict_proba()")

    print(f"  Classifier: '{clf_name}' -> {type(clf).__name__}")
    print(f"  n_features_in_: {getattr(clf, 'n_features_in_', '?')}")
    print(f"  classes_:       {getattr(clf, 'classes_', '?')}")

    # 2) bangun sub-pipeline dari semua step sebelum classifier
    all_steps = list(steps.items())
    idx = [n for n, _ in all_steps].index(clf_name)
    pre_steps = all_steps[:idx]

    feature_names = None
    if pre_steps:
        try:
            pre_pipe = Pipeline(pre_steps)
            raw = list(pre_pipe.get_feature_names_out())
            # strip prefix seperti 'preprocessor__' / 'ohe__'
            feature_names = [
                re.sub(r"^[a-zA-Z_]\w*__", "", str(n)) for n in raw
            ]
            print(f"  ✅ feature_names_out: {len(feature_names)} kolom")
            print(f"     5 pertama : {feature_names[:5]}")
            print(f"     3 terakhir: {feature_names[-3:]}")
        except Exception as exc:
            print(f"  ⚠ get_feature_names_out gagal: {exc}")

    # 3) ekstrak OHE categories dari ColumnTransformer
    ohe_categories: dict[str, list[str]] = {}
    for step_name, step in pre_steps:
        if not hasattr(step, "transformers_"):
            continue
        for trans_name, trans, cols in step.transformers_:
            if not hasattr(trans, "categories_"):
                continue
            if isinstance(cols, slice):
                print(f"  ⚠ ColumnTransformer '{trans_name}' pakai slice; "
                      f"nama kolom OHE tidak ter-recover")
                continue
            col_list = list(cols) if isinstance(cols, (list, tuple)) else [cols]
            for col_name, cats in zip(col_list, trans.categories_):
                ohe_categories[str(col_name)] = [str(c) for c in cats]
                print(f"  ✅ OHE: {col_name} -> {len(cats)} kelas "
                      f"{list(ohe_categories[col_name])[:5]}")

    return clf, feature_names, ohe_categories


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", default="models/xgboost_best.pkl")
    ap.add_argument("--target-dir", default="models")
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()

    src = Path(args.source)
    target_dir = Path(args.target_dir)
    if not src.exists():
        print(f"❌ Tidak ada file: {src}")
        return 1

    print(f"→ Memuat {src} ({src.stat().st_size / 1024:.1f} KB)")
    obj = load_artifact(src)
    print(f"  Tipe top-level: {type(obj).__name__}")

    clf = None
    feature_names = None
    ohe_categories: dict[str, list[str]] = {}

    # ---- Case A: sklearn Pipeline ----
    if hasattr(obj, "named_steps"):
        try:
            clf, feature_names, ohe_categories = extract_from_pipeline(obj)
        except Exception as exc:
            print(f"❌ Gagal ekstrak pipeline: {exc}")
            return 2

    # ---- Case B: XGBClassifier langsung ----
    elif isinstance(obj, xgb.XGBClassifier):
        clf = obj
        fn = getattr(obj, "feature_names_in_", None)
        if fn is not None:
            feature_names = list(fn)
        elif obj.get_booster().feature_names:
            feature_names = list(obj.get_booster().feature_names)

    # ---- Case C: Booster langsung ----
    elif isinstance(obj, xgb.Booster):
        clf = xgb.XGBClassifier()
        clf._Booster = obj
        if obj.feature_names:
            feature_names = list(obj.feature_names)

    else:
        print(f"❌ Tipe tidak dikenal: {type(obj)}")
        return 3

    # ---- Validasi feature names ----
    if feature_names is None:
        print("❌ feature_names tidak ter-recover.")
        print("   Model kemungkinan dilatih dari numpy array.")
        print("   Solusi: buka notebook skripsi -> print(X_train.columns.tolist())")
        return 4

    if all(re.fullmatch(r"f\d+", n) for n in feature_names):
        print("❌ Feature names generik (f0..fN). Reconstruct manual diperlukan.")
        return 5

    # ---- Validasi classifier XGB ----
    if not isinstance(clf, xgb.XGBClassifier):
        print(f"❌ Classifier bukan XGBClassifier ({type(clf).__name__})")
        return 6

    n_model = getattr(clf, "n_features_in_", None)
    if n_model is not None and n_model != len(feature_names):
        print(f"❌ Mismatch: n_features_in_={n_model} vs "
              f"len(feature_names)={len(feature_names)}")
        return 7

    # ---- Simpan ----
    target_dir.mkdir(parents=True, exist_ok=True)

    xgb_out = target_dir / "xgb_known_threats.json"
    if xgb_out.exists() and not args.force:
        print(f"⚠ {xgb_out} sudah ada (pakai --force untuk overwrite)")
    else:
        clf.save_model(str(xgb_out))
        print(f"✅ {xgb_out} ({xgb_out.stat().st_size / 1024:.1f} KB)")

    feat_out = target_dir / "feature_columns.json"
    feat_out.write_text(json.dumps(feature_names, indent=2), encoding="utf-8")
    print(f"✅ {feat_out} ({len(feature_names)} kolom)")

    if ohe_categories:
        cat_out = target_dir / "isolation_categorical_categories.json"
        if cat_out.exists():
            existing = json.loads(cat_out.read_text(encoding="utf-8"))
            existing.update(ohe_categories)
            ohe_categories = existing
        cat_out.write_text(json.dumps(ohe_categories, indent=2), encoding="utf-8")
        print(f"✅ {cat_out}")

    # ---- Peringatan identitas ----
    bad = [f for f in feature_names if f.lower() in {
        "id.orig_p", "id.resp_p", "unnamed: 0", "unnamed:0",
        "src_ip", "dst_ip", "index",
    }]
    if bad:
        print(f"⚠ Fitur identitas/port terdeteksi: {bad}")
        print("   Patch _zero_non_informative di detectors.py WAJIB aktif.")

    print("\n✅ Migrasi selesai. Langkah berikutnya:")
    print("   python train_layer2.py --input data/raw/RT_IoT2022.csv")
    return 0


if __name__ == "__main__":
    sys.exit(main())