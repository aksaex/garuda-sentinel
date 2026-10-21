#!/usr/bin/env python3
"""scripts/diagnose_fast.py — Diagnostik Isolation Forest (vectorized)."""
from __future__ import annotations
import sys
from pathlib import Path
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from engine.detectors import DualLayerDetector, DetectorConfig


def batch_score(detector, df, name):
    """Vectorized: bangun seluruh matrix sekali, predict sekali."""
    records = df.to_dict(orient="records")
    # 1) Bangun semua baris hasil preprocess dalam satu list
    rows = [detector.preprocess(r).iloc[0] for r in records]
    X_all = pd.DataFrame(rows)[detector._feature_columns]

    # 2) Zero non-informative untuk L2
    X_iso = detector._zero_non_informative(X_all)

    # 3) Batch predict (ini yang bikin cepat)
    X_scaled = detector.artifacts.iso_scaler.transform(X_iso.values)
    iso_scores = detector.artifacts.iso_model.decision_function(X_scaled)
    xgb_probs = detector.artifacts.xgb_model.predict_proba(X_all)[:, 1]

    print(f"\n=== {name} (n={len(df)}) ===")
    print(f"iso_score : min={iso_scores.min():+.4f}  max={iso_scores.max():+.4f}  "
          f"mean={iso_scores.mean():+.4f}  median={np.median(iso_scores):+.4f}")
    for thr in [0.0, 0.02, 0.05, 0.08, 0.10]:
        cnt = (iso_scores < thr).sum()
        print(f"  < {thr:+.2f}  : {cnt:>6}  ({cnt/len(df)*100:5.2f}%)")
    print(f"xgb_prob  : min={xgb_probs.min():.4f}  max={xgb_probs.max():.4f}  "
          f"mean={xgb_probs.mean():.4f}")
    print(f"  >= 0.50 : {(xgb_probs >= 0.50).sum():>6}  ({(xgb_probs >= 0.50).mean()*100:5.2f}%)")
    return iso_scores, xgb_probs


def main():
    d = DualLayerDetector.load(
        DetectorConfig(model_dir=Path("models")), with_explainer=False,
    )
    print(f"iso_threshold = {d._iso_threshold:+.6f}")

    lb = pd.read_csv("data/raw/lockbox_test.csv")
    print(f"Lockbox total: {len(lb)}")
    print(f"Distribusi label: {lb['label'].value_counts().to_dict()}")

    lb_norm = lb[lb["label"] == 0].reset_index(drop=True).head(500)
    lb_att = lb[lb["label"] == 1].reset_index(drop=True).head(500)
    s_norm, _ = batch_score(d, lb_norm, "LOCKBOX Normal (label=0, n=500)")
    s_att, _ = batch_score(d, lb_att, "LOCKBOX Attack (label=1, n=500)")

    # Overlap analysis
    print("\n=== OVERLAP ANALYSIS ===")
    print(f"Normal  iso_score: mean={s_norm.mean():+.4f}  median={np.median(s_norm):+.4f}")
    print(f"Attack  iso_score: mean={s_att.mean():+.4f}  median={np.median(s_att):+.4f}")
    delta = s_att.mean() - s_norm.mean()
    print(f"Delta mean (attack − normal) = {delta:+.4f}")
    if delta < -0.03:
        print("→ ✅ Model BISA membedakan. Attack punya skor lebih rendah.")
        print(f"→ Threshold optimal ≈ {(s_norm.mean() + s_att.mean()) / 2:+.4f}")
    elif delta < 0:
        print("→ ⚠ Model membedakan tipis. Threshold harus di bawah +0.02.")
    else:
        print("→ ❌ Attack TIDAK lebih rendah dari Normal. Model tidak diskriminatif.")
        print("   Butuh unzero id.resp_p + retrain (lihat Step 3).")


if __name__ == "__main__":
    main()