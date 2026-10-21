#!/usr/bin/env python3
"""scripts/diagnose_layer2.py — Diagnostik Isolation Forest."""
from __future__ import annotations
import sys
from pathlib import Path
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from engine.detectors import DualLayerDetector, DetectorConfig


def score_df(detector, df, name, n=None):
    if n:
        df = df.head(n)
    iso_scores, xgb_probs = [], []
    for _, row in df.iterrows():
        X = detector.preprocess(row.to_dict())
        X_iso = detector._zero_non_informative(X)
        X_scaled = detector.artifacts.iso_scaler.transform(X_iso.values)
        iso_scores.append(float(detector.artifacts.iso_model.decision_function(X_scaled)[0]))
        xgb_probs.append(float(detector.artifacts.xgb_model.predict_proba(X)[0, 1]))
    iso_scores = np.array(iso_scores)
    xgb_probs = np.array(xgb_probs)

    print(f"\n=== {name} (n={len(df)}) ===")
    print(f"iso_score : min={iso_scores.min():+.4f}  max={iso_scores.max():+.4f}  "
          f"mean={iso_scores.mean():+.4f}  median={np.median(iso_scores):+.4f}")
    print(f"  <  0.00 : {(iso_scores < 0.00).sum():>6}  ({(iso_scores < 0.00).mean()*100:5.2f}%)")
    print(f"  < -0.02 : {(iso_scores < -0.02).sum():>6}  ({(iso_scores < -0.02).mean()*100:5.2f}%)")
    print(f"  < -0.05 : {(iso_scores < -0.05).sum():>6}  ({(iso_scores < -0.05).mean()*100:5.2f}%)")
    print(f"  < -0.10 : {(iso_scores < -0.10).sum():>6}  ({(iso_scores < -0.10).mean()*100:5.2f}%)")
    print(f"xgb_prob  : min={xgb_probs.min():.4f}  max={xgb_probs.max():.4f}  "
          f"mean={xgb_probs.mean():.4f}")
    print(f"  >= 0.50 : {(xgb_probs >= 0.50).sum():>6}  ({(xgb_probs >= 0.50).mean()*100:5.2f}%)")
    return iso_scores


def main():
    detector = DualLayerDetector.load(
        DetectorConfig(model_dir=Path("models")), with_explainer=False,
    )
    print(f"iso_threshold = {detector._iso_threshold:+.10f}")

    train = pd.read_csv("data/raw/train.csv")
    train_norm = train[train["label"] == 0].reset_index(drop=True)
    score_df(detector, train_norm, "TRAIN Normal (label=0)", n=1000)

    lb = pd.read_csv("data/raw/lockbox_test.csv")
    print(f"\nLockbox total: {len(lb)}")
    print(f"Label distribusi: {lb['label'].value_counts().to_dict()}")
    print(f"First 200 baris label: {lb.head(200)['label'].value_counts().to_dict()}")

    lb_norm = lb[lb["label"] == 0].reset_index(drop=True)
    lb_att = lb[lb["label"] == 1].reset_index(drop=True)
    score_df(detector, lb_norm, "LOCKBOX Normal (label=0)", n=500)
    score_df(detector, lb_att, "LOCKBOX Attack (label=1)", n=500)


if __name__ == "__main__":
    main()