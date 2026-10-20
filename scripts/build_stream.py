#!/usr/bin/env python3
"""scripts/build_stream.py — Bangun simulation_stream.csv dengan metadata IP."""
from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd


def assign_ips(df: pd.DataFrame, seed: int = 42) -> pd.DataFrame:
    n = len(df)
    df = df.copy()
    df["src_ip"] = [f"192.168.{(i // 250) % 10}.{(i % 250) + 1}" for i in range(n)]
    df["dst_ip"] = [f"10.0.0.{(i % 20) + 1}" for i in range(n)]
    return df


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", default="data/processed/simulation_stream.csv")
    ap.add_argument("--stride", type=int, default=5, help="Ambil setiap baris ke-N")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    df = pd.read_csv(args.input, low_memory=False)
    df = df.iloc[:: args.stride].reset_index(drop=True)
    df = assign_ips(df, seed=args.seed)

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out, index=False)
    print(f"Tersimpan: {out} ({len(df)} baris, {len(df.columns)} kolom)")


if __name__ == "__main__":
    main()