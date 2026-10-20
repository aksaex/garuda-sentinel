"""scripts/smoke_test.py — sanity check Phase 1 + Phase 2."""
from __future__ import annotations

import logging
import time
from pathlib import Path

from engine import (
    DetectorConfig,
    DualLayerDetector,
    StreamConfig,
    StreamGenerator,
    TriageConfig,
    TriageEngine,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s")

def main() -> None:
    detector = DualLayerDetector.load(
        DetectorConfig(model_dir=Path("models"), strict_ips=False),
        with_explainer=True,
    )
    triage = TriageEngine(
        TriageConfig(window_seconds=3.0, threshold=5, card_idle_timeout=30.0),
    )
    streamer = StreamGenerator(
        StreamConfig(csv_path=Path("data/processed/simulation_stream.csv"),
                     delay_ms=150, loop=True, max_rows=500),
    )

    last_flush = time.time()
    for record in streamer:
        alert = detector.predict(record, stream_ts=record.get("_stream_ts"))
        if alert is not None:
            card = triage.ingest(alert)
            if card is not None:
                print(f"\n=== THREAT CARD {card.card_id} ===")
                print(f"  dst      : {card.dst_ip} ({card.dst_asset})")
                print(f"  severity : {card.severity}  |  alerts: {card.alert_count}")
                print(f"  mitre    : {[t['id'] for t in card.mitre_techniques]}")
                print(f"  brief    : {card.sample_alerts[-1].features.get('explanation', '-')}\n")

        if time.time() - last_flush > 1.0:
            triage.flush_expired()
            last_flush = time.time()

    print("Stats:", triage.stats())

if __name__ == "__main__":
    main()