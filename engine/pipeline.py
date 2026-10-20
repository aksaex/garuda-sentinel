#!/usr/bin/env python3
"""
engine/pipeline.py
==================
Orkestrasi GARUDA SENTINEL:
    StreamGenerator (background thread)
        → DualLayerDetector.predict()
        → TriageEngine.ingest()
        → ThreatCard (dipoll oleh UI Streamlit)

Thread-safe: state internal dilindungi RLock. `snapshot()` mengembalikan
dict murni (JSON-serializable) yang bisa dipakai UI tanpa risiko
race condition.
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from engine.detectors import DetectorConfig, DualLayerDetector
from engine.streamer import StreamConfig, StreamGenerator
from engine.triage_engine import ThreatCard, TriageConfig, TriageEngine

LOGGER = logging.getLogger("garuda.pipeline")


# --------------------------------------------------------------------------- #
# Konfigurasi
# --------------------------------------------------------------------------- #
@dataclass
class PipelineConfig:
    model_dir: Path = Path("models")
    stream_csv: Path = Path("data/processed/simulation_stream.csv")
    delay_ms: int = 200
    loop_stream: bool = True
    max_rows: Optional[int] = None
    flush_interval_s: float = 1.0
    recent_actions_limit: int = 200
    triage_config: TriageConfig = field(default_factory=TriageConfig)
    detector_config: DetectorConfig = field(default_factory=DetectorConfig)


# --------------------------------------------------------------------------- #
# Pipeline
# --------------------------------------------------------------------------- #
class GarudaPipeline:
    """Orkestrasi end-to-end: streamer → detector → triage."""

    def __init__(
        self,
        config: PipelineConfig,
        detector: DualLayerDetector,
        triage: TriageEngine,
        streamer: StreamGenerator,
    ) -> None:
        self.config = config
        self.detector = detector
        self.triage = triage
        self.streamer = streamer

        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._paused = threading.Event()
        self._lock = threading.RLock()

        self._actions: List[Dict[str, Any]] = []
        self._started_at: Optional[float] = None
        self._stopped_at: Optional[float] = None
        self._stats: Dict[str, int] = {
            "records_processed": 0,
            "alerts_generated": 0,
            "alerts_l1": 0,
            "alerts_l2": 0,
            "errors": 0,
            "loops_completed": 0,
        }

        # wiring isolation handler → audit log
        self.triage.register_isolation_handler(self._on_isolation)

    # ------------------------------------------------------------------ #
    # Factory
    # ------------------------------------------------------------------ #
    @classmethod
    def build(cls, config: Optional[PipelineConfig] = None) -> "GarudaPipeline":
        config = config or PipelineConfig()
        LOGGER.info("Membangun pipeline: model_dir=%s stream=%s",
                    config.model_dir, config.stream_csv)

        detector = DualLayerDetector.load(config.detector_config, with_explainer=True)
        triage = TriageEngine(config.triage_config)
        streamer = StreamGenerator(StreamConfig(
            csv_path=config.stream_csv,
            delay_ms=config.delay_ms,
            loop=config.loop_stream,
            max_rows=config.max_rows,
        ))
        return cls(config=config, detector=detector, triage=triage, streamer=streamer)

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #
    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def is_paused(self) -> bool:
        return self._paused.is_set()

    def start(self) -> bool:
        with self._lock:
            if self.is_running:
                LOGGER.info("Pipeline sudah berjalan; start diabaikan")
                return False
            self._stop.clear()
            self._paused.clear()
            self.streamer.start_control()
            self._started_at = time.time()
            self._stopped_at = None
            self._thread = threading.Thread(
                target=self._run, name="garuda-pipeline", daemon=True
            )
            self._thread.start()
            LOGGER.info("Pipeline STARTED")
            return True

    def stop(self, timeout: float = 5.0) -> bool:
        with self._lock:
            self._stop.set()
            self.streamer.stop()
            self._paused.clear()
            thread = self._thread

        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout)
            if thread.is_alive():
                LOGGER.warning("Pipeline thread tidak berhenti dalam %.1fs", timeout)

        with self._lock:
            self._stopped_at = time.time()
            self._thread = None
        LOGGER.info("Pipeline STOPPED")
        return True

    def pause(self) -> None:
        self._paused.set()
        LOGGER.info("Pipeline PAUSED")

    def resume(self) -> None:
        self._paused.clear()
        LOGGER.info("Pipeline RESUMED")

    # ------------------------------------------------------------------ #
    # Main loop
    # ------------------------------------------------------------------ #
    def _run(self) -> None:
        last_flush = time.time()
        try:
            for record in self.streamer:
                if self._stop.is_set():
                    break

                # pause loop
                while self._paused.is_set() and not self._stop.is_set():
                    time.sleep(0.1)
                if self._stop.is_set():
                    break

                self._safe_process(record)

                now = time.time()
                if now - last_flush >= self.config.flush_interval_s:
                    try:
                        self.triage.flush_expired(now)
                    except Exception:  # noqa: BLE001
                        LOGGER.exception("flush_expired gagal")
                        with self._lock:
                            self._stats["errors"] += 1
                    last_flush = now

        except Exception:  # noqa: BLE001
            LOGGER.exception("Pipeline fatal error")
            with self._lock:
                self._stats["errors"] += 1
        finally:
            try:
                self.triage.flush_expired()
            except Exception:  # noqa: BLE001
                LOGGER.exception("Final flush gagal")
            LOGGER.info("Pipeline loop exited")

    def _safe_process(self, record: Dict[str, Any]) -> None:
        try:
            alert = self.detector.predict(record, stream_ts=record.get("_stream_ts"))
        except Exception:  # noqa: BLE001
            LOGGER.exception("Detector.predict gagal")
            with self._lock:
                self._stats["errors"] += 1
            return

        with self._lock:
            self._stats["records_processed"] += 1

        if alert is None:
            return

        with self._lock:
            self._stats["alerts_generated"] += 1
            if alert.layer == 1:
                self._stats["alerts_l1"] += 1
            elif alert.layer == 2:
                self._stats["alerts_l2"] += 1

        try:
            self.triage.ingest(alert)
        except Exception:  # noqa: BLE001
            LOGGER.exception("Triage.ingest gagal")
            with self._lock:
                self._stats["errors"] += 1

    # ------------------------------------------------------------------ #
    # Isolation audit
    # ------------------------------------------------------------------ #
    def _on_isolation(self, card: ThreatCard, action: Dict[str, Any]) -> None:
        entry = {
            "ts": action["ts"],
            "type": "ISOLATION",
            "card_id": card.card_id,
            "dst_ip": card.dst_ip,
            "dst_asset": card.dst_asset,
            "severity": card.severity,
            "operator": action["operator"],
            "note": action["note"],
        }
        with self._lock:
            self._actions.append(entry)
            if len(self._actions) > self.config.recent_actions_limit:
                self._actions = self._actions[-self.config.recent_actions_limit:]
        LOGGER.warning(
            "ISOLATION | card=%s dst=%s operator=%s",
            card.card_id, card.dst_ip, action["operator"],
        )

    # ------------------------------------------------------------------ #
    # Public API untuk UI
    # ------------------------------------------------------------------ #
    def isolate(self, card_id: str, operator: str = "SOC_OPERATOR") -> Optional[ThreatCard]:
        try:
            return self.triage.isolate(card_id, operator=operator)
        except KeyError:
            LOGGER.warning("isolate: card tidak ditemukan %s", card_id)
            return None

    def acknowledge(self, card_id: str, operator: str = "SOC_OPERATOR") -> Optional[ThreatCard]:
        try:
            return self.triage.acknowledge(card_id, operator=operator)
        except KeyError:
            LOGGER.warning("acknowledge: card tidak ditemukan %s", card_id)
            return None

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            stats_copy = dict(self._stats)
            actions = list(self._actions)
            started = self._started_at
            stopped = self._stopped_at

        triage_stats = self.triage.stats()
        now = time.time()
        if started is None:
            duration = 0.0
        else:
            end = now if self.is_running else (stopped or now)
            duration = max(0.0, end - started)
        elapsed = max(duration, 1e-6)
        throughput = stats_copy["records_processed"] / elapsed

        return {
            "running": self.is_running,
            "paused": self.is_paused,
            "started_at": started,
            "stopped_at": stopped,
            "duration_s": duration,
            "uptime_s": (now - started) if (started and self.is_running) else 0.0,
            "throughput_pps": throughput,
            "stats": stats_copy,
            "triage": triage_stats,
            "recent_actions": actions[-20:],
        }

    def get_active_cards(self) -> List[Dict[str, Any]]:
        return [c.to_public_dict() for c in self.triage.get_active_cards()]

    def get_all_cards(self) -> List[Dict[str, Any]]:
        return [c.to_public_dict() for c in self.triage.get_all_cards()]