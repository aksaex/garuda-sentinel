#!/usr/bin/env python3
"""
engine/streamer.py
==================
Generator trafik live untuk GARUDA SENTINEL.

Membaca `simulation_stream.csv` baris demi baris, dengan jeda milidetik,
dan loop tak terbatas (opsional) untuk mensimulasikan edge sensor.

Metadata yang diinjeksi ke setiap record:
    _stream_ts  : epoch float saat baris dipancarkan
    _row_index  : nomor urut global (1-based)
    _loop_index : iterasi loop ke-berapa (0-based)

Thread-safe: pause/resume/stop via threading.Event.
"""
from __future__ import annotations

import csv
import logging
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Generator, Iterator, List, Optional

LOGGER = logging.getLogger("garuda.streamer")


@dataclass
class StreamConfig:
    csv_path: Path
    delay_ms: int = 250
    loop: bool = True
    max_rows: Optional[int] = None
    strict_columns: bool = True

    def __post_init__(self) -> None:
        self.csv_path = Path(self.csv_path)
        if self.delay_ms < 0:
            raise ValueError("delay_ms tidak boleh negatif")
        if self.max_rows is not None and self.max_rows <= 0:
            raise ValueError("max_rows harus > 0 atau None")


class StreamGenerator:
    """Generator trafik live berbasis CSV untuk simulasi Edge-Native Pipeline."""

    METADATA_KEYS = ("_stream_ts", "_row_index", "_loop_index")

    def __init__(
        self,
        config: StreamConfig,
        on_emit: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        self.config = config
        self._on_emit = on_emit
        self._stop = threading.Event()
        self._pause = threading.Event()
        self._running = threading.Event()
        self._rows_emitted = 0
        self._loops_completed = 0
        self._columns: List[str] = []
        self._validate_file()

    # ------------------------------------------------------------------ #
    # Validasi & properti
    # ------------------------------------------------------------------ #
    def _validate_file(self) -> None:
        if not self.config.csv_path.exists():
            raise FileNotFoundError(f"Stream CSV tidak ditemukan: {self.config.csv_path}")
        with self.config.csv_path.open(newline="", encoding="utf-8") as fh:
            reader = csv.reader(fh)
            try:
                header = next(reader)
            except StopIteration as exc:
                raise ValueError(f"CSV kosong: {self.config.csv_path}") from exc
        self._columns = [h.strip() for h in header if h and h.strip()]
        if not self._columns:
            raise ValueError("Header CSV tidak valid / kosong")

    @property
    def columns(self) -> List[str]:
        return list(self._columns)

    @property
    def rows_emitted(self) -> int:
        return self._rows_emitted

    @property
    def loops_completed(self) -> int:
        return self._loops_completed

    @property
    def is_running(self) -> bool:
        return self._running.is_set()

    # ------------------------------------------------------------------ #
    # Kontrol lifecycle
    # ------------------------------------------------------------------ #
    def start_control(self) -> None:
        """Reset sinyal stop agar generator bisa dijalankan ulang."""
        self._stop.clear()

    def stop(self) -> None:
        self._stop.set()
        self._pause.clear()

    def pause(self) -> None:
        self._pause.set()

    def resume(self) -> None:
        self._pause.clear()

    def _wait_if_paused(self) -> None:
        while self._pause.is_set() and not self._stop.is_set():
            time.sleep(0.05)

    # ------------------------------------------------------------------ #
    # Koersi tipe & payload
    # ------------------------------------------------------------------ #
    @staticmethod
    def _coerce(value: Optional[str]) -> Any:
        if value is None:
            return None
        text = value.strip()
        if text == "":
            return None
        low = text.lower()
        if low in {"true", "false"}:
            return low == "true"
        try:
            if any(ch in low for ch in (".", "e")) and not low.startswith("0x"):
                return float(text)
            return int(text)
        except ValueError:
            return text

    def _row_to_payload(self, raw: Dict[str, Optional[str]], loop_index: int) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            key: self._coerce(val) for key, val in raw.items() if key is not None
        }
        payload["_stream_ts"] = time.time()
        payload["_row_index"] = self._rows_emitted
        payload["_loop_index"] = loop_index
        return payload

    # ------------------------------------------------------------------ #
    # Generator utama
    # ------------------------------------------------------------------ #
    def stream(self) -> Generator[Dict[str, Any], None, None]:
        self.start_control()
        self._running.set()
        loop_index = 0
        delay_s = self.config.delay_ms / 1000.0

        try:
            while not self._stop.is_set():
                with self.config.csv_path.open(newline="", encoding="utf-8") as fh:
                    reader = csv.DictReader(fh)

                    if self.config.strict_columns and reader.fieldnames:
                        available = {str(x).strip() for x in reader.fieldnames if x}
                        missing = set(self._columns) - available
                        if missing:
                            raise ValueError(
                                f"Kolom wajib hilang dari CSV: {sorted(missing)}"
                            )

                    for raw in reader:
                        if self._stop.is_set():
                            return
                        self._wait_if_paused()
                        if self._stop.is_set():
                            return

                        self._rows_emitted += 1
                        payload = self._row_to_payload(raw, loop_index)

                        if self._on_emit is not None:
                            try:
                                self._on_emit(payload)
                            except Exception:  # noqa: BLE001
                                LOGGER.exception("on_emit callback gagal")

                        yield payload

                        if self.config.max_rows and self._rows_emitted >= self.config.max_rows:
                            return
                        if delay_s > 0:
                            time.sleep(delay_s)

                loop_index += 1
                self._loops_completed = loop_index

                if not self.config.loop:
                    return
                LOGGER.info("Loop stream #%d selesai, restarting...", loop_index)

        finally:
            self._running.clear()

    def __iter__(self) -> Iterator[Dict[str, Any]]:
        return self.stream()

    def __enter__(self) -> "StreamGenerator":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:  # noqa: ANN001
        self.stop()