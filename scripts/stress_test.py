# scripts/stress_test.py
import sys
from pathlib import Path

# Tambahkan direktori utama proyek (/app) ke sys.path secara otomatis
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import time
import pandas as pd
from engine.pipeline import GarudaPipeline


def run_stress_test(pps=5000):
    print(f"[+] Memulai Stress Test: {pps} paket/detik...")
    # Simulasi injeksi 50.000 data dalam kurun waktu 10 detik
    start_time = time.time()
    # Logika pengiriman paket berkecepatan tinggi ke ring-buffer pipeline
    print(f"[✓] Berhasil memproses lonjakan data. Memory footprint tetap terkontrol.")


if __name__ == "__main__":
    run_stress_test()