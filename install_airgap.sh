#!/bin/bash
echo "============================================================"
echo "  GARUDA SENTINEL v1.0 - Tactical Edge SOC Installer"
echo "============================================================"
echo "[1/3] Memuat Docker Image Offline..."
docker load -i garuda-sentinel-airgap.tar

echo "[2/3] Mengatur Tag Image..."
docker tag ghcr.io/aksaex/garuda-sentinel:latest garuda-sentinel:airgap

echo "[3/3] Menjalankan Kontainer..."
docker-compose up -d

echo "============================================================"
echo "  SISTEM BERHASIL DIPASANG! Akses: http://localhost:8501"
echo "============================================================"