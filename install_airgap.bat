@echo off
title GARUDA SENTINEL - Air-Gapped Deployment
echo ============================================================
echo   GARUDA SENTINEL v1.0 - Tactical Edge SOC Installer
echo ============================================================
echo.
echo [1/3] Memuat Docker Image Offline dari Tarball...
docker load -i garuda-sentinel-airgap.tar

echo.
echo [2/3] Mengatur Tag Image Taktis...
docker tag ghcr.io/aksaex/garuda-sentinel:latest garuda-sentinel:airgap

echo.
echo [3/3] Menjalankan Orkestrasi Kontainer...
docker-compose up -d

echo.
echo ============================================================
echo   SISTEM BERHASIL DIPASANG KANP TKN KONEKSI INTERNET!
echo   Buka Browser: http://localhost:8501
echo ============================================================
pause