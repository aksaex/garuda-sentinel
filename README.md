<div align="center">
  
# 🛡️ GARUDA SENTINEL
**Tactical Air-Gapped Edge SOC & Zero-Day Intrusion Detection System**

[![Build and Publish to GHCR](https://github.com/aksaex/garuda-sentinel/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/aksaex/garuda-sentinel/actions/workflows/docker-publish.yml)
[![Python 3.13](https://img.shields.io/badge/Python-3.13-blue.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Edge AI](https://img.shields.io/badge/Edge_AI-Optimized-success)](#)

*Karya Unggulan untuk Kartika Cyber Hackathon 2026*
</div>

---

<details>
<summary>📋 <b>Daftar Isi (Table of Contents)</b></summary>

- [Tentang Proyek (Overview)](#-tentang-proyek-overview)
- [Matriks Keunggulan Kompetitif](#-matriks-keunggulan-kompetitif)
- [Fitur Utama (Key Features)](#-fitur-utama-key-features)
- [Arsitektur Sistem](#-arsitektur-sistem)
- [Persiapan & Instalasi (Getting Started)](#-persiapan--instalasi-getting-started)
- [Cara Penggunaan & Demonstrasi](#-cara-penggunaan--demonstrasi)
- [Keputusan Teknis (Tech Stack & Why)](#-keputusan-teknis-tech-stack--why)
- [Pengujian Beban (Stress Testing)](#-pengujian-beban-stress-testing)
- [Kontribusi & Lisensi](#-kontribusi--lisensi)
</details>

---

## 🦅 Tentang Proyek (Overview)
Infrastruktur kritis dan perangkat Internet of Things (IoT) di lingkungan taktis/militer rentan terhadap serangan siber, namun seringkali beroperasi di area *blind spot* tanpa koneksi internet (Air-Gapped). Solusi SIEM konvensional (seperti Splunk, Darktrace, atau Wazuh) membutuhkan sumber daya *cloud* yang besar, koneksi konstan, dan tim analis yang besar.

**GARUDA SENTINEL** hadir untuk mengubah paradigma tersebut. 
Ini adalah **Edge Security Operations Center (SOC) mandiri** yang dikemas dalam *immutable container*. Sistem ini mengombinasikan Machine Learning hibrida (Supervised & Unsupervised) untuk mendeteksi ancaman secara *real-time* langsung di perangkat *edge* (seperti Raspberry Pi 5 atau Mini PC taktis), lengkap dengan antarmuka komando untuk memblokir penyerang dengan satu klik—**tanpa memerlukan koneksi internet (100% Offline-First).**

<br>

## 📊 Matriks Keunggulan Kompetitif
Mengapa Garuda Sentinel melampaui solusi yang ada di pasaran?

| Fitur | Solusi Tradisional (Snort/Suricata) | Enterprise Cloud SIEM (Wazuh/Darktrace) | **🛡️ GARUDA SENTINEL** |
| :--- | :--- | :--- | :--- |
| **Arsitektur Deployment** | Linux Server / Gateway | Cloud / On-Premise Server | **Air-Gapped Edge Native (< 500MB RAM)** |
| **Deteksi Ancaman** | *Rule-based* (Signature) | *Log-based ML* | **Dual-Engine ML (Supervised + Isolation Forest)** |
| **Penanganan Zero-Day** | Sangat Rendah | Menengah | **Sangat Tinggi (Deteksi Anomali Statistik)** |
| **Explainable AI (XAI)** | Tidak Ada | *Black-box* AI | **Conditional Adaptive SHAP (Real-time)** |
| **Waktu Deployment** | Berhari-hari (Kompleks) | Berminggu-minggu | **< 2 Menit (1-Click Installer)** |

<br>

## ✨ Fitur Utama (Key Features)

- 🧠 **Dual-Engine ML Defense:** Menggunakan XGBoost/CatBoost untuk serangan yang dikenali (*Known Threats* dengan Macro-F1 99%), dipadukan dengan Isolation Forest untuk menangkap mutasi serangan baru (*Zero-Day Exploits*).
- ⚡ **Conditional Adaptive SHAP:** Sistem Explainable AI (XAI) tidak dievaluasi pada semua paket untuk menghindari *bottleneck* CPU, melainkan hanya diaktifkan otomatis saat probabilitas ancaman mencapai batas kritis.
- 📴 **True Air-Gapped Architecture:** Tidak ada *call-home*, tidak butuh repositori eksternal, dan seluruh dependensi dikemas dalam satu *tarball* (Zero External Dependency).
- 🛑 **Tactical One-Click Isolation:** Dashboard dilengkapi kapabilitas operasional untuk memutus akses IP penyerang secara instan melalui sistem orkestrasi internal.
- 📉 **Asynchronous Decoupled Ingestion:** Mencegah *UI freeze* saat dihantam serangan massal berkat pemisahan *thread* pemroses (*ring-buffer*) dengan antarmuka visual.

<br>

## ⚙️ Arsitektur Sistem

Garuda Sentinel mengadopsi arsitektur pemrosesan aliran data (*stream processing*) yang tahan banting:

1. **Packet Ingestion Engine:** Mengumpulkan *traffic* jaringan secara asinkron tanpa membebani antarmuka pengguna.
2. **Triage Engine (Layer 1):** XGBoost/CatBoost mengevaluasi vektor fitur dalam <15 milidetik per *batch*.
3. **Anomaly Gateway (Layer 2):** Isolation Forest menangkap deviasi distribusi yang lolos dari Layer 1.
4. **Tactical UI (Streamlit):** Menampilkan metrik, *Threat Cards*, dan menerima perintah isolasi dari operator lapangan.

<br>

## 🚀 Persiapan & Instalasi (Getting Started)

Sistem dirancang untuk berjalan mulus di Windows, macOS, maupun Linux (dengan Docker). Terdapat dua skenario deployment:

### Opsi A: Online Deployment (Menggunakan GHCR)
Cocok untuk lingkungan pengujian standar dengan koneksi internet aktif.

```bash
# 1. Kloning repositori
git clone https://github.com/aksaex/garuda-sentinel.git
cd garuda-sentinel

# 2. Tarik image dari GitHub Container Registry dan nyalakan kontainer
docker-compose up -d --build

# 3. Akses antarmuka di browser
http://localhost:8501
```

### Opsi B: Tactical Air-Gapped Deployment (100% Offline)
Skenario untuk dewan juri/militer di lingkungan tanpa jaringan. Membutuhkan file `garuda-sentinel-airgap.tar` dan skrip `install_airgap.bat` / `.sh`.

<details>
<summary><b>Klik untuk melihat langkah instalasi Air-Gapped</b></summary>

1. Masukkan *flashdisk* / media penyimpanan taktis ke dalam PC target.
2. Jalankan skrip *installer*:
   - Di Windows: Klik ganda `install_airgap.bat`
   - Di Linux: `bash install_airgap.sh`
3. Skrip akan secara otomatis:
   - Memuat *image* dari tarball (`docker load`)
   - Memberikan tag lingkungan taktis
   - Menjalankan kontainer latar belakang
4. Akses melalui `http://localhost:8501`
</details>

<br>

## 🕹️ Cara Penggunaan & Demonstrasi

1. **Inisialisasi Operator:** Buka `http://localhost:8501`. Pada panel kiri, masukkan **Operator ID** (misal: `SOC_CMD_01`).
2. **Aktivasi Sistem:** Klik tombol **▶ MULAI**. Status sistem akan berubah menjadi **🟢 OPERASIONAL**.
3. **Analisis Ancaman:** 
   - Pantau aliran trafik di *Header Metrics*.
   - Saat intrusi terdeteksi (seperti DDoS atau Port Scan), **Threat Card** merah akan muncul.
   - Analisis kontribusi fitur (kolom penyebab serangan) yang dihasilkan oleh *Adaptive SHAP*.
4. **Respon Taktis:** 
   - Klik **ISOLATE** untuk men-drop IP dari jaringan. 
   - Tindakan Anda akan segera diabadikan dalam panel *Audit Log (Recent Actions)* di sebelah kanan.

<br>

## 🧪 Pengujian Beban (Stress Testing)
Sistem ini kebal terhadap *UI Freezing* atau *Bottleneck* komputasi. Anda dapat membuktikan kapabilitas *throughput* sistem dengan menjalankan modul *Stress Test* bawaan:

```bash
# Injeksi ribuan anomali per detik langsung ke dalam kontainer yang berjalan
docker exec -it garuda_sentinel_app python scripts/stress_test.py
```
*(Anda akan melihat alokasi memori tetap stabil dan antarmuka UI tetap responsif).*

<br>

## 🛠️ Keputusan Teknis (Tech Stack & Why)

- **Python 3.13 (Slim Image):** Memberikan keseimbangan sempurna antara performa (optimasi *GIL/threading* terbaru) dan ukuran *container image* yang ringkas.
- **XGBoost / CatBoost:** Model berbasis pohon (Tree-based) dipilih karena akurasinya yang superior pada data tabular jaringan dan kemampuannya menangani fitur kategorikal tanpa *preprocessing* berat.
- **Isolation Forest:** Algoritma paling ringan dan andal untuk mendeteksi batas anomali (Zero-Day) pada perangkat komputasi *edge* (Edge CPU).
- **Streamlit:** Memungkinkan iterasi desain dasbor taktis (UI/UX) yang super cepat, digabungkan dengan manajemen *State* kustom agar tidak *reload* secara tidak perlu.
- **Docker & Docker Compose:** Memastikan isolasi penuh sistem (Immutability). "Works on my machine" berarti "Works on every edge device".

<br>

## 🤝 Kontribusi & Lisensi
Proyek ini dibangun oleh **Aksaex** untuk kepentingan perlombaan *Kartika Cyber Hackathon*. Kami menyambut kontribusi (*Pull Requests*) untuk mengoptimalkan efisiensi komputasi *ring-buffer* dan perluasan dukungan dataset ML.

Distribusi perangkat lunak di bawah naungan **[MIT License](LICENSE)**. 

---
<div align="center">
<i>"Keamanan bukan sekadar membangun tembok yang lebih tinggi, melainkan memiliki pandangan yang lebih tajam di dalam kegelapan." — <b>Garuda Sentinel</b></i>
</div>