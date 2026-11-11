FROM python:3.13-slim

# Mencegah Python menulis file .pyc dan mem-buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Menambahkan /app ke PYTHONPATH agar modul 'engine' selalu terdeteksi
ENV PYTHONPATH=/app

# Menetapkan direktori kerja di dalam container
WORKDIR /app

# Menginstal dependensi sistem
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Menyalin requirements terlebih dahulu untuk mengoptimalkan cache Docker
COPY requirements.txt .

# Menginstal pustaka Python
RUN pip install --no-cache-dir -r requirements.txt

# Menyalin seluruh struktur folder proyek ke dalam container
COPY . .

# Mengekspos port standar Streamlit
EXPOSE 8501

# Perintah utama untuk menjalankan aplikasi
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]