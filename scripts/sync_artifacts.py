import joblib
import json
import shutil
import os

print("Menyinkronkan artefak untuk UI Garuda Sentinel...")

# 1. Konversi feature_columns.pkl (joblib) ke feature_columns.json
try:
    features = joblib.load('models/preprocessors/feature_columns.pkl')
    with open('models/pretrained/feature_columns.json', 'w') as f:
        json.dump(features, f)
    print("✅ feature_columns.json berhasil dibuat di models/pretrained/")
except Exception as e:
    print(f"❌ Gagal memproses feature_columns: {e}")

# 2. Gandakan dan sesuaikan nama model XGBoost agar terdeteksi otomatis
try:
    if os.path.exists('models/pretrained/xgboost_model.pkl'):
        shutil.copy('models/pretrained/xgboost_model.pkl', 'models/pretrained/xgboost_best.pkl')
        print("✅ xgboost_best.pkl berhasil disiapkan.")
except Exception as e:
    print(f"❌ Gagal menyalin model XGBoost: {e}")

# 3. Buat file JSON kosong untuk kategori agar warning log tetap bersih
try:
    with open('models/pretrained/isolation_categorical_categories.json', 'w') as f:
        json.dump({}, f)
    print("✅ isolation_categorical_categories.json berhasil dibuat.")
except Exception as e:
    pass

print("\n--- SINKRONISASI SELESAI ---")