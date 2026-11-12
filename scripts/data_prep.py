import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
import joblib
import os

# 1. Setup Direktori untuk Output
os.makedirs('data/processed', exist_ok=True)
os.makedirs('models/preprocessors', exist_ok=True)

# 2. Load Data Raw
print("Memuat dataset RT_IOT2022...")
df = pd.read_csv('data/raw/RT_IOT2022.csv')

print(f"Bentuk data awal: {df.shape}")

# Hapus kolom index default bawaan CSV jika ada
if 'Unnamed: 0' in df.columns:
    df = df.drop(columns=['Unnamed: 0'])

# 3. Pisahkan Fitur dan Target
# Catatan: Sesuaikan 'Attack_type' dengan nama kolom label di dataset asli Anda (bisa 'label' atau 'Attack_type')
target_col = 'Attack_type' 
X = df.drop(columns=[target_col])
y = df[target_col]

# 4. Encoding Kategori
print("Melakukan encoding pada fitur kategorikal dan label...")

# Label Encoding untuk kelas target (Intrusi vs Normal)
label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)
joblib.dump(label_encoder, 'models/preprocessors/label_encoder.pkl')

# One-Hot Encoding untuk fitur kategorikal (seperti 'proto', 'service')
cat_cols = X.select_dtypes(include=['object', 'category']).columns
X_encoded = pd.get_dummies(X, columns=cat_cols, drop_first=True)

# Simpan struktur kolom fitur untuk memastikan urutan kolom sama saat inferensi/streaming di app.py
joblib.dump(list(X_encoded.columns), 'models/preprocessors/feature_columns.pkl')

# 5. Pemisahan Dataset (Train 70%, Val 15%, Hold-out 15%)
print("Membagi dataset menjadi Train, Validation, dan Hold-out...")
# Pisahkan 15% untuk Hold-out terlebih dahulu (Stratified agar distribusi kelas seimbang)
X_temp, X_holdout, y_temp, y_holdout = train_test_split(
    X_encoded, y_encoded, test_size=0.15, random_state=42, stratify=y_encoded
)
# Sisa 85% dibagi lagi menjadi Train (70%) dan Val (15%) -> 0.15 / 0.85 = ~0.1765
X_train, X_val, y_train, y_val = train_test_split(
    X_temp, y_temp, test_size=0.1765, random_state=42, stratify=y_temp
)

# 6. Scaling / Normalisasi (Fit HANYA pada data training untuk mencegah Data Leakage)
print("Melakukan scaling fitur numerik...")
scaler = StandardScaler()
X_train_scaled = pd.DataFrame(scaler.fit_transform(X_train), columns=X_train.columns)
X_val_scaled = pd.DataFrame(scaler.transform(X_val), columns=X_val.columns)
X_holdout_scaled = pd.DataFrame(scaler.transform(X_holdout), columns=X_holdout.columns)

# Simpan Scaler untuk digunakan oleh sistem SOC Streamlit
joblib.dump(scaler, 'models/preprocessors/scaler.pkl')

# 7. Simpan Data yang Telah Diproses
print("Menyimpan data latih, validasi, dan hold-out...")
train_data = X_train_scaled.copy()
train_data[target_col] = y_train
val_data = X_val_scaled.copy()
val_data[target_col] = y_val
holdout_data = X_holdout_scaled.copy()
holdout_data[target_col] = y_holdout

train_data.to_csv('data/processed/train.csv', index=False)
val_data.to_csv('data/processed/val.csv', index=False)
holdout_data.to_csv('data/processed/holdout.csv', index=False)

print("\n--- FASE 1 SELESAI ---")
print("✅ Data Train, Val, Hold-out tersimpan di 'data/processed/'")
print("✅ Label Encoder, Feature Columns, dan Scaler tersimpan di 'models/preprocessors/'")