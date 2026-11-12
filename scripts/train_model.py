import pandas as pd
import numpy as np
import optuna
import joblib
import os
from xgboost import XGBClassifier
from catboost import CatBoostClassifier
from sklearn.metrics import f1_score, classification_report

# 1. Setup Direktori
os.makedirs('models/pretrained', exist_ok=True)

# 2. Muat Data yang Sudah Diproses
print("Memuat data Train, Validation, dan Hold-out...")
target_col = 'Attack_type'
train_df = pd.read_csv('data/processed/train.csv')
val_df = pd.read_csv('data/processed/val.csv')
holdout_df = pd.read_csv('data/processed/holdout.csv')

X_train = train_df.drop(columns=[target_col])
y_train = train_df[target_col]
X_val = val_df.drop(columns=[target_col])
y_val = val_df[target_col]
X_holdout = holdout_df.drop(columns=[target_col])
y_holdout = holdout_df[target_col]

# Muat label encoder untuk mendapatkan nama kelas saat laporan evaluasi
label_encoder = joblib.load('models/preprocessors/label_encoder.pkl')
target_names = label_encoder.classes_

print(f"Jumlah kelas terdeteksi: {len(target_names)}")

# 3. Fungsi Objektif Optuna untuk XGBoost
def objective_xgb(trial):
    param = {
        'n_estimators': trial.suggest_int('n_estimators', 50, 200),
        'max_depth': trial.suggest_int('max_depth', 3, 9),
        'learning_rate': trial.suggest_float('learning_rate', 0.01, 0.3, log=True),
        'subsample': trial.suggest_float('subsample', 0.6, 1.0),
        'tree_method': 'hist', # Lebih cepat untuk data besar
        'random_state': 42
    }
    
    model = XGBClassifier(**param)
    model.fit(X_train, y_train, eval_set=[(X_val, y_val)], verbose=False)
    preds = model.predict(X_val)
    
    # Kita menggunakan Macro-F1 sesuai fokus skripsi
    return f1_score(y_val, preds, average='macro')

# 4. Fungsi Objektif Optuna untuk CatBoost
def objective_cat(trial):
    param = {
        'iterations': trial.suggest_int('iterations', 50, 200),
        'depth': trial.suggest_int('depth', 4, 10),
        'learning_rate': trial.suggest_float('learning_rate', 0.01, 0.3, log=True),
        'l2_leaf_reg': trial.suggest_float('l2_leaf_reg', 1, 10),
        'random_seed': 42,
        'verbose': False
    }
    
    model = CatBoostClassifier(**param)
    model.fit(X_train, y_train, eval_set=(X_val, y_val), early_stopping_rounds=20, verbose=False)
    preds = model.predict(X_val)
    
    return f1_score(y_val, preds, average='macro')

# 5. Jalankan Optuna Tuning (Set n_trials=10 untuk tes cepat. Untuk final skripsi bisa dinaikkan ke 50 atau 100)
N_TRIALS = 10 

print("\n--- Memulai Tuning XGBoost dengan Optuna ---")
study_xgb = optuna.create_study(direction='maximize')
study_xgb.optimize(objective_xgb, n_trials=N_TRIALS)
print("Best Macro-F1 XGBoost (Validation):", study_xgb.best_value)

print("\n--- Memulai Tuning CatBoost dengan Optuna ---")
study_cat = optuna.create_study(direction='maximize')
study_cat.optimize(objective_cat, n_trials=N_TRIALS)
print("Best Macro-F1 CatBoost (Validation):", study_cat.best_value)

# 6. Latih Model Final dengan Parameter Terbaik
print("\nMelatih Model Final dengan Hyperparameter Terbaik...")
best_xgb_model = XGBClassifier(**study_xgb.best_params, tree_method='hist', random_state=42)
best_xgb_model.fit(X_train, y_train)

best_cat_model = CatBoostClassifier(**study_cat.best_params, random_seed=42, verbose=False)
best_cat_model.fit(X_train, y_train)

# 7. Evaluasi Komparatif pada Data Hold-out
print("\n==================================================")
print("HASIL EVALUASI PADA DATA HOLD-OUT (DATA TAK TERLIHAT)")
print("==================================================")

preds_xgb = best_xgb_model.predict(X_holdout)
preds_cat = best_cat_model.predict(X_holdout)

macro_f1_xgb = f1_score(y_holdout, preds_xgb, average='macro')
macro_f1_cat = f1_score(y_holdout, preds_cat, average='macro')

print(f"\n[XGBoost] Macro-F1 Score: {macro_f1_xgb:.4f}")
print("Classification Report XGBoost:")
# Handle zero_division error jika ada kelas minoritas yang tidak terprediksi
print(classification_report(y_holdout, preds_xgb, target_names=target_names, zero_division=0))

print(f"\n[CatBoost] Macro-F1 Score: {macro_f1_cat:.4f}")
print("Classification Report CatBoost:")
print(classification_report(y_holdout, preds_cat, target_names=target_names, zero_division=0))

# 8. Simpan Model Terbaik untuk Tactical SOC Streamlit
print("\nMenyimpan model terbaik untuk inferensi...")
joblib.dump(best_xgb_model, 'models/pretrained/xgboost_model.pkl')
# CatBoost memiliki format natif yang lebih ringan dan cepat dimuat
best_cat_model.save_model('models/pretrained/catboost_model.cbm')

print("\n--- FASE 2 SELESAI ---")
print("✅ Model tersimpan di 'models/pretrained/'")