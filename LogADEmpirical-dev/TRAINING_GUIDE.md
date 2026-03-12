# Training Windows Log dengan DeepLog & LogAnomaly

## ✅ Yang Sudah Dikerjakan

### 1. **Pembersihan Proyek**
   - Dihapus model yang tidak digunakan: CNN, LogRobust, NeuralLog, LogBERT, PLELog
   - Fokus hanya pada **DeepLog** dan **LogAnomaly**
   - File yang dihapus:
     - `config/cnn.yaml`, `config/logrobust.yaml`, `config/neurallog.yaml`
     - `logadempirical/models/cnn.py`, `transformers.py`, `bert.py`, `autoencoder.py`
     - `logadempirical/models/LogBert/` (folder lengkap)
     - `logadempirical/models/PLELog/` (folder lengkap)

### 2. **Preprocessing Windows Log**
   - File input: `output.log` (10 juta baris Windows CBS log)
   - Script: `dataset/preprocess_windows_efficient.py`
   - **Hasil preprocessing:**
     - Total entries: **99,675** (sampling dari 10M lines)
     - Date range: 2014-03-12 sampai 2017-04-24
     - Components: 3 (CBS, CSI, lainnya)
     - Unique templates: 26,762
     - Output: `dataset/Windows/output.log_structured.csv`

### 3. **Konfigurasi Training**
   - **DeepLog config**: `config/windows_deeplog.yaml`
     - Sequential features: ✅
     - Window size: 10
     - Step size: 5
     - Batch size: 256
     - Epochs: 10
     - Train/Test split: 80/20
   
   - **LogAnomaly config**: `config/windows_loganomaly.yaml`
     - Sequential + Quantitative features
     - Same parameters as DeepLog

### 4. **Training Status** (SEDANG BERJALAN)
   - Model: **DeepLog**
   - Device: CUDA (GPU)
   - Progress: **55%** selesai (epoch 1/10)
   - Loss: **0.002** (turun dari 10)
   - Training log: `training_log.txt`

## 📁 Struktur File

```
LogADEmpirical-dev/
├── output.log                          # Log file asli (10M baris)
├── config/
│   ├── deeplog.yaml                    # Config HDFS (original)
│   ├── loganomaly.yaml                 # Config HDFS (original)
│   ├── windows_deeplog.yaml            # ✨ Config Windows DeepLog
│   └── windows_loganomaly.yaml         # ✨ Config Windows LogAnomaly
├── dataset/
│   ├── preprocess_windows_efficient.py # ✨ Script preprocessing
│   └── Windows/                        # ✨ Dataset Windows
│       ├── output.log_structured.csv   # Data sudah diparse
│       └── embeddings_average.json     # Embeddings (kosong untuk DeepLog)
└── logadempirical/
    └── models/
        ├── lstm.py                     # DeepLog & LogAnomaly
        ├── utils.py
        └── __init__.py

```

## 🚀 Cara Melanjutkan Training

### Jika Training Terhenti
```bash
# Lanjutkan DeepLog training
python main_run.py --config_file config/windows_deeplog.yaml

# Lihat progress
Get-Content training_log.txt -Tail 20
```

### Training LogAnomaly (Setelah DeepLog Selesai)
```bash
python main_run.py --config_file config/windows_loganomaly.yaml
```

## 📊 Monitoring Training

```powershell
# Cek progress real-time
Get-Content training_log.txt -Wait

# Cek model yang tersimpan
Get-ChildItem output/Windows/sliding/W10_S5_CTrue_train0.8/models/

# Cek hasil akhir
Get-Content training_log.txt -Tail 50
```

## 💡 Tips

1. **DeepLog** tidak memerlukan embeddings (hanya sequential features)
2. **LogAnomaly** memerlukan quantitative features (event counts)
3. Training akan save model di `output/Windows/sliding/.../models/`
4. Hasil evaluasi akan ditampilkan di akhir training
5. GPU training jauh lebih cepat (~5-10x) dari CPU

## ⚠️ Catatan

- Dataset Windows ini adalah **unsupervised** (semua label = normal/"-")
- Untuk testing yang realistis, Anda perlu menambahkan label anomaly manual di beberapa log entries
- Atau gunakan dataset yang sudah ada labelnya (HDFS, BGL, dll) dari Zenodo

## 🎯 Next Steps

1. ✅ Tunggu DeepLog training selesai (~5-10 menit)
2. Evaluasi hasil DeepLog
3. Train LogAnomaly
4. Bandingkan performa kedua model
5. (Optional) Tambahkan anomaly labels untuk testing yang lebih baik
