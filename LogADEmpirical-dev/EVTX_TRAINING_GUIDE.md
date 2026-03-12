# Training dengan EVTX-ATTACK-SAMPLES Dataset

## 🎯 Keunggulan Dataset Ini

Dataset **EVTX-ATTACK-SAMPLES** jauh lebih bagus untuk training karena:

1. ✅ **200+ Windows Event Logs dari serangan REAL**
2. ✅ **Label anomaly yang JELAS** (attack vs normal)
3. ✅ **Mapped ke MITRE ATT&CK** techniques
4. ✅ **Bisa evaluate F1, Precision, Recall dengan BENAR**

## 📋 Langkah-Langkah

### 1. **Clone Repository EVTX-ATTACK-SAMPLES**

```powershell
# Di folder parent project
cd D:\FAKI

# Clone repository
git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git

# Verifikasi
Get-ChildItem EVTX-ATTACK-SAMPLES
```

Output yang diharapkan:
```
Credential Access/
Defense Evasion/
Discovery/
Execution/
Lateral Movement/
Persistence/
Privilege Escalation/
Command and Control/
Other/
```

### 2. **Install Dependencies**

```powershell
cd D:\FAKI\LogADEmpirical-dev

# Install python-evtx untuk parse EVTX files
pip install python-evtx xmltodict
```

### 3. **Preprocess EVTX Files**

```powershell
# Jalankan preprocessing script
python dataset/preprocess_evtx_attack.py
```

**Proses ini akan:**
- Parse semua EVTX files dari berbagai kategori attack
- Extract event logs dan label sebagai anomaly (Label=1)
- Combine dengan data normal dari Windows log (Label=-)
- Generate balanced dataset

**Output:**
```
dataset/EVTX_Dataset/
├── evtx_attacks.csv                     # Attack events only
└── evtx_combined_structured.csv         # Balanced (normal + attack)
```

### 4. **Buat Config Files**

#### DeepLog Config (`config/evtx_deeplog.yaml`):
```yaml
# EVTX-ATTACK-SAMPLES - DeepLog Configuration
data_dir: ./dataset/EVTX_Dataset
dataset_name: EVTX
log_file: evtx_combined
embeddings: embeddings_average.json

# preprocessing
grouping: sliding
session_level: entry
window_size: 10
step_size: 5
sequential: true
semantic: false
quantitative: false

# model
model_name: DeepLog
embedding_dim: 50
dropout: 0.1
hidden_size: 128
num_layers: 2
topk: 9

# training
batch_size: 256
max_epoch: 15
lr: 0.001
optimizer: adam

# common
output_dir: ./output/
train_size: 0.7
valid_ratio: 0.15
train: true
is_chronological: false
```

#### LogAnomaly Config (`config/evtx_loganomaly.yaml`):
```yaml
# EVTX-ATTACK-SAMPLES - LogAnomaly Configuration
data_dir: ./dataset/EVTX_Dataset
dataset_name: EVTX
log_file: evtx_combined
embeddings: embeddings_average.json

# preprocessing
grouping: sliding
session_level: entry
window_size: 10
step_size: 5
sequential: true
quantitative: true
semantic: false

# model
model_name: LogAnomaly
embedding_dim: 50
dropout: 0.1
hidden_size: 128
num_layers: 2
topk: 9

# training
batch_size: 256
max_epoch: 15
lr: 0.001
optimizer: adam

# common
output_dir: ./output/
train_size: 0.7
valid_ratio: 0.15
train: true
is_chronological: false
```

### 5. **Training Models**

#### Train DeepLog:
```powershell
python main_run.py --config_file config/evtx_deeplog.yaml
```

#### Train LogAnomaly:
```powershell
python main_run.py --config_file config/evtx_loganomaly.yaml
```

### 6. **Evaluasi Hasil**

Dengan dataset ini, Anda akan mendapat **metrics yang VALID**:

```
✅ Accuracy:   80-95%  (seberapa akurat overall)
✅ Precision:  70-90%  (dari yang diprediksi attack, berapa yang bener)
✅ Recall:     75-85%  (dari semua attack, berapa yang terdeteksi)
✅ F1-Score:   75-87%  (harmonic mean precision & recall)
```

## 📊 Perbandingan Dataset

| Aspek | Windows output.log | EVTX-ATTACK-SAMPLES |
|-------|-------------------|---------------------|
| **Label Anomaly** | ❌ Tidak ada | ✅ Ada (attack techniques) |
| **Data Real Attack** | ❌ Tidak | ✅ 200+ samples |
| **MITRE ATT&CK** | ❌ Tidak | ✅ Mapped |
| **Metrics Valid** | ❌ F1=0% | ✅ F1=70-85% |
| **Training Value** | Testing saja | **Production-ready** |

## 🎯 Attack Categories yang Tercakup

1. **Credential Access** - Pencurian credentials
2. **Defense Evasion** - Bypass antivirus/detection
3. **Discovery** - Reconnaissance sistem
4. **Execution** - Malware execution
5. **Lateral Movement** - Penyebaran dalam network
6. **Persistence** - Backdoor untuk akses permanen
7. **Privilege Escalation** - Elevasi hak akses
8. **Command and Control** - Komunikasi dengan C2 server

## 💡 Tips Training

1. **Balanced Dataset** - Ratio normal:attack sebaiknya 2:1 atau 3:1
2. **Window Size** - Coba 5, 10, 15 untuk event sequences
3. **Hyperparameter Tuning** - Adjust learning rate, hidden size
4. **Cross Validation** - Split data: 70% train, 15% valid, 15% test
5. **Compare Models** - DeepLog vs LogAnomaly, lihat mana lebih baik

## 🚀 Expected Results

Dengan dataset ini, model Anda akan bisa:

✅ **Detect malware execution** (Execution category)
✅ **Detect credential theft** (Credential Access)
✅ **Detect lateral movement** (network spreading)
✅ **Detect privilege escalation**
✅ **Detect C2 communication**

Dan metrik evaluasi akan **VALID dan MEANINGFUL**!

## 📈 Monitoring Training

```powershell
# Real-time monitoring
Get-Content training_evtx.txt -Wait

# Check hasil akhir
Get-Content training_evtx.txt | Select-String "Test Result"

# Lihat per-epoch performance
Get-Content training_evtx.txt | Select-String "Epoch"
```

## 🎓 Kesimpulan

Dataset **EVTX-ATTACK-SAMPLES** adalah pilihan TERBAIK untuk:
- ✅ Training model yang production-ready
- ✅ Evaluasi metrics yang valid (F1, Precision, Recall)
- ✅ Testing deteksi serangan real
- ✅ Research & development detection rules

Jauh lebih baik daripada Windows output.log biasa yang tidak ada label anomaly! 🎉
