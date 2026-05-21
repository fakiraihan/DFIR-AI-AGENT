# Analisis: Mengapa DeepLog Gagal Deteksi pada EVTX-ATTACK-SAMPLES

## Ringkasan Masalah

Dataset [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) berisi file EVTX yang **seharusnya seluruhnya anomali**, namun DeepLog banyak yang melewatkan (miss). Setelah menelusuri pipeline, ada **6 root cause** yang teridentifikasi.

---

## Root Cause 1: Template Mismatch — Event Baru = "Unknown"

### Apa yang terjadi
DeepLog tidak bekerja dengan raw log. Ia bekerja dengan **event templates** yang dihasilkan Drain, lalu dicocokkan ke **vocab** yang dibentuk saat training.

### Alur krusial:
```
EVTX raw → Drain → event_template → vocab.get_event() → indeks
```

Jika event template dari file serangan **tidak ada di vocab training**, `get_event()` mengembalikan `unk_index`. Window yang mengandung banyak unknown langsung **di-skip**:

```python
# anomaly.py:189-197
def _should_skip_window(self, actual_idx: int, unknown_ratio: float) -> bool:
    if actual_idx == self.unk_index:
        return True  # ← Window langsung di-skip!
    return unknown_ratio >= self.max_unknown_ratio  # default 0.4
```

### Mengapa ini terjadi pada EVTX-ATTACK-SAMPLES
- File EVTX dari repo ini berisi event **yang sangat spesifik ke teknik serangan** (Sysmon EventID 1, 3, 7, 10, dll)
- Model dilatih dari data **lmd2023** (Windows event log normal) — vocab tidak mengandung template dari serangan
- **Hampir semua** event di file serangan bisa jadi unknown → skip massal

> [!CAUTION]
> Ini kemungkinan root cause terbesar. Event dari EVTX-ATTACK-SAMPLES kemungkinan besar tidak pernah ada di training data lmd2023, sehingga seluruh window di-skip dan `is_anomaly = False`.

---

## Root Cause 2: Skip Logic Terlalu Agresif

### Kode:
```python
# anomaly.py:140-144
if self._should_skip_window(actual_idx, unknown_ratio):
    evaluation_status = "skipped_unknown_template"
    is_anomaly = False          # ← Force False!
    strict_is_anomaly = False   # ← Force False!
    anomaly_score = 0.0
```

### Logika skip:
| Kondisi | Akibat |
|---------|--------|
| `actual_idx == unk_index` | Skip (anomali tidak terdeteksi) |
| `unknown_ratio >= 0.4` | Skip (40% token unknown = skip) |

### Paradoks
Pada file serangan dengan event yang **belum pernah dilihat model**:
- `actual_idx = unk_index` hampir pasti → **skip**
- Bahkan jika tidak skip, model tidak bisa memprediksi event yang tidak ada di vocab → **false normal**

---

## Root Cause 3: Window Size vs Jumlah Event File Serangan

### Config saat ini:
```python
# config.py
deeplog_window_size: int = 10   # ← 10 event per window
```

### Kode cek minimal:
```python
# anomaly.py:97
if df.empty or len(df) <= self.window_size:
    return pd.DataFrame(columns=[...])  # ← return kosong!
```

### Masalah
File EVTX dari EVTX-ATTACK-SAMPLES sering **sangat kecil** — bisa hanya berisi **5–15 event** spesifik ke satu teknik serangan (misalnya hanya 1 file EVTX untuk teknik T1055 Process Injection). Jika `len(events) <= 10`, tidak ada satu pun window yang diproses.

Contoh: file seperti `T1055_ProcessInjection_CreateRemoteThread.evtx` mungkin hanya punya 8 event.

---

## Root Cause 4: `topk` Terlalu Kecil

### Config saat ini:
```python
deeplog_topk: int = 3   # ← hanya 3 kandidat!
```

Tapi `DeepLogDetector.__init__` default:
```python
topk: int = 9   # dari anomaly.py baris 31
```

### Yang mana yang dipakai?
Ini bergantung dari cara service memanggil detector. Jika dari config `deeplog_topk=3` yang dipakai → model hanya toleran terhadap 3 kandidat berikutnya. Ini sangat ketat dan tidak fleksibel.

> [!IMPORTANT]
> Perlu dicek: apakah `topk=3` atau `topk=9` yang aktif saat runtime? Cek di service/router yang memanggil `DeepLogDetector`.

---

## Root Cause 5: Model Dilatih dari Data Normal — Bias Bawaan

### Training data:
```
lmd2023_2_3m_per_host → Windows event log normal (non-attack)
```

DeepLog adalah **sequence anomaly detector** — ia belajar urutan event yang *normal*, lalu mendeteksi event berikutnya yang tidak terduga. Ini berarti:

1. **Jika data training hanya normal** → model membangun distribusi event normal
2. **Data serangan dari EVTX-ATTACK-SAMPLES** → berisi event yang mungkin juga ada di log normal (EventID 4624, 4688, dll)
3. **Model bisa melewatkan anomali** jika urutan event serangan secara statistik **mirip** urutan event normal

### Contoh konkrit
Teknik **Pass the Hash** menghasilkan EventID 4624 (Logon) dengan LogonType=3. Pada data normal pun EventID 4624 sangat sering muncul → **model tidak menganggapnya anomali**.

---

## Root Cause 6: Template Generation Tidak Konsisten antara Training dan Inference

### Saat training (dari training workspace):
```python
# Menggunakan training Drain.py (logadempirical dataset/Drain.py)
parser = drain_module.LogParser(...)
```

### Saat inference EVTX (parsing.py:440-448):
```python
def _build_evtx_template(self, provider, event_id, raw_line):
    if self.template_strategy == "provider_eventid":
        template = f"{provider} EventID={event_id}"
        return template, template
    
    result = self.template_miner.add_log_message(raw_line)  # ← drain3 berbeda!
    return result["template_mined"], result["cluster_id"]
```

### Masalah
- Training menggunakan `logadempirical`'s Drain dengan parameter spesifik
- Inference menggunakan `drain3` (library berbeda!)
- Template yang dihasilkan **BERBEDA FORMAT** → vocab mismatch 100%

> [!WARNING]
> Ini adalah masalah **template-to-vocab gap** yang fundamental. Template dari drain3 tidak akan cocok dengan vocab yang dibangun dari template logadempirical's Drain.

---

## Ringkasan Diagnosis

| # | Root Cause | Dampak | Probabilitas |
|---|-----------|--------|-------------|
| 1 | Event attack tidak ada di vocab training | Semua window di-skip | 🔴 Sangat Tinggi |
| 2 | Skip logic agresif (unk = auto-False) | Anomali nyata diabaikan | 🔴 Sangat Tinggi |
| 3 | File EVTX terlalu kecil (< window_size) | Tidak ada window yang diproses | 🟠 Tinggi |
| 4 | topk=3 terlalu ketat | True anomali tidak masuk top-3 | 🟡 Sedang |
| 5 | Model hanya tahu pola normal | Event normal dalam konteks serangan terlewat | 🟡 Sedang |
| 6 | Drain vs drain3 template mismatch | 100% template jadi unknown | 🔴 Sangat Tinggi |

---

## Langkah Investigasi yang Disarankan

### Step 1: Cek evaluation_status di hasil
Tambahkan logging untuk melihat distribusi `evaluation_status`:
```python
# Jalankan deteksi lalu cek:
status_counts = results_df["evaluation_status"].value_counts()
print(status_counts)
# Jika mayoritas "skipped_unknown_template" → Root Cause 1/2/6 terkonfirmasi
```

### Step 2: Cek unknown_ratio rata-rata
```python
print(results_df["unknown_ratio"].describe())
# Jika mean > 0.4 → hampir semua window di-skip
```

### Step 3: Verifikasi vocab coverage
```python
# Di Python:
import pickle
with open("path/to/DeepLog.pkl", "rb") as f:
    vocab = pickle.load(f)
print(f"Vocab size: {len(vocab.itos)}")
print(f"Sample vocab entries: {vocab.itos[:20]}")
# Lihat apakah templatenya berbentuk "Microsoft-Windows-Sysmon/Operational EventID=1" atau format lain
```

### Step 4: Bandingkan template format
```python
# Parse satu file attack EVTX, print event_template-nya
# Lalu bandingkan dengan format di vocab
```

### Step 5: Coba disable skip_unknown_windows
```python
detector = DeepLogDetector(
    ...,
    skip_unknown_windows=False,  # ← nonaktifkan skip
    topk=20,  # ← naikkan topk
)
```

---

## Rekomendasi Perbaikan (Prioritas)

### P0 — Segera: Audit template format
Verifikasi bahwa template yang dihasilkan saat inference **sama persis format**-nya dengan yang ada di vocab training.

### P1 — Penting: Pisahkan skip vs mark
Alih-alih paksa `is_anomaly = False` untuk window unknown, gunakan label terpisah:
```python
evaluation_status = "skipped_unknown_template"
is_anomaly = None  # ← bukan False! Biarkan LLM layer yang putuskan
```

### P2 — Pertimbangkan: Retrain dengan data attack
Latih ulang DeepLog dengan campuran data normal **dan** serangan (tapi tanpa label) — biarkan model belajar pola urutan dari **kedua jenis** data, lalu anomali adalah deviasi dari keduanya.

### P3 — Fallback: Tambahkan rule-based layer
Untuk EVTX dengan event yang tidak ada di vocab, gunakan **rule-based heuristic** (EventID-based rules) sebagai fallback sebelum mengandalkan DeepLog.
