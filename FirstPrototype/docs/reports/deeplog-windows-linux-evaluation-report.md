# Laporan Evaluasi DeepLog Terbaik: Windows LMD/Sysmon Enriched dan Linux APT 2024

Tanggal kompilasi: 2026-05-29

## Ruang Lingkup

Laporan ini hanya memuat dua jalur DeepLog terbaik yang sudah punya evidence paling kuat:

1. Windows LMD/Sysmon Enriched Cached Evaluation.
2. Linux APT Dataset 2024 Cached Evaluation.

Format kedua subbab dibuat sama: identitas run, dataset, konfigurasi training, artefak, tabel evaluasi natural per top-k, tabel evaluasi balanced per top-k, titik terbaik, dan interpretasi. Eksperimen lain seperti Organization-X, AIT-LDS, Loghub cross-dataset, Apache subset, dan Windows LogHub tidak dimasukkan sebagai hasil utama di dokumen ini.

## Ringkasan Hasil Utama

| Jalur | Natural best point | Balanced best point | Kesimpulan singkat |
| --- | --- | --- | --- |
| Windows LMD/Sysmon enriched | top-k 9: accuracy 0.9765, precision 0.9211, recall 0.9963, F1 0.9572, FPR 0.0307 | top-k 9: accuracy 0.9821, precision 0.9688, recall 0.9963, F1 0.9823, FPR 0.0321 | Jalur terbaik dan paling matang untuk Windows/Sysmon candidate anomaly generation. |
| Linux APT 2024 | top-k 328/329: accuracy 0.9089, precision 0.8247, recall 0.6667, F1 0.7373, FPR 0.0336 | top-k 50: accuracy 0.8042, precision 0.7852, recall 0.8375, F1 0.8105, FPR 0.2292 | Jalur Linux terbaik; natural precision/FPR kuat, recall masih menjadi batas utama. |

## 1. Windows LMD/Sysmon Enriched Cached Evaluation

### 1.1 Identitas Run

| Komponen | Nilai |
| --- | --- |
| Tujuan | Mengevaluasi model DeepLog LMD/Sysmon enriched sebagai kandidat runtime Sysmon. |
| Profile/runtime | `sysmon`, template enrichment `lmd_sysmon_v1` |
| Config evaluasi | `D:\FAKI\FirstPrototype\backend\tools\deeplog_lmd2023_enriched_per_host.yaml` |
| Output evaluasi | `D:\FAKI\FirstPrototype\output\evaluation\deeplog\enriched_full_cached_20260528` |
| Natural records | `D:\FAKI\NEWMLMODL\output_lmd2023_2_3m_enriched_per_host\lmd2023\sliding\W20_S20_CTrue_train0.8_per_host_chronological\eval.records.gz` |
| Balanced records | `D:\FAKI\NEWMLMODL\output_lmd2023_2_3m_enriched_per_host\lmd2023\sliding\W20_S20_CTrue_train0.8_per_host_chronological\balanced_eval.records.gz` |
| Decision policy | `topk` |
| Score threshold | 0.38495731353759766 |
| Target recall gate | 0.8 |

### 1.2 Dataset

| Komponen | Nilai |
| --- | ---: |
| Input structured source | `D:\FAKI\NEWMLMODL\dataset\lmd2023_2_3m\lmd2023.log_structured.csv` |
| Enriched structured output | `D:\FAKI\NEWMLMODL\dataset\lmd2023_2_3m_enriched\lmd2023.log_structured.csv` |
| Rows | 2,144,008 |
| Unique event templates | 510 |
| Label normal `-` | 1,632,903 |
| Label `EoHT` | 135,866 |
| Label `EoRS` | 375,239 |
| Enrichment mode | `lmd_sysmon_v1` |

### 1.3 Konfigurasi Training

| Parameter | Nilai |
| --- | --- |
| Dataset name | `lmd2023` |
| Grouping | `sliding` |
| Session level | `entry` |
| Window size | 20 |
| Step size | 20 |
| History size | 10 |
| Split mode | `per_host_chronological` |
| Train size | 0.8 |
| Valid ratio | 0.1 |
| Balanced eval | `true` |
| Remove duplicates | `true` |
| Model | `DeepLog` |
| Embedding dim | 128 |
| Hidden size | 128 |
| Layers | 2 |
| Dropout | 0.1 |
| Optimizer | `adam` |
| Learning rate | 0.001 |
| Max epoch | 10 |
| Training top-k default | 9 |

### 1.4 Artefak

| Artefak | Path | Size bytes |
| --- | --- | ---: |
| Model | `D:\FAKI\NEWMLMODL\output_lmd2023_2_3m_enriched_per_host\lmd2023\sliding\W20_S20_CTrue_train0.8_per_host_chronological\models\DeepLog.pt` | 4,006,823 |
| Vocab | `D:\FAKI\NEWMLMODL\output_lmd2023_2_3m_enriched_per_host\lmd2023\sliding\W20_S20_CTrue_train0.8_per_host_chronological\vocabs\DeepLog.pkl` | 98,530 |
| Train records | `...\train.records.gz` | 3,696,392 |
| Natural eval records | `...\eval.records.gz` | 1,896,832 |
| Balanced eval records | `...\balanced_eval.records.gz` | 1,776,367 |

### 1.5 Evaluasi Natural per Top-k

Natural cached eval memakai 21,444 windows: 15,775 normal dan 5,669 abnormal. Kolom Gate mengikuti promotion gate evaluator: recall >= 0.8, precision >= 0.65, F1 > 0.5347, FPR <= 0.5, dan precision-recall gap <= 0.3.

| Top-k | Total | Normal | Abnormal | TN | FP | FN | TP | Accuracy | Precision | Recall | F1 | Specificity | FPR | ROC-AUC | Avg Precision | Gate |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 1 | 21,444 | 15,775 | 5,669 | 177 | 15,598 | 3 | 5,666 | 0.2725 | 0.2665 | 0.9995 | 0.4207 | 0.0112 | 0.9888 | 0.9966 | 0.9921 | FAIL |
| 3 | 21,444 | 15,775 | 5,669 | 5,016 | 10,759 | 11 | 5,658 | 0.4978 | 0.3446 | 0.9981 | 0.5124 | 0.3180 | 0.6820 | 0.9966 | 0.9921 | FAIL |
| 5 | 21,444 | 15,775 | 5,669 | 13,398 | 2,377 | 15 | 5,654 | 0.8885 | 0.7040 | 0.9974 | 0.8254 | 0.8493 | 0.1507 | 0.9966 | 0.9921 | PASS |
| 9 | 21,444 | 15,775 | 5,669 | 15,291 | 484 | 21 | 5,648 | 0.9765 | 0.9211 | 0.9963 | 0.9572 | 0.9693 | 0.0307 | 0.9966 | 0.9921 | PASS |

### 1.6 Evaluasi Balanced per Top-k

Balanced cached eval memakai 11,338 windows: 5,669 normal dan 5,669 abnormal. Evaluasi ini dipakai sebagai pembanding class-balance, bukan pengganti natural eval.

| Top-k | Total | Normal | Abnormal | TN | FP | FN | TP | Accuracy | Precision | Recall | F1 | Specificity | FPR | ROC-AUC | Avg Precision | Gate |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 1 | 11,338 | 5,669 | 5,669 | 52 | 5,617 | 3 | 5,666 | 0.5043 | 0.5022 | 0.9995 | 0.6685 | 0.0092 | 0.9908 | 0.9968 | 0.9971 | FAIL |
| 3 | 11,338 | 5,669 | 5,669 | 1,794 | 3,875 | 11 | 5,658 | 0.6573 | 0.5935 | 0.9981 | 0.7444 | 0.3165 | 0.6835 | 0.9968 | 0.9971 | FAIL |
| 5 | 11,338 | 5,669 | 5,669 | 4,818 | 851 | 15 | 5,654 | 0.9236 | 0.8692 | 0.9974 | 0.9289 | 0.8499 | 0.1501 | 0.9968 | 0.9971 | PASS |
| 9 | 11,338 | 5,669 | 5,669 | 5,487 | 182 | 21 | 5,648 | 0.9821 | 0.9688 | 0.9963 | 0.9823 | 0.9679 | 0.0321 | 0.9968 | 0.9971 | PASS |

### 1.7 Titik Terbaik

| Eval | Top-k terbaik | Alasan |
| --- | ---: | --- |
| Natural | 9 | F1 tertinggi 0.9572, precision 0.9211, recall 0.9963, FPR rendah 0.0307, Gate PASS. |
| Balanced | 9 | F1 tertinggi 0.9823, precision 0.9688, recall 0.9963, Gate PASS. |

### 1.8 Interpretasi

Windows LMD/Sysmon enriched top-k 9 adalah pilihan utama. Top-k 1 dan 3 terlalu agresif karena recall hampir sempurna tetapi false positive sangat tinggi. Top-k 5 sudah lulus gate, tetapi top-k 9 lebih seimbang: precision naik dari 0.7040 ke 0.9211 pada natural eval, sementara recall hanya turun tipis dari 0.9974 ke 0.9963. Karena itu top-k 9 paling layak dipakai untuk klaim evaluasi Windows.

## 2. Linux APT Dataset 2024 Cached Evaluation

### 2.1 Identitas Run

| Komponen | Nilai |
| --- | --- |
| Tujuan | Mengevaluasi model DeepLog Linux terbaik pada Linux APT Dataset 2024. |
| Profile/runtime | Linux APT explicit dataset/config, tidak mengubah Windows/EVTX defaults |
| Config evaluasi | `D:\FAKI\FirstPrototype\backend\tools\deeplog_linux_apt_2024_quick.yaml` |
| Output evaluasi coarse | `D:\FAKI\FirstPrototype\output\evaluation\linux_apt_2024_cached` |
| Output evaluasi ultrafine | `D:\FAKI\FirstPrototype\output\evaluation\linux_apt_2024_cached_topk_ultrafine` |
| Natural records | `D:\FAKI\NEWMLMODL\output_linux_apt_2024\lmd2023\sliding\W20_S20_CTrue_train0.8_per_host_chronological\eval.records.gz` |
| Balanced records | `D:\FAKI\NEWMLMODL\output_linux_apt_2024\lmd2023\sliding\W20_S20_CTrue_train0.8_per_host_chronological\balanced_eval.records.gz` |
| Decision policy | `topk` |
| Score threshold | 0.38495731353759766 |
| Target recall gate | 0.8 |

### 2.2 Dataset

| Komponen | Nilai |
| --- | ---: |
| Source workbook | `D:\FAKI\DATASETLINUX\Linux-APT-Dataset-2024\Processed Version.xlsx` |
| Generated dataset | `D:\FAKI\NEWMLMODL\dataset\linux_apt_2024` |
| Rows written | 124,925 |
| Normal rows | 100,073 |
| Attack rows | 24,852 |
| Event templates | 648 |
| Structured CSV size | 145,200,354 bytes |

Leakage guard: MITRE/TTP dan rule metadata hanya dipakai untuk audit/reporting. `EventTemplate` dibangun dari `full_log`, sedangkan label berasal dari `Malicious / General`.

### 2.3 Konfigurasi Training

| Parameter | Nilai |
| --- | --- |
| Dataset name | `lmd2023` |
| Grouping | `sliding` |
| Session level | `entry` |
| Window size | 20 |
| Step size | 20 |
| History size | 10 |
| Split mode | `per_host_chronological` |
| Train size | 0.8 |
| Valid ratio | 0.1 |
| Balanced eval | `true` |
| Remove duplicates | `true` |
| Model | `DeepLog` |
| Embedding dim | 128 |
| Hidden size | 128 |
| Layers | 2 |
| Dropout | 0.1 |
| Optimizer | `adam` |
| Learning rate | 0.001 |
| Max epoch | 8 |
| Training top-k default | 9 |

### 2.4 Split dan Artefak

| Komponen | Nilai |
| --- | ---: |
| Train before normal-only filter | 4,997 windows |
| Train after normal-only filter | 3,153 windows |
| Natural eval | 1,251 windows, 1,011 normal / 240 abnormal |
| Balanced eval | 480 windows, 240 normal / 240 abnormal |
| Vocabulary size | 405 |

| Artefak | Path | Size bytes |
| --- | --- | ---: |
| Model | `D:\FAKI\NEWMLMODL\output_linux_apt_2024\lmd2023\sliding\W20_S20_CTrue_train0.8_per_host_chronological\models\DeepLog.pt` | 4,432,487 |
| Vocab | `D:\FAKI\NEWMLMODL\output_linux_apt_2024\lmd2023\sliding\W20_S20_CTrue_train0.8_per_host_chronological\vocabs\DeepLog.pkl` | 134,728 |
| Train records | `...\train.records.gz` | 3,731,375 |
| Natural eval records | `...\eval.records.gz` | 1,631,694 |
| Balanced eval records | `...\balanced_eval.records.gz` | 727,668 |

### 2.5 Evaluasi Natural Coarse per Top-k

Natural eval coarse memakai 1,251 windows: 1,011 normal dan 240 abnormal.

| Top-k | Total | Normal | Abnormal | TN | FP | FN | TP | Accuracy | Precision | Recall | F1 | Specificity | FPR | ROC-AUC | Avg Precision | Gate |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 3 | 1,251 | 1,011 | 240 | 340 | 671 | 2 | 238 | 0.4620 | 0.2618 | 0.9917 | 0.4143 | 0.3363 | 0.6637 | 0.8781 | 0.6241 | FAIL |
| 5 | 1,251 | 1,011 | 240 | 362 | 649 | 4 | 236 | 0.4780 | 0.2667 | 0.9833 | 0.4196 | 0.3581 | 0.6419 | 0.8781 | 0.6241 | FAIL |
| 9 | 1,251 | 1,011 | 240 | 427 | 584 | 12 | 228 | 0.5236 | 0.2808 | 0.9500 | 0.4335 | 0.4224 | 0.5776 | 0.8781 | 0.6241 | FAIL |
| 20 | 1,251 | 1,011 | 240 | 580 | 431 | 28 | 212 | 0.6331 | 0.3297 | 0.8833 | 0.4802 | 0.5737 | 0.4263 | 0.8781 | 0.6241 | FAIL |
| 50 | 1,251 | 1,011 | 240 | 782 | 229 | 39 | 201 | 0.7858 | 0.4674 | 0.8375 | 0.6000 | 0.7735 | 0.2265 | 0.8781 | 0.6241 | FAIL |
| 100 | 1,251 | 1,011 | 240 | 861 | 150 | 52 | 188 | 0.8385 | 0.5562 | 0.7833 | 0.6505 | 0.8516 | 0.1484 | 0.8781 | 0.6241 | FAIL |
| 150 | 1,251 | 1,011 | 240 | 901 | 110 | 63 | 177 | 0.8617 | 0.6167 | 0.7375 | 0.6717 | 0.8912 | 0.1088 | 0.8781 | 0.6241 | FAIL |
| 182 | 1,251 | 1,011 | 240 | 933 | 78 | 65 | 175 | 0.8857 | 0.6917 | 0.7292 | 0.7099 | 0.9228 | 0.0772 | 0.8781 | 0.6241 | FAIL |
| 220 | 1,251 | 1,011 | 240 | 950 | 61 | 72 | 168 | 0.8937 | 0.7336 | 0.7000 | 0.7164 | 0.9397 | 0.0603 | 0.8781 | 0.6241 | FAIL |
| 260 | 1,251 | 1,011 | 240 | 956 | 55 | 76 | 164 | 0.8953 | 0.7489 | 0.6833 | 0.7146 | 0.9456 | 0.0544 | 0.8781 | 0.6241 | FAIL |
| 300 | 1,251 | 1,011 | 240 | 971 | 40 | 80 | 160 | 0.9041 | 0.8000 | 0.6667 | 0.7273 | 0.9604 | 0.0396 | 0.8781 | 0.6241 | FAIL |
| 350 | 1,251 | 1,011 | 240 | 990 | 21 | 196 | 44 | 0.8265 | 0.6769 | 0.1833 | 0.2885 | 0.9792 | 0.0208 | 0.8781 | 0.6241 | FAIL |

### 2.6 Evaluasi Natural Ultrafine Top-k 321 sampai 339

Ultrafine sweep dibuat untuk mencari titik terbaik di sekitar top-k 328/329.

| Top-k | Total | Normal | Abnormal | TN | FP | FN | TP | Accuracy | Precision | Recall | F1 | Specificity | FPR | ROC-AUC | Avg Precision | Gate |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 321 | 1,251 | 1,011 | 240 | 975 | 36 | 80 | 160 | 0.9073 | 0.8163 | 0.6667 | 0.7339 | 0.9644 | 0.0356 | 0.8781 | 0.6241 | FAIL |
| 322 | 1,251 | 1,011 | 240 | 975 | 36 | 80 | 160 | 0.9073 | 0.8163 | 0.6667 | 0.7339 | 0.9644 | 0.0356 | 0.8781 | 0.6241 | FAIL |
| 323 | 1,251 | 1,011 | 240 | 975 | 36 | 80 | 160 | 0.9073 | 0.8163 | 0.6667 | 0.7339 | 0.9644 | 0.0356 | 0.8781 | 0.6241 | FAIL |
| 324 | 1,251 | 1,011 | 240 | 975 | 36 | 80 | 160 | 0.9073 | 0.8163 | 0.6667 | 0.7339 | 0.9644 | 0.0356 | 0.8781 | 0.6241 | FAIL |
| 325 | 1,251 | 1,011 | 240 | 976 | 35 | 80 | 160 | 0.9081 | 0.8205 | 0.6667 | 0.7356 | 0.9654 | 0.0346 | 0.8781 | 0.6241 | FAIL |
| 326 | 1,251 | 1,011 | 240 | 976 | 35 | 80 | 160 | 0.9081 | 0.8205 | 0.6667 | 0.7356 | 0.9654 | 0.0346 | 0.8781 | 0.6241 | FAIL |
| 327 | 1,251 | 1,011 | 240 | 976 | 35 | 80 | 160 | 0.9081 | 0.8205 | 0.6667 | 0.7356 | 0.9654 | 0.0346 | 0.8781 | 0.6241 | FAIL |
| 328 | 1,251 | 1,011 | 240 | 977 | 34 | 80 | 160 | 0.9089 | 0.8247 | 0.6667 | 0.7373 | 0.9664 | 0.0336 | 0.8781 | 0.6241 | FAIL |
| 329 | 1,251 | 1,011 | 240 | 977 | 34 | 80 | 160 | 0.9089 | 0.8247 | 0.6667 | 0.7373 | 0.9664 | 0.0336 | 0.8781 | 0.6241 | FAIL |
| 330 | 1,251 | 1,011 | 240 | 977 | 34 | 81 | 159 | 0.9081 | 0.8238 | 0.6625 | 0.7344 | 0.9664 | 0.0336 | 0.8781 | 0.6241 | FAIL |
| 331 | 1,251 | 1,011 | 240 | 977 | 34 | 88 | 152 | 0.9025 | 0.8172 | 0.6333 | 0.7136 | 0.9664 | 0.0336 | 0.8781 | 0.6241 | FAIL |
| 332 | 1,251 | 1,011 | 240 | 977 | 34 | 91 | 149 | 0.9001 | 0.8142 | 0.6208 | 0.7045 | 0.9664 | 0.0336 | 0.8781 | 0.6241 | FAIL |
| 333 | 1,251 | 1,011 | 240 | 978 | 33 | 94 | 146 | 0.8985 | 0.8156 | 0.6083 | 0.6969 | 0.9674 | 0.0326 | 0.8781 | 0.6241 | FAIL |
| 334 | 1,251 | 1,011 | 240 | 979 | 32 | 96 | 144 | 0.8977 | 0.8182 | 0.6000 | 0.6923 | 0.9683 | 0.0317 | 0.8781 | 0.6241 | FAIL |
| 335 | 1,251 | 1,011 | 240 | 979 | 32 | 104 | 136 | 0.8913 | 0.8095 | 0.5667 | 0.6667 | 0.9683 | 0.0317 | 0.8781 | 0.6241 | FAIL |
| 336 | 1,251 | 1,011 | 240 | 979 | 32 | 114 | 126 | 0.8833 | 0.7975 | 0.5250 | 0.6332 | 0.9683 | 0.0317 | 0.8781 | 0.6241 | FAIL |
| 337 | 1,251 | 1,011 | 240 | 980 | 31 | 126 | 114 | 0.8745 | 0.7862 | 0.4750 | 0.5922 | 0.9693 | 0.0307 | 0.8781 | 0.6241 | FAIL |
| 338 | 1,251 | 1,011 | 240 | 983 | 28 | 144 | 96 | 0.8625 | 0.7742 | 0.4000 | 0.5275 | 0.9723 | 0.0277 | 0.8781 | 0.6241 | FAIL |
| 339 | 1,251 | 1,011 | 240 | 984 | 27 | 150 | 90 | 0.8585 | 0.7692 | 0.3750 | 0.5042 | 0.9733 | 0.0267 | 0.8781 | 0.6241 | FAIL |

### 2.7 Evaluasi Balanced Coarse per Top-k

Balanced eval memakai 480 windows: 240 normal dan 240 abnormal.

| Top-k | Total | Normal | Abnormal | TN | FP | FN | TP | Accuracy | Precision | Recall | F1 | Specificity | FPR | ROC-AUC | Avg Precision | Gate |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 3 | 480 | 240 | 240 | 84 | 156 | 2 | 238 | 0.6708 | 0.6041 | 0.9917 | 0.7508 | 0.3500 | 0.6500 | 0.8762 | 0.8385 | FAIL |
| 5 | 480 | 240 | 240 | 91 | 149 | 4 | 236 | 0.6813 | 0.6130 | 0.9833 | 0.7552 | 0.3792 | 0.6208 | 0.8762 | 0.8385 | FAIL |
| 9 | 480 | 240 | 240 | 108 | 132 | 12 | 228 | 0.7000 | 0.6333 | 0.9500 | 0.7600 | 0.4500 | 0.5500 | 0.8762 | 0.8385 | FAIL |
| 20 | 480 | 240 | 240 | 145 | 95 | 28 | 212 | 0.7438 | 0.6906 | 0.8833 | 0.7751 | 0.6042 | 0.3958 | 0.8762 | 0.8385 | PASS |
| 50 | 480 | 240 | 240 | 185 | 55 | 39 | 201 | 0.8042 | 0.7852 | 0.8375 | 0.8105 | 0.7708 | 0.2292 | 0.8762 | 0.8385 | PASS |
| 100 | 480 | 240 | 240 | 197 | 43 | 52 | 188 | 0.8021 | 0.8139 | 0.7833 | 0.7983 | 0.8208 | 0.1792 | 0.8762 | 0.8385 | FAIL |
| 150 | 480 | 240 | 240 | 209 | 31 | 63 | 177 | 0.8042 | 0.8510 | 0.7375 | 0.7902 | 0.8708 | 0.1292 | 0.8762 | 0.8385 | FAIL |
| 182 | 480 | 240 | 240 | 222 | 18 | 65 | 175 | 0.8271 | 0.9067 | 0.7292 | 0.8083 | 0.9250 | 0.0750 | 0.8762 | 0.8385 | FAIL |
| 220 | 480 | 240 | 240 | 225 | 15 | 72 | 168 | 0.8187 | 0.9180 | 0.7000 | 0.7943 | 0.9375 | 0.0625 | 0.8762 | 0.8385 | FAIL |
| 260 | 480 | 240 | 240 | 226 | 14 | 76 | 164 | 0.8125 | 0.9213 | 0.6833 | 0.7847 | 0.9417 | 0.0583 | 0.8762 | 0.8385 | FAIL |
| 300 | 480 | 240 | 240 | 229 | 11 | 80 | 160 | 0.8104 | 0.9357 | 0.6667 | 0.7786 | 0.9542 | 0.0458 | 0.8762 | 0.8385 | FAIL |
| 350 | 480 | 240 | 240 | 233 | 7 | 196 | 44 | 0.5771 | 0.8627 | 0.1833 | 0.3024 | 0.9708 | 0.0292 | 0.8762 | 0.8385 | FAIL |

### 2.8 Titik Terbaik

| Eval | Top-k terbaik | Alasan |
| --- | ---: | --- |
| Natural | 328/329 | F1 tertinggi 0.7373, accuracy 0.9089, precision 0.8247, specificity 0.9664, FPR 0.0336. Gate tetap FAIL karena recall 0.6667 di bawah target 0.8. |
| Natural operating point alternatif | 300 | Sedikit lebih rendah dari best F1, tetapi masih kuat: F1 0.7273, precision 0.8000, recall 0.6667, FPR 0.0396. |
| Balanced | 50 | F1 tertinggi 0.8105 dan Gate PASS: precision 0.7852, recall 0.8375, FPR 0.2292. |
| Balanced accuracy terbaik | 182 | Accuracy 0.8271 dan FPR 0.0750, tetapi recall 0.7292 sehingga Gate FAIL. |

### 2.9 Interpretasi

Linux APT 2024 adalah jalur Linux terbaik karena natural eval memiliki accuracy, precision, specificity, FPR, ROC-AUC, dan average precision yang kuat. Polanya jelas: top-k kecil memberikan recall tinggi tetapi FP tinggi; top-k besar menekan FP dan menaikkan precision, tetapi recall turun. Titik terbaik natural berada pada top-k 328/329, namun gate tetap gagal karena recall 0.6667. Balanced eval menunjukkan bahwa ketika kelas diseimbangkan, top-k 50 mencapai F1 0.8105 dan gate lulus.

## 3. Perbandingan Akhir

| Aspek | Windows LMD/Sysmon Enriched | Linux APT 2024 |
| --- | --- | --- |
| Eval utama | Natural cached eval | Natural cached eval |
| Best top-k natural | 9 | 328/329 |
| Natural F1 | 0.9572 | 0.7373 |
| Natural precision | 0.9211 | 0.8247 |
| Natural recall | 0.9963 | 0.6667 |
| Natural FPR | 0.0307 | 0.0336 |
| Natural gate | PASS | FAIL karena recall |
| Best top-k balanced | 9 | 50 |
| Balanced F1 | 0.9823 | 0.8105 |
| Balanced gate | PASS | PASS |
| Posisi laporan | Hasil utama Windows | Hasil utama Linux |

Kesimpulan: Windows LMD/Sysmon enriched adalah hasil paling siap dipromosikan sebagai candidate anomaly generator. Linux APT 2024 adalah baseline Linux terbaik, tetapi klaimnya harus lebih hati-hati: natural precision dan FPR sudah bagus, sedangkan recall masih perlu perbaikan jika target gate recall 0.8 wajib dipenuhi.

## 4. Evidence Path

| Area | Path |
| --- | --- |
| Windows enriched comparison | `D:\FAKI\FirstPrototype\output\evaluation\deeplog\enriched_full_cached_20260528\deeplog_evaluation_comparison.md` |
| Windows natural top-k summary | `D:\FAKI\FirstPrototype\output\evaluation\deeplog\enriched_full_cached_20260528\cached_eval\cached_topk_summary_eval.csv` |
| Windows balanced top-k summary | `D:\FAKI\FirstPrototype\output\evaluation\deeplog\enriched_full_cached_20260528\cached_balanced_eval\cached_topk_summary_balanced_eval.csv` |
| Windows EVTX/retraining discussion | `D:\FAKI\FirstPrototype\backend\data\deeplog_evtx_retraining_evaluation_report.md` |
| Windows config | `D:\FAKI\FirstPrototype\backend\tools\deeplog_lmd2023_enriched_per_host.yaml` |
| Linux APT RTK | `D:\FAKI\FirstPrototype\docs\aegis\plans\2026-05-28-linux-apt-2024-training-rtk.md` |
| Linux APT coarse comparison | `D:\FAKI\FirstPrototype\output\evaluation\linux_apt_2024_cached\deeplog_evaluation_comparison.md` |
| Linux APT natural top-k summary | `D:\FAKI\FirstPrototype\output\evaluation\linux_apt_2024_cached\cached_eval\cached_topk_summary_eval.csv` |
| Linux APT balanced top-k summary | `D:\FAKI\FirstPrototype\output\evaluation\linux_apt_2024_cached\cached_balanced_eval\cached_topk_summary_balanced_eval.csv` |
| Linux APT ultrafine summary | `D:\FAKI\FirstPrototype\output\evaluation\linux_apt_2024_cached_topk_ultrafine\cached_topk_summary_eval.csv` |
| Linux APT config | `D:\FAKI\FirstPrototype\backend\tools\deeplog_linux_apt_2024_quick.yaml` |
