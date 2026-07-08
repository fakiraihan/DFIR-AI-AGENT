# BAB IV - Evaluasi Retraining DeepLog Enriched dan Pengujian EVTX

## 4.1 Tujuan Evaluasi

Evaluasi ini dilakukan untuk menilai apakah retraining DeepLog dengan *template enrichment* Sysmon memberikan peningkatan nyata dibandingkan model LMD lama. Fokus pengujian adalah kemampuan model menghasilkan kandidat anomali pada data LMD-2023 dan file EVTX eksternal, tanpa mengklaim hasil sebagai putusan final kompromi sistem.

## 4.2 Artefak dan Konfigurasi yang Dievaluasi

| Komponen | Artefak / Konfigurasi |
| --- | --- |
| Model lama LMD plain | `D:\FAKI\NEWMLMODL\output_lmd2023_2_3m_per_host\lmd2023\sliding\W20_S20_CTrue_train0.8_per_host_chronological\models\DeepLog.pt` |
| Model baru LMD enriched | `D:\FAKI\NEWMLMODL\output_lmd2023_2_3m_enriched_per_host\lmd2023\sliding\W20_S20_CTrue_train0.8_per_host_chronological\models\DeepLog.pt` |
| Vocab model baru | `D:\FAKI\NEWMLMODL\output_lmd2023_2_3m_enriched_per_host\lmd2023\sliding\W20_S20_CTrue_train0.8_per_host_chronological\vocabs\DeepLog.pkl` |
| Enrichment runtime | `lmd_sysmon_v1` melalui `backend/modules/deeplog_template_enrichment.py` |
| Profile Sysmon runtime | `sysmon`, `top-k=9`, `window_size=10` |
| Profile EVTX non-Sysmon | `windows_apt`, fallback runtime untuk Security/System/Windows non-Sysmon |

Perbaikan konfigurasi runtime juga dilakukan karena `backend/.env` sebelumnya masih mengarah ke model Sysmon lama. Setelah koreksi, `SYSMON_DEEPLOG_MODEL_PATH`, `SYSMON_DEEPLOG_VOCAB_PATH`, `SYSMON_DEEPLOG_TOPK=9`, dan `SYSMON_DEEPLOG_TEMPLATE_ENRICHMENT=lmd_sysmon_v1` sudah konsisten dengan model enriched.

## 4.3 Dataset dan Skenario Pengujian

| Skenario | Sumber Data | Jumlah Data | Tujuan |
| --- | --- | ---: | --- |
| Natural cached eval | `eval.records.gz` model enriched | 21.444 sesi; 15.775 normal, 5.669 anomali | Gate promosi model baru |
| Balanced cached eval | `balanced_eval.records.gz` model enriched | 11.338 sesi; 5.669 normal, 5.669 anomali | Pembanding seimbang, bukan dasar utama promosi |
| EVTX attack corpus | `D:\FAKI\LogADEmpirical-dev\EVTX-ATTACK-SAMPLES` | 278 file EVTX | Sample recall terhadap file attack |
| EVTX Sysmon subset | Bagian dari EVTX attack corpus | 191 file Sysmon | Perbandingan langsung model Sysmon lama vs enriched |
| EVTX non-Sysmon subset | Bagian dari EVTX attack corpus | 87 file | Mengukur fallback `windows_apt` pada file non-Sysmon |
| Normal raw EVTX | `D:\FAKI\SecurityAuditNormalCorpus\security_audit_normal.evtx` | 287 event | Estimasi noise pada Security Audit normal |

Pada corpus EVTX attack, setiap file diperlakukan sebagai sampel positif. Metrik `sample_recall` berarti proporsi file attack yang menghasilkan minimal satu kandidat anomali DeepLog. Metrik ini tidak sama dengan akurasi per-event dan tidak menyatakan bahwa semua event dalam file adalah malicious.

## 4.4 Evaluasi Natural LMD-2023

Tabel berikut membandingkan performa natural evaluation antara model lama dan model enriched. Angka model lama berasal dari `lmd2023_2_3m_per_host_fair_eval_report.md`, sedangkan angka model enriched berasal dari `deeplog_cached_eval_report.md`.

| Model | Top-k | Accuracy | Precision | Recall | F1 | FPR | Status |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| LMD plain lama | 5 | 0.6025 | 0.9935 | 0.3637 | 0.5325 | 0.0040 | Baseline natural terbaik yang tercatat |
| LMD plain lama | 9 | 0.6016 | 0.9992 | 0.3601 | 0.5294 | 0.0005 | Sangat konservatif, banyak FN |
| LMD enriched baru | 5 | 0.8885 | 0.7040 | 0.9974 | 0.8254 | 0.1507 | PASS gate |
| LMD enriched baru | 9 | 0.9765 | 0.9211 | 0.9963 | 0.9572 | 0.0307 | PASS gate, kandidat runtime Sysmon |

Hasil natural menunjukkan bahwa enrichment meningkatkan recall dan F1 secara signifikan. Model lama cenderung sangat konservatif: precision tinggi tetapi recall hanya sekitar 0,36. Model enriched pada top-k 9 mencapai recall 0,9963 dan F1 0,9572 dengan FPR 0,0307, sehingga memenuhi kriteria promosi yang digunakan pada evaluasi ini.

## 4.5 Evaluasi Balanced LMD-2023

Balanced evaluation tetap dilaporkan untuk pembanding, tetapi tidak digunakan sebagai klaim utama promosi model.

| Model | Top-k | Accuracy | Precision | Recall | F1 | Specificity | FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| LMD plain lama | 3 | 0.9532 | 0.9854 | 0.9151 | 0.9489 | 0.9877 | 0.0123 |
| LMD plain lama | 9 | 0.9482 | 1.0000 | 0.8911 | 0.9424 | 1.0000 | 0.0000 |
| LMD enriched baru | 5 | 0.9236 | 0.8692 | 0.9974 | 0.9289 | 0.8499 | 0.1501 |
| LMD enriched baru | 9 | 0.9821 | 0.9688 | 0.9963 | 0.9823 | 0.9679 | 0.0321 |

Pada balanced eval, model enriched top-k 9 juga lebih kuat secara F1 dibanding baseline lama yang tercatat. Namun, balanced eval berdistribusi 50:50 normal-anomali sehingga tidak merepresentasikan distribusi operasional natural.

## 4.6 Pengujian EVTX Attack Corpus

### 4.6.1 Hasil Global

Pengujian dilakukan terhadap 278 file EVTX attack. File Sysmon diarahkan ke profile Sysmon, sedangkan file non-Sysmon diarahkan ke profile `windows_apt`.

| Skenario Runtime | Total Detected | Sample Recall | Catatan |
| --- | ---: | ---: | --- |
| Old Sysmon top-k 9 + Windows-APT top-k 9 | 93/278 | 0.3345 | Baseline lama pada top-k yang sama |
| New enriched Sysmon top-k 9 + Windows-APT top-k 9 | 213/278 | 0.7662 | Peningkatan besar pada subset Sysmon |
| New enriched Sysmon top-k 9 + Windows-APT top-k 5 | 254/278 | 0.9137 | Skenario runtime-like terbaik dari sweep yang tersedia |

Hasil global menunjukkan bahwa model enriched meningkatkan kemampuan sistem untuk menghasilkan kandidat anomali pada corpus attack. Peningkatan paling jelas terjadi pada subset Sysmon, karena itulah bagian yang menggunakan model hasil retraining enriched.

### 4.6.2 Perbandingan Khusus Subset Sysmon

| Model Sysmon | Top-k | File Sysmon | Detected | Missed | Sample Recall | Anomaly Window Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| LMD plain lama | 9 | 191 | 50 | 141 | 0.2618 | 0.3181 |
| LMD plain lama | 3 | 191 | 83 | 108 | 0.4346 | 0.4223 |
| LMD enriched baru | 9 | 191 | 170 | 21 | 0.8901 | 1.0000 |

Pada top-k 9 yang sama, model enriched menaikkan deteksi Sysmon EVTX dari 50/191 menjadi 170/191. Seluruh 21 file Sysmon yang tidak terdeteksi pada model enriched memiliki `windows=0`, yaitu file berisi satu event sehingga DeepLog tidak memiliki konteks sequence untuk dievaluasi.

### 4.6.3 Perbandingan per Kategori ATT&CK pada Subset Sysmon

| Kategori | File Sysmon | Detected Model Lama top-k 9 | Detected Model Enriched top-k 9 |
| --- | ---: | ---: | ---: |
| `(root)` | 1 | 0 | 1 |
| AutomatedTestingTools | 7 | 6 | 7 |
| Command and Control | 2 | 1 | 2 |
| Credential Access | 19 | 9 | 15 |
| Defense Evasion | 28 | 7 | 22 |
| Discovery | 6 | 2 | 4 |
| Execution | 30 | 3 | 29 |
| Lateral Movement | 28 | 4 | 25 |
| Other | 1 | 0 | 0 |
| Persistence | 16 | 3 | 12 |
| Privilege Escalation | 53 | 15 | 53 |

Kategori Execution, Lateral Movement, Persistence, Defense Evasion, dan Privilege Escalation mendapat peningkatan paling terlihat. Sebagai contoh, pada Privilege Escalation, model lama top-k 9 mendeteksi 15/53 file Sysmon, sedangkan model enriched mendeteksi 53/53.

### 4.6.4 Catatan OOV dan Agresivitas Model

Pada subset Sysmon attack EVTX, model enriched menghasilkan `unknown_window_ratio=1.0` dan `anomaly_window_ratio=1.0` untuk window yang berhasil dievaluasi. Artinya, setiap window Sysmon attack yang dievaluasi mengandung token tidak dikenal dan berakhir sebagai top-k miss. Ini berguna untuk menangkap kandidat anomali, tetapi juga menunjukkan adanya domain shift antara data training LMD enriched dan corpus EVTX attack eksternal.

Konsekuensinya, hasil ini kuat untuk menyatakan bahwa model enriched lebih sensitif dibanding model lama, tetapi belum cukup untuk menyatakan precision operasional pada Sysmon EVTX normal.

## 4.7 Pengujian Normal EVTX

Normal EVTX yang tersedia pada workspace adalah Security Audit normal, bukan benign Sysmon EVTX. Karena itu, hasil berikut menguji profile `windows_apt`, bukan profile Sysmon enriched.

| Sumber Normal | Top-k | Windows | Anomalies | Anomaly Window Ratio |
| --- | ---: | ---: | ---: | ---: |
| Raw `security_audit_normal.evtx` | 3 | 287 | 4 | 0.0139 |
| Raw `security_audit_normal.evtx` | 5 | 287 | 2 | 0.0070 |
| Raw `security_audit_normal.evtx` | 9 | 287 | 1 | 0.0035 |
| Structured normal sample | 5 | 556 | 38 | 0.0683 |
| Structured normal sample | 9 | 556 | 25 | 0.0450 |

Pada raw Security Audit normal, noise profile `windows_apt` relatif rendah pada top-k 5 dan top-k 9. Namun, angka ini tidak boleh dipakai sebagai FPR Sysmon enriched karena jenis log dan model profile berbeda.

## 4.8 Integrasi Runtime Backend

Pengujian smoke dari folder `backend` memverifikasi bahwa runtime sekarang memakai model enriched:

```text
sysmon_model D:\FAKI\NEWMLMODL\output_lmd2023_2_3m_enriched_per_host\...\models\DeepLog.pt
sysmon_vocab  D:\FAKI\NEWMLMODL\output_lmd2023_2_3m_enriched_per_host\...\vocabs\DeepLog.pkl
sysmon_topk   9
sysmon_enrichment lmd_sysmon_v1
```

Contoh template runtime setelah enrichment:

```text
Microsoft-Windows-Sysmon EventID=1 ImageClass=cmd CmdClass=other ParentClass=explorer UserClass=user
Microsoft-Windows-Sysmon EventID=3 ImageClass=cmd UserClass=user DestinationClass=unknown DestinationPortClass=unknown
```

Unit test terkait enrichment dan evaluator juga berhasil dijalankan:

```text
python -m unittest backend.test_deeplog_template_enrichment backend.evaluation.test_deeplog_eval
Ran 22 tests in 0.085s
OK
```

## 4.9 Pembahasan

Secara umum, retraining enriched dapat dinilai berhasil untuk tujuan peningkatan recall. Pada natural cached evaluation, model enriched top-k 9 memenuhi promotion gate dengan F1 0,9572, precision 0,9211, recall 0,9963, dan FPR 0,0307. Pada EVTX attack corpus, subset Sysmon meningkat dari 50/191 pada model lama top-k 9 menjadi 170/191 pada model enriched top-k 9.

Namun, hasil EVTX juga memperlihatkan model enriched bersifat agresif pada data attack eksternal. Semua evaluated Sysmon attack windows menjadi anomali, dan seluruhnya memiliki unknown window. Kondisi ini dapat diterima untuk tahap candidate generation karena tujuan sistem adalah memunculkan kandidat investigasi, tetapi belum cukup untuk klaim precision atau FPR Sysmon di lingkungan produksi.

Keterbatasan utama evaluasi ini adalah belum tersedianya benign Sysmon EVTX normal corpus. Normal EVTX yang tersedia adalah Security Audit normal sehingga hanya relevan untuk profile `windows_apt`. Oleh karena itu, klaim formal yang aman adalah: model enriched lebih baik dalam menangkap attack Sysmon EVTX dibanding model lama, tetapi estimasi false positive Sysmon enriched masih membutuhkan dataset normal Sysmon yang representatif.

## 4.10 Kesimpulan

1. Model DeepLog enriched layak dipromosikan untuk profile Sysmon runtime berdasarkan natural cached evaluation LMD-2023 karena memenuhi gate precision, recall, F1, FPR, dan precision-recall gap.
2. Dibanding model LMD plain lama, model enriched meningkatkan sample recall Sysmon EVTX attack dari 0,2618 menjadi 0,8901 pada top-k 9.
3. Dalam skenario runtime-like terbaik yang tersedia, kombinasi Sysmon enriched top-k 9 dan Windows-APT top-k 5 mendeteksi 254/278 file EVTX attack atau 0,9137 sample recall.
4. Model enriched sebaiknya diposisikan sebagai candidate anomaly generator, bukan verdict final compromise.
5. Evaluasi lanjutan wajib menggunakan benign Sysmon EVTX untuk mengukur false positive rate Sysmon enriched secara fair.

## 4.11 Artefak Bukti Evaluasi

| Jenis Bukti | Path |
| --- | --- |
| Natural cached eval enriched | `D:\FAKI\FirstPrototype\output\evaluation\deeplog\enriched_full_cached_20260528\cached_eval\deeplog_cached_eval_report.md` |
| Balanced cached eval enriched | `D:\FAKI\FirstPrototype\output\evaluation\deeplog\enriched_full_cached_20260528\cached_balanced_eval\deeplog_cached_balanced_eval_report.md` |
| Baseline old LMD fair eval | `D:\FAKI\NEWMLMODL\output_lmd2023_2_3m_per_host\lmd2023_2_3m_per_host_fair_eval_report.md` |
| EVTX attack enriched validation | `D:\FAKI\FirstPrototype\backend\data\evtx_attack_validation_lmd_enriched_20260528\evtx_attack_validation_summary.json` |
| EVTX attack old Sysmon top-k 9 validation | `D:\FAKI\FirstPrototype\backend\data\evtx_attack_validation_old_sysmon_topk9_20260528\evtx_attack_validation_summary.json` |
| EVTX normal validation | `D:\FAKI\FirstPrototype\backend\data\evtx_normal_validation_lmd_enriched_20260528\evtx_normal_validation_report.md` |
