# Evaluasi & Rekonsiliasi Angka — JejakAgent

> Dokumen ini merekonsiliasi **angka-angka evaluasi** yang dikutip di
> `Evaluasi_TA_Muhammad_Faki_Raihan.md` (terutama BAGIAN II, V, dan
> KESIMPULAN EVALUASI) dengan **artefak evaluasi aktual** di repository
> (`docs/reports/*.md`, `evaluation/reports/*.md`,
> `evaluation/results/*.json`). Tujuannya: memastikan Bab IV/V skripsi
> mengutip angka yang **bisa ditelusuri (traceable)** ke sumbernya, dan
> menjelaskan setiap selisih yang ditemukan secara transparan — bukan untuk
> menyalahkan, tetapi untuk memudahkan revisi.

---

## 0. Tabel Ringkasan Rekonsiliasi

| # | Metrik | Dikutip di Tesis | Ditemukan di Repo | Status | Detail |
|---|---|---|---|---|---|
| 1 | DeepLog F1 (Windows) | **0,9823** (Kesimpulan Evaluasi) | `0.9823` — balanced top-k=9 (`docs/reports/deeplog-windows-linux-evaluation-report.md:18`) | **Cocok** — tapi `HeroLanding.jsx` menampilkan angka lain (0.9489/0.9151) | §1.1 |
| 2 | DeepLog Linux — top-k & recall "natural evaluation" | top-k **182**, recall **0,7292** | top-k 182/recall 0.7292 **ADA**, tapi berasal dari tabel **BALANCED**, bukan natural (`...report.md:250`) | **Tertukar label** | §1.2 |
| 3 | DeepLog Linux — F1 terbaik (balanced) | top-k **50** | top-k 50, F1=0.8105, Gate PASS (`...report.md:262`) | **Cocok** | §1.2 |
| 4 | Tool Correctness | **0,864** | mean=0.864, pass\_rate@0.8=50% (`evaluation/reports/tool_correctness_eval.md`) | **Cocok nilainya**, tapi pass-rate 50% perlu narasi *judge bias* | §2 |
| 5 | G-Eval (laporan AI Agent) | **0,8675** | **0.8625** (≈0.863, run final 2026-06-05T02:44–02:51 UTC) | **Tidak cocok persis** — kemungkinan salah tulis | §3 |
| 6 | SUS | 80,31 / 80,33 / 83,33 (tiga versi berbeda) | 1285 ÷ 16 = **80,3125 → 80,31** | 80,31 **benar**; dua lainnya typo di teks tesis | §5 |

---

## 1. Rekonsiliasi DeepLog (F1 / Recall / Top-k)

### 1.1 Windows — F1 0,9823 vs angka di `HeroLanding.jsx`

`Evaluasi_TA_Muhammad_Faki_Raihan.md` (KESIMPULAN EVALUASI) mengutip:

> "F1-score DeepLog 0,9823 pada Windows..."

Angka ini **cocok** dengan baris *balanced* top-k=9 pada
`docs/reports/deeplog-windows-linux-evaluation-report.md:18`:

| Eval | Top-k | Accuracy | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|---|
| Windows natural | 9 | 0.9765 | 0.9211 | 0.9963 | 0.9572 | 0.0307 |
| Windows balanced | 9 | 0.9821 | 0.9688 | 0.9963 | **0.9823** | 0.0321 |

Namun, halaman landing frontend (`frontend/src/components/HeroLanding.jsx`)
menampilkan angka **berbeda**:

```js
// HeroLanding.jsx:153
desc: "LSTM deep learning model scores log sequences for next-event
       anomalies. Validated at F1 0.9489, Recall 0.9151, FPR only 1.23%."

// HeroLanding.jsx:187, 194
value: "0.9489"   // F1
value: "0.9151"   // Recall
```

**Pengecekan**: tidak ada satupun baris di tabel natural *maupun* balanced
(top-k 1, 3, 5, 9 — Windows) yang menghasilkan kombinasi F1≈0.9489,
recall≈0.9151, **dan** FPR≈0.0123 secara bersamaan. FPR=0.0123 bahkan tidak
muncul di tabel manapun (nilai FPR Windows yang ada: 0.9888, 0.6820, 0.1507,
0.0307 untuk natural; 0.9908, 0.6835, 0.1501, 0.0321 untuk balanced).

**Kesimpulan**: angka di `HeroLanding.jsx` adalah **angka lama (stale)** dari
iterasi model sebelum retraining "enriched" yang didokumentasikan di
`docs/reports/deeplog-windows-linux-evaluation-report.md` (lihat juga
[03-pipeline-parsing-deeplog.md](03-pipeline-parsing-deeplog.md) §6). Angka
ini ditulis manual (hardcoded) di komponen landing page dan tidak pernah
disinkronkan ulang setelah model di-retrain.

**Rekomendasi**:
- **Untuk tesis**: kutip **0,9823** (balanced, top-k=9) sebagai F1 utama
  Windows di Bab IV — ini adalah hasil evaluasi *terkini* dan punya jejak
  artefak yang jelas. Sebutkan juga F1 *natural* 0,9572 sebagai pembanding
  realistis (distribusi kelas tidak seimbang).
- **Untuk sistem**: perbarui `HeroLanding.jsx:153,187,194` agar konsisten
  dengan hasil evaluasi terbaru, atau — lebih baik — ambil angka ini dari
  artefak evaluasi/`config` backend secara dinamis supaya tidak perlu
  diperbarui manual setiap kali model di-retrain (lihat
  [06-rekomendasi.md](06-rekomendasi.md)).

### 1.2 Linux — top-k 182 vs top-k 328/329 ("natural evaluation")

`Evaluasi_TA_Muhammad_Faki_Raihan.md` BAGIAN V.5.2a mengutip:

> "F1-score terbaik diraih di top-k 50 (balanced evaluation), sedangkan pada
> natural evaluation, top-k optimal berada di 182 dengan recall hanya
> 0,7292."

Mari kita periksa baris-baris terkait di
`docs/reports/deeplog-windows-linux-evaluation-report.md`:

**Tabel Natural per Top-k (Linux APT 2024)** — bagian 2.5/2.6:

| Top-k | Accuracy | Precision | Recall | F1 | FPR | Gate |
|---|---|---|---|---|---|---|
| 50 | 0.7858 | 0.4674 | 0.8375 | 0.6000 | 0.2265 | FAIL |
| 182 | 0.8857 | 0.6917 | **0.7292** | 0.7099 | 0.0772 | FAIL |
| 300 | 0.9041 | 0.8000 | 0.6667 | 0.7273 | 0.0396 | FAIL |
| **328/329** | **0.9089** | **0.8247** | **0.6667** | **0.7373** | **0.0336** | FAIL |

→ **F1 tertinggi natural ada di top-k 328/329 (F1=0,7373, recall=0,6667)**,
bukan top-k 182.

**Tabel Balanced per Top-k (Linux APT 2024)** — bagian 2.7:

| Top-k | Accuracy | Precision | Recall | F1 | FPR | Gate |
|---|---|---|---|---|---|---|
| 50 | 0.8042 | 0.7852 | 0.8375 | **0.8105** | 0.2292 | **PASS** |
| **182** | 0.8271 | 0.9067 | **0.7292** | 0.8083 | 0.0750 | FAIL |
| 300 | 0.8104 | 0.9357 | 0.6667 | 0.7786 | 0.0458 | FAIL |

→ Top-k **182 dengan recall 0,7292 memang ada** — tetapi nilai ini berasal
dari **tabel BALANCED**, sebagai *titik akurasi terbaik* (Accuracy=0.8271,
FPR=0.0750), **bukan dari tabel natural**.

**Diagnosis**: kalimat tesis terlihat **mencampur dua baris dari tabel
balanced yang sama** —

- top-k 50 (F1 terbaik balanced, Gate PASS) — dikutip dengan benar sebagai
  "balanced evaluation"
- top-k 182 (akurasi terbaik balanced, recall 0,7292, Gate FAIL) — dikutip
  tetapi **diberi label "natural evaluation" yang salah**

Sementara itu, **titik natural yang sebenarnya** (top-k 328/329, F1=0,7373,
recall=0,6667) **tidak disebut sama sekali** — padahal titik inilah yang
relevan untuk argumen "recall masih menjadi batas utama" yang justru
**lebih kuat** (recall 0,6667 lebih rendah dari 0,7292, sehingga makin
mendukung narasi keterbatasan).

**Rekomendasi** (pilih salah satu, sesuaikan dengan maksud aslinya):

1. **Jika maksudnya memang "titik terbaik natural eval"**: ganti menjadi
   *"pada natural evaluation, top-k optimal (F1 tertinggi) berada di
   328/329 dengan F1=0,7373 dan recall hanya 0,6667 — gate tetap FAIL
   karena recall di bawah target 0,8"*. Ini konsisten dengan narasi
   keterbatasan yang sudah direncanakan di
   [03-pipeline-parsing-deeplog.md](03-pipeline-parsing-deeplog.md) §6.
2. **Jika maksudnya memang ingin menyebut top-k 182**: betulkan labelnya
   menjadi *"...sedangkan pada balanced evaluation, titik operasi
   alternatif (akurasi/FPR terbaik) berada di top-k 182 dengan recall hanya
   0,7292"* — dan jelaskan bahwa ini adalah titik *akurasi* terbaik, bukan
   *F1* terbaik (F1 terbaik balanced tetap top-k 50).

Baik opsi 1 maupun 2, kalimat **"top-k 50 (balanced evaluation), F1
terbaik"** sudah benar dan **tidak perlu diubah**.

---

## 2. Tool Correctness — 0,864 (mean) vs 50% (pass rate) & Judge Bias

`Evaluasi_TA_Muhammad_Faki_Raihan.md` mengutip **Tool Correctness 0,864** di
KESIMPULAN EVALUASI. Angka ini **cocok persis** dengan
`evaluation/reports/tool_correctness_eval.md` (generated
2026-06-01T16:06:03):

- 6 *cases* × 3 repetisi = 18 *runs*
- **mean ToolCorrectness = 0,864**, macro avg = 0,864
- **pass rate @ threshold 0,8 = 50,0%**
- *expected-tool coverage* = 100% (semua tool yang seharusnya dipanggil,
  selalu dipanggil)

Per kategori:

| Kategori | Mean Score | Pass Rate |
|---|---|---|
| mixed_multi_ioc_coverage | 0.933 | 100% |
| single_domain_reputation | 1.000 | 100% |
| single_ip_reputation | 1.000 | 100% |
| single_md5_file_hash | 0.750 | **0%** |
| single_sha256_file_hash | 0.750 | **0%** |
| single_url_malware_delivery | 0.750 | **0%** |

### 2.1 Bukti konkret untuk kritik "judge bias" (V.5.2c)

Penguji II (V.5.2c) menulis:

> "Terdapat bias judge model — saran sebaiknya menilai 'apakah informasi
> yang dibutuhkan berhasil didapatkan dengan benar', bukan 'apakah semua
> alat dipanggil'."

Untuk **ketiga kategori berskor 0,750/0% pass** di atas, alasan (reason)
yang dicatat oleh judge **secara eksplisit menyatakan**:

> "All expected tools [...] were called (order not considered)... Missing
> Tools: None, Extra Tools: None, Argument Mismatches: 0"

Artinya: menurut catatan judge sendiri, **tidak ada tool yang
hilang/kelebihan/salah argumen** — namun skor tetap 0,750, **di bawah
threshold 0,8**, sehingga dinyatakan **FAIL**.

Ini adalah **bukti langsung dan konkret** yang mendukung argumen Penguji II:
metrik `ToolCorrectnessMetric` dari DeepEval, sebagaimana dikonfigurasi di
proyek ini, dapat memberi skor **di bawah threshold pass** meskipun
**cakupan pemanggilan tool 100% benar** — mengindikasikan ada komponen
penilaian lain (kemungkinan terkait *output*/informasi yang dihasilkan dari
hasil tool, bukan sekadar *input parameters* pemanggilan tool) yang menarik
skor turun, sementara *reasoning* yang ditampilkan ke pengguna berfokus pada
cakupan tool semata — **mismatch antara reasoning yang ditampilkan dan skor
akhir**.

**Rekomendasi untuk Bab V**:
- Jadikan ini **bukti utama** untuk butir V.5.2c — sertakan kutipan
  *reason* di atas sebagai cuplikan langsung di Bab V (gunakan salah satu
  dari tiga *case* 0,750: `tc_url_malware_delivery_001`,
  `tc_md5_file_hash_001`, atau `tc_sha256_file_hash_001`).
- Gunakan temuan ini untuk **mengusulkan metrik tambahan/pengganti** sesuai
  saran Penguji II: ukur "apakah informasi yang relevan berhasil diperoleh
  dari tool" (misalnya via `ToolCorrectnessMetric` dengan parameter
  evaluasi yang difokuskan pada *output*, atau metrik G-Eval kustom seperti
  "Tool Result Utilization") — ini menjadi *future work* yang konkret dan
  bisa langsung disambungkan ke poin V.5.2c.
- Catatan kalibrasi: pass rate 50% **dengan mean 0,864** menunjukkan
  *threshold* 0,8 mungkin **terlalu ketat relatif terhadap skala skor**
  metrik ini (skor terpusat di 0,75–1,00, sehingga selisih kecil
  menentukan pass/fail) — ini juga layak disebut sebagai keterbatasan
  desain evaluasi, terlepas dari isu *judge bias* di atas.

---

## 3. G-Eval — 0,863 (aktual) vs 0,8675 (dikutip di tesis)

`Evaluasi_TA_Muhammad_Faki_Raihan.md` KESIMPULAN EVALUASI mengutip:

> "...G-Eval 0,8675..."

Tiga artefak relevan diperiksa:

| Artefak | Timestamp (UTC) | mean\_geval\_score | pass\_rate |
|---|---|---|---|
| `evaluation/results/report_generation_geval_nilai80.json` | 2026-06-05T01:59:25 | 0.8225 | 62.5% (5/8 tactic-pairs PASS) |
| `evaluation/results/report_generation_geval_summary.json` (`source_generated_at_utc`) | 2026-06-05T02:44:51 | **0.8625** | **100%** |
| `evaluation/reports/report_generation_geval_eval.md` | 2026-06-05T02:51:15 | **0.863** (dibulatkan) | 100% |

**Pengamatan**:

1. **Tidak ada satupun** dari ketiga artefak yang berisi nilai **0,8675**.
2. `report_generation_geval_summary.json` (02:44) dan
   `report_generation_geval_eval.md` (02:51) **konsisten satu sama lain**
   — 0,8625 dibulatkan ke 3 desimal menjadi 0,863. Keduanya juga
   sama-sama melaporkan **pass rate 100%** (8 *cases* × 2 repetisi = 16
   *runs*, *frozen\_replay*).
3. `report_generation_geval_nilai80.json` (01:59) adalah **snapshot lebih
   awal** (±45 menit sebelum hasil final), dengan skor lebih rendah
   (0,8225) dan pass rate 62,5% — tiga tactic (*Defense Evasion*,
   *Discovery*, *Privilege Escalation*) gagal di run ini (skor 0,78 <
   0,8) tetapi **lulus** di run final (0,92 / 0,86 / 0,84).

**Kesimpulan**: nilai final/terbaru yang konsisten dan punya jejak artefak
ganda (`*_summary.json` + `*_eval.md`) adalah **0,8625 (≈0,863)**. Angka
**0,8675** di tesis kemungkinan besar adalah **kesalahan transkripsi** dari
**0,8625** (selisih hanya pada digit ketiga: 2 vs 7 — kemungkinan salah
ketik atau salah baca angka serupa).

**Rekomendasi untuk Bab IV/V**:
- Ganti **0,8675 → 0,863** (atau 0,8625 jika ingin presisi 4 digit), dengan
  sumber `evaluation/reports/report_generation_geval_eval.md`
  (`generated_at_utc: 2026-06-05T02:51:15+00:00`).
- **Peluang narasi positif (opsional)**: snapshot `nilai80.json` (0,8225,
  pass 62,5%) vs hasil final (0,8625, pass 100%) — keduanya dari tanggal
  yang sama dengan selisih ±45 menit — bisa dijadikan **ilustrasi siklus
  DSRM** (build → evaluate → refine → re-evaluate) di Bab III/IV, yang
  langsung menjawab kritik Penguji I tentang kerangka *Define–Prescript–
  Result* (BAGIAN I): hasil akhir bukan angka tunggal yang turun dari
  langit, melainkan **hasil iterasi yang terukur**. Ini sifatnya opsional —
  jangan dipaksakan jika menambah kompleksitas narasi Bab IV.
- **Jangan campur** angka G-Eval ini dengan angka di §4 (full-pipeline
  smoke test, 0,500) — keduanya mengukur hal yang berbeda, lihat di bawah.

---

## 4. EVTX Full-Pipeline G-Eval Smoke Test (0,500 / 0% pass) — Data Terpisah

`evaluation/reports/report_geval_evtx_eval.md` (generated
2026-06-02T04:13:22, **tiga hari sebelum** run G-Eval di §3) melaporkan:

- **Mode**: full live-pipeline run (bukan `frozen_replay`)
- **Cakupan**: 1 *case* (*Command and Control* / `bits_openvpn.evtx`), 1
  repetisi
- **Hasil**: mean = **0,500**, pass rate = **0%** (threshold 0,8)
  - mode JSON = 0,400
  - mode Markdown = 0,600
  - runtime = 339,85 detik

### 4.1 Mengapa angka ini berbeda drastis dari §3 (0,863)?

Kedua evaluasi G-Eval ini **mengukur cakupan (scope) yang berbeda**:

| | §3 — `report_generation_geval_eval.md` | §4 — `report_geval_evtx_eval.md` |
|---|---|---|
| Mode | `frozen_replay` | full live pipeline |
| Yang diukur | Kualitas **Report Generator** *given* evidence yang sudah benar (terisolasi dari variabilitas parsing/DeepLog/agent) | Kualitas **end-to-end**: parsing → DeepLog → LLM Gate → AI Agent (tool execution) → Report Generator |
| N | 8 *cases* × 2 repetisi = 16 *runs* | 1 *case* × 1 repetisi |
| Hasil | 0,863, pass 100% | 0,500, pass 0% |

Keduanya **tidak kontradiktif** — keduanya sah, tetapi menjawab pertanyaan
yang berbeda: "*apakah Report Generator menulis laporan yang baik jika
evidence-nya benar?*" (§3) vs "*apakah seluruh pipeline, ujung ke ujung,
menghasilkan laporan yang baik pada satu kasus nyata?*" (§4, N=1, lebih
mirip *smoke test* daripada evaluasi statistik).

**Rekomendasi untuk Bab IV/V**:
- Saat mengutip G-Eval **0,863** di Bab IV, **sebutkan eksplisit cakupannya**
  — misalnya: *"G-Eval rata-rata 0,863 (N=16, mode frozen-replay, mengukur
  kualitas Report Generator dengan evidence yang sudah terverifikasi)"* —
  agar tidak disalahartikan sebagai klaim performa pipeline end-to-end.
- Angka **0,500 (N=1, full pipeline)** sebaiknya **tidak dijadikan klaim
  utama** (N terlalu kecil untuk generalisasi), tetapi **layak disebut di
  Bab V sebagai limitation/future work**: *"evaluasi G-Eval end-to-end
  (full pipeline) baru dilakukan pada 1 kasus sebagai smoke test (skor
  0,500); evaluasi end-to-end berskala lebih besar adalah pekerjaan
  lanjutan"*. Ini juga selaras dengan butir V.5.2h (tidak ada data
  latensi) — keduanya bisa digabung sebagai satu paragraf "evaluasi
  end-to-end belum komprehensif".

---

## 5. SUS — 80,31 (benar), 80,33 / 83,33 (typo)

`Evaluasi_TA_Muhammad_Faki_Raihan.md` BAGIAN II mencatat **tiga nilai SUS
berbeda** muncul di lokasi berbeda dalam draf tesis:

- Abstrak (ID): **80,33**
- Abstrak (EN): **83,33**
- Bab IV.3.4 + Lampiran 2: **80,31**

**Verifikasi matematis**: 16 responden, total skor = 1285.
**1285 ÷ 16 = 80,3125 → 80,31** (pembulatan 2 desimal sesuai SNI ISO 80000).

→ **80,31 adalah nilai yang benar dan konsisten dengan data mentah
(Lampiran 2)**. Nilai 80,33 dan 83,33 adalah **kesalahan
penulisan/transkripsi di teks tesis** — tidak ada artefak sistem yang perlu
diperiksa lebih lanjut untuk ini.

**Rekomendasi**: ganti **kedua kemunculan di Abstrak (ID dan EN)** menjadi
**80,31**, agar konsisten dengan Bab IV.3.4 dan Lampiran 2. Detail lokasi
perbaikan teks → [06-rekomendasi.md](06-rekomendasi.md) (dipetakan ke item
BAGIAN II evaluasi).

---

## 6. Catatan Tambahan: Penamaan "Profile" di Laporan Evaluasi vs Dokumentasi Pipeline

[03-pipeline-parsing-deeplog.md](03-pipeline-parsing-deeplog.md) §2
mendokumentasikan **5 nilai `model_profile`** dari `build_model_profile()`:
`linux_log`, `windows_sysmon`, `windows_evtx`, `lmd_enriched`, `general`.

Namun, tabel *evidence cases* di `evaluation/reports/report_generation_geval_eval.md`
dan `report_geval_evtx_eval.md` memiliki kolom **"Profile"** dengan nilai
**`windows_apt`** (7 dari 8 *cases*) dan **`sysmon`** (1 *case*,
*privilege\_escalation*) — **tidak ada satupun yang persis cocok** dengan 5
nilai `model_profile` di atas.

**Penjelasan**: `windows_apt` adalah **nama dataset/model**, bukan nilai
`model_profile`. Ini terlihat dari `backend/config.py:60-64` —
`windows_evtx_deeplog_model_path` menunjuk ke direktori
`output_windows_evtx_bos_lowunk\windows_apt\...`, dan
`backend/data/windows_apt_model_context.md` mengonfirmasi "Windows-APT"
adalah nama dataset training (`Windows-APT 2025 A Dataset for APT-Inspired
Attack`). Jadi, kolom "Profile" pada tabel *evidence cases* sebenarnya
melaporkan **nama dataset/varian model** yang dipakai (`windows_apt` →
profil `windows_evtx`; `sysmon` → profil `windows_sysmon`), bukan nilai
enum `model_profile` itu sendiri.

**Dampak**: tidak mempengaruhi validitas hasil evaluasi, tetapi bisa
membingungkan pembaca yang mencocokkan tabel *evidence cases* (Bab IV) dengan
definisi `model_profile` di Bab III. **Rekomendasi**: tambahkan catatan kaki
singkat di Bab IV saat menampilkan tabel *evidence cases*, contoh: *"Kolom
'Profile' merujuk pada varian dataset/model yang dipakai (Windows-APT 2025
↔ profil parsing `windows_evtx`; Sysmon ↔ profil `windows_sysmon`), bukan
nilai `model_profile` yang dibahas di Bab III.3.2"*.

---

## 7. Ringkasan untuk Bab IV/V Skripsi

1. **DeepLog Windows**: kutip F1=0,9823 (balanced, top-k=9) sebagai hasil
   utama — sudah benar di Kesimpulan, tapi perbarui `HeroLanding.jsx`
   (frontend) yang masih menampilkan angka lama 0,9489/0,9151 (§1.1).
2. **DeepLog Linux**: perbaiki kalimat V.5.2a — top-k 50/balanced/F1=0,8105
   sudah benar; top-k "182/natural/recall=0,7292" salah label (sebenarnya
   dari tabel balanced). Pertimbangkan mengganti dengan titik natural yang
   sebenarnya: top-k 328/329, F1=0,7373, recall=0,6667 (§1.2).
3. **Tool Correctness**: 0,864 sudah benar; gunakan bukti konkret skor 0,750
   dengan "Missing Tools: None" untuk memperkuat argumen *judge bias*
   V.5.2c di Bab V (§2).
4. **G-Eval**: ganti 0,8675 → 0,863 (sumber:
   `report_generation_geval_eval.md`, 2026-06-05T02:51:15Z); sebutkan
   cakupan evaluasi (frozen-replay, report-generation only, N=16) agar
   tidak tertukar dengan smoke test full-pipeline (0,500, N=1) (§3, §4).
5. **SUS**: 80,31 benar; perbaiki dua kemunculan lain (80,33 di Abstrak ID,
   83,33 di Abstrak EN) (§5).
6. **Penamaan profile**: tambahkan catatan kaki di Bab IV untuk
   menjembatani istilah "Profile" (dataset/model variant) di tabel evidence
   cases dengan istilah `model_profile` di Bab III (§6).

Detail tindak lanjut & pemetaan ke 27 item rekomendasi evaluator →
[06-rekomendasi.md](06-rekomendasi.md).
