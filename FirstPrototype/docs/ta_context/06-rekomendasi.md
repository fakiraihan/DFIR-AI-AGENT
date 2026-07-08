# Rekomendasi Perbaikan — Pemetaan ke 27 Item Evaluasi & Saran Sistem

> Dokumen ini memetakan **27 item rekomendasi** di
> `Evaluasi_TA_Muhammad_Faki_Raihan.md` BAGIAN VI ke **konteks teknis aktual**
> yang sudah didokumentasikan di
> [01-product-frontend.md](01-product-frontend.md),
> [02-backend-orkestrasi-api.md](02-backend-orkestrasi-api.md),
> [03-pipeline-parsing-deeplog.md](03-pipeline-parsing-deeplog.md),
> [04-ai-agent-langgraph.md](04-ai-agent-langgraph.md), dan
> [05-evaluasi-rekonsiliasi.md](05-evaluasi-rekonsiliasi.md) — sehingga setiap
> revisi bisa langsung mengutip sumber yang *traceable*. Bagian terakhir
> (§5) memuat rekomendasi **di luar 27 item**, untuk sistem itu sendiri,
> yang ditemukan selama eksplorasi repository.

---

## 1. Prioritas Tinggi — Wajib Sebelum Penyerahan (Item 1–7)

Ketujuh item ini bersifat **editorial/definisional** — sebagian besar tidak
memerlukan investigasi kode lebih lanjut, karena ground truth-nya sudah ada
di dokumen 01–05.

| # | Temuan | Rujukan Konteks | Tindakan Konkret |
|---|---|---|---|
| 1 | Tiga nilai SUS (80,33 / 83,33 / 80,31) | [05§5](05-evaluasi-rekonsiliasi.md#5-sus--8031-benar-8033--8333-typo) — 1285÷16=80,3125→**80,31** terverifikasi benar | Ganti Abstrak ID (80,33→80,31) dan Abstrak EN (83,33→80,31). Bab IV.3.4/Lampiran 2 sudah benar, tidak diubah. |
| 2 | Duplikasi paragraf Abstrak EN | — (murni teks) | Hapus satu dari dua paragraf identik *"Log-based cyber incident investigation still faces challenges..."*. |
| 3 | Judul III.3.3.3 tidak sesuai isi | [04§6](04-ai-agent-langgraph.md#6-mapping-ke-sub-bab-skripsi) — tabel mapping lengkap | Ganti judul → **"Implementasi AI Agent Berbasis LangGraph"**. Isi sub-bab diambil dari [04§1-2](04-ai-agent-langgraph.md#1-kelas-dfiragent--gambaran-umum) (kelas `DFIRAgent`, 11 node, diagram state machine). |
| 4 | "tiga bab" + sisa kata "Proposal" | — (murni teks, I.5) | Ganti "tiga bab" → "empat bab"; ganti "Penulisan Proposal ini" → "Laporan Tugas Akhir ini". |
| 5 | "dapat dapat" | — (murni teks, Latar Belakang hal. 5) | Hapus satu kata duplikat. |
| 6 | Separator desimal tidak konsisten | Semua angka di [05](05-evaluasi-rekonsiliasi.md) memakai notasi titik (gaya kode/laporan teknis) | Saat memindahkan angka dari dok 01–05 ke Bab IV, **konversi ke format koma + 2 digit** (mis. `0.9823` → `0,98`; `0.864` → `0,86`; `0.863` → `0,86`). **Konsisten 2 digit** kecuali pada kasus yang memang membutuhkan presisi lebih (misalnya tabel top-k DeepLog yang sudah 4 digit di laporan asli — diskusikan dengan pembimbing apakah tabel teknis ini ikut dibulatkan atau dipertahankan sebagai lampiran). |
| 7 | Konfusi nomenklatur "tools" | [04§3](04-ai-agent-langgraph.md#3-nomenklatur-tools-agentic-tools-vs-external-api-tools) — **definisi lengkap + tabel 2 kategori + kalimat siap-pakai** | Tambahkan sub-bab baru di Bab II berisi tabel [04§3.1](04-ai-agent-langgraph.md#31-dua-kategori-tools-yang-berbeda-secara-fundamental) (Agentic Tools vs External API Tools). Gunakan kalimat klarifikasi siap-pakai di [04§3.2](04-ai-agent-langgraph.md#32-mengapa-pembedaan-ini-penting) untuk Bab IV saat membahas Tool Correctness. |

---

## 2. Prioritas Tinggi — Perbaikan Substansial Konten (Item 8–17)

Item-item ini memerlukan **konten teknis baru** di Bab II/III/IV. Untuk
sebagian besar, konten tersebut **sudah ditulis lengkap** di dok 03/04 dan
bisa diadaptasi langsung.

### Item 8 — Arsitektur layering & diagram state machine LangGraph 🔴

Ini temuan terbesar Penguji I, dengan tiga sub-permintaan:

| Sub-permintaan PG | Sumber konten siap-pakai |
|---|---|
| "Layer Connector" (frontend → backend → pipeline → AI Agent → external tools) belum terpetakan | [02§1](02-backend-orkestrasi-api.md#1-posisi-dalam-arsitektur) (diagram Frontend↔FastAPI↔Orchestrator↔modules) + [03§1](03-pipeline-parsing-deeplog.md) (diagram pipeline end-to-end Drain→DeepLog→LLM Gate→Agent→Report) + [04§3.1](04-ai-agent-langgraph.md#31-dua-kategori-tools-yang-berbeda-secara-fundamental) (tabel agentic vs external tools, menunjukkan siapa memanggil apa). **Gabungkan ketiganya menjadi satu diagram layer tunggal** untuk Bab III.3.1. |
| Diagram state machine LangGraph "tidak sesimpel itu" (Gambar 4.9-4.10 belum memadai) | [04§2.1](04-ai-agent-langgraph.md#21-definisi-graph-_build_graph-agentpy105-158) — diagram Mermaid **lengkap**: 11 node + 9 cabang kondisional bernama, plus tabel node ([04§2.2](04-ai-agent-langgraph.md#22-tabel-node--fungsi-peran-dan-modul-pendukung)) dan tabel router ([04§2.3](04-ai-agent-langgraph.md#23-tabel-conditional-edge-router-kondisi-tujuan)). **Render diagram Mermaid ini sebagai gambar pengganti/tambahan Gambar 4.9-4.10.** |
| "Kemampuan LangGraph dalam konteks ini apa?" | [04§2.4](04-ai-agent-langgraph.md#24-mekanisme-bounded--fail-open) — jawaban konkret: LangGraph memberi (a) **conditional routing** berbasis isi state runtime (3 router dengan 9 cabang — bukan `if/else` linear sederhana), (b) **bounded loop** terkontrol via counter di state (`tool_execution_round`, `reflection_round`, `planning_round`) sehingga *ReAct loop* tidak berjalan tak terbatas, (c) **accumulator state** (`Annotated[List, operator.add]`) yang mengakumulasi jejak penalaran (`reasoning_steps`, `tool_calls`, dll.) lintas-node sebagai *audit trail* — sesuatu yang harus diimplementasikan manual jika memakai pendekatan *loop* sederhana. |

### Item 9 — Asal-usul/inspirasi desain sistem (Bab III.3.3) 🟠

Dok 01–05 mendokumentasikan **apa** yang dibangun, tetapi tidak (dan tidak
bisa) mendokumentasikan **rujukan literatur** di balik setiap keputusan
desain — ini perlu ditulis oleh penulis sendiri. Sebagai titik awal,
berikut pemetaan komponen → kandidat rujukan literatur standar yang relevan
(perlu diverifikasi terhadap daftar pustaka yang sudah ada):

| Komponen sistem | Kandidat basis literatur |
|---|---|
| Pola **ReAct** (reasoning → action → observation) di `DFIRAgent` ([04§1](04-ai-agent-langgraph.md#1-kelas-dfiragent--gambaran-umum)) | Yao et al., *"ReAct: Synergizing Reasoning and Acting in Language Models"* (2022) |
| **DeepLog** (LSTM next-event prediction, top-k) ([03§3](03-pipeline-parsing-deeplog.md)) | Du et al., *"DeepLog: Anomaly Detection and Diagnosis from System Logs through Deep Learning"* (2017) |
| **Drain3** template mining ([03§2](03-pipeline-parsing-deeplog.md)) | He et al., *"Drain: An Online Log Parsing Approach with Fixed Depth Tree"* (2017) |
| **LangGraph `StateGraph`** (graph beranotasi dengan *conditional edges*) ([04§2](04-ai-agent-langgraph.md#2-state-machine-langgraph--diagram-lengkap)) | Dokumentasi resmi LangGraph (LangChain, Inc.) — kerangka *stateful multi-step agent* |
| **Tool-Augmented LLM** / *function calling* untuk tool selection ([04§3](04-ai-agent-langgraph.md#3-nomenklatur-tools-agentic-tools-vs-external-api-tools)) | Literatur TaLLM yang sudah dirujuk Bab I/II (perlu konsistensi sitasi) |

**Tindakan**: setiap baris di atas perlu diubah menjadi 1-2 kalimat di
III.3.3 yang menyatakan secara eksplisit *"komponen X diadaptasi dari
[Penulis, Tahun] dengan modifikasi/penyesuaian [...]"* — bukan hanya
referensi implisit di daftar pustaka.

### Item 10 & 11 — Bab II diperkaya, Bab IV murni hasil (Define→Prescript→Result) 🔴🟠

Tabel di [04§6](04-ai-agent-langgraph.md#6-mapping-ke-sub-bab-skripsi)
mencantumkan istilah yang "tiba-tiba muncul" di Bab IV. Untuk masing-masing,
berikut sumber definisi yang sudah ditulis dan tinggal diadaptasi ke Bab II:

| Istilah yang perlu dipindah ke Bab II | Sumber definisi siap-pakai |
|---|---|
| `event_template`, `parameter_array`, *anomaly window* | [03§2-3](03-pipeline-parsing-deeplog.md) (Drain3, parameter extraction regex, sliding window) |
| `InvestigationState` (kontainer memori AI Agent) | [04§4](04-ai-agent-langgraph.md#4-investigationstate--kontrak-data-antar-node) — tabel field lengkap per kelompok (Input/Episodic Memory/Output/Control) |
| *Agentic tools* vs *external API tools* | [04§3](04-ai-agent-langgraph.md#3-nomenklatur-tools-agentic-tools-vs-external-api-tools) (lihat juga Item 7) |
| *LangGraph node*, *edge kondisional*, *stateful graph* | [04§2](04-ai-agent-langgraph.md#2-state-machine-langgraph--diagram-lengkap) |
| Mekanisme *sliding window* DeepLog | [03§3](03-pipeline-parsing-deeplog.md) — termasuk cuplikan kode `_build_windows()` |
| *IOC enrichment* & 6 layanan threat-intel | [04§3.3](04-ai-agent-langgraph.md#33-6-external-api-tools--ringkasan-pemetaan-ioc--tool) — tabel 6 tool × tipe IOC |

**Tindakan**: pindahkan tabel/diagram di atas ke sub-bab Bab II yang sesuai
(II.1.x), lalu di Bab IV **hapus** definisi ulang dan **ganti** dengan
kalimat referensi: *"sebagaimana didefinisikan pada II.1.x, ..."* diikuti
langsung oleh hasil pengujian/observasi.

### Item 12 — Diagram transformasi log → input LSTM 🟠

[03§3](03-pipeline-parsing-deeplog.md) sudah memuat **diagram Mermaid
lengkap** "Raw Log → Input LSTM": *raw log → event template (Drain) → event
ID (vocab lookup) → sequence array → sliding window → tensor →
`DeepLogModel.forward()` → softmax → top-k → `strict_is_anomaly` → decision
policy → `is_anomaly` final*. Dokumen ini juga menjawab pertanyaan PG secara
langsung:

- *"Apakah log parsing prasyarat wajib?"* → Ya — dijelaskan di [03§1-2](03-pipeline-parsing-deeplog.md) (5 profil parsing, semuanya menghasilkan `event_template` sebelum DeepLog dapat dipanggil).
- *"Vocabulary/model Windows vs Linux terpisah atau shared?"* → **Terpisah** — `config.py` mendefinisikan path model/vocab berbeda per profil (`windows_evtx_deeplog_model_path` vs `lmd_enriched_deeplog_model_path`, dst. — lihat [05§6](05-evaluasi-rekonsiliasi.md#6-catatan-tambahan-penamaan-profile-di-laporan-evaluasi-vs-dokumentasi-pipeline)). Alasannya: vocabulary event template Windows dan Linux secara fundamental berbeda (nama proses, syscall, dll.), sehingga model per-platform diperlukan agar prediksi top-k bermakna.

**Tindakan**: salin diagram Mermaid dari [03§3](03-pipeline-parsing-deeplog.md)
ke Bab II/III sebagai gambar baru, dan tambahkan 1 paragraf yang menjawab
dua poin di atas secara eksplisit.

### Item 13 — Tabel justifikasi pemilihan DeepLog 🔴

[03§5](03-pipeline-parsing-deeplog.md) sudah memuat **tabel perbandingan
DeepLog vs 3 kategori alternatif** (classifier supervised, statistik/PCA,
*autoencoder* unsupervised) di 6 kriteria — termasuk kriteria yang relevan
untuk pertanyaan PG: ketersediaan label anomali, kebutuhan *online
detection*, kompatibilitas *forecasting-based approach*, kompleksitas
implementasi.

**Catatan penting**: jawaban lisan *"lebih cepat dan lebih bisa menangkap
semantik log"* (dinilai tidak akurat oleh PG) **tidak perlu dipertahankan**
— ganti dengan argumen dari tabel [03§5](03-pipeline-parsing-deeplog.md):
DeepLog dipilih karena (a) **tidak memerlukan dataset berlabel anomali**
(dataset DFIR publik jarang punya label lengkap), dan (b) **forecasting-based**
(prediksi *next-event*) cocok untuk deteksi *online* tanpa perlu
pre-komputasi statistik global seperti PCA.

**Tindakan**: salin tabel dari [03§5](03-pipeline-parsing-deeplog.md) ke Bab
II/III sebagai "Tabel Kriteria Pemilihan Metode Deteksi Anomali", dan revisi
narasi justifikasi sesuai poin di atas.

### Item 14 — Investigasi top-k tinggi DeepLog Linux 🔴

Lihat [05§1.2](05-evaluasi-rekonsiliasi.md#12-linux--top-k-182-vs-top-k-328329-natural-evaluation)
untuk analisis lengkap + **koreksi kutipan** (top-k 182/recall 0,7292
sebenarnya dari tabel *balanced*, bukan *natural*). Untuk **analisis
penyebab** (yang diminta PB: *"kenapa top-k harus ratusan?"*), gunakan
3 poin yang sudah dirumuskan di [03§6](03-pipeline-parsing-deeplog.md):

1. Vocabulary event Linux jauh lebih kecil/homogen dibanding Windows
   (template AIT-LDS lebih sedikit variasi dibanding EVTX/Sysmon) →
   prediksi top-k kecil tidak cukup "menutup" variasi urutan event normal.
2. Kurva F1 terhadap top-k (tabel ultrafine 321-339, [05§1.2](05-evaluasi-rekonsiliasi.md))
   menunjukkan **plateau**, bukan lonjakan tajam — top-k besar adalah
   *operating point* yang masuk akal pada distribusi ini, bukan tanda model
   "rusak".
3. Top-k besar **bukan konfigurasi operasional default** — ini adalah hasil
   *sweep* evaluasi untuk mencari titik F1 terbaik, sedangkan konfigurasi
   default produksi tetap `top-k=9` (sama dengan Windows, lihat
   `config.py` `training top-k default`).

**Tindakan**: tulis paragraf analisis di Bab IV.3.1 berdasarkan 3 poin di
atas + tabel terkoreksi dari [05§1.2](05-evaluasi-rekonsiliasi.md), dan
**framing eksplisit** bahwa recall Linux yang lebih rendah adalah
**keterbatasan yang diakui** (bukan klaim "performa setara Windows") — ini
juga menjawab kalimat evaluasi *"implikasinya terhadap klaim multi-platform
secara setara"*.

### Item 15 — Tidak ada lokus penelitian → pembatasan masalah resmi 🟢

Tidak memerlukan konteks sistem. **Tindakan**: tambahkan ke I.3 (Pembatasan
Masalah) kalimat yang menyatakan: lokus penelitian operasional tidak
tersedia (karena pergantian pimpinan), sehingga pengujian dilakukan dengan
**dataset publik** (sebutkan nama dataset: Linux APT 2024, Windows-APT 2025,
LMD/Sysmon enriched — lihat [03](03-pipeline-parsing-deeplog.md) dan
[05§6](05-evaluasi-rekonsiliasi.md#6-catatan-tambahan-penamaan-profile-di-laporan-evaluasi-vs-dokumentasi-pipeline))
sebagai pengganti data operasional, dengan implikasi generalisasi hasil yang
terbatas pada karakteristik dataset publik tersebut.

### Item 16 — Homogenitas responden SUS → keterbatasan resmi 🔴

Lihat [05§5](05-evaluasi-rekonsiliasi.md#5-sus--8031-benar-8033--8333-typo)
untuk angka yang sudah benar (80,31). Untuk narasi keterbatasan: tambahkan
ke I.3 dan IV.3.4 bahwa 16 responden adalah mahasiswa/taruna (homogen dari
sisi latar belakang/usia/pengalaman), dan definisikan **kriteria inklusi
ideal** untuk pengujian SUS DFIR — misalnya: memiliki sertifikasi keamanan
siber (CEH/eJPT/GCFA/dll.), minimal N bulan pengalaman investigasi log
insiden, atau pernah menggunakan tool SIEM/SOAR.

### Item 17 — Bias judge model Tool Correctness 🔴

[05§2](05-evaluasi-rekonsiliasi.md#21-bukti-konkret-untuk-kritik-judge-bias-v52c)
memuat **bukti konkret siap-kutip**: 3 kategori (single_md5_file_hash,
single_sha256_file_hash, single_url_malware_delivery) bernilai 0,750 dengan
*reason* eksplisit *"Missing Tools: None, Extra Tools: None, Argument
Mismatches: 0"* namun tetap FAIL pada threshold 0,8.

**Tindakan**: kutip langsung *reason* ini di Bab IV.3.2 sebagai bukti bahwa
**coverage 100% tidak menjamin pass**, lalu sambungkan ke diskusi
*outcome-based metric* sesuai saran PB (lihat juga [05§2](05-evaluasi-rekonsiliasi.md)
untuk catatan tambahan soal kalibrasi threshold 0,8 vs skala skor 0,75-1,00).

---

## 3. Prioritas Menengah (Item 18–24)

| # | Temuan | Rujukan & Tindakan |
|---|---|---|
| 18 | Inkonsistensi "Forensic" vs "Forensics" | Standarkan ke **"Digital Forensics and Incident Response (DFIR)"** (NIST SP 800-86) di seluruh dokumen — *find & replace* global. Dok 01–05 di repo ini sudah konsisten memakai "Forensics". |
| 19 | Judul Tabel 4.24 & 4.26 identik | Tabel 4.24 (agregat) → ganti judul jadi **"Hasil Agregat Pengujian G-Eval"**. Untuk isi tabel agregat, [05§3](05-evaluasi-rekonsiliasi.md#3-g-eval--0863-aktual-vs-08675-dikutip-di-tesis) memuat nilai `mean_geval_score`/`pass_rate` terkoreksi (0,863, bukan 0,8675) yang sebaiknya dipakai di Tabel 4.24. |
| 20 | Sintesis gap di akhir II.2 tidak ada | Gunakan poin novelitas di BAGIAN V.5.1 evaluasi sebagai basis paragraf sintesis: *integrasi end-to-end Drain→DeepLog→LLMAnomalyFilter→AI Agent→Report, LLM lokal open-source untuk kerahasiaan artefak digital, evaluasi multi-dimensi*. Tambahkan kolom "Keterbatasan/Gap" di Tabel 2.1 yang merujuk ke kelemahan kandidat/peneliti terdahulu yang **belum** mengintegrasikan kelima komponen ini secara end-to-end. |
| 21 | Elaborasi prompting untuk Tool Correctness | [04§3.4](04-ai-agent-langgraph.md#34-prompt-llm-untuk-tool-selection) — deskripsi prompt *tool selection* yang sudah ada (persona "Security Analyst TNI AL", limit 15 IOC, *mapping guideline* per tipe IOC, format output `tipe:nilai -> nama_tool`). Untuk diskusi perbaikan potensial: *few-shot examples*, *structured output* (JSON mode dengan skema tetap, mengurangi kesalahan parsing `_parse_tool_selections()`), atau penyempurnaan deskripsi tool individual. |
| 22 | Kemampuan LangGraph belum dijelaskan | Sama dengan Item 8 sub-poin 3 — [04§2.4](04-ai-agent-langgraph.md#24-mekanisme-bounded--fail-open). |
| 23 | Tool Correctness tidak terhubung ke arsitektur | [04§3.2-3.3](04-ai-agent-langgraph.md#32-mengapa-pembedaan-ini-penting) — tambahkan kalimat referensi silang: *"Tool Correctness (0,86) mengukur fungsi `select_tools()` pada node `tool_selector` (Tabel [04§2.2](04-ai-agent-langgraph.md#22-tabel-node--fungsi-peran-dan-modul-pendukung) baris 3), yang memilih di antara 6 external API tools (Tabel [04§3.3](04-ai-agent-langgraph.md#33-6-external-api-tools--ringkasan-pemetaan-ioc--tool)) berdasarkan tipe IOC."* — hubungkan langsung ke diagram state machine Item 8. |
| 24 | LLMAnomalyFilter tidak ada landasan teori | [03§4](03-pipeline-parsing-deeplog.md) — sub-bab teori **sudah lengkap**: *batch sanity gate*, 20 anomali teratas, 5 *policy* (`keep_all`, `keep_high_confidence_only`, `prioritize_critical`, `request_more_context`, `skip_low_signal_with_note`), dua mekanisme *fail-open* (`LOW_CONFIDENCE_THRESHOLD=0.4` dan *empty-result fail-open*), serta field anotasi. Salin sebagai sub-bab baru Bab II — judul disarankan: *"Landasan Teori LLM Anomaly Gate (Filter Anomali Berbasis LLM)"*. |

---

## 4. Prioritas Pengembangan — Versi Jurnal/Publikasi (Item 25–27)

| # | Temuan | Rujukan & Tindakan |
|---|---|---|
| 25 | Tidak ada data latency investigasi | [02§6](02-backend-orkestrasi-api.md#6-telemetri--observability) — dua mekanisme telemetri (`activity_events`, `gate_observations.jsonl`) sudah berjalan tetapi **tidak secara eksplisit mencatat durasi siklus investigasi**. Periksa apakah `gate_observations.jsonl` (ditulis di `orchestrator_service.py:471-490`) sudah memiliki *timestamp* yang cukup untuk menghitung latensi end-to-end secara retroaktif dari data yang sudah ada (low-cost win). Jika tidak, tambahkan pencatatan `started_at`/`completed_at` per sesi di `session_store` sebagai instrumentasi minimal untuk evaluasi lanjutan. |
| 26 | Definisi maturitas prototipe tidak ada | `PRODUCT.md` ([01§1](01-product-frontend.md)) tidak mendefinisikan tingkat maturitas. Berdasarkan observasi sistem (pipeline lengkap berjalan, UI fungsional, sesi persisten, evaluasi kuantitatif tersedia, namun belum diuji pada data operasional/lokus nyata — Item 15), klasifikasikan sebagai **"functional prototype"** (bukan *proof-of-concept* murni, juga bukan *pilot system* yang sudah divalidasi di lingkungan operasional). Sebutkan definisi ini secara eksplisit di I.3 atau II, sejalan dengan taksonomi maturitas artefak DSRM (Hevner et al.). |
| 27 | Foundation-Sec-8B tidak dikaitkan dengan hasil evaluasi | [02§4.1](02-backend-orkestrasi-api.md#41-catatan-penting-provider-llm-dapat-berbeda-per-peran) — model default kedua peran (`filter` & `agent`) adalah `sec-foundation:8b-gpu` via Ollama. Diskusikan: ukuran model 8B (relatif kecil) sebagai kemungkinan faktor di balik (a) Tool Correctness pass-rate 50% (model kecil cenderung kurang presisi mengikuti instruksi format output `tipe:nilai -> nama_tool`, lihat Item 21), dan (b) G-Eval 0,863 yang tetap baik untuk *generative* (menulis laporan) meski *instruction-following* terstruktur (tool selection) lebih lemah. Sarankan sebagai *future work*: ablasi dengan model lebih besar atau model umum (non-security-tuned) untuk membandingkan trade-off domain-specialization vs *instruction-following* size. |

---

## 5. Rekomendasi Sistem (Di Luar 27 Item Evaluasi)

Ditemukan selama eksplorasi kode untuk dok 01–05 — **tidak diminta
evaluator**, tetapi relevan untuk kualitas sistem dan/atau bisa memperkuat
narasi Bab III jika disebutkan.

| # | Temuan | Lokasi | Rekomendasi |
|---|---|---|---|
| S1 | `HeroLanding.jsx` menampilkan F1=0,9489/Recall=0,9151/FPR=1,23% — angka **lama**, tidak cocok dengan hasil evaluasi terkini (F1=0,9823) | `frontend/src/components/HeroLanding.jsx:153,187,194` | Update ke angka terkini ([05§1.1](05-evaluasi-rekonsiliasi.md#11-windows--f1-09823-vs-angka-di-herolandingjsx)), atau jadikan dinamis (ambil dari artefak evaluasi/`config` backend) agar tidak perlu update manual setiap retraining. |
| S2 | `react-router-dom` ada di `package.json` tetapi **tidak digunakan** untuk routing — satu-satunya kemunculan adalah ikon `RouteOutlinedIcon` | `frontend/package.json`, dipakai di `ReportDashboard.jsx` (hanya ikon) | Hapus dependency `react-router-dom` (mengecilkan bundle), **atau** jika navigasi berbasis `VALID_VIEWS`/state di [01§4](01-product-frontend.md) ingin direfaktor jadi routing berbasis URL, gunakan library ini secara nyata. Untuk skripsi: jangan sebut "menggunakan React Router" jika tidak benar dipakai (navigasi aktual = *state-driven*, lihat [01§4](01-product-frontend.md)). |
| S3 | `frontend/README.md` outdated — menyebut `ChatbotPage.jsx` dan *"pure CSS tanpa framework"*, tidak sesuai realitas (MUI v5 + Emotion) | `frontend/README.md` | Update README agar sesuai stack aktual ([01§3](01-product-frontend.md)), atau hapus jika tidak dipelihara — **jangan jadi rujukan** saat menulis Bab III/IV (sudah ditandai di [01](01-product-frontend.md)). |
| S4 | Tidak ada UI untuk konfigurasi LLM **per-role** (`filter` vs `agent`), meski backend mendukungnya | `SettingsPage.jsx` ([01§5](01-product-frontend.md)) vs `build_role_client(role=...)` ([02§4.1](02-backend-orkestrasi-api.md#41-catatan-penting-provider-llm-dapat-berbeda-per-peran)) | Jika Bab III ingin mengklaim *"fleksibilitas konfigurasi LLM per peran"* sebagai kekuatan desain, **tambahkan kontrol UI**-nya agar klaim dapat didemonstrasikan di Bab IV (demo). Jika tidak, jangan klaim fleksibilitas ini sebagai fitur *user-facing* — sebut sebagai *"arsitektur mendukung, belum diekspos ke UI"*. |
| S5 | Kolom "Profile" di tabel *evidence cases* G-Eval (`windows_apt`, `sysmon`) ≠ nilai `model_profile` di [03](03-pipeline-parsing-deeplog.md) (`windows_evtx`, `windows_sysmon`, dll.) | `evaluation/reports/report_generation_geval_eval.md`, `report_geval_evtx_eval.md` | Tambahkan catatan kaki di Bab IV ([05§6](05-evaluasi-rekonsiliasi.md#6-catatan-tambahan-penamaan-profile-di-laporan-evaluasi-vs-dokumentasi-pipeline)) yang menjembatani kedua istilah, agar pembaca tidak menganggap ada profil ke-6 yang belum dijelaskan. |
| S6 | Angka metrik (F1, G-Eval, dll.) tersebar di banyak file (`docs/reports/*.md`, `evaluation/results/*.json`, hardcoded di `HeroLanding.jsx`) tanpa satu sumber kebenaran tunggal | Lintas-repo | Untuk jangka panjang (di luar lingkup revisi tesis): pertimbangkan satu *metrics manifest* (JSON/YAML) yang dibaca baik oleh laporan Markdown maupun `HeroLanding.jsx`, untuk mencegah drift seperti S1 dan [05§3](05-evaluasi-rekonsiliasi.md#3-g-eval--0863-aktual-vs-08675-dikutip-di-tesis) terjadi lagi di masa depan. |

---

## 6. Roadmap Singkat Pengerjaan

Mengingat evaluator menyarankan **mendiskusikan poin 8-11 dengan
pembimbing** terlebih dahulu karena sifatnya struktural, berikut urutan
pengerjaan yang disarankan berdasarkan ketersediaan konten dan tingkat
risiko:

1. **Fase 1 — Quick wins editorial (bisa langsung, tanpa diskusi)**:
   Item 1, 2, 4, 5, 6, 18, 19 — semua murni perbaikan teks/format,
   nilai-nilai sudah terverifikasi di [05](05-evaluasi-rekonsiliasi.md).
2. **Fase 2 — Konten siap-pakai (adaptasi dari dok 03/04/05)**:
   Item 3, 7, 12, 13, 14, 17, 21, 23, 24 — konten teknis **sudah ditulis
   lengkap**, hanya perlu diadaptasi ke format Bab II/III/IV (termasuk
   konversi format angka per Item 6).
3. **Fase 3 — Struktural, perlu diskusi pembimbing**:
   Item 8, 9, 10, 11 — diagram layering + restrukturisasi
   Define→Prescript→Result. Risiko waktu terbesar; gunakan tabel pemetaan
   di §2 sebagai bahan diskusi cakupan dengan pembimbing.
4. **Fase 4 — Narasi keterbatasan (sensitif, perlu kehati-hatian wording)**:
   Item 15, 16, 20 — pastikan framing sebagai *pembatasan masalah yang
   diakui*, bukan kelemahan yang ditutupi.
5. **Fase 5 — Opsional/jurnal (jika waktu memungkinkan)**:
   Item 22, 25, 26, 27 — memperkuat naskah untuk publikasi setelah sidang.
