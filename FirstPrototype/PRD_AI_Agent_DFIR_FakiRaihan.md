**PRODUCT REQUIREMENTS DOCUMENT**

**AI Agent Berbasis Tool-Augmented LLM**

untuk Otomatisasi Investigasi Insiden Siber dengan Integritas Laporan

*(Studi Kasus: Pusat Siber TNI AL)*

|  |  |
| --- | --- |
| **Disusun oleh** | Muhammad Faki Raihan |
| **NPM** | 2221101820 |
| **Program Studi** | Rekayasa Kriptografi |
| **Institusi** | Politeknik Siber dan Sandi Negara |
| **Versi Dokumen** | 1.0.0 |
| **Tanggal** | 24 Februari 2026 |
| **Status** | Draft — Internal Review |

# **1. Overview Produk**

## **1.1 Latar Belakang**

Pusat Siber TNI Angkatan Laut menghadapi tantangan dalam investigasi insiden siber pada konteks operasi taktis, di mana infrastruktur SIEM enterprise tidak selalu tersedia. Proses investigasi Digital Forensics and Incident Response (DFIR) saat ini dilakukan secara manual: parsing log dari berbagai sumber (Windows Event Log, Sysmon, Linux logs), korelasi artefak, dan enrichment threat intelligence dilakukan terpisah-pisah menggunakan tools seperti Chainsaw dan Splunk.

Kondisi ini mengakibatkan tingginya beban kognitif analis, waktu investigasi yang panjang, serta potensi inkonsistensi dalam penggunaan tool analitik. Sistem yang dikembangkan bertujuan mengotomasi pipeline investigasi berbasis log melalui AI Agent yang berjalan sepenuhnya secara lokal, tanpa ketergantungan cloud.

## **1.2 Tujuan Produk**

* Merancang dan membangun prototipe AI Agent berbasis Tool-Augmented LLM (TaLLM) yang mengotomasi investigasi DFIR dari parsing log hingga laporan investigasi terstruktur.
* Mengevaluasi performa teknis AI Agent: ketepatan penggunaan tool analitik (Tool Correctness) dan kualitas laporan (G-Eval).
* Mengukur efisiensi waktu investigasi dibandingkan metode manual (Time Reduction Rate).
* Mengukur tingkat usability sistem menggunakan System Usability Scale (SUS).

## **1.3 Ruang Lingkup**

Sistem mencakup:

* Parsing log semi-terstruktur (Windows EVTX/Sysmon, Linux logs) menggunakan algoritma Drain.
* Deteksi anomali berbasis deep learning menggunakan DeepLog (LSTM-based sequence model with top-k prediction).
* Orkestrasi investigasi oleh AI Agent berbasis LangGraph dengan model Foundation-Sec-8B (local inference).
* Enrichment IOC via threat intelligence API: ThreatFox, MalwareBazaar, URLHaus, AlienVault OTX, GreyNoise, VirusTotal.
* Generasi laporan investigasi terstruktur.
* Antarmuka pengguna berbasis React (web).

Di luar ruang lingkup:

* Pre-incident detection / real-time streaming log.
* Integrasi langsung dengan SIEM enterprise.
* Fine-tuning atau re-training model LLM.
* Evaluasi forensik formal untuk kepentingan pembuktian hukum.
* Pembangunan infrastruktur threat intelligence mandiri.

## **1.4 Pengguna Target**

| **Persona** | **Deskripsi** | **Kebutuhan Utama** |
| --- | --- | --- |
| Analis DFIR (Primer) | Personel Satgas Siber TNI AL yang melakukan investigasi insiden di lapangan | Kecepatan triase, akurasi enrichment IOC, laporan siap-pakai |
| Komandan / Pengambil Keputusan | Perwira yang membutuhkan ringkasan eksekutif insiden | Laporan singkat, terverifikasi, dapat dipertanggungjawabkan |
| Peneliti / Akademisi | Evaluator sistem dan kontributor metodologi | Metrik evaluasi kuantitatif, reprodusibilitas eksperimen |

# **2. Arsitektur Sistem**

## **2.1 Gambaran Umum Arsitektur**

Sistem dibangun dengan arsitektur client-server. Frontend (React) mengirimkan file log melalui REST API ke backend (FastAPI/Python). Backend mengorkestrasi empat modul utama secara sekuensial:

| **Modul** | **Teknologi** | **Input** | **Output** |
| --- | --- | --- | --- |
| Log Parsing | Drain (Python) | Raw log files | Event templates + parameter arrays |
| Anomaly Detection | DeepLog (LSTM) | Event template sequences | Anomaly predictions per window |
| AI Agent Orchestration | LangGraph + Foundation-Sec-8B | Anomaly candidates | Tool calls + investigation context |
| Report Generation | LLM | Investigation context | Investigation report |

## **2.2 Stack Teknologi**

| **Layer** | **Komponen** | **Keterangan** |
| --- | --- | --- |
| Frontend | React.js | UI upload log, visualisasi hasil |
| Backend API | FastAPI (Python) | REST API, orchestration controller |
| Log Parsing | Drain3 (drain3 library) | depth=4, sim\_threshold=0.5 |
| Anomaly Detection | DeepLog / PyTorch | LSTM embedding=128, hidden=128, layers=2 |
| AI Agent Framework | LangGraph | Stateful graph, conditional edges |
| LLM Inference | Foundation-Sec-8B (local) | Llama-3.1 based, cybersecurity domain |
| Cryptography | cryptography (Python lib) | (optional — used for non-signature cryptographic utilities if needed) |
| Evaluation | DeepEval framework | Tool Correctness + G-Eval metrics |
| Dataset | Loghub (Windows Event Log) | Disediakan di folder lokal |

## **2.3 Alur Data End-to-End**

* User mengunggah file log (EVTX/Sysmon/.log) melalui antarmuka React.
* Backend menerima file dan menjalankan Drain: preprocessing (regex masking IP/numerik) → tokenisasi → penelusuran pohon depth-4 → output {event\_template, parameter\_array}.
* Event template sequences dikirim ke DeepLog: sliding window (size=10, step=5) → LSTM embedding (dim=128) → top-k prediction matching → anomaly detection per window.
* Window dengan anomaly (actual event not in top-k predictions) dieskalasikan sebagai kandidat anomali ke modul AI Agent.
* AI Agent (LangGraph stateful graph) menjalankan: ekstraksi IOC dari parameter\_array → pemilihan API threat intelligence → pemanggilan tool wrapper (Python) → penerimaan respons JSON → korelasi konteks → update episodic memory.
* Setelah siklus reasoning selesai, LLM menghasilkan narasi laporan investigasi terstruktur.
* Laporan final tersedia untuk unduh oleh user.

# **3. Spesifikasi Modul**

## **3.1 Modul Parsing Log (Drain)**

Catatan implementasi: Dataset dan implementasi Drain disediakan di folder lokal oleh peneliti. PRD ini mendefinisikan antarmuka dan parameter konfigurasi.

### **3.1.1 Konfigurasi Parameter**

| **Parameter** | **Nilai** | **Keterangan** |
| --- | --- | --- |
| depth | 4 | Kedalaman pohon parsing untuk pengelompokan template |
| sim\_threshold | 0.5 | Rasio minimum token cocok untuk merge ke template existing |
| max\_children | 100 | Batas maksimum anak node untuk mencegah pohon tak terbatas |
| regex\_preprocess | [custom patterns] | Masking IPv4, angka, timestamp sebelum tokenisasi |

### **3.1.2 Format Input/Output**

* Input: raw log lines (string), mendukung format Windows Event Log (text export dari EVTX), Sysmon logs, Linux syslog (/var/log/\*).
* Output per baris: { event\_id: str, event\_template: str, parameters: list[str], raw\_line: str }.
* Output agregat: DataFrame dengan kolom di atas, disimpan sebagai JSON/CSV untuk passing ke modul berikutnya.

### **3.1.3 Acceptance Criteria**

* Template extraction berjalan tanpa crash pada file log berukuran hingga 500MB.
* Parameter array mempertahankan nilai original (tidak di-mask) untuk keperluan IOC extraction.
* Waktu parsing < 60 detik untuk 100.000 log lines pada hardware target.

## **3.2 Modul Deteksi Anomali (DeepLog)**

Catatan implementasi: Model DeepLog dan dataset pelatihan (Wintrim) sudah dilatih dan tersedia di folder lokal. Backend melakukan inferensi menggunakan model yang sudah dilatih.

### **3.2.1 Konfigurasi Model**

| **Parameter** | **Nilai** | **Keterangan** |
| --- | --- | --- |
| Sliding window size | 10 | Jumlah event per window untuk prediksi |
| Step size | 5 | Offset antar window (overlap 50%) |
| Embedding dimension | 128 | Dimensi embedding vektor per event template |
| Hidden size | 128 | Ukuran hidden layer LSTM |
| Num layers | 2 | Jumlah layer LSTM |
| Architecture | LSTM | Standard LSTM dengan embedding layer |
| Training dataset | Wintrim (Windows CBS logs) | 996,699 entries, pure normal logs |
| Detection method | Top-k prediction | Default k=9, deteksi jika actual event not in top-k |
| Anomaly threshold | Top-k parameter (1-10) | Lower k = stricter, higher k = lenient |

### **3.2.2 Pipeline Inferensi**

* Input: list of event\_template (output Drain, ordered by timestamp).
* Preprocessing: pembentukan sliding windows dari sequence event templates.
* Embedding: setiap template di-map ke vocabulary index → embedding layer (dim=128).
* Inferensi: window sequences diproses oleh LSTM → output top-k predictions untuk next event.
* Detection: jika actual next event tidak ada di top-k predictions → window dianggap anomali.
* Filtering: window anomali → kandidat → diteruskan ke AI Agent beserta metadata (window\_id, event\_templates, parameters, prediction\_confidence).

### **3.2.3 Acceptance Criteria**

* Model ter-load dari file yang disediakan (DeepLog.pt + vocab.pkl) tanpa error pada startup backend.
* Inferensi menghasilkan top-k predictions untuk setiap window.
* Windows dengan anomaly (actual event not in top-k) ter-eskalasi ke modul AI Agent.
* Waktu inferensi < 30 detik untuk 10.000 windows pada hardware target.
* Detection rate: target ≥ 90% pada EVTX attack samples (baseline: 100% achieved in testing).

## **3.3 Modul AI Agent (LangGraph + Foundation-Sec-8B)**

### **3.3.1 Arsitektur Graf LangGraph**

* Graf stateful dengan node-node berikut:
  + ioc\_extractor: Mengekstrak IOC (IP, domain, URL, file hash) dari parameter\_array anomali kandidat.
  + tool\_selector: LLM menentukan tool threat intelligence yang relevan berdasarkan tipe IOC.
  + tool\_executor: Memanggil wrapper Python untuk API yang dipilih, menyimpan respons ke episodic memory.
  + correlator: Mengkorelasikan temuan tool calls dengan konteks anomali, memperbarui reasoning state.
  + report\_generator: LLM menghasilkan narasi laporan investigasi terstruktur.
* Edge kondisional: transisi antar node bergantung pada hasil eksekusi node sebelumnya (adaptive reasoning).
* Memori episodik: basis data terstruktur yang menyimpan anomali ringkasan, hasil tool calls, korelasi, dan laporan akhir per sesi investigasi.

### **3.3.2 Konfigurasi Model LLM**

| **Parameter** | **Nilai / Keterangan** |
| --- | --- |
| Model | Foundation-Sec-8B (Llama-3.1-FoundationAI-SecurityLLM-Base-8B) |
| Inference mode | Local (offline, no cloud dependency) |
| Reasoning pattern | ReAct (Reasoning and Acting) — think before tool call |
| Fine-tuning | Tidak dilakukan — model digunakan as-is |
| Tool calling format | Structured JSON representation, divalidasi sebelum eksekusi |

### **3.3.3 Integrasi Tool Threat Intelligence**

| **Tool / API** | **IOC Type Target** | **Informasi yang Diperoleh** |
| --- | --- | --- |
| ThreatFox | IP, domain, URL, hash | IOC network — malware family, confidence level |
| MalwareBazaar | File hash (MD5/SHA256) | Metadata malware, sample tags, first seen |
| URLHaus | URL, domain | Status distribusi malware via URL, threat category |
| AlienVault OTX | IP, domain, URL, hash | Community threat intel, pulse associations, geolocation |
| GreyNoise | IP address | Klasifikasi: benign/malicious/unknown, scanner activity |
| VirusTotal | IP, domain, URL, hash | Reputasi multi-vendor AV, deteksi rasio, sandbox reports |

### **3.3.4 Acceptance Criteria AI Agent**

* Agent berhasil mengidentifikasi tipe IOC dari parameter\_array dan memetakan ke tool yang sesuai.
* Tool call JSON valid sebelum eksekusi (divalidasi oleh lapisan kontrol — tidak langsung di-execute).
* Respons API ter-simpan di episodic memory dan dimasukkan kembali ke reasoning context.
* Agent tidak memanggil tool yang tidak relevan (hallucination tool call) — diukur melalui Tool Correctness metric.

## **3.4 Modul Laporan**

### **3.4.1 Struktur Laporan Investigasi**

* Executive Summary: kronologi insiden, severity, jumlah anomali terdeteksi.
* IOC Analysis: tabel IOC yang ditemukan beserta hasil enrichment per tool.
* Attack Timeline: rekonstruksi urutan event anomali secara kronologis.
* Tool Intelligence Summary: narasi korelasi dari seluruh respons threat intelligence API.
* Recommendations: rekomendasi tindak lanjut berdasarkan temuan.
* Metadata: timestamp analisis, model yang digunakan, versi model yang dipakai.

### **3.4.2 Acceptance Criteria**

* Laporan terstruktur yang lengkap dengan section yang ditentukan.
* Laporan dapat diekspor ke format PDF/JSON untuk dokumentasi dan distribusi.

# **4. Functional Requirements**

## **4.1 Tabel Functional Requirements**

| **FR-ID** | **Modul** | **Deskripsi** | **Prioritas** |
| --- | --- | --- | --- |
| FR-01 | Upload | User dapat mengunggah file log (EVTX, Sysmon, syslog) melalui antarmuka web. | Must Have |
| FR-02 | Parsing | Sistem menjalankan Drain pada log yang diunggah dan menghasilkan event templates + parameter arrays. | Must Have |
| FR-03 | Parsing | Sistem mempertahankan nilai parameter original (non-masked) untuk keperluan IOC extraction. | Must Have |
| FR-04 | Anomaly | Sistem menjalankan DeepLog pada event template sequences dan mendeteksi anomali per sliding window menggunakan top-k prediction. | Must Have |
| FR-05 | Anomaly | Sistem mengekskalasi windows dengan anomaly (not in top-k) ke AI Agent. | Must Have |
| FR-06 | Agent | AI Agent mengekstrak IOC dari parameter arrays kandidat anomali. | Must Have |
| FR-07 | Agent | AI Agent memanggil tool threat intelligence yang relevan berdasarkan tipe IOC menggunakan pola ReAct. | Must Have |
| FR-08 | Agent | Sistem memvalidasi format JSON tool call sebelum eksekusi (schema validation). | Must Have |
| FR-09 | Agent | Respons API tersimpan di episodic memory dan dimasukkan kembali ke reasoning context agen. | Must Have |
| FR-10 | Report | Sistem menghasilkan laporan investigasi terstruktur berdasarkan konteks agen. | Must Have |

| FR-15 | UI | Antarmuka menampilkan visualisasi hasil anomaly detection (anomaly score timeline). | Should Have |

# **5. Non-Functional Requirements**

## **5.1 Keamanan**

* Seluruh inferensi LLM berjalan secara lokal — tidak ada data log yang dikirim ke layanan cloud pihak ketiga.
* Koneksi ke threat intelligence API (ThreatFox, VirusTotal, dll.) menggunakan HTTPS dengan API key yang dikonfigurasi di environment variable.
* Kunci kriptografi yang diperlukan untuk operasi internal harus disimpan aman dan tidak diekspos melalui API.
* Data log yang diunggah tidak dipersistensikan setelah sesi investigasi selesai (sesuai prinsip data minimization).

## **5.2 Performa**

| **Metrik** | **Target** | **Kondisi Pengujian** |
| --- | --- | --- |
| Waktu parsing log | < 60 detik | 100.000 log lines |
| Waktu inferensi DeepLog | < 30 detik | 10.000 sliding windows |
| Waktu total pipeline (parse → laporan) | < 10 menit | File log tipikal skenario demonstrasi |
 

## **5.3 Portabilitas**

* Sistem dapat dijalankan pada mesin standalone tanpa konektivitas internet (kecuali untuk koneksi threat intelligence API yang bersifat opsional/configurable).
* Docker atau virtual environment Python tersedia untuk deployment yang konsisten.
* Model Foundation-Sec-8B dan LogRobust tersedia dalam format file lokal (disediakan di folder oleh peneliti).

## **5.4 Usability**

* Target skor SUS >= 70 (kategori Good pada skala Bangor et al.).
* Analis dapat menyelesaikan satu siklus investigasi (upload → laporan) tanpa pelatihan teknis mendalam.
* Antarmuka menampilkan status progres setiap tahap pipeline secara real-time.

# **6. Rencana Evaluasi & Metrik Keberhasilan**

## **6.1 Dimensi Evaluasi**

Sistem dievaluasi pada empat dimensi sesuai rumusan masalah penelitian:

### **6.1.1 Tool Correctness (DeepEval)**

| **Aspek** | **Detail** |
| --- | --- |
| Framework | DeepEval — Tool Correctness Metric |
| Konfigurasi | should\_exact\_match = True |
| Formula | S\_TC = Jumlah Penggunaan Tool Benar / Total Tool Dipanggil |
| Rentang skor | 0.0 — 1.0 (1.0 = seluruh tool tepat, no hallucination) |
| Validasi kriteria | (1) Nama tool sesuai skenario, (2) Parameter JSON identik, (3) Tidak ada runtime error |
| Target minimum | >= 0.80 untuk dinyatakan acceptable |

### **6.1.2 Kualitas Laporan — G-Eval (DeepEval)**

| **Aspek** | **Detail** |
| --- | --- |
| Framework | DeepEval — G-Eval (Generative Evaluation) |
| Evaluator model | GPT-4 (LLM-as-a-Judge) |
| Pendekatan | Chain-of-Thought rubrik penilaian |
| Kriteria rubrik | Relevansi narasi, konsistensi logis, kelengkapan IOC extraction |
| Formula | S\_GEval = Sigma(s\_i \* p(s\_i)), s\_i ∈ {1,2,3,4,5} |
| Output | Skor kontinu yang selaras dengan penilaian pakar manusia |
| Target minimum | >= 3.5 dari skala 5.0 |

### **6.1.3 Efisiensi Waktu (Time Reduction Rate)**

| **Aspek** | **Detail** |
| --- | --- |
| Titik awal (T0) | Saat analis/sistem menerima file log mentah yang terindikasi anomali |
| Titik akhir (T1) | Saat laporan investigasi terstruktur dengan enrichment IOC selesai dihasilkan |
| T\_manual | Waktu investigasi manual — dicatat dengan stopwatch selama simulasi analis |
| T\_ai | Waktu AI Agent — dicatat oleh backend (pipeline start → laporan tersimpan) |
| Formula | Efisiensi (%) = ((T\_manual - T\_ai) / T\_manual) x 100% |
| Target | Reduksi waktu investigasi yang signifikan dibandingkan metode manual |

### **6.1.4 Usability — SUS (System Usability Scale)**

| **Aspek** | **Detail** |
| --- | --- |
| Instrumen | 10 pernyataan SUS, skala Likert 1-5 |
| Responden | Personel Satgas / analis yang menggunakan sistem pada skenario demonstrasi |
| Formula | SUS = (2.5/N) \* Sigma(Sigma(Xi,k - 1) + Sigma(5 - Xi,k)) |
| Interpretasi | Berdasarkan kategori Bangor et al.: Not Acceptable / Marginal / Acceptable |
| Target minimum | >= 70.0 (kategori Good / Acceptable) |

## **6.2 Dataset & Skenario Uji**

| **Skenario** | **Dataset** | **Tujuan** |
| --- | --- | --- |
| Demonstrasi fungsional | EVTX-ATTACK-SAMPLES (log historis publik, Windows EVTX/Sysmon) | Validasi pipeline end-to-end |
| Training LogRobust | Loghub — Windows Event Log (disediakan di folder) | Melatih model deteksi anomali |
| Evaluasi Tool Correctness | Skenario investigasi buatan dengan expected tools terdefinisi | Mengukur akurasi pemanggilan tool agen |
| Evaluasi G-Eval | Konteks anomali + laporan agen yang dihasilkan | Mengukur kualitas narasi laporan |
| Evaluasi SUS | Sesi penggunaan sistem oleh responden analis | Mengukur usability |

# **7. Spesifikasi Antarmuka Pengguna**

## **7.1 Halaman Utama — Upload & Pipeline**

* Komponen upload file: mendukung drag-and-drop, validasi ekstensi (.evtx, .log, .txt, .csv).
* Status progres: indikator tahap aktif (Parsing → Anomaly Detection → AI Agent → Report Generation).
* Preview hasil parsing: tabel event templates yang diekstrak (sortable, searchable).
* Visualisasi anomaly: timeline/chart anomaly score per sliding window, threshold line yang dapat diatur.
* Panel kandidat anomali: daftar window yang tereskala, dapat diklik untuk melihat detail event.

## **7.2 Halaman Laporan Investigasi**

* Tampilan laporan terstruktur dengan section-section (Executive Summary, IOC Analysis, Timeline, dll.).
* Tombol unduh laporan (format PDF/JSON).



# **8. Struktur Proyek yang Diharapkan**

## **8.1 Struktur Direktori**

Berikut adalah struktur folder yang direkomendasikan untuk proyek ini. Dataset Drain, model LogRobust, dan dataset pelatihan disediakan oleh peneliti di folder yang sudah ditentukan:

| **Path** | **Keterangan** |
| --- | --- |
| data/raw\_logs/ | Folder upload log sementara (per sesi) |
| data/loghub/ | Dataset Loghub Windows Event Log (disediakan) |
| data/evtx\_attack\_samples/ | Dataset demonstrasi EVTX-ATTACK-SAMPLES (disediakan) |
| models/drain/ | Konfigurasi Drain (drain\_config.ini, regex patterns) |
| models/deeplog/ | Model DeepLog terlatih (DeepLog.pt), vocabulary (DeepLog.pkl) |
| models/foundation\_sec/ | Foundation-Sec-8B model weights (GGUF/HF format) |
| backend/ | FastAPI application (main.py, routers/, services/) |
| backend/modules/parsing/ | Drain wrapper dan preprocessing utilities |
| backend/modules/anomaly/ | LogRobust inference pipeline |
| backend/modules/agent/ | LangGraph graph definition, tool wrappers, memory |
| backend/modules/report/ | Report generator module |
| frontend/ | React application |
| evaluation/ | DeepEval test scripts, SUS form, hasil evaluasi |
| .env | API keys (ThreatFox, VirusTotal, dll.) — gitignored |
| docker-compose.yml | Orchestrasi container untuk deployment lokal |

# **9. Risiko & Mitigasi**

| **#** | **Risiko** | **Tingkat** | **Mitigasi** |
| --- | --- | --- | --- |
| R1 | Foundation-Sec-8B menghasilkan tool call yang tidak valid / hallucination tinggi | Tinggi | Lapisan validasi schema JSON wajib sebelum eksekusi; fallback ke default tool set; metrik Tool Correctness sebagai gating. |
| R2 | Performa DeepLog rendah pada dataset TNI AL yang berbeda dari training data | Sedang | Evaluasi awal pada dataset demonstrasi publik (EVTX-ATTACK-SAMPLES); top-k parameter dikonfigurasi manual; dokumentasikan gap performa. Catatan: Model saat ini trained on Wintrim CBS logs, tested on Sysmon attack logs dengan 100% detection rate. |
| R3 | API threat intelligence rate limiting atau downtime | Sedang | Implementasi retry dengan exponential backoff; caching respons per IOC dalam sesi; graceful degradation tanpa crash pipeline. |
| R4 | Hardware target tidak mencukupi untuk inferensi Foundation-Sec-8B | Sedang | Uji dengan quantized model (GGUF Q4/Q5); dokumentasikan spesifikasi hardware minimum; fallback ke model lebih kecil jika perlu. |
| R5 | Kompleksitas LangGraph memperlambat iterasi pengembangan | Rendah | Mulai dengan graf linear sederhana, tambahkan edge kondisional secara incremental; unit test per node secara terpisah. |
| R6 | Data operasional TNI AL tidak dapat digunakan dalam penelitian (data sensitif) | Rendah | Evaluasi menggunakan dataset publik (EVTX-ATTACK-SAMPLES, Loghub); demonstrasi dengan skenario non-operasional. |

# **10. Milestone & Deliverables**

| **Fase** | **Aktivitas Utama** | **Deliverable** |
| --- | --- | --- |
| M1 | Setup environment, integrasi Drain dari folder yang disediakan, unit test parsing | Drain pipeline berjalan, output JSON tervalidasi |
| M2 | Integrasi DeepLog dari model yang sudah dilatih (Wintrim dataset), validasi inferensi pada EVTX samples | DeepLog inference pipeline, anomaly detection output JSON |
| M3 | Implementasi LangGraph graph + 6 tool wrappers threat intelligence | AI Agent berjalan end-to-end dengan tool calls |
| M4 | Integrasi Foundation-Sec-8B lokal + ReAct prompting | LLM reasoning + tool selection terintegrasi |
| M5 | Report generator + React frontend | Laporan investigasi + UI lengkap |
| M7 | Demonstrasi end-to-end dengan EVTX-ATTACK-SAMPLES | Demo fungsional terdokumentasi |
| M8 | Evaluasi lengkap: Tool Correctness, G-Eval, Time Efficiency, SUS | Laporan evaluasi kuantitatif + analisis |

*PRD v1.0.0 | Muhammad Faki Raihan | Rekayasa Kriptografi | Politeknik Siber dan Sandi Negara | 2026*