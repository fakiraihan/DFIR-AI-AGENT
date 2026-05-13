# Reverse Prompt Repository Analysis untuk Codex CLI

Dokumen ini berisi prompt yang dapat dimasukkan ke Codex CLI pada root repository untuk melakukan reverse engineering repository secara read-only. Output yang diharapkan adalah file Markdown bernama `REPO_REVERSE_ANALYSIS.md` yang nantinya dapat digunakan sebagai bahan penyusunan BAB IV Tugas Akhir.

---

# Prompt Utama

```markdown
Kamu adalah analis repository dan technical writer untuk Tugas Akhir. Tugasmu adalah melakukan reverse engineering terhadap repository ini secara read-only, lalu menghasilkan dokumen Markdown bernama `REPO_REVERSE_ANALYSIS.md`.

Tujuan dokumen ini adalah membantu penulis Tugas Akhir memahami arsitektur program, fungsi-fungsi utama, alur data, endpoint, modul AI Agent, modul log parsing, modul deteksi anomali, integrasi tool, backend, frontend, serta bagian-bagian yang layak dijelaskan pada BAB IV.

## Batasan penting

1. Jangan mengubah file apa pun selain membuat file `REPO_REVERSE_ANALYSIS.md`.
2. Jangan menjalankan command yang destruktif.
3. Jangan mencetak atau menyalin isi rahasia seperti API key, token, secret, credential, password, `.env`, private key, atau file konfigurasi sensitif.
4. Jika menemukan secret atau credential, tulis hanya bahwa secret ditemukan pada path tertentu, tetapi nilainya harus disensor sebagai `[REDACTED]`.
5. Abaikan folder atau file yang tidak relevan seperti:
   - `.git`
   - `node_modules`
   - `.venv`
   - `venv`
   - `__pycache__`
   - `.pytest_cache`
   - `dist`
   - `build`
   - file binary besar
   - dataset mentah besar, kecuali hanya untuk mencatat nama dan formatnya.
6. Fokus pada pemahaman struktur dan fungsi sistem, bukan memperbaiki kode.
7. Sertakan path file dan nama fungsi/class ketika menjelaskan komponen.
8. Jika memungkinkan, sertakan nomor baris penting dengan format `path/to/file.py:L10-L25`. Jika nomor baris tidak tersedia, cukup gunakan path file dan nama fungsi.

## Konteks penelitian

Repository ini merupakan prototipe sistem untuk Tugas Akhir berjudul:

"Rancang Bangun AI Agent Berbasis Tool-Augmented Large Language Model untuk Otomatisasi Investigasi Insiden Siber"

Sistem yang perlu dipetakan mencakup kemungkinan komponen berikut:

- pengumpulan/pembacaan dataset log;
- preprocessing log;
- log parsing menggunakan Drain atau pendekatan serupa;
- pemetaan event template;
- pembentukan sequence/sliding window;
- deteksi anomali menggunakan DeepLog/LSTM atau model sejenis;
- AI Agent berbasis LangGraph atau framework agent lain;
- Tool-Augmented LLM;
- local LLM atau LLM wrapper;
- ekstraksi IOC seperti IP address, domain, URL, hash;
- tool registry;
- tool validator;
- wrapper API threat intelligence seperti VirusTotal, GreyNoise, URLHaus, MalwareBazaar, ThreatFox, AlienVault OTX, atau tool lain;
- korelasi evidence;
- generasi laporan investigasi;
- backend API, misalnya FastAPI;
- frontend, misalnya React;
- database atau storage;
- request-response JSON;
- file konfigurasi;
- evaluasi metrik seperti precision, recall, F1-score, Tool Correctness, G-Eval, dan SUS.

## Langkah analisis yang harus dilakukan

Lakukan inspeksi repository dengan urutan berikut.

### 1. Pemetaan struktur repository

Identifikasi struktur folder utama. Jelaskan fungsi setiap folder penting.

Output yang diharapkan:

~~~markdown
## 1. Struktur Repository

```text
root/
├── ...
```

### Ringkasan Folder

| Folder/File | Fungsi |
|---|---|
| `...` | ... |
~~~

### 2. Identifikasi tech stack

Identifikasi bahasa pemrograman, framework, library, dependency, dan tool yang digunakan dari file seperti:

- `requirements.txt`
- `pyproject.toml`
- `package.json`
- `Dockerfile`
- `docker-compose.yml`
- `.env.example`
- `README.md`
- file konfigurasi lain.

Output yang diharapkan:

~~~markdown
## 2. Tech Stack dan Dependency

| Komponen | Teknologi/Library | Bukti File | Fungsi dalam Sistem |
|---|---|---|---|
| Backend | ... | ... | ... |
| Frontend | ... | ... | ... |
| AI Agent | ... | ... | ... |
| LLM | ... | ... | ... |
| Deteksi Anomali | ... | ... | ... |
~~~

### 3. Identifikasi entry point aplikasi

Cari entry point aplikasi backend, frontend, script training, script inference, script agent, dan script evaluasi.

Output yang diharapkan:

~~~markdown
## 3. Entry Point Aplikasi

| Entry Point | Path | Cara Kerja | Komponen yang Dipanggil |
|---|---|---|---|
| Backend server | ... | ... | ... |
| Frontend app | ... | ... | ... |
| Training DeepLog | ... | ... | ... |
| Agent runner | ... | ... | ... |
| Evaluasi | ... | ... | ... |
~~~

### 4. Pemetaan modul backend

Jika ada backend API, identifikasi endpoint, method, request body, response body, dan fungsi yang dipanggil.

Output yang diharapkan:

~~~markdown
## 4. Backend API

| Endpoint | Method | File/Fungsi | Input | Output | Fungsi |
|---|---|---|---|---|---|
| `/...` | POST | ... | ... | ... | ... |
~~~

Tambahkan contoh ringkas request dan response JSON, tetapi sensor data sensitif.

~~~json
{
  "example": "request"
}
~~~

~~~json
{
  "example": "response"
}
~~~

### 5. Pemetaan modul dataset dan preprocessing log

Cari fungsi yang berkaitan dengan:

- load dataset;
- read log file;
- normalize log;
- preprocessing;
- regex;
- parsing timestamp;
- parsing row;
- split line;
- data cleaning.

Output yang diharapkan:

~~~markdown
## 5. Modul Dataset dan Preprocessing Log

### 5.1 Alur Proses

```text
dataset/log file → read file → preprocessing → output log siap parsing
```

### 5.2 Fungsi Penting

| Fungsi/Class | Path | Input | Output | Deskripsi |
|---|---|---|---|---|
| `...` | ... | ... | ... | ... |
~~~

Tambahkan kandidat gambar BAB IV:

~~~markdown
### Kandidat Gambar BAB IV

- Gambar: Fungsi `...`
- Gambar: Alur preprocessing log
- Gambar: Contoh log mentah sebelum dan sesudah preprocessing
~~~

### 6. Pemetaan modul log parsing

Cari implementasi Drain atau parser log lain. Identifikasi konfigurasi seperti depth, similarity threshold, regex masking, tokenization, event template, dan parameter extraction.

Output yang diharapkan:

~~~markdown
## 6. Modul Log Parsing

### 6.1 Alur Parsing

```text
raw log → regex masking → tokenization → template matching → event template + parameter
```

### 6.2 Fungsi/Class Penting

| Fungsi/Class | Path | Input | Output | Deskripsi |
|---|---|---|---|---|
| `...` | ... | ... | ... | ... |

### 6.3 Konfigurasi Parser

| Parameter | Nilai | Lokasi | Keterangan |
|---|---|---|---|
| depth | ... | ... | ... |
| similarity threshold | ... | ... | ... |
| regex | ... | ... | ... |
~~~

Tambahkan contoh output parsing jika tersedia.

### 7. Pemetaan modul DeepLog / deteksi anomali

Cari fungsi/class terkait:

- event mapping;
- event template to index;
- sequence builder;
- sliding window;
- model LSTM;
- training loop;
- inference;
- anomaly decision;
- top-k prediction;
- confusion matrix;
- precision, recall, F1-score.

Output yang diharapkan:

~~~markdown
## 7. Modul Deteksi Anomali Log

### 7.1 Alur Deteksi Anomali

```text
event template → event index → sequence/sliding window → DeepLog/LSTM → top-k prediction → kandidat anomali
```

### 7.2 Fungsi/Class Penting

| Fungsi/Class | Path | Input | Output | Deskripsi |
|---|---|---|---|---|
| `...` | ... | ... | ... | ... |

### 7.3 Konfigurasi Model

| Parameter | Nilai | Lokasi | Keterangan |
|---|---|---|---|
| window size | ... | ... | ... |
| hidden size | ... | ... | ... |
| epoch | ... | ... | ... |
| batch size | ... | ... | ... |
| learning rate | ... | ... | ... |
| top-k | ... | ... | ... |

### 7.4 Output Modul

Jelaskan struktur output kandidat anomali.

```json
{
  "example": "anomaly result"
}
```

### Kandidat Gambar BAB IV

- Fungsi pembentukan sequence.
- Fungsi training/inference DeepLog.
- Fungsi deteksi anomali.
- Contoh output kandidat anomali.
~~~

### 8. Pemetaan modul AI Agent

Cari implementasi AI Agent, terutama jika memakai LangGraph, LangChain, ReAct, function calling, tool calling, graph state, node, edge, memory, atau planner.

Output yang diharapkan:

~~~markdown
## 8. Modul AI Agent

### 8.1 Arsitektur Agent

```text
anomaly context → IOC extraction → planning → tool validation → tool execution → evidence correlation → report generation
```

### 8.2 State Agent

Jelaskan struktur state yang digunakan agent.

| Field State | Tipe | Fungsi |
|---|---|---|
| ... | ... | ... |

### 8.3 Node Agent

| Node | Path/Fungsi | Input | Output | Deskripsi |
|---|---|---|---|---|
| ... | ... | ... | ... | ... |

### 8.4 Edge / Routing Logic

Jelaskan bagaimana agent berpindah dari satu node ke node lain.

### 8.5 Fungsi Penting

| Fungsi/Class | Path | Input | Output | Deskripsi |
|---|---|---|---|---|
| `...` | ... | ... | ... | ... |

### Kandidat Gambar BAB IV

- Alur graph agent.
- Struktur state agent.
- Fungsi node IOC extraction.
- Fungsi planner.
- Fungsi report generator.
~~~

### 9. Pemetaan Tool-Augmented LLM

Cari bagaimana LLM dipanggil dan bagaimana tool digunakan. Identifikasi:

- model yang digunakan;
- local inference;
- prompt template;
- system prompt;
- tool schema;
- function calling;
- tool registry;
- validator;
- error handling;
- hallucination control;
- grounding terhadap hasil tool.

Output yang diharapkan:

~~~markdown
## 9. Tool-Augmented LLM

### 9.1 LLM yang Digunakan

| Komponen | Nilai | Lokasi |
|---|---|---|
| Model | ... | ... |
| Runtime | ... | ... |
| Prompt Template | ... | ... |

### 9.2 Tool Registry

| Tool | Fungsi Wrapper | Jenis IOC | Parameter | Output |
|---|---|---|---|---|
| ... | ... | ... | ... | ... |

### 9.3 Validasi Tool Call

Jelaskan mekanisme validasi tool call.

| Fungsi | Path | Validasi yang Dilakukan |
|---|---|---|
| ... | ... | ... |

### 9.4 Wrapper Threat Intelligence

| Tool | Path/Fungsi | Input | Output | Keterangan |
|---|---|---|---|---|
| VirusTotal | ... | ... | ... | ... |
| GreyNoise | ... | ... | ... | ... |
| URLHaus | ... | ... | ... | ... |
| MalwareBazaar | ... | ... | ... | ... |
| ThreatFox | ... | ... | ... | ... |
| AlienVault OTX | ... | ... | ... | ... |

Sensor API key atau token.
~~~

### 10. Pemetaan modul laporan investigasi

Cari fungsi yang membuat laporan, summary, markdown report, JSON report, PDF report, atau response final.

Output yang diharapkan:

~~~markdown
## 10. Modul Generasi Laporan Investigasi

### 10.1 Struktur Laporan

Jelaskan bagian-bagian laporan yang dihasilkan sistem.

| Bagian Laporan | Isi |
|---|---|
| Ringkasan kejadian | ... |
| Kandidat anomali | ... |
| IOC | ... |
| Enrichment | ... |
| Interpretasi teknis | ... |
| Rekomendasi | ... |

### 10.2 Fungsi Penting

| Fungsi/Class | Path | Input | Output | Deskripsi |
|---|---|---|---|---|
| `...` | ... | ... | ... | ... |

### 10.3 Contoh Output Laporan

Berikan contoh ringkas laporan, tetapi sensor data sensitif.

### Kandidat Gambar BAB IV

- Fungsi generasi laporan.
- Contoh struktur laporan.
- Contoh output laporan pada UI.
~~~

### 11. Pemetaan frontend

Jika ada frontend, identifikasi halaman, komponen, state management, API call, dan alur UI.

Output yang diharapkan:

~~~markdown
## 11. Frontend dan Antarmuka Pengguna

### 11.1 Halaman/Komponen

| Halaman/Komponen | Path | Fungsi | API yang Dipanggil |
|---|---|---|---|
| Upload Log | ... | ... | ... |
| Parsing Result | ... | ... | ... |
| Anomaly Result | ... | ... | ... |
| IOC Enrichment | ... | ... | ... |
| Investigation Report | ... | ... | ... |

### 11.2 Alur UI

```text
upload log → parsing result → anomaly result → investigation → report
```

### Kandidat Screenshot BAB IV

- Halaman unggah log.
- Halaman hasil parsing.
- Halaman kandidat anomali.
- Halaman enrichment IOC.
- Halaman laporan investigasi.
~~~

### 12. Pemetaan database/storage

Cari model database, schema, migration, ORM, file storage, atau JSON storage.

Output yang diharapkan:

~~~markdown
## 12. Database dan Penyimpanan

| Tabel/Collection/File | Path/Model | Fungsi | Field Utama |
|---|---|---|---|
| ... | ... | ... | ... |
~~~

Tambahkan relasi data secara tekstual.

~~~text
dataset → raw_logs → parsed_logs → anomaly_results → iocs → tool_results → investigation_reports
~~~

Jika ERD formal belum ada, buat rekomendasi ERD berdasarkan kode.

### 13. Evaluasi dan metrik

Cari script evaluasi atau fungsi terkait:

- accuracy;
- precision;
- recall;
- F1-score;
- confusion matrix;
- Tool Correctness;
- DeepEval;
- G-Eval;
- SUS;
- benchmark;
- test cases.

Output yang diharapkan:

~~~markdown
## 13. Evaluasi Sistem

### 13.1 Evaluasi DeepLog

| Fungsi/Script | Path | Metrik | Deskripsi |
|---|---|---|---|
| ... | ... | ... | ... |

### 13.2 Evaluasi Tool Correctness

| Fungsi/Script | Path | Input | Output |
|---|---|---|---|
| ... | ... | ... | ... |

### 13.3 Evaluasi G-Eval

| Fungsi/Script | Path | Kriteria | Output |
|---|---|---|---|
| ... | ... | ... | ... |

### 13.4 Evaluasi SUS

Jelaskan apakah ada instrumen SUS atau belum. Jika belum ada, tulis rekomendasi struktur file evaluasi SUS.
~~~

### 14. Alur end-to-end sistem

Buat ringkasan alur sistem dari awal sampai akhir.

Output yang diharapkan:

~~~markdown
## 14. Alur End-to-End Sistem

```text
1. User mengunggah log
2. Backend menerima file log
3. Sistem melakukan preprocessing
4. Drain menghasilkan event template dan parameter
5. Event template dipetakan menjadi event ID
6. Sequence dibentuk dengan sliding window
7. DeepLog mendeteksi kandidat anomali
8. AI Agent menerima konteks anomali
9. IOC diekstraksi
10. Agent memilih tool
11. Tool call divalidasi
12. Tool threat intelligence dipanggil
13. Evidence dikorelasikan
14. Laporan investigasi dibuat
15. Hasil ditampilkan di frontend
```
~~~

### 15. Rekomendasi isi BAB IV berdasarkan repository

Buat bagian khusus yang memetakan hasil repository ke struktur BAB IV Tugas Akhir.

Output yang diharapkan:

~~~markdown
## 15. Rekomendasi Penulisan BAB IV

### IV.1 DESIGN AND DEVELOPMENT

| Bagian BAB IV | Isi yang Bisa Ditulis | Bukti dari Repository | Gambar/Tabel yang Disarankan |
|---|---|---|---|
| Pengumpulan Dataset | ... | ... | ... |
| Implementasi Pipeline Log | ... | ... | ... |
| Implementasi DeepLog | ... | ... | ... |
| Implementasi AI Agent | ... | ... | ... |
| Implementasi Tool-Augmented LLM | ... | ... | ... |
| Implementasi Backend | ... | ... | ... |
| Implementasi Frontend | ... | ... | ... |

### IV.2 DEMONSTRATION

| Bagian | Isi yang Bisa Ditulis | Bukti dari Repository | Gambar/Tabel yang Disarankan |
|---|---|---|---|
| Lingkungan Demonstrasi | ... | ... | ... |
| Skenario Pengguna | ... | ... | ... |
| Hasil Demonstrasi End-to-End | ... | ... | ... |

### IV.3 EVALUATION

| Bagian | Isi yang Bisa Ditulis | Bukti dari Repository | Gambar/Tabel yang Disarankan |
|---|---|---|---|
| Evaluasi DeepLog | ... | ... | ... |
| Evaluasi Tool Correctness | ... | ... | ... |
| Evaluasi G-Eval | ... | ... | ... |
| Evaluasi SUS | ... | ... | ... |
~~~

### 16. Daftar fungsi yang paling penting untuk ditampilkan pada BAB IV

Pilih fungsi-fungsi yang paling layak dijadikan gambar dalam BAB IV. Prioritaskan fungsi yang menjelaskan kontribusi utama penelitian.

Output yang diharapkan:

~~~markdown
## 16. Fungsi yang Layak Ditampilkan pada BAB IV

| Prioritas | Fungsi/Class | Path | Alasan Ditampilkan |
|---|---|---|---|
| 1 | `...` | ... | ... |
| 2 | `...` | ... | ... |
| 3 | `...` | ... | ... |
~~~

### 17. Daftar lampiran yang disarankan

Buat daftar lampiran yang cocok berdasarkan isi repository.

Output yang diharapkan:

~~~markdown
## 17. Lampiran yang Disarankan

| Lampiran | Isi | Sumber dari Repository |
|---|---|---|
| Lampiran 1 | Source code modul log parsing | ... |
| Lampiran 2 | Source code modul DeepLog | ... |
| Lampiran 3 | Source code AI Agent | ... |
| Lampiran 4 | Source code tool wrapper | ... |
| Lampiran 5 | Contoh respons API threat intelligence | ... |
| Lampiran 6 | Dataset evaluasi Tool Correctness | ... |
~~~

## Format akhir

Buat file `REPO_REVERSE_ANALYSIS.md` dengan struktur berikut:

~~~markdown
# REPO REVERSE ANALYSIS

## 1. Struktur Repository
## 2. Tech Stack dan Dependency
## 3. Entry Point Aplikasi
## 4. Backend API
## 5. Modul Dataset dan Preprocessing Log
## 6. Modul Log Parsing
## 7. Modul Deteksi Anomali Log
## 8. Modul AI Agent
## 9. Tool-Augmented LLM
## 10. Modul Generasi Laporan Investigasi
## 11. Frontend dan Antarmuka Pengguna
## 12. Database dan Penyimpanan
## 13. Evaluasi Sistem
## 14. Alur End-to-End Sistem
## 15. Rekomendasi Penulisan BAB IV
## 16. Fungsi yang Layak Ditampilkan pada BAB IV
## 17. Lampiran yang Disarankan
## 18. Catatan Ketidakpastian
~~~

Pada bagian `Catatan Ketidakpastian`, tuliskan bagian repo yang belum jelas, file yang tidak bisa dibaca, dependency yang belum pasti, atau asumsi yang dibuat selama analisis.

Setelah file selesai dibuat, tampilkan ringkasan singkat di terminal:

- jumlah file yang dianalisis;
- bahasa/framework utama;
- entry point utama;
- jumlah endpoint ditemukan;
- jumlah fungsi penting ditemukan;
- lokasi file `REPO_REVERSE_ANALYSIS.md`.
```

---

# Prompt Versi Pendek

Gunakan versi ini jika Codex CLI tidak nyaman dengan prompt utama yang panjang.

```markdown
Analisis repository ini secara read-only dan buat file `REPO_REVERSE_ANALYSIS.md`.

Jangan ubah file apa pun selain file markdown tersebut. Jangan tampilkan secret/API key/token/password; sensor sebagai `[REDACTED]`.

Konteks repo: prototipe TA "Rancang Bangun AI Agent Berbasis Tool-Augmented LLM untuk Otomatisasi Investigasi Insiden Siber". Sistem kemungkinan mencakup dataset log, preprocessing, Drain/log parsing, DeepLog/LSTM anomaly detection, LangGraph/AI Agent, local LLM, IOC extraction, tool registry, threat intelligence wrapper, backend FastAPI, frontend React, database/storage, report generator, dan evaluasi.

Isi markdown harus memuat:

1. Struktur repository dan fungsi tiap folder.
2. Tech stack dan dependency.
3. Entry point backend, frontend, training, inference, agent, dan evaluasi.
4. Daftar endpoint API beserta input-output.
5. Modul dataset/preprocessing: fungsi, input, output, dan alur.
6. Modul log parsing: fungsi, konfigurasi Drain/parser, input-output, contoh hasil parsing.
7. Modul DeepLog/anomaly detection: event mapping, sequence builder, model, training, inference, top-k prediction, metrik evaluasi.
8. Modul AI Agent: graph/state/node/edge/memory/planner.
9. Tool-Augmented LLM: model, prompt, tool registry, tool validator, tool wrapper, API threat intelligence, contoh response yang disensor.
10. Modul report generator: struktur laporan, fungsi pembentuk laporan, contoh output laporan.
11. Frontend: halaman, komponen, API call, alur UI.
12. Database/storage: tabel/model/file yang dipakai dan relasi data.
13. Evaluasi: precision, recall, F1-score, Tool Correctness, G-Eval, SUS; jelaskan script/fungsi terkait.
14. Alur end-to-end sistem dari upload log sampai laporan.
15. Rekomendasi BAB IV: petakan bagian repo ke `IV.1 Design and Development`, `IV.2 Demonstration`, dan `IV.3 Evaluation`.
16. Fungsi yang paling layak ditampilkan sebagai gambar di BAB IV.
17. Lampiran yang disarankan.
18. Catatan ketidakpastian.

Gunakan tabel untuk daftar fungsi penting. Sertakan path file dan nama fungsi/class. Sertakan nomor baris jika memungkinkan. Fokus pada pemahaman arsitektur dan fungsi sistem, bukan memperbaiki kode.
```

---