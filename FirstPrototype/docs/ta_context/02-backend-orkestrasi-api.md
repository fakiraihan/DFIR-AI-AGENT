# Backend & Orkestrasi API — JejakAgent

> Dokumen ini menjelaskan **lapisan backend** (FastAPI) dan **layanan orkestrasi**
> yang menjalankan seluruh pipeline investigasi: dari upload log sampai laporan
> DFIR jadi. Tujuannya memberi konteks akurat untuk Bab III (rancangan sistem)
> dan Bab IV (implementasi) skripsi, khususnya bagian arsitektur backend dan
> alur data antar komponen.

---

## 1. Posisi dalam Arsitektur

```
┌─────────────┐      HTTP/JSON       ┌─────────────────────────────────────┐
│  Frontend    │ ───────────────────▶ │            FastAPI Backend           │
│  (React/MUI) │ ◀─────────────────── │  backend/main.py + routers/*         │
└─────────────┘                       └──────────────┬────────────────────┘
                                                       │
                                          background task
                                                       ▼
                                  ┌─────────────────────────────────────┐
                                  │  orchestrator_service.run_           │
                                  │  investigation_pipeline(session_id)  │
                                  └──────────────┬────────────────────────┘
                                                  │
        ┌─────────────────┬──────────────────────┬──────────────────────┬───────────────┐
        ▼                  ▼                      ▼                      ▼               ▼
  parsing_service   modules/anomaly.py     agent_modules/         modules/agent.py  modules/report.py
  (Drain3 parsing)  (DeepLogDetector)       triage.py              (DFIRAgent/      (ReportGenerator)
                                           (anomaly_triage node)   LangGraph)
```

Backend `main.py` (`backend/main.py:40-59`) hanya bertugas merangkai (wiring)
aplikasi FastAPI: membuat instance `FastAPI`, memasang CORS middleware, dan
mendaftarkan lima router (`health`, `auth`, `settings`, `upload`,
`investigation`). Semua logika bisnis didelegasikan ke modul `routers/*` dan
`services/*` — ini penting untuk argumen *separation of concerns* di Bab III.

---

## 2. Router & Endpoint API

| Router | Prefix | Endpoint | Method | Fungsi |
|---|---|---|---|---|
| `health` | `/` | `/health` (asumsi) | GET | Health check dasar |
| `auth` | `/api/auth` | `/me`, `/logout`, dll | GET/POST | Autentikasi pengguna (sesi login) |
| `settings` | `/api/settings` | konfigurasi LLM provider | GET/POST | Pengaturan provider LLM (Ollama/OpenAI-compatible) |
| `upload` | `/api/upload` | `POST /api/upload` | POST | Unggah file log, buat sesi baru |
| `upload` | `/api/analyze` | `POST /api/analyze` | POST | "Quick analysis" — parsing + DeepLog saja, tanpa AI Agent |
| `investigation` | `/api/sessions` | `GET /api/sessions` | GET | Daftar sesi investigasi milik pengguna |
| `investigation` | `/api/sessions/{id}` | `PATCH /api/sessions/{id}` | PATCH | Rename sesi |
| `investigation` | `/api/sessions/{id}` | `DELETE /api/sessions/{id}` | DELETE | Hapus sesi + artefak |
| `investigation` | `/api/investigate/{id}` | `POST /api/investigate/{id}` | POST | **Memulai pipeline investigasi penuh** (background task) |
| `investigation` | `/api/status/{id}` | `GET /api/status/{id}` | GET | Polling status/progress pipeline |
| `investigation` | `/api/report/{id}` | `GET /api/report/{id}` | GET | Ambil laporan DFIR final (JSON) |
| `investigation` | `/api/report-export/pdf` | `POST /api/report-export/pdf` | POST | Render laporan HTML → PDF |
| `investigation` | `/api/export/{id}` | `GET /api/export/{id}?format=...` | GET | Unduh artefak parsed-log (manifest/jsonl/ndjson/csv) |

Sumber: `backend/routers/upload.py:27-88`, `backend/routers/investigation.py:151-378`.

### 2.1 Alur sesi (session lifecycle)

1. **Upload** — `POST /api/upload` (`upload.py:27-72`) menyimpan file via
   `store_uploaded_file()`, membuat `session_id` baru, dan menulis entri awal
   ke `session_store` dengan `status="uploaded"`, `stage="pending"`.
2. **Mulai investigasi** — `POST /api/investigate/{session_id}`
   (`investigation.py:209-254`) memvalidasi provider LLM siap
   (`get_ready_provider_snapshot()`), mereset state sesi (`status="processing"`,
   `progress=0`, `activity_events=[]`), lalu menjadwalkan
   `run_investigation_pipeline(session_id)` sebagai **FastAPI
   `BackgroundTasks`** — artinya request POST langsung kembali (non-blocking)
   sementara pipeline berjalan di background.
3. **Polling status** — Frontend memanggil `GET /api/status/{session_id}`
   (`investigation.py:257-280`) secara berkala untuk membaca `stage`,
   `progress` (0-100), `current_message`, dan `activity_events` (log terminal
   yang disanitasi).
4. **Ambil laporan** — Setelah `status == "completed"`, `GET
   /api/report/{session_id}` (`investigation.py:283-304`) mengembalikan objek
   laporan JSON penuh.
5. **Quick analysis (opsional)** — `POST /api/analyze` (`upload.py:75-88`)
   menjalankan *hanya* parsing + DeepLog (tanpa AI Agent) untuk eksplorasi
   cepat, dipanggil terpisah dari sesi investigasi penuh.

---

## 3. `session_store` — State Sesi

`session_store` (didefinisikan di `backend/session_store.py`, diekspos via
`app_context`) adalah **penyimpanan state sesi in-process** yang menampung
seluruh metadata dan hasil antara setiap sesi investigasi: status, progress,
`activity_events` (log terminal), hasil parsing (`parsed_logs_count`,
`templates_count`), hasil DeepLog (`anomalies_count`,
`deeplog_evaluation_status_counts`), path artefak ekspor, dan laporan
final (`report`, `report_path`). Label triage per-window (`triage_labels`)
disimpan di dalam `InvestigationState` (in-process), bukan di session_store.

Setiap sesi diidentifikasi dengan `session_id` dan dimiliki oleh satu
`user_id` (lihat `_get_owned_session()` di `investigation.py:92-101`) —
sehingga pengguna hanya bisa mengakses sesi miliknya sendiri (otorisasi
berbasis kepemilikan sesi, bukan role-based access control).

---

## 4. `run_investigation_pipeline` — Orkestrator Utama

Fungsi `run_investigation_pipeline(session_id)`
(`backend/services/orchestrator_service.py:134-559`) adalah **jantung
orkestrasi**. Fungsi ini berjalan sebagai background task dan melalui empat
stage besar, masing-masing melaporkan progress (0-100) ke `session_store`
lewat `update_session_status()` dan `append_session_activity_event()`:

| Stage (`stage` value) | Progress range | Aksi utama | Modul yang dipanggil |
|---|---|---|---|
| `parsing` | 10 → 25 | Parsing log dengan profil yang sesuai (Drain3 + strategi template) | `parse_with_profile()` (`parsing_service.py`) |
| `anomaly_detection` | 30 → 50 | (a) Deteksi anomali DeepLog, (b) generate artefak ekspor | `detect_anomalies_in_logs()` (`modules/anomaly.py`), `build_export_artifacts()` |
| `ai_agent` | 55 → 85 | Jalankan `DFIRAgent` (LangGraph) — **triage semantik** (node `anomaly_triage`), ekstraksi IOC, planning, tool selection/execution, korelasi, refleksi, timeline | `DFIRAgent.investigate()` (`modules/agent.py`), `agent_modules/triage.py` |
| `report_generation` | 85 → 100 | Susun & simpan laporan DFIR (Markdown + JSON) | `ReportGenerator` (`modules/report.py`) |

Sumber baris kunci:
- Inisialisasi & stage parsing: `orchestrator_service.py:134-216`
- Stage anomaly detection (DeepLog): `orchestrator_service.py:218-297`
- Pembuatan artefak ekspor: `orchestrator_service.py:299-420`
- Stage AI Agent: `orchestrator_service.py:422-490`
- Stage report generation & penyelesaian: `orchestrator_service.py:492-559`
- Penanganan error global (`try/except`): `orchestrator_service.py:561-596`

### 4.1 Catatan penting: triage semantik ada di dalam AI Agent

Triage LLM **bukan** tahap terpisah di orkestrator — ia berjalan sebagai
node pertama (`anomaly_triage`) di dalam `DFIRAgent.investigate()`. Ini
berarti orkestrator menyerahkan `anomalies_df` langsung ke agent tanpa
preprocessing LLM, dan agent yang menentukan window mana layak diselidiki
lebih lanjut berdasarkan konten log aktual.

Pendekatan ini lebih clean secara arsitektur:
- **Pipeline deteksi** (`parsing → DeepLog`) murni deterministik dan
  reproducible.
- **Penalaran semantik** sepenuhnya menjadi tanggung jawab AI Agent.

Orkestrator hanya memanggil `build_role_client(provider_snapshot,
role="agent")` **satu kali** — tidak ada `role="filter"` lagi. Lihat
`backend/modules/agent_modules/triage.py` dan
[03-pipeline-parsing-deeplog.md §4](03-pipeline-parsing-deeplog.md).

---

## 5. Layanan Pendukung (`backend/services/*`)

| Modul | Peran |
|---|---|
| `parsing_service.py` | `parse_with_profile()` — memilih profil parser (Windows EVTX/Sysmon/LogHub, Linux AIT-LDS, general) dan menjalankan `DrainParser`. Lihat [03-pipeline-parsing-deeplog.md](03-pipeline-parsing-deeplog.md). |
| `storage_service.py` | Validasi ekstensi file upload, sanitasi nama file, penyimpanan file mentah per sesi. |
| `llm_service.py` | `get_ready_provider_snapshot()`, `build_role_client()` — abstraksi provider LLM (Ollama lokal vs OpenAI-compatible) per peran (`filter`/`agent`/dll). |
| `export_service.py` | `build_export_artifacts()` — menghasilkan ekspor parsed-log dalam format manifest/JSONL/NDJSON/CSV untuk pipeline visualisasi eksternal. |
| `report_pdf_service.py` | `render_html_report_pdf()` — merender HTML laporan (dari frontend) menjadi PDF yang bisa dipilih teksnya (selectable text). |
| `analyze_service.py` | `run_quick_analysis()` — jalur cepat parsing + DeepLog tanpa AI Agent, dipakai endpoint `/api/analyze`. |

---

## 6. Telemetri & Observability

Dua mekanisme telemetri berjalan paralel selama pipeline:

1. **`activity_events`** (per-sesi, disimpan di `session_store`) — log
   terminal yang ditampilkan real-time di UI "Agent Terminal" frontend
   (lihat [01-product-frontend.md](01-product-frontend.md)). Disanitasi via
   `_sanitize_terminal_line()` (maks. 1200 karakter, tanpa `\r`).
2. **`gate_observations.jsonl`** (lintas-sesi, file JSONL, lihat
   `modules/gate_observations.py` dan
   [03-pipeline-parsing-deeplog.md](03-pipeline-parsing-deeplog.md)) — log
   pasif yang mencatat keputusan DeepLog + label triage (`triage.verdict`)
   + hasil investigasi AI Agent untuk setiap sesi, dipanggil di
   `orchestrator_service.py:471-490` via `append_gate_observations()`.
   Field `triage_labels` dibaca dari `investigation_state` (hasil node
   `anomaly_triage`).

Kedua mekanisme ini adalah bagian dari argumen *"pipeline transparency"* dan
*"analyst trust visibility"* yang disebut di `PRODUCT.md` — relevan untuk
menjawab pertanyaan evaluator tentang *explainability* sistem (Bab II/III).

---

## 7. Ringkasan untuk Bab III/IV Skripsi

- Backend **bukan monolit** — `main.py` hanya 84 baris, murni *wiring*. Logika
  bisnis tersebar rapi ke `routers/` (HTTP layer) dan `services/` +
  `modules/` (domain layer). Ini bisa dijadikan argumen desain modular pada
  Bab III.3.1 (arsitektur sistem).
- Pipeline investigasi adalah **satu fungsi orkestrator panjang** namun
  terbagi jelas menjadi 4 stage dengan pelaporan progress granular —
  cocok untuk diagram alur (flowchart) di Bab III dan untuk menjelaskan
  bagaimana UI "Investigation Pipeline" (lihat DESIGN.md) memetakan progress
  bar ke stage backend secara 1:1.
- Eksekusi investigasi bersifat **asynchronous (background task)** dengan
  **polling** dari frontend — bukan WebSocket/streaming. Ini detail teknis
  yang sebaiknya disebutkan jika ada pertanyaan evaluator soal real-time
  feedback.
- Triage semantik (`anomaly_triage`) **bukan** tahap pipeline terpisah —
  ia node pertama di dalam AI Agent graph. Ini argumen desain penting untuk
  Bab III: LLM hanya digunakan di lapisan yang membutuhkan penalaran bahasa
  (agent), bukan di pipeline deteksi yang harus deterministik dan reproducible.
