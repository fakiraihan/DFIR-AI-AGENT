# Produk & Frontend — JejakAgent

> Dokumen ini menjelaskan **identitas produk** (JejakAgent), **sistem desain**
> ("Secure Command Console"), dan **arsitektur frontend** (React + Vite +
> MUI). Tujuannya memberi konteks untuk Bab III (perancangan
> antarmuka/UX) dan Bab IV (implementasi frontend), serta membantu
> menjelaskan *bagaimana* tampilan memetakan progres pipeline backend ke
> pengalaman analis secara linear.
>
> Sumber: `PRODUCT.md`, `DESIGN.md`, `frontend/package.json`,
> `frontend/src/App.jsx`, `frontend/src/theme.js`, dan seluruh
> `frontend/src/components/*.jsx`.

---

## 1. Identitas Produk

### 1.1 Nama, Pengguna, dan Tujuan (`PRODUCT.md`)

- **Nama produk**: **JejakAgent**.
- **Pengguna target**: analis DFIR, operator SOC, evaluator keamanan siber,
  dan mahasiswa yang mengerjakan investigasi insiden berbasis evidence
  (log EVTX, LOG, TXT, CSV).
- **Tujuan produk**: mengotomasi tahap **awal hingga menengah** investigasi
  insiden siber — parsing log, deteksi anomali (DeepLog), penyaringan via
  LLM gate, pengayaan IOC dengan threat intelligence, dan penyusunan laporan
  DFIR terstruktur (evidence provenance, timeline, MITRE ATT&CK mapping,
  limitations, rekomendasi respons).
- **Definisi sukses**: analis dapat berpindah dari log mentah ke laporan
  ber-evidence lebih cepat, **tanpa** kehilangan visibilitas terhadap state
  antara — sehingga sistem dapat dipahami, ditantang, dan divalidasi.

### 1.2 Prinsip Desain Produk

| Prinsip | Arti operasional |
|---|---|
| **Evidence first, spectacle second** | Setiap layar memprioritaskan keterbacaan evidence/state/confidence/limitations di atas estetika. |
| **Show the pipeline honestly** | Pengguna selalu tahu posisi investigasi dalam alur: upload → parsing → DeepLog → LLM gate → AI agent → threat intel → report. |
| **Keep analyst trust visible** | Provenance, uncertainty, severity, evidence ID, opsi ekspor, dan failure state harus terlihat — sistem terasa *auditable*, bukan "magic box". |
| **Futurism with restraint** | Atmosfer "cyber" datang dari kepadatan informasi & kontras tajam, bukan gradient biru generik ala AI SaaS. |
| **Design for repeated operational use** | Scanability, kontrol ramah keyboard, layout stabil, tabel yang mudah dibaca, penanganan teks panjang yang baik. |

**Relevansi untuk evaluasi**: jika evaluator mempertanyakan *mengapa* UI
menampilkan begitu banyak detail teknis (terminal agent, progress per-stage,
chip status, dsb.), jawabannya adalah keputusan desain yang disengaja dan
terdokumentasi (`PRODUCT.md`, `DESIGN.md`), bukan kebetulan implementasi —
ini bisa dikutip langsung di Bab III sebagai *design rationale*.

---

## 2. Sistem Desain — "Secure Command Console" (`DESIGN.md`)

### 2.1 Konsep Inti

JejakAgent menggunakan **dark operational canvas** dengan **steel blue**
sebagai warna sinyal langka ("Blue Scarcity Rule": jika >10% layar berwarna
biru, tampilan mulai terasa seperti produk AI generik). Warna semantik
(emerald/amber/rose/blue) **hanya** dipakai untuk makna status (sukses,
peringatan, error, info) — bukan variasi dekoratif ("Semantic State Rule").

### 2.2 Palet Warna Kunci

| Token | Hex | Penggunaan |
|---|---|---|
| `primary-blue` (Signal Blue) | `#2563eb` | CTA utama, navigasi aktif, progress bar |
| `primary-blue-dark` | `#1d4ed8` | Hover state tombol primary |
| `secondary-indigo` | `#818cf8` | Konteks model/provider LLM (aksen sekunder) |
| `info-blue` | `#3b82f6` | Status informasi netral |
| `success-emerald` | `#10b981` | Sukses, evidence terverifikasi |
| `warning-amber` | `#f59e0b` | Limitations, confidence caveat, peringatan |
| `danger-rose` | `#f43f5e` | Error, baris anomali, aksi destruktif |
| `background-abyss` | `#070b14` | Kanvas aplikasi (paling gelap) |
| `surface-slate` | `#0f172a` (alpha) | Panel/card utama |
| `surface-sidebar` | `#0b0f19` | Drawer/sidebar |

### 2.3 Tipografi

Font: **Segoe UI Variable / Aptos** (sans) untuk semua teks UI; monospace
sistem khusus untuk **session ID, command trace, event template, hash, dan
nilai IOC** ("Evidence Readability Rule" — string evidence panjang harus
tetap terbaca, wajib `overflow-wrap: anywhere`).

| Level | Berat | Ukuran | Penggunaan |
|---|---|---|---|
| Display | 700 | 2.75rem | Hero landing saja |
| Headline | 700 | 2.2rem | Judul layar utama (settings, status investigasi) |
| Title | 600 | 1.1rem | Card, panel, judul section |
| Body | 400 | 1rem | Teks penjelasan, ringkasan laporan |
| Label | 700 | 0.68rem | Label operasional pendek, kicker status |

### 2.4 Implementasi di `theme.js`

`frontend/src/theme.js` mengimplementasikan token desain di atas sebagai MUI
`createTheme()`:
- `palette.mode: 'dark'`, `primary.main = #2563eb`, `background.default =
  #070b14`, `background.paper = rgba(15, 23, 42, 0.62)`.
- `shape.borderRadius: 12` (sesuai token `rounded.md`).
- Override komponen MUI: `MuiButton` (primary solid biru, hover lebih gelap,
  outlined translucent), `MuiCard`/`MuiPaper` (border 1px low-alpha, tanpa
  shadow), `MuiAppBar` (translucent + border bawah), `MuiDrawer` (sidebar
  gelap `#0b0f19`), `MuiListItemButton` (item terpilih = fill biru low-alpha
  + border mist-blue), `MuiChip`, `MuiLinearProgress` (progress bar biru
  pill-shape), `MuiAlert` (4 varian severity dengan warna semantik dari
  §2.2).

**Konsistensi**: seluruh token warna di `DESIGN.md` **konsisten 1:1** dengan
nilai hex di `theme.js` — ini membuktikan sistem desain bukan dokumen
aspirational semata, melainkan **benar-benar diimplementasikan**. Poin ini
relevan untuk argumen *design-to-implementation traceability* di Bab III/IV.

---

## 3. Tech Stack Frontend

Dari `frontend/package.json`:

| Kategori | Library | Catatan |
|---|---|---|
| Framework | React 18.2 | Functional components + hooks |
| Build tool | Vite 5 | Dev server port 3000, proxy `/api` → backend |
| UI Library | MUI v5 (`@mui/material`, `@mui/icons-material`) + Emotion | Implementasi sistem desain §2 |
| HTTP client | `axios` 1.6 | Semua panggilan REST API |
| Markdown | `react-markdown` 10 + `remark-gfm` 4 | Render narasi laporan (executive summary, rekomendasi) |
| Chart | `recharts` 2.10 | (tersedia sebagai dependency; cek pemakaian aktual sebelum diklaim di skripsi) |
| Export | `docx` 9.7 | Generate file `.docx` di sisi klien (`exportUtils.js`) |
| Routing | `react-router-dom` 6.20 | **Terdaftar sebagai dependency tetapi TIDAK dipakai untuk routing** — satu-satunya match adalah nama ikon MUI `RouteOutlinedIcon` di `ReportDashboard.jsx`. Navigasi antar-"halaman" sepenuhnya berbasis state lokal di `App.jsx` (lihat §4). |

> **Catatan untuk Bab IV / rekomendasi**: `react-router-dom` adalah
> *dependency* yang tidak terpakai (dead dependency) — bisa dihapus, atau
> jika skripsi menyebut "routing" sebagai bagian arsitektur frontend,
> sebaiknya diklarifikasi bahwa navigasi memakai **state-driven view
> switching**, bukan client-side routing berbasis URL. Lihat juga
> [06-rekomendasi.md](06-rekomendasi.md).

> **Catatan README**: `frontend/README.md` menyebut "pure CSS tanpa
> framework" dan komponen `ChatbotPage.jsx` — keduanya **sudah tidak
> sesuai** dengan kondisi kode saat ini (frontend memakai MUI penuh, dan
> tidak ada `ChatbotPage.jsx` di `frontend/src/components/`). README ini
> tampaknya dokumentasi awal yang belum diperbarui; **jangan dikutip** sebagai
> sumber arsitektur untuk skripsi — gunakan dokumen ini sebagai gantinya.

---

## 4. `App.jsx` — Shell Aplikasi & State Navigasi

`frontend/src/App.jsx` (366 baris) adalah komponen akar yang mengatur:

### 4.1 Empat "View" (`VALID_VIEWS`, baris 24)

```js
const VALID_VIEWS = new Set(["upload", "auth", "investigation", "settings"]);
```

| View | Komponen | Dimuat |
|---|---|---|
| `upload` | `UploadPage` | Selalu (eager import) |
| `auth` | `AuthGate` | Selalu (eager import) |
| `investigation` | `InvestigationPage` | **Lazy** (`React.lazy`, baris 16) |
| `settings` | `SettingsPage` | **Lazy** (`React.lazy`, baris 17) |

Plus `HeroLanding` (landing page, ditampilkan saat `!appStarted &&
currentView === "upload"`, baris 75, 268-270) dan `ErrorBoundary` (pembungkus
global, dicek di komponen lain).

### 4.2 Persistensi State via `localStorage` (baris 19-55, 83-112)

- `dfir.currentView` dan `dfir.sessionId` disimpan di `localStorage` —
  sehingga refresh halaman browser **tidak menghilangkan** sesi investigasi
  yang sedang dilihat pengguna.
- `getStoredWorkspaceState()` (baris 26-55) memvalidasi state tersimpan:
  view `"auth"` direstorasi sebagai `"upload"`; view `"investigation"` tanpa
  `sessionId` direstorasi sebagai `"upload"`.

### 4.3 Alur Autentikasi (baris 114-188)

- Saat mount, `App` memanggil `GET /api/auth/me` (baris 119):
  - Jika **berhasil** (user login) → `setCurrentUser(payload.user)`; jika
    view tersimpan adalah `"auth"`, dialihkan ke `"upload"`.
  - Jika **gagal** (belum login) → `setCurrentUser(null)`; jika view
    tersimpan adalah `"investigation"` atau `"settings"`, dialihkan ke
    `"auth"` dan `sessionId` dihapus.
- `handleAuthenticated(user)` (baris 172-176): dipanggil oleh `AuthGate`
  setelah login/register sukses → set user, `appStarted=true`, view =
  `"upload"`.
- `handleLogout()` (baris 178-188): `POST /api/auth/logout`, reset
  `currentUser`/`sessionId`, view = `"auth"`.

### 4.4 Shell Layout (baris 214-361)

- `showShell = appStarted && !isAuthPage` (baris 76) — `Header` dan
  `Sidebar` hanya dirender saat shell aktif (bukan landing/auth page).
- Layout: `Box` flex (sidebar + main content), `drawerWidth = 260px`
  (baris 57), responsif via `useMediaQuery(theme.breakpoints.down("md"))`.
- `Suspense` fallback untuk `InvestigationPage`/`SettingsPage` menampilkan
  `CircularProgress` + teks loading (baris 312-358) — konsisten dengan
  *progressive loading* pada aplikasi dense seperti command console.

### 4.5 Handler Navigasi Utama

| Handler | Efek |
|---|---|
| `handleUploadSuccess(sessionId)` | Set `sessionId`, pindah ke view `"investigation"` — dipanggil `UploadPage` setelah `POST /api/upload` + `POST /api/investigate/{id}` sukses |
| `handleSelectSession(sessionId)` | Pilih sesi dari riwayat Sidebar, pindah ke `"investigation"` |
| `handleBackToUpload()` | Reset `sessionId`, kembali ke `"upload"` |
| `handleSessionDeleted(id)` | Jika sesi yang dihapus = sesi aktif, panggil `handleBackToUpload()` |

---

## 5. Halaman & Komponen Utama

### 5.1 `HeroLanding.jsx` (875 baris) — Landing Page

Ditampilkan hanya saat `!appStarted` (sebelum pengguna menekan "Start").
Berisi:
- **Hero**: logo JejakAgent, headline, CTA "Start Investigation".
- **Tech stack showcase**: Frontend (React 18, Vite 5, MUI v5), Backend
  (FastAPI, LangGraph), Model (Foundation-Sec-8B, DeepLog, Drain, Ollama),
  Threat Intel (VirusTotal, OTX, ThreatFox, GreyNoise, URLHaus,
  MalwareBazaar).
- **Pipeline steps visual**: 7 langkah alur dari upload → report generation,
  termasuk metrik **DeepLog F1=0.9489, Recall=0.9151** yang ditampilkan
  sebagai *stats banner*.
- **Supported formats**: EVTX, CSV, LOG, TXT.

> **Catatan penting untuk Bab IV/V**: angka **F1=0.9489 / Recall=0.9151**
> yang ditampilkan di landing page **berbeda** dari angka F1=0.9823 (Windows
> balanced) yang dibahas di
> [03-pipeline-parsing-deeplog.md §6](03-pipeline-parsing-deeplog.md). Ini
> kemungkinan merepresentasikan **snapshot evaluasi yang berbeda** (mis.
> evaluasi natural gabungan, atau snapshot model sebelumnya). Lihat
> [05-evaluasi-rekonsiliasi.md](05-evaluasi-rekonsiliasi.md) untuk
> rekonsiliasi semua angka metrik yang beredar di kode/dokumen/UI — **jangan
> mengutip angka dari UI tanpa verifikasi** karena UI bisa memuat angka yang
> belum disinkronkan dengan hasil retraining terbaru.

### 5.2 `AuthGate.jsx` (149 baris) — Login & Register

- Form toggle Login/Register (baris 92-107).
- Login → `POST /api/auth/login` dengan `{username, password}` (baris 38).
- Register → `POST /api/auth/register` dengan `{username, email, password}`
  (baris 37).
- Sukses → `onAuthenticated(response.data.user)` (baris 40), diteruskan ke
  `App.handleAuthenticated`.
- Sesi dikelola via **cookie** (tidak ada token disimpan manual di
  frontend) — konsisten dengan model otorisasi *session-cookie* yang dicek
  ulang lewat `/api/auth/me` setiap reload (§4.3).

### 5.3 `UploadPage.jsx` (524 baris) — Upload & Quick Analysis

Dua aksi utama (lihat juga [02-backend-orkestrasi-api.md](02-backend-orkestrasi-api.md)):

1. **"Start Full Investigation"** (baris 74-94): `POST /api/upload`
   (multipart) → ambil `session_id` → `POST /api/investigate/{session_id}`
   → `onUploadSuccess(sessionId)` → App pindah ke view `investigation`.
2. **"Run Quick Analysis"** (baris 96-119): `POST /api/analyze` (multipart,
   dengan `max_lines=20000`, `sample_step=1`, `anomaly_limit=40`) → hasil
   ditampilkan **inline di halaman yang sama** sebagai "Phase 1 Debug
   Result" — menampilkan stat cards (Parsed Lines, Templates, Windows,
   Anomalies, Strict Anomalies, Skipped Windows, Avg Unknown Ratio) dan
   daftar window anomali dengan baris log yang ditandai (`is_anomalous_line`
   → highlight rose).

UI lain: dropzone drag-and-drop dengan validasi ekstensi
(`.evtx/.log/.txt/.csv`, baris 53-62), alert "Signed in as {user}" (baris
249-261), peringatan "High unknown template ratio" jika
`avg_unknown_ratio >= max_unknown_ratio` (baris 415-421) — **early warning
UI** untuk mismatch profil parser, relevan dengan diskusi profil di
[03-pipeline-parsing-deeplog.md §2](03-pipeline-parsing-deeplog.md).

### 5.4 `InvestigationPage.jsx` (855 baris) — Halaman Inti Investigasi

Ini adalah komponen **paling kompleks** dan paling penting untuk menjelaskan
*"show the pipeline honestly"* (§1.2) secara konkret.

#### 5.4.1 Polling Status (baris 388-438)

- Polling `GET /api/status/{sessionId}` setiap **1500ms** hingga
  `status === "completed"` (atau error).
- `getProgressValue()` (baris 289-293) memetakan `progress` backend (0-100)
  ke nilai progress bar, dianimasikan halus via `requestAnimationFrame`
  (baris 445-468) agar progress bar tidak "melompat" antar polling.

#### 5.4.2 Stepper 7 Langkah (baris 344-352)

Frontend memecah 4 stage backend
([02-backend-orkestrasi-api.md §4](02-backend-orkestrasi-api.md)) menjadi
**7 langkah** yang lebih granular untuk ditampilkan ke pengguna:

```
Upload → Log Parsing → DeepLog Detection → LLM Anomaly Gate →
JejakAgent Investigation → Threat Intel Enrichment → Report Generation
```

Pemetaan stage backend → label stepper dilakukan di `getAgentStageLabel()`
(baris 307-318): `QUEUE / PARSER / DEEPLOG / AGENT / REPORT / DONE`.

#### 5.4.3 Agent Terminal (baris 759-901)

- Menampilkan `status.activity_events` (lihat
  [02-backend-orkestrasi-api.md §6](02-backend-orkestrasi-api.md)) sebagai
  **feed log terminal monospace**, menunjukkan 10 event terakhir dengan
  timestamp, label stage, dan warna per level:
  - `success` → `#86efac` (hijau)
  - `warning` → `#fbbf24` (amber)
  - `error` → `#fb7185` (rose)
  - `stage` → `#bfdbfe` (mist blue)
  - `status` → `#c4b5fd` (indigo)
- Ini adalah implementasi langsung dari prinsip **"Keep analyst trust
  visible"** (§1.2) — pengguna melihat *real-time* apa yang dilakukan
  backend/AI Agent, bukan hanya progress bar generik.

#### 5.4.4 Live Stat Cards (baris 734-757)

Selama `status="processing"`, ditampilkan kartu statistik live: jumlah
anomali terdeteksi, IOC ditemukan, evidence pending — diperbarui setiap
polling.

#### 5.4.5 Integrasi `ReportDashboard` (baris ~21, 392-411)

Setelah `status.status === "completed"`, halaman memanggil `GET
/api/report/{sessionId}` dan merender `<ReportDashboard report={...}
formatDisplayDate={...} />` (lazy-loaded).

#### 5.4.6 Ekspor (baris 30-280, 470-666)

Tombol "Export" membuka menu dengan 6 opsi:

| Opsi | Mekanisme |
|---|---|
| Export PDF | `exportToPdf()` (baris 490-503) → `PDFExportTemplate` + `exportUtils.js` → `POST /api/report-export/pdf` |
| Export DOCX | `exportToDocx()` (baris 473-488) menggunakan `buildExportSummaryV2()` (baris 105-280, Markdown) → `docx` package |
| Export Parsed JSONL/NDJSON/CSV/Manifest | `GET /api/export/{sessionId}?format=...` (baris 505-549) |

`buildExportSummary()`/`buildExportSummaryV2()` menyusun ringkasan Markdown
dari `report` (metadata, anomali, IOC, timeline, rekomendasi) sebagai konten
ekspor DOCX/PDF.

### 5.5 `ReportDashboard.jsx` (427 baris) — Tampilan Laporan DFIR

Komponen tab (6 tab, baris 147-427), masing-masing memetakan ke bagian
laporan JSON (lihat juga [02-backend-orkestrasi-api.md](02-backend-orkestrasi-api.md)
dan [04-ai-agent-langgraph.md](04-ai-agent-langgraph.md) untuk asal data laporan):

| # | Tab | Field laporan yang dikonsumsi | Isi |
|---|---|---|---|
| 0 | **Overview** | `case_overview`, `executive_summary`, `objectives_scope.objectives` | Status kasus, severity, confidence, ringkasan eksekutif (Markdown), top-5 rekomendasi prioritas, tujuan investigasi |
| 1 | **Evidence** | `evidence_provenance.items[]` | Grid 2 kolom: `evidence_id`, `type`, `description`, `reference`, `timestamp` |
| 2 | **Detection** | `detection_analysis`, `attack_timeline`/`appendices.timeline` | Strongest compromise indicators, detection findings, timeline 20 event terakhir |
| 3 | **MITRE** | `mitre_attack_mapping.{status,tactics,techniques[]}` | Teknik ATT&CK: `technique_id`, `technique_name`, `tactic`, `confidence`, `rationale` |
| 4 | **Impact** | `impact_assessment`, `limitations_confidence` | Dampak bisnis/operasional, data exposure, service disruption, limitations |
| 5 | **Appendix** | `ioc_analysis[]`, `methodology` | Tabel IOC (`indicator`, `type`, `threat_intel`, `threat_level`), validasi metodologi |

Pola UI: stat card di atas (anomaly windows, curated IOCs, evidence items)
dengan warna sesuai tone (`severitySx()`, baris 32-40); IOC/hash ditampilkan
`fontFamily: monospace` (baris 275) sesuai "Evidence Readability Rule"
(§2.3); narasi (`executive_summary`, `recommendations`) dirender lewat
`MarkdownRenderer` dalam `Suspense` (baris 189-211).

> **Relevansi untuk evaluasi**: struktur 6-tab ini **adalah** representasi
> visual dari struktur JSON laporan yang disusun `ReportGenerator`
> (lihat [04-ai-agent-langgraph.md](04-ai-agent-langgraph.md) dan
> `backend/modules/report_modules/*`). Jika evaluator mempertanyakan apakah
> laporan "lengkap" sesuai kerangka DFIR standar (evidence, timeline, MITRE,
> impact, limitations, rekomendasi) — jawabannya dapat ditunjukkan langsung
> dari pemetaan tab ini.

### 5.6 `SettingsPage.jsx` (349 baris) — Konfigurasi Provider LLM

- Memilih **provider LLM**: Ollama / Gemini / OpenRouter (dropdown, baris
  259-272).
- Form per-provider (`emptyProviderForm`, baris 23-27, 76-91):
  - **Ollama**: `base_url` (default `http://localhost:11434`), `model`.
  - **Gemini**: `model`, `api_key`.
  - **OpenRouter**: `base_url`, `model`, `api_key`.
- Endpoint backend: `GET /api/settings/llm` (ambil config), `GET
  /api/settings/llm/status` (cek kesehatan provider — `ok` /
  `not_configured` / `unavailable`, dengan `latency_ms`), `PUT
  /api/settings/llm` (simpan).
- **Tidak ada** kontrol UI terpisah untuk role `filter` vs `agent`
  (lihat [02-backend-orkestrasi-api.md §4.1](02-backend-orkestrasi-api.md))
  — pengaturan provider berlaku **global** untuk semua role. Jika skripsi
  ingin mengklaim "konfigurasi LLM per-peran dapat diatur pengguna", ini
  **belum** terimplementasi di UI — baru tersedia di level konfigurasi
  backend (`config.py`/`llm_settings_store.py`). Catat sebagai *future work*
  di Bab V atau [06-rekomendasi.md](06-rekomendasi.md).

### 5.7 `Sidebar.jsx` (408 baris) & `Header.jsx` (53 baris)

- **Header**: app bar tetap (fixed), logo JejakAgent, tombol toggle sidebar.
  Tidak ada elemen lain (search bar, notifikasi, dll.) — minimalis sesuai
  prinsip "dense but readable, no decorative elements".
- **Sidebar**: drawer persisten (desktop) / temporary (mobile, via
  `isMobile`). Berisi:
  - Menu workspace: "Upload Log" (selalu aktif untuk user login),
    "Investigation" (aktif hanya jika `sessionId` ada).
  - **Riwayat sesi**: `GET /api/sessions`, dengan aksi rename
    (`PATCH /api/sessions/{id}`) dan delete (`DELETE /api/sessions/{id}`)
    per item — *hover-to-reveal* action buttons.
  - **Profile menu**: nama/username pengguna, link ke Settings, Logout.

### 5.8 Komponen Pendukung

| Komponen | Baris | Fungsi |
|---|---|---|
| `MarkdownRenderer.jsx` | 193 | `react-markdown` + `remark-gfm`, `skipHtml`. Custom styling: link buka tab baru; paragraf/kode/tabel semua `overflow-wrap: anywhere` + `word-break: break-word` (Evidence Readability Rule); tabel `overflow-x: auto`. Dipakai untuk merender `executive_summary`, `recommendations`, dan teks naratif lain dari laporan. |
| `PDFExportTemplate.jsx` | 243 | Template HTML print-safe (A4, margin 10mm/8mm, `print-color-adjust: exact`) yang dikirim ke `POST /api/report-export/pdf` (lihat [02-backend-orkestrasi-api.md](02-backend-orkestrasi-api.md), `report_pdf_service.py`). |
| `exportUtils.js` | — | `buildPrintableReportHtml()` (clone DOM + inject CSS cetak), `exportToDocx()` (via `docxReportFormatter.js` + paket `docx`), download helper (File System Access API dengan fallback anchor `<a download>`). |
| `ErrorBoundary.jsx` | 57 | React error boundary global — menangkap exception render-time, menampilkan kartu error + tombol "Reload application", log ke console. |

---

## 6. Ringkasan untuk Bab III/IV Skripsi

1. **Sistem desain bukan dekorasi** — `DESIGN.md` mendefinisikan token warna,
   tipografi, dan aturan ("Blue Scarcity Rule", "Evidence Readability Rule")
   yang **terverifikasi konsisten** dengan implementasi `theme.js` dan
   komponen. Ini bisa dijadikan bagian *design system* di Bab III.2.
2. **Navigasi adalah state-driven, bukan URL routing** — empat "view"
   (`upload/auth/investigation/settings`) dikontrol oleh state React di
   `App.jsx` + `localStorage`, **bukan** `react-router-dom` (meski terdaftar
   sebagai dependency). Jika skripsi menyebut "routing", gunakan istilah
   "view/state-based navigation" agar akurat.
3. **UI memetakan pipeline backend secara granular** — `InvestigationPage`
   memecah 4 stage backend menjadi 7 langkah stepper + agent terminal
   real-time, langsung mengimplementasikan prinsip produk "show the pipeline
   honestly". Ini adalah bukti kuat untuk argumen *transparency* di Bab
   III/V.
4. **Laporan JSON ↔ 6 tab `ReportDashboard`** memberi pemetaan 1:1 yang jelas
   antara output `ReportGenerator` dan struktur DFIR standar (evidence,
   detection, MITRE, impact, limitations, rekomendasi) — berguna untuk
   menjawab pertanyaan kelengkapan laporan.
5. **Dua catatan untuk dibersihkan/diklarifikasi** (lihat
   [06-rekomendasi.md](06-rekomendasi.md)): (a) `frontend/README.md` yang
   sudah usang (menyebut pure-CSS & `ChatbotPage`), dan (b) dependency
   `react-router-dom` yang tidak terpakai.
6. **Angka metrik di `HeroLanding` (F1=0.9489/Recall=0.9151) berbeda dari
   angka di laporan evaluasi DeepLog** — perlu direkonsiliasi atau
   diperbarui sebelum sidang (lihat
   [05-evaluasi-rekonsiliasi.md](05-evaluasi-rekonsiliasi.md)).
