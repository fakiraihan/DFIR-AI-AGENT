PRIORITAS UTAMA:
Preserve behavior. This is a UI/UX facelift only. The application already works. Do not rewrite the app flow. Do not change API contracts. Do not mock backend responses. Improve only the interface, layout, styling, visual hierarchy, buttons, status presentation, and report readability.

Saya ingin kamu melakukan UI/UX facelift pada frontend aplikasi DFIR/AI Agent saya berdasarkan source code yang sudah ada. Ini BUKAN pembuatan aplikasi baru dan BUKAN rewrite fungsi. Fokus hanya pada penyesuaian tampilan, layout, button, card, status, hierarchy, dan glassmorphism ringan.

Konteks aplikasi:
Aplikasi ini adalah AI Agent berbasis Tool-Augmented LLM untuk otomatisasi investigasi insiden siber/DFIR. Program sudah punya fungsi utama dan flow backend yang berjalan. Saya ingin fungsi tersebut tetap dipertahankan seperti aslinya.

Stack frontend:
- React 18
- Vite
- MUI
- Emotion
- MUI Icons
- Axios
- Recharts
- react-markdown
- html2pdf
- md-to-docx

Jangan migrasi ke Tailwind.
Jangan mengganti MUI dengan library lain.
Jangan membuat project baru.
Tetap gunakan struktur komponen frontend yang sudah ada.

File frontend yang perlu diperhatikan:
- frontend/src/App.jsx
- frontend/src/components/UploadPage.jsx
- frontend/src/components/InvestigationPage.jsx
- frontend/src/components/Sidebar.jsx
- frontend/src/components/SettingsPage.jsx
- frontend/src/components/MarkdownRenderer.jsx
- frontend/src/utils/exportUtils.js

Fungsi yang HARUS tetap berjalan:
1. Upload log melalui POST /api/upload
2. Quick analyze melalui POST /api/analyze
3. Start full investigation melalui POST /api/investigate/{sessionId}
4. Polling status melalui GET /api/status/{sessionId}
5. Fetch report melalui GET /api/report/{sessionId}
6. Session history melalui GET /api/sessions
7. Rename session melalui PATCH /api/sessions/{sessionId}
8. Delete session melalui DELETE /api/sessions/{sessionId}
9. LLM settings melalui:
   - GET /api/settings/llm
   - PUT /api/settings/llm
   - GET /api/settings/llm/status
10. Export laporan ke PDF dan DOCX
11. localStorage state untuk current view dan session id

Aturan keras:
- Jangan ubah endpoint API.
- Jangan ubah payload request/response.
- Jangan hapus quick analyze.
- Jangan hapus full investigation.
- Jangan hapus session sidebar.
- Jangan hapus settings LLM.
- Jangan hapus export PDF/DOCX.
- Jangan ubah business logic pipeline.
- Jangan ubah backend.
- Jangan membuat dummy data untuk menggantikan response backend.
- Jangan membuat flow baru yang tidak tersambung ke fungsi asli.
- Jangan mengubah nama handler/function utama jika tidak perlu.
- Kalau perlu refactor komponen, pastikan behavior tetap sama.
- Kalau ada state existing seperti sessionId, currentView, selectedFile, loading, status, report, error, settings, pertahankan logic-nya.

Arah visual:
Saya ingin tampilan UI/UX mengambil inspirasi dari dark futuristic cybersecurity dashboard/landing page seperti referensi:
- Deep navy / black background
- Accent electric blue, cyan, indigo, violet
- Light glassmorphism
- Border halus
- Glow lembut
- Circuit / grid ornament subtle
- Enterprise-grade
- Clean, modern, premium
- Tidak terlalu ramai
- Readable untuk analyst workspace

Karena ini aplikasi dashboard, bukan landing page, jangan membuat hero section marketing yang terlalu besar. Buat workspace yang tetap fungsional, tetapi terlihat modern.

Global theme:
Gunakan MUI theme dark yang lebih matang:
- palette.background.default: very dark navy
- palette.background.paper: translucent dark surface
- primary: blue/cyan
- secondary: indigo/violet
- text.primary: #F8FAFC
- text.secondary: #CBD5E1
- divider: rgba(255,255,255,0.10)

Tambahkan global background:
- radial gradient biru/cyan sangat halus di pojok atas
- radial gradient indigo/violet sangat halus di bawah
- optional subtle grid pattern memakai CSS pseudo/background-image
- jangan sampai mengganggu readability

Glass style yang diinginkan:
Gunakan light glass, bukan heavy frosted glass.
Contoh style MUI sx:
{
  background: 'rgba(15, 23, 42, 0.62)',
  backdropFilter: 'blur(14px)',
  border: '1px solid rgba(148, 163, 184, 0.16)',
  boxShadow: '0 24px 80px rgba(2, 8, 23, 0.45), 0 0 40px rgba(56, 189, 248, 0.06)',
  borderRadius: 4
}

Jangan membuat glass terlalu terang.
Jangan membuat blur terlalu berat.
Gunakan glow hanya sebagai accent, bukan dominan.

Target UX:
Aplikasi harus terasa seperti SOC/DFIR analyst workspace:
- Ada struktur yang jelas
- Upload mudah ditemukan
- Status investigasi mudah dipantau
- Hasil investigasi mudah dibaca
- Report tidak melelahkan
- Export jelas
- Settings mudah diakses
- Session history tetap berguna

Perbaikan App.jsx:
- Pertahankan routing/view logic existing.
- Pertahankan localStorage key existing jika sudah ada.
- Rapikan layout utama menjadi app shell.
- Buat background utama dark futuristic.
- Sidebar tetap ada, tetapi tampilannya dibuat lebih modern.
- Header/topbar dibuat lebih clean.
- Area content diberi max width atau responsive layout.
- Jangan membuat halaman terasa seperti landing page publik.
- Buat transition antar-view halus bila mudah, tetapi jangan pakai library tambahan.

Perbaikan Sidebar.jsx:
- Buat sidebar menjadi glass panel gelap.
- Brand/app title di atas, misalnya:
  "DFIR AI Agent"
  subtitle kecil: "Cyber Incident Investigation"
- Session history dibuat lebih readable:
  - active session highlight cyan/blue
  - hover state halus
  - rename/delete tetap tersedia
  - status badge jika data status tersedia
- Tambahkan divider halus.
- Tombol new/upload/settings jika sudah ada tetap gunakan handler existing.
- Mobile: sidebar jangan menyebabkan horizontal overflow.

Perbaikan Header:
Kalau ada Header component atau header di App.jsx:
- Buat header ringkas:
  title sesuai current view:
  - Upload: "Investigation Workspace"
  - Investigation: "Investigation Results"
  - Settings: "LLM Provider Settings"
- Tambahkan subtitle kecil.
- Tambahkan backend/provider status jika sudah tersedia dari settings/status.
- Gunakan glass topbar ringan atau simple header dalam content area.

Perbaikan UploadPage.jsx:
Tujuan: upload page harus terlihat seperti command center untuk memulai investigasi, bukan form biasa.

Layout yang disarankan:
- Bagian atas:
  - Title: "AI-Powered Cyber Incident Investigation"
  - Subtitle: "Upload security logs to parse events, detect anomalies, enrich IOCs, and generate an investigation report."
  - Badge kecil:
    "EVTX"
    "CSV"
    "LOG"
    "TXT"
    "DeepLog"
    "Tool-Augmented LLM"

- Main content grid desktop:
  Kiri: Upload card
  Kanan: Quick analysis / pipeline preview / supported workflow card

Upload card:
- Gunakan drag & drop area existing, jangan ubah logic upload-nya.
- Style drag area:
  - dashed border cyan/blue
  - glass background
  - hover glow ringan
  - icon upload besar
  - text jelas
- Tampilkan file terpilih:
  - file name
  - file size jika sudah ada
  - extension
- Button utama:
  "Start Full Investigation"
  Terhubung ke flow existing: upload lalu POST /api/investigate/{sessionId}
- Button secondary:
  "Run Quick Analysis"
  Terhubung ke POST /api/analyze existing
- Disabled state:
  - saat tidak ada file
  - saat upload/loading
  - saat proses berjalan
- Loading state harus jelas:
  - spinner
  - label seperti "Uploading..." atau "Starting investigation..."

Tambahkan panel "Investigation Pipeline":
Visual stepper statis/informatif, bukan mengganti logic:
1. Upload & Session
2. Parsing
3. DeepLog Detection
4. LLM Anomaly Gate
5. AI Agent Investigation
6. Threat Intel Enrichment
7. Report Generation

Panel ini hanya menjelaskan workflow, kecuali status real sudah tersedia. Jangan membuat status palsu.

Quick analyze result:
- Jika quick analyze sudah ada, tampilkan dalam card modern.
- Ringkas metrik:
  - parsed_lines
  - template_count
  - window_count
  - anomaly_count
  - strict_anomaly_count
  - skipped_windows
  - avg_unknown_ratio
- Tampilkan anomalies preview jika data ada.
- Jangan mengarang field yang tidak tersedia.

Perbaikan InvestigationPage.jsx:
Tujuan: halaman ini menjadi pusat monitoring dan pembacaan hasil investigasi.

Layout yang disarankan:
- Top summary card:
  - session id atau file name
  - status
  - stage
  - progress
  - current_message
  - severity jika report sudah ada
- Progress visual:
  Buat pipeline stepper berdasarkan status/stage existing dari GET /api/status/{sessionId}.
  Mapping stage ke label UI:
  - upload/session
  - parsing
  - anomaly_detection
  - llm_filter / anomaly_filter
  - investigation / agent
  - report_generation
  - completed
  - failed

Jika stage dari backend tidak persis sama, buat mapping defensive:
- unknown stage tetap tampil sebagai current backend stage
- jangan crash jika field null/undefined

Stepper visual:
- pending: muted grey
- running: cyan pulse
- completed: emerald check
- failed: red alert
- progress bar tetap tampil dari progress backend

Results overview:
Jika status summary tersedia, tampilkan metric cards:
- Parsed Logs
- Templates
- Anomalies
- Relevant Anomalies
- IOCs
- Tool Results
- Report Status

Gunakan field yang benar-benar ada dari response status/report. Kalau field tidak ada, tampilkan "N/A" atau sembunyikan card.

Report layout:
- Setelah completed dan report tersedia, tampilkan report dengan tabs atau segmented navigation:
  1. Overview
  2. Technical Findings
  3. IOCs
  4. Timeline
  5. Recommendations
  6. Raw Report / Markdown

Jangan ubah isi data report.
Hanya ubah cara render agar lebih readable.

Report sections:
- Executive summary di card besar
- Severity badge jika ada
- IOC analysis dalam table/card list
- Technical findings dalam accordion/list
- Attack timeline dalam vertical timeline
- Recommendations dalam checklist/card
- Evidence references dalam collapsible area bila panjang

Export buttons:
- Letakkan di kanan atas report section atau sticky small toolbar.
- Button:
  - "Export PDF"
  - "Export DOCX"
- Tetap gunakan function export existing dari exportUtils.js.
- Disable jika report belum ada.
- Jangan ubah isi export kecuali styling trigger button.

Polling:
- Pertahankan logic polling existing.
- Jangan menambah polling agresif.
- Pastikan cleanup interval tetap aman.
- Jangan membuat infinite loop.

Error state:
- Buat error alert yang jelas:
  - glass/dark alert
  - red accent
  - retry button jika handler existing tersedia
- Jangan menyembunyikan error.

Perbaikan SettingsPage.jsx:
Tujuan: settings LLM terlihat seperti provider configuration panel yang rapi.

Layout:
- Title: "LLM Provider Settings"
- Subtitle: "Configure the model provider used by anomaly filtering and AI agent investigation."
- Provider cards/tabs untuk:
  - Ollama
  - Gemini
  - OpenRouter
  sesuai data existing
- Jangan mengubah payload PUT settings.
- API key field tetap aman.
- Jika response public hanya has_api_key, tampilkan status "API key configured" tanpa membuka secret.
- Health/status provider ditampilkan sebagai badge:
  - connected/ready
  - unavailable
  - error
  - unknown
- Buttons:
  - Save Settings
  - Refresh Status
  - Back/Cancel jika sudah ada
- Loading dan error state harus rapi.

Perbaikan MarkdownRenderer.jsx:
- Buat markdown report lebih readable di dark UI.
- Heading punya ukuran dan spacing jelas.
- Paragraph line-height nyaman.
- Code block dan table punya background dark surface.
- Table responsive horizontal scroll.
- Link dan emphasis tetap jelas.
- Jangan mengubah markdown content.

Perbaikan exportUtils.js:
- Jangan ubah fungsi utama export jika sudah berjalan.
- Boleh rapikan nama file export jika sudah existing aman.
- Jangan merusak html2pdf dan md-to-docx usage.
- Pastikan export tetap bisa dipanggil dari InvestigationPage.

Komponen reusable yang boleh dibuat:
Buat hanya jika membantu dan tidak mengganggu logic:
- GlassCard
- PrimaryButton
- SecondaryButton
- StatusBadge
- MetricCard
- PipelineStepper
- SectionHeader
- EmptyState
- ErrorPanel
- LoadingPanel

Jika membuat komponen baru, letakkan di folder components atau file yang sesuai dengan struktur existing. Jangan membuat dependency baru jika tidak perlu.

Button style:
Primary:
- gradient blue/cyan
- text white
- rounded 12-16px
- hover glow cyan ringan
- disabled jelas

Secondary:
- glass background
- border white/cyan subtle
- text slate/cyan

Ghost:
- transparent
- hover rgba white subtle

Danger:
- red accent
- untuk delete session atau destructive action

Contoh label button:
- "Start Full Investigation"
- "Run Quick Analysis"
- "View Report"
- "Export PDF"
- "Export DOCX"
- "Open Settings"
- "Refresh Status"
- "Rename"
- "Delete"
- "Back to Upload"

Jangan membuat button yang tidak punya fungsi existing.

Card style:
- rounded 24px
- glass dark
- border subtle
- padding cukup
- hover state hanya untuk interactive card
- text readable
- jangan terlalu banyak neon

Typography:
- Heading: kuat, clean, tidak terlalu kecil
- Body: minimal 14-16px
- Muted text jangan terlalu redup
- Gunakan text contrast baik di dark background
- Hindari paragraph panjang full width; gunakan max width

Responsive:
Desktop:
- Sidebar + content workspace
- Grid 2 kolom untuk upload/pipeline
- Report full width

Tablet:
- Grid menyesuaikan 1-2 kolom

Mobile:
- Semua stack vertical
- Sidebar collapse atau responsif sesuai existing
- Buttons full width jika perlu
- Tabs horizontal scroll
- Tidak boleh ada horizontal overflow

Accessibility:
- Button focus-visible jelas
- Jangan hanya mengandalkan warna untuk status
- Tambahkan icon/text untuk success/error/running
- Input file tetap accessible
- aria-label untuk icon-only buttons
- Contrast teks cukup
- Loading state harus terbacakan

Data handling:
- Gunakan optional chaining dan fallback aman.
- Jangan crash jika response field kosong.
- Jangan mengarang data.
- Jika field tidak tersedia, tampilkan "N/A", "Not available", atau sembunyikan section.
- Jangan mengganti response backend dengan dummy static data.

Stage mapping yang disarankan:
Buat helper function seperti:
getStageState(currentStage, status, progress)
atau mapBackendStageToPipelineStep(stage)

Pipeline labels:
- upload: "Upload & Session"
- parsing: "Log Parsing"
- anomaly_detection: "DeepLog Detection"
- llm_filter: "LLM Anomaly Gate"
- investigation: "AI Agent Investigation"
- threat_intel: "Threat Intel Enrichment"
- report_generation: "Report Generation"
- completed: "Completed"

Karena backend stage mungkin berbeda, mapping harus toleran:
- stage?.toLowerCase()
- cek includes('parse'), includes('anomaly'), includes('filter'), includes('agent'), includes('tool'), includes('report'), includes('complete')
- fallback ke raw stage string

Visual inspiration:
Ambil nuansa dari futuristic cybersecurity UI:
- dark navy canvas
- subtle circuit lines
- glowing AI/security node
- glass cards
- gradient CTA
- enterprise SOC dashboard feel
Namun jangan membuat landing page panjang. Ini tetap aplikasi kerja.

Hal yang TIDAK boleh dilakukan:
- Jangan membuat hero marketing "World-Leading Cybersecurity Powered by AI" sebagai halaman utama besar.
- Jangan menghapus upload panel.
- Jangan mengganti investigation page dengan landing page.
- Jangan membuat form palsu.
- Jangan membuat dummy testimonial/pricing/marketing section.
- Jangan membuat endpoint baru.
- Jangan mengubah backend.
- Jangan mengganti MUI dengan Tailwind.
- Jangan menambah dependency berat.
- Jangan mengubah algoritma/program utama.

Validasi setelah selesai:
Pastikan:
1. npm run dev berjalan.
2. npm run build berjalan.
3. Upload file tetap bekerja.
4. Quick analyze tetap bekerja.
5. Full investigation tetap berjalan.
6. Polling status tetap berjalan.
7. Report tampil saat completed.
8. Export PDF tetap bekerja.
9. Export DOCX tetap bekerja.
10. Settings LLM bisa dibuka, disimpan, dan refresh status.
11. Sidebar session history bisa list, select, rename, delete.
12. Tidak ada horizontal overflow.
13. Tidak ada console error karena undefined/null.
14. Tidak ada dummy data yang menggantikan backend response.

Output:
Lakukan perubahan langsung pada kode frontend existing.
Berikan ringkasan singkat file apa saja yang diubah dan apa efeknya.
Jangan jelaskan terlalu panjang.
Fokus pada hasil UI/UX yang lebih modern, glass ringan, readable, dan tetap mempertahankan fungsi asli.