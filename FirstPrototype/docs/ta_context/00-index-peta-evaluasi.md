# Indeks & Peta Evaluasi — Dokumentasi Konteks TA "JejakAgent"

> Dokumen ini adalah **titik masuk (entry point)** untuk 6 dokumen lain di
> `docs/ta_context/`. Keenamnya ditulis untuk memberi **konteks teknis yang
> akurat dan dapat ditelusuri (traceable)** tentang bagaimana sistem
> *"Rancang Bangun AI Agent Berbasis Tool-Augmented Large Language Model
> untuk Otomatisasi Investigasi Insiden Siber"* benar-benar bekerja —
> sehingga setiap poin di
> `C:\Users\Pluto_06\Documents\Evaluasi_TA_Muhammad_Faki_Raihan.md`
> (selanjutnya disebut **"dokumen evaluasi"**) dapat ditindaklanjuti dengan
> rujukan konkret ke kode, laporan evaluasi, dan desain sistem — bukan
> sekadar opini.
>
> **Bahasa & konvensi**: dokumen ditulis dalam Bahasa Indonesia (agar
> langsung dapat diadaptasi ke naskah skripsi), dengan istilah teknis,
> nama fungsi/file, dan path (`file.py:baris`) dipertahankan dalam Bahasa
> Inggris/aslinya untuk memudahkan verifikasi terhadap kode.

---

## 1. Daftar Dokumen

| Dokumen | Isi Utama | Paling Relevan untuk |
|---|---|---|
| [01-product-frontend.md](01-product-frontend.md) | Identitas produk (`PRODUCT.md`), desain sistem "Secure Command Console" (`DESIGN.md`), stack frontend (React/Vite/MUI), arsitektur `App.jsx`, breakdown setiap halaman (Landing, Auth, Upload, Investigation, Report Dashboard, Settings, Sidebar/Header) | Bab III.3.1 (arsitektur), Bab IV (demonstrasi UI) |
| [02-backend-orkestrasi-api.md](02-backend-orkestrasi-api.md) | Arsitektur backend FastAPI, daftar endpoint, siklus sesi, `run_investigation_pipeline` (3 stage — LLM Gate dihapus Juni 2026), triage semantik di dalam AI Agent, telemetri | Bab III.3.1 (arsitektur backend), Bab III (desain pipeline) |
| [03-pipeline-parsing-deeplog.md](03-pipeline-parsing-deeplog.md) | Pipeline parsing (5 profil, Drain3), transformasi log→input LSTM (diagram lengkap), arsitektur DeepLog, tabel justifikasi pemilihan DeepLog, teori node `anomaly_triage` (pengganti LLMAnomalyFilter), hasil evaluasi Windows vs Linux | Bab II (kajian teori parsing/DeepLog/triage semantik), Bab III.3.2c/d/e, Bab IV.3.1 |
| [04-ai-agent-langgraph.md](04-ai-agent-langgraph.md) | Kelas `DFIRAgent`, diagram state machine LangGraph lengkap (**12 node** termasuk `anomaly_triage` baru, 9 edge kondisional), **definisi agentic tools vs external API tools**, `InvestigationState`, Procedural Memory | Bab II (kajian teori AI Agent & tools), Bab III.3.2a/b, Bab III.3.3.3 |
| [05-evaluasi-rekonsiliasi.md](05-evaluasi-rekonsiliasi.md) | Rekonsiliasi semua angka evaluasi (DeepLog F1/recall, Tool Correctness, G-Eval, SUS) antara dokumen evaluasi vs artefak repo, termasuk koreksi top-k Linux dan G-Eval 0,8675→0,863 | Bab IV (hasil & evaluasi), Bab V (analisis kelemahan) |
| [06-rekomendasi.md](06-rekomendasi.md) | Pemetaan **27 item rekomendasi** (BAGIAN VI dokumen evaluasi) ke dokumen 01-05 + tindakan konkret + roadmap pengerjaan + rekomendasi sistem di luar 27 item | Revisi naskah skripsi (semua bab) + perbaikan sistem |
| [07-prompts-agent.md](07-prompts-agent.md) | **4 LLM call** dalam `DFIRAgent`: template prompt lengkap + format input/output + desain keputusan (few-shot grounding, ReAct scaffolding, anti-halusinasi) untuk Triage, Tool Selection, Correlation, dan Report Generation | Bab III (rancangan prompt), Bab II (prompt engineering), Bab IV (evaluasi kualitas laporan) |

**Urutan baca yang disarankan**: jika baru pertama kali, baca **06** lebih
dulu (peta tindakan), lalu rujuk **01-05** sesuai kebutuhan per item, dan
gunakan **05** sebagai sumber angka final saat menulis Bab IV.

---

## 2. Peta Cepat: 27 Item Evaluasi → Dokumen

Tabel ini adalah ringkasan navigasi cepat. Detail tindakan ada di
[06-rekomendasi.md](06-rekomendasi.md).

| # | Item (ringkas) | Prioritas | Dokumen rujukan utama |
|---|---|---|---|
| 1 | Tiga nilai SUS berbeda | Tinggi (wajib) | [05§5](05-evaluasi-rekonsiliasi.md#5-sus--8031-benar-8033--8333-typo) |
| 2 | Duplikasi paragraf Abstrak EN | Tinggi (wajib) | — (teks) |
| 3 | Judul III.3.3.3 tidak sesuai isi | Tinggi (wajib) | [04§6](04-ai-agent-langgraph.md#6-mapping-ke-sub-bab-skripsi) |
| 4 | "tiga bab" + "Proposal" | Tinggi (wajib) | — (teks) |
| 5 | "dapat dapat" | Tinggi (wajib) | — (teks) |
| 6 | Separator desimal tidak konsisten | Tinggi (wajib) | [06§1](06-rekomendasi.md#1-prioritas-tinggi--wajib-sebelum-penyerahan-item-17) |
| 7 | Konfusi nomenklatur "tools" | Tinggi (wajib) | [04§3](04-ai-agent-langgraph.md#3-nomenklatur-tools-agentic-tools-vs-external-api-tools) |
| 8 | Arsitektur layering & diagram state machine | Tinggi (substansial) | [02§1](02-backend-orkestrasi-api.md#1-posisi-dalam-arsitektur), [04§2](04-ai-agent-langgraph.md#2-state-machine-langgraph--diagram-lengkap) |
| 9 | Asal-usul/inspirasi desain sistem | Tinggi (substansial) | [06§2 Item 9](06-rekomendasi.md#item-9--asal-usulinspirasi-desain-sistem-bab-iii33-) |
| 10 | Bab II perlu diperkaya (istilah tiba-tiba muncul) | Tinggi (substansial) | [04§6](04-ai-agent-langgraph.md#6-mapping-ke-sub-bab-skripsi), [06§2 Item 10](06-rekomendasi.md#item-10--11--bab-ii-diperkaya-bab-iv-murni-hasil-defineprescriptresult-) |
| 11 | Bab IV harus murni hasil (Define→Prescript→Result) | Tinggi (substansial) | [06§2 Item 11](06-rekomendasi.md#item-10--11--bab-ii-diperkaya-bab-iv-murni-hasil-defineprescriptresult-) |
| 12 | Diagram transformasi log → input LSTM | Tinggi (substansial) | [03§3](03-pipeline-parsing-deeplog.md) |
| 13 | Tabel justifikasi pemilihan DeepLog | Tinggi (substansial) | [03§5](03-pipeline-parsing-deeplog.md) |
| 14 | Investigasi top-k tinggi DeepLog Linux | Tinggi (substansial) | [05§1.2](05-evaluasi-rekonsiliasi.md#12-linux--top-k-182-vs-top-k-328329-natural-evaluation), [03§6](03-pipeline-parsing-deeplog.md) |
| 15 | Tidak ada lokus penelitian | Tinggi (substansial) | [06§2 Item 15](06-rekomendasi.md#item-15--tidak-ada-lokus-penelitian--pembatasan-masalah-resmi-) |
| 16 | Homogenitas responden SUS | Tinggi (substansial) | [05§5](05-evaluasi-rekonsiliasi.md#5-sus--8031-benar-8033--8333-typo) |
| 17 | Bias judge model Tool Correctness | Tinggi (substansial) | [05§2](05-evaluasi-rekonsiliasi.md#2-tool-correctness--0864-mean-vs-50-pass-rate--judge-bias) |
| 18 | "Forensic" vs "Forensics" | Menengah | — (teks, *find & replace*) |
| 19 | Judul Tabel 4.24/4.26 identik | Menengah | [05§3](05-evaluasi-rekonsiliasi.md#3-g-eval--0863-aktual-vs-08675-dikutip-di-tesis) |
| 20 | Sintesis gap II.2 tidak ada | Menengah | [06§3 Item 20](06-rekomendasi.md#3-prioritas-menengah-item-1824) |
| 21 | Elaborasi prompting Tool Correctness | Menengah | [04§3.4](04-ai-agent-langgraph.md#34-prompt-llm-untuk-tool-selection) |
| 22 | Kemampuan LangGraph belum dijelaskan | Menengah | [04§2.4](04-ai-agent-langgraph.md#24-mekanisme-bounded--fail-open) |
| 23 | Tool Correctness ↔ arsitektur tidak terhubung | Menengah | [04§3.2-3.3](04-ai-agent-langgraph.md#32-mengapa-pembedaan-ini-penting) |
| 24 | Komponen triage LLM tanpa landasan teori | Menengah | [03§4](03-pipeline-parsing-deeplog.md) — digantikan node `anomaly_triage` (Juni 2026) |
| 25 | Tidak ada data latency | Pengembangan | [02§6](02-backend-orkestrasi-api.md#6-telemetri--observability) |
| 26 | Definisi maturitas prototipe | Pengembangan | [01§1](01-product-frontend.md), [06§4 Item 26](06-rekomendasi.md#4-prioritas-pengembangan--versi-jurnalpublikasi-item-2527) |
| 27 | Foundation-Sec-8B vs hasil evaluasi | Pengembangan | [02§4.1](02-backend-orkestrasi-api.md#41-catatan-penting-provider-llm-dapat-berbeda-per-peran) |

---

## 3. Glosarium / Nomenklatur Kunci

Daftar istilah yang **sering disalahpahami atau perlu didefinisikan secara
konsisten** — semuanya muncul sebagai temuan evaluasi.

| Istilah | Definisi singkat | Definisi lengkap |
|---|---|---|
| **DFIR** | *Digital **Forensics** and Incident Response* (dengan huruf "s") — sesuai NIST SP 800-86. Gunakan ejaan ini **secara konsisten** di seluruh dokumen (Item 18). | — |
| **Agentic Tools** | Fungsi/node internal LangGraph yang menjalankan tugas non-LLM dalam control flow agent (IOC Extractor, Planner, Timeline Builder, Report Generator). **Tidak** diuji oleh Tool Correctness. | [04§3.1](04-ai-agent-langgraph.md#31-dua-kategori-tools-yang-berbeda-secara-fundamental) |
| **External API Tools** | 6 layanan threat-intel eksternal (`threatfox_lookup`, `malwarebazaar_lookup`, `urlhaus_lookup`, `alienvault_otx_lookup`, `greynoise_lookup`, `virustotal_lookup`), dipilih oleh node `tool_selector`. **Inilah** yang diukur oleh Tool Correctness (0,864). | [04§3.1-3.3](04-ai-agent-langgraph.md#3-nomenklatur-tools-agentic-tools-vs-external-api-tools) |
| **`model_profile`** | 5 nilai enum hasil `build_model_profile()`: `linux_log`, `windows_sysmon`, `windows_evtx`, `lmd_enriched`, `general`. Menentukan strategi parsing & model DeepLog yang dipakai. | [03§2](03-pipeline-parsing-deeplog.md) |
| **"Profile" di tabel evidence case G-Eval** | Nilai `windows_apt` / `sysmon` pada kolom "Profile" di `report_generation_geval_eval.md` — ini adalah **nama dataset/model**, bukan nilai `model_profile`. `windows_apt` ↔ profil `windows_evtx`; `sysmon` ↔ profil `windows_sysmon`. | [05§6](05-evaluasi-rekonsiliasi.md#6-catatan-tambahan-penamaan-profile-di-laporan-evaluasi-vs-dokumentasi-pipeline) |
| **Mode `filter` vs `annotate`** (LLM Anomaly Gate) | `filter` = anomali yang dideprioritaskan **dibuang**; `annotate` = anomali **tetap diteruskan** dengan metadata prioritas (aktif jika *decision policy* = `f1_constrained_recall`). | [02§4.2](02-backend-orkestrasi-api.md#42-catatan-penting-mode-filter-vs-annotate-pada-llm-gate) |
| **`InvestigationState`** | `TypedDict` yang menjadi *working memory* seluruh graph LangGraph — berisi field input, *episodic memory* (akumulator `tool_calls`, `reasoning_steps`, dll.), dan output. | [04§4](04-ai-agent-langgraph.md#4-investigationstate--kontrak-data-antar-node) |
| **Decision policy DeepLog** | `topk` (default/strict) vs `f1_constrained_recall` (override via `score_threshold`, dirancang menjaga recall ≥ target). | [03§3](03-pipeline-parsing-deeplog.md) |
| **`frozen_replay` vs full pipeline (G-Eval)** | `frozen_replay` = evaluasi Report Generator dengan *evidence* yang sudah tetap/benar (N=16, hasil 0,863). Full pipeline = evaluasi end-to-end termasuk parsing/DeepLog/Agent (N=1, hasil 0,500, *smoke test*). **Jangan dicampur** saat dikutip di Bab IV. | [05§3-4](05-evaluasi-rekonsiliasi.md#3-g-eval--0863-aktual-vs-08675-dikutip-di-tesis) |

---

## 4. Ringkasan Rekonsiliasi Angka (Quick Reference)

Sumber lengkap: [05-evaluasi-rekonsiliasi.md](05-evaluasi-rekonsiliasi.md).
Gunakan kolom **"Pakai di Bab IV"** sebagai nilai final yang sudah
diverifikasi terhadap artefak repo.

| Metrik | Dikutip di Dok. Evaluasi | Pakai di Bab IV | Sumber Artefak |
|---|---|---|---|
| DeepLog F1 (Windows, balanced top-k=9) | 0,9823 | **0,9823** (benar, tidak diubah) | `docs/reports/deeplog-windows-linux-evaluation-report.md:18` |
| DeepLog Linux — top-k & recall (natural) | "182, recall 0,7292" | **328/329, F1=0,7373, recall=0,6667** (Gate FAIL) — *atau* relabel 182 sebagai titik balanced | `...report.md:224-225,250` — lihat [05§1.2](05-evaluasi-rekonsiliasi.md#12-linux--top-k-182-vs-top-k-328329-natural-evaluation) |
| DeepLog Linux — F1 terbaik (balanced) | top-k 50 | **top-k 50, F1=0,8105, Gate PASS** (benar, tidak diubah) | `...report.md:262` |
| Tool Correctness | 0,864 | **0,864** (benar; tambahkan diskusi pass-rate 50% & judge bias) | `evaluation/reports/tool_correctness_eval.md` |
| G-Eval (laporan AI Agent, frozen-replay) | 0,8675 | **0,863** (atau 0,8625) | `evaluation/reports/report_generation_geval_eval.md` (2026-06-05T02:51:15Z) |
| G-Eval full-pipeline smoke test (N=1) | (tidak dikutip) | **0,500** — sebut sebagai limitation/future work, bukan klaim utama | `evaluation/reports/report_geval_evtx_eval.md` |
| SUS | 80,33 / 83,33 / 80,31 (3 versi) | **80,31** (1285÷16) | Lampiran 2 + Bab IV.3.4 |

---

## 5. Cara Menggunakan Dokumen Ini untuk Revisi Skripsi

1. Buka [06-rekomendasi.md](06-rekomendasi.md) §6 (Roadmap), mulai dari
   **Fase 1** (quick wins editorial) — semua nilai sudah tersedia di §4 di
   atas dan [05](05-evaluasi-rekonsiliasi.md).
2. Untuk **Fase 2** (konten substansial siap-pakai), salin
   tabel/diagram/penjelasan dari dokumen 03/04 sesuai pemetaan di §2 di
   atas — sebagian besar tinggal diterjemahkan ke format Bab II/III/IV dan
   dikonversi notasi angkanya (koma, 2 digit, Item 6).
3. Untuk **Fase 3** (struktural — Item 8-11), gunakan diagram di
   [02§1](02-backend-orkestrasi-api.md#1-posisi-dalam-arsitektur),
   [03§1](03-pipeline-parsing-deeplog.md), dan
   [04§2.1](04-ai-agent-langgraph.md#21-definisi-graph-_build_graph-agentpy105-158)
   sebagai bahan diskusi cakupan dengan dosen pembimbing.
4. Saat menulis Bab IV, **selalu rujuk tabel §4 di atas** untuk angka final
   — jangan menyalin ulang dari versi draf tesis sebelumnya yang mungkin
   masih mengandung nilai 0,8675/182/0,7292/dst.
5. Rekomendasi perbaikan **sistem** (di luar revisi naskah) ada di
   [06§5](06-rekomendasi.md#5-rekomendasi-sistem-di-luar-27-item-evaluasi)
   — bersifat opsional, tidak memengaruhi kelulusan sidang, tapi relevan
   jika ingin melanjutkan proyek ke versi jurnal/publikasi.
