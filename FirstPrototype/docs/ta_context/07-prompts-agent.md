# Prompt Engineering — Semua LLM Call dalam DFIRAgent

> Dokumen ini adalah referensi teknis lengkap untuk seluruh prompt yang digunakan
> oleh `DFIRAgent` dalam pipeline JejakAgent. Tujuannya menjadi rujukan untuk
> **Bab III (rancangan prompt)** dan **Bab IV (implementasi & evaluasi)**, serta
> menjawab pertanyaan evaluasi terkait desain input LLM.
>
> Sumber utama: `backend/modules/agent_modules/triage.py`,
> `backend/modules/agent_modules/prompts/tool_selection.py`,
> `backend/modules/agent_modules/prompts/correlation.py`,
> `backend/modules/agent_modules/prompts/report.py`,
> `backend/modules/agent.py`.

---

## 1. Gambaran Umum — Berapa LLM Call?

Pipeline `DFIRAgent` melakukan tepat **4 LLM call** sepanjang satu sesi investigasi.
Node lain (planner, assessor, reflector, timeline, IOC extractor) bersifat
**deterministik** — tidak memanggil LLM sama sekali.

| # | Node (LangGraph) | Fungsi Prompt | File Sumber | Tujuan |
|---|---|---|---|---|
| 1 | `anomaly_triage` | `_build_triage_prompt()` | `triage.py:109-138` | Klasifikasikan window anomali: suspicious / uncertain / noise |
| 2 | `tool_selector` | `create_tool_selection_prompt()` | `prompts/tool_selection.py:6-65` | Pilih threat-intel API tool yang tepat per IOC |
| 3 | `correlator` | `create_correlation_prompt()` | `prompts/correlation.py:8-159` | Korelasikan anomali dengan hasil enrichment threat intel |
| 4 | `reporter` | `create_report_prompt()` | `prompts/report.py:8-184` | Hasilkan laporan investigasi DFIR final |

**Catatan penting:** Node `tool_selector` hanya memanggil LLM jika **procedural
memory dan static fallback tidak menghasilkan rencana tool**. Jadi dalam praktik,
jumlah LLM call bisa 3 atau 4 tergantung apakah procedural memory tersedia.

---

## 2. Konfigurasi LLM

Semua 4 LLM call menggunakan instance LLM yang sama — dibangun oleh
`build_role_client(..., role="agent")` di `orchestrator_service.py` (bukan
default constructor `agent.py`). Konfigurasi runtime:

```python
Ollama(
    model="foundation-sec-8b",   # default; dapat diganti via llm_settings
    temperature=0.1,
    top_p=0.7,
    top_k=20,
    num_ctx=16384,
    num_predict=8192,
    repeat_penalty=1.15,
)
```

`temperature=0.1` dipilih rendah untuk menjaga konsistensi output terstruktur
(JSON, format baris `ioc:value -> tool`). `num_ctx=16384` memberikan ruang
untuk prompt terpanjang (report prompt) yang bisa mencapai 4000–6000 token.

---

## 3. Prompt 1 — Anomaly Triage

**Node:** `anomaly_triage`  
**File:** `backend/modules/agent_modules/triage.py:109-138`  
**Kapan dipanggil:** Entry point graph — sebelum ekstraksi IOC, dijalankan
**sekali** per sesi investigasi.

### 3.1 Preprocessing Input

Sebelum prompt dibangun, `_enrich_with_log_content()` (`triage.py:68-84`)
memperkaya tiap anomali dengan **log lines aktual** dari `parsed_logs` DataFrame:

```python
{
    "window_id": 5,
    "anomaly_score": 0.9241,
    "actual_event": "1203",       # template ID yang muncul di window
    "predicted_event": "892",     # template ID yang diprediksi LSTM
    "log_lines": [                # max 10 baris dari parsed_logs
        "Mar 15 02:31:12 sshd[1234]: Failed password for root from 192.168.1.50",
        "Mar 15 02:31:13 sshd[1234]: Failed password for root from 192.168.1.50",
    ]
}
```

Batasan: maksimum **20 window** (diambil yang skor tertinggi), maksimum **10
log lines per window** (`MAX_TRIAGE_WINDOWS=20`, `MAX_LOG_LINES_PER_WINDOW=10`).

### 3.2 Template Prompt

```
You are a DFIR analyst performing anomaly triage.

DeepLog flagged the following log windows as anomalous. Read the actual log content and classify each window.

window_id=5 score=0.9241
  actual=1203 predicted=892
  log_lines:
    Mar 15 02:31:12 sshd[1234]: Failed password for root from 192.168.1.50
    Mar 15 02:31:13 sshd[1234]: Failed password for root from 192.168.1.50

window_id=12 score=0.7810
  actual=445 predicted=210
  log_lines:
    (no log lines available)

For each window, decide:
- "suspicious": likely malicious or worth investigating
- "uncertain": ambiguous, keep for investigation to be safe
- "noise": clearly benign or a false positive, safe to drop

Return a JSON array only — no other text:
[
  {"window_id": <id>, "verdict": "suspicious" | "uncertain" | "noise", "reason": "<max 20 words>"},
  ...
]
```

### 3.3 Format Output yang Diminta

JSON array. Contoh response yang valid:

```json
[
  {"window_id": 5, "verdict": "suspicious", "reason": "Repeated SSH failure from single IP suggests brute force"},
  {"window_id": 12, "verdict": "noise", "reason": "Routine cron job, no network activity"}
]
```

### 3.4 Parsing Response (`_parse_triage_response`, `triage.py:141-164`)

1. Strip markdown code fence (` ```json ` atau ` ``` `) jika ada.
2. Jika tidak ada fence, cari `[...]` dengan regex DOTALL.
3. Parse JSON — validasi `verdict` ∈ `{"suspicious", "uncertain", "noise"}`,
   fallback ke `"uncertain"` jika tidak valid.
4. Window dengan `verdict == "noise"` **di-drop** dari `anomalies` sebelum
   diteruskan ke node `extractor`.

### 3.5 Fail-Open Behavior

Jika LLM gagal (timeout, parse error), **semua window diberi label `"uncertain"`**
dan tidak ada yang di-drop (`triage.py:49-54`). Ini mencegah false-negative
karena kegagalan LLM.

---

## 4. Prompt 2 — Tool Selection

**Node:** `tool_selector`  
**File:** `backend/modules/agent_modules/prompts/tool_selection.py:6-65`  
**Kapan dipanggil:** Setelah node `planner`, **hanya jika** procedural memory
dan static fallback tidak menghasilkan tool call (`selection.py:239`).

### 4.1 Input ke Prompt

List `iocs_extracted` dari state — dibatasi **15 entri pertama** (`iocs[:15]`):

```python
[
    {"type": "ip",     "value": "192.168.1.50"},
    {"type": "domain", "value": "evil-c2.example.com"},
    {"type": "sha256", "value": "abc123..."},
]
```

### 4.2 Template Prompt

```
# DFIR Tool Selection - Threat Intel Framework

Anda adalah Security Analyst TNI AL yang ahli dalam Digital Forensics & Incident Response.
Tugas: pilih threat intelligence tools yang paling tepat untuk setiap IOC.

## CONTEXT
Total IOC Extracted: 3

**IOC List:**
- IP: 192.168.1.50
- DOMAIN: evil-c2.example.com
- SHA256: abc123...

## AVAILABLE TOOLS

1) threatfox_lookup        — IOC abuse.ch feed, malware family, threat type
2) malwarebazaar_lookup    — file sample intel, signature, tags
3) urlhaus_lookup          — URL malware hosting status dan payload context
4) alienvault_otx_lookup   — pulse komunitas, reputasi, IOC relasi
5) greynoise_lookup        — klasifikasi scanner/noise vs malicious
6) virustotal_lookup       — agregasi multi-engine reputation

## MAPPING GUIDELINES
- IP: prioritaskan greynoise_lookup dan threatfox_lookup; ...
- Domain: prioritaskan threatfox_lookup, alienvault_otx_lookup, atau virustotal_lookup.
- URL: prioritaskan urlhaus_lookup lalu threatfox_lookup atau virustotal_lookup.
- MD5/SHA256: prioritaskan malwarebazaar_lookup lalu virustotal_lookup; ...

## OUTPUT FORMAT
ip:192.168.1.100 -> greynoise_lookup
domain:evil.com -> virustotal_lookup
sha256:abc123... -> malwarebazaar_lookup

Pilih 1-3 tools per IOC dan hanya gunakan nama tool dari daftar di atas.
```

### 4.3 Format Output yang Diminta

Plain text, satu baris per tool call:

```
ip:192.168.1.50 -> greynoise_lookup
ip:192.168.1.50 -> threatfox_lookup
domain:evil-c2.example.com -> virustotal_lookup
sha256:abc123... -> malwarebazaar_lookup
sha256:abc123... -> virustotal_lookup
```

### 4.4 Parsing Response

Diparse oleh `_parse_tool_selections()` di `agent.py` — regex split ` -> `
per baris, validasi nama tool dari `AVAILABLE_TOOLS`, lalu dibangun menjadi
`tool_calls` list di state.

### 4.5 Catatan Desain: Instruction Grounding untuk LLM Kecil

Prompt ini mengandung **few-shot instruction grounding** eksplisit berupa
mapping guideline per tipe IOC. Ini dirancang khusus untuk LLM kecil (8B
parameter) agar output konsisten dan tidak menghasilkan nama tool yang tidak
ada dalam daftar. Tanpa guideline ini, LLM kecil cenderung "mengarang" nama
tool atau menggunakan tool yang tidak kompatibel dengan tipe IOC.

---

## 5. Prompt 3 — Correlation Analysis

**Node:** `correlator`  
**File:** `backend/modules/agent_modules/prompts/correlation.py:8-159`  
**Kapan dipanggil:** Setelah node `assessor` memutuskan evidence cukup
(`sufficient_evidence`). Dipanggil **sekali** — follow-up dari `reflector`
tidak memicu LLM call korelasi lagi, hanya tool executor.

### 5.1 Preprocessing Input

Dua sumber data yang digabung ke dalam prompt:

**a) Anomaly context** — top 10 anomali, diambil `actual_event` dipotong 80 char:

```
1. Window 5: Failed password for root...  | score=0.9241
2. Window 12: su: BAD SU root to root...  | score=0.8102
```

**b) Threat intel findings** — top 30 tool results, di-sort prioritas
malicious → suspicious → clean, dengan `status == "skipped"` dan
`status == "error"` difilter keluar:

```
- virustotal_lookup: IOC `192.168.1.50` -> MALICIOUS | Malware: Mirai | Threat: botnet | Detections: 45
- greynoise_lookup: IOC `192.168.1.50` -> SUSPICIOUS | Classification: malicious | Detections: 12
- threatfox_lookup: IOC `evil.com` -> Clean/Unknown
```

### 5.2 Template Prompt (struktur ReAct)

```
# DFIR Correlation Analysis - ReAct Framework

Anda adalah Lead DFIR Analyst TNI AL yang berpengalaman dalam cyber threat hunting.
Tugas: Korelasikan temuan anomali dengan threat intelligence untuk membangun hypothesis serangan.

## INPUT DATA

### Anomaly Detection Results
Total Anomalies: 2
**Anomaly Windows:**
1. Window 5: Failed password for root...
2. Window 12: su: BAD SU root to root...

### Threat Intelligence Results
Total Queries: 3
- Malicious IOCs: 1
- Suspicious IOCs: 1
- Clean/Unknown: 1

**Detailed Findings:**
- virustotal_lookup: IOC `192.168.1.50` -> MALICIOUS | Malware: Mirai | ...
- greynoise_lookup: IOC `192.168.1.50` -> SUSPICIOUS | ...

## REACT CORRELATION PROCESS

### THOUGHT 1: Analyze Threat Landscape
**Question:** Apa pola IOC yang teridentifikasi?
**Reasoning:** [Analisis pola threat intelligence]

### THOUGHT 2: Map to Anomalies
**Question:** Bagaimana IOC malicious berkorelasi dengan anomali log?
**Reasoning:** [Hubungkan IOC dengan anomaly windows]

### THOUGHT 3: Construct Attack Hypothesis
**Question:** Apa skenario serangan yang paling mungkin?
**Reasoning:** [Bangun hypothesis berdasarkan evidence]

## OUTPUT REQUIREMENTS

### 1. THREAT SUMMARY (2-3 kalimat)
### 2. CORRELATION FINDINGS (3-5 poin)
### 3. ATTACK HYPOTHESIS (2-3 paragraf)
### 4. CONFIDENCE ASSESSMENT

Begin correlation analysis:
```

### 5.3 Format Output yang Diminta

Teks bebas terstruktur (Markdown heading `###`). Output ini disimpan ke
`state["correlation_analysis"]` sebagai string — **tidak diparsing secara
terstruktur**. Verdict (malicious/suspicious/inconclusive) ditentukan secara
deterministik oleh `build_structured_correlation()` dari `normalized_evidence`,
bukan dari teks korelasi ini.

### 5.4 Desain Pola ReAct di Prompt

Prompt ini secara eksplisit menggunakan pola **Thought → Action → Observation**:
- **THOUGHT 1:** Observasi pola threat landscape dari tool results
- **THOUGHT 2:** Reasoning — hubungkan IOC dengan anomali windows
- **THOUGHT 3:** Action — bangun hypothesis serangan

Pola ini membantu LLM kecil melakukan *chain-of-thought* terstruktur sebelum
menghasilkan kesimpulan. Tanpa chain-of-thought scaffolding, LLM kecil cenderung
langsung melompat ke kesimpulan tanpa reasoning yang koheren.

---

## 6. Prompt 4 — Report Generation

**Node:** `reporter`  
**File:** `backend/modules/agent_modules/prompts/report.py:8-184`  
**Kapan dipanggil:** Node terminal setelah `timeline`. Ini adalah prompt
**paling panjang** dan paling kompleks, mengagregasi seluruh state investigasi.

### 6.1 Input ke Prompt (agregasi seluruh state)

| Komponen | Sumber State | Batas |
|---|---|---|
| Jumlah anomali, IOC, tool queries | `len(state["anomalies"])`, dll. | Angka saja |
| Malicious IOCs summary | `tool_results` where `malware_family` ada | Top 5 |
| DeepLog anomaly evidence | `state["anomalies"]` | Top 12 window |
| Threat intel evidence | `state["tool_results"]` | Top 30 entries |
| Timeline evidence | `state["attack_timeline"]` | Top 12 events |
| Correlation analysis | `state["correlation_analysis"]` | Dipotong 1400 char |
| Reasoning chain | `state["reasoning_steps"][-5:]` | 5 langkah terakhir |

### 6.2 Template Prompt (ringkas)

```
# DFIR Executive Summary Report - ReAct Framework

Anda adalah Chief Security Officer TNI AL yang akan mempresentasikan hasil
investigasi kepada stakeholder.
Tugas: Buat laporan investigasi DFIR yang PANJANG, KAYA INFORMASI, COMPREHENSIVE,
ACTIONABLE, dan PROFESIONAL.

ATURAN OUTPUT WAJIB:
- Jawab HANYA dalam Bahasa Indonesia formal.
- Jangan membuat contoh log, IOC, timestamp, atau proses yang tidak ada di input.
- Jika evidence tidak cukup, tulis "belum cukup bukti" dan jelaskan gap datanya.
- Setiap klaim penting harus menyebut evidence: window ID, IOC, tool result, ...
- Panjang target minimal 900 kata jika data mencukupi.
- Output harus langsung berupa laporan final.

## INVESTIGATION METRICS
- Total Anomalies Detected: 2 windows
- IOCs Extracted: 3 indicators
- ...

### DeepLog Anomaly Evidence
1. Window 5: event=Failed password... | score=0.9241
...

### Threat Intelligence Evidence
1. tool=virustotal_lookup | ioc=192.168.1.50 | malicious=45 | ...
...

### Correlation Analysis Summary
[1400 char pertama dari correlation_analysis...]

## OUTPUT CONTRACT

### 1. RINGKASAN EKSEKUTIF
### 2. TINGKAT SEVERITY
### 3. INDIKATOR KOMPROMI UTAMA
### 4. MITRE ATT&CK MAPPING
### 5. ATTACK TIMELINE
### 6. DAMPAK POTENSIAL
### 7. RECOMMENDATIONS

### 1. RINGKASAN EKSEKUTIF
```

### 6.3 Format Output yang Diminta

Laporan Markdown dimulai **langsung dari `### 1. RINGKASAN EKSEKUTIF`** — bukan
JSON, bukan template. Prompt secara sengaja menutup dengan heading pertama agar
LLM melanjutkan tanpa preamble.

### 6.4 Instruksi Anti-Halusinasi

Prompt ini memiliki **explicit grounding constraint** paling ketat di antara
keempat prompt:

- *"Jangan membuat contoh log, IOC, timestamp, atau proses yang tidak ada di input"*
- *"Setiap klaim penting harus menyebut evidence: window ID, IOC, tool result..."*
- *"Jika tidak ada bukti compromise, tetap tulis 'belum cukup bukti'"*
- *"Jangan menaikkan anomaly count menjadi compromise count"*

Ini adalah mitigasi utama terhadap *hallucination* pada LLM kecil yang cenderung
mengisi gap evidence dengan informasi fiktif ketika diminta menulis laporan
panjang.

---

## 7. Node yang TIDAK Memanggil LLM

Untuk kelengkapan, berikut node deterministik yang **tidak** menggunakan LLM:

| Node | Alasan tidak pakai LLM |
|---|---|
| `extractor` | Regex + heuristik tipe IOC dari `anomalies` + `parsed_logs` |
| `planner` | Procedural memory lookup → static fallback (LLM hanya jika keduanya gagal, via `tool_selector`) |
| `assessor` | Rule-based: hitung `normalized_evidence` vs round limit |
| `reflector` | Deterministik: baca `structured_correlation["evidence_gaps"]` + `follow_up_requests` |
| `inconclusive` | Hanya mengisi field state dengan pesan fallback |
| `timeline` | Regex + sorting dari `anomalies` + `tool_results` |

---

## 8. Alur Data Prompt Secara End-to-End

```
DeepLog output
(anomalies_df + parsed_logs)
        │
        ▼
[PROMPT 1 — TRIAGE]
Input : window_id, score, actual/predicted event, raw log lines (max 10/window)
Output: JSON [{window_id, verdict, reason}]
Effect: drop "noise" windows → anomalies yang tersisa diteruskan
        │
        ▼
extractor  (regex, no LLM)
        │
        ▼
planner    (procedural memory / static fallback, no LLM)
        │
        ▼
[PROMPT 2 — TOOL SELECTION]  ← hanya jika memory/fallback kosong
Input : list IOC {type, value} (max 15)
Output: "ioc:value -> tool_name" per baris
Effect: mengisi tool_calls untuk executor
        │
        ▼
tool_executor → assessor → (loop jika perlu, no LLM)
        │
        ▼
[PROMPT 3 — CORRELATION]
Input : anomaly summary (max 10) + tool_results sorted (max 30)
Output: teks analisis ReAct terstruktur (Markdown)
Effect: mengisi correlation_analysis + structured_correlation
        │
        ▼
reflector (deterministik, no LLM)
        │
        ▼
timeline  (deterministik, no LLM)
        │
        ▼
[PROMPT 4 — REPORT]
Input : seluruh state (metrics, anomalies, tool_results, timeline,
        correlation preview, reasoning chain)
Output: laporan DFIR Markdown, min 900 kata, bahasa Indonesia
Effect: mengisi investigation_summary → diteruskan ke ReportGenerator
```

---

## 9. Mapping ke Sub-Bab Skripsi

| Sub-bab | Konten dari dokumen ini |
|---|---|
| II — Prompt Engineering / LLM | §2 (konfigurasi LLM), §3.5/§4.5 (teknik few-shot & grounding), §5.4 (ReAct pattern di prompt) |
| III — Rancangan Sistem | §1 (tabel 4 LLM call), §8 (diagram alur data prompt end-to-end) |
| III — Triage Semantik | §3 (Prompt 1 — input, template, output, fail-open) |
| III — Tool Selection | §4 (Prompt 2 — instruction grounding untuk LLM kecil) |
| III — Correlation | §5 (Prompt 3 — ReAct scaffolding, batasan input) |
| III — Report Generation | §6 (Prompt 4 — anti-halusinasi, output contract) |
| IV — Evaluasi Kualitas Laporan | §6.4 (constraint anti-halusinasi sebagai desain mitigasi eksplisit) |
