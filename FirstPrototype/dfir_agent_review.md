# Review & Planning: DFIR AI Agent — Audit Menyeluruh

> **Scope:** Analisis terhadap seluruh pipeline AI Agent pada `d:\FAKI\FirstPrototype\backend`  
> **Tanggal Review:** 2026-05-20  
> **Status keseluruhan:** ✅ Secara arsitektur sudah solid — beberapa gap teknis perlu ditangani sebelum produksi

---

## 1. Ringkasan Arsitektur Pipeline

```
Log Upload
   │
   ▼
[Parsing — Drain Algorithm]          ← parsing_service.py
   │
   ▼
[Anomaly Detection — DeepLog LSTM]   ← anomaly.py
   │
   ▼
[LLM Filter — Batch Sanity Gate]     ← llm_filter.py     ← PILAR 1
   │
   ▼
[AI Agent — LangGraph ReAct]         ← agent.py
   ├── IOC Extractor
   ├── Planner
   ├── Tool Selector
   ├── Tool Executor (parallel)       ← threat_intel.py   ← PILAR 2
   ├── Correlator
   ├── Post-Correlation Reflection
   ├── Timeline Builder
   └── Report Generator               ← report.py         ← PILAR 3
   │
   ▼
[Gate Observations Logger]           ← gate_observations.py
   │
   ▼
Report Output (Markdown + JSON)
```

---

## 2. Pilar 1: LLM Filtering (`llm_filter.py`)

### 2.1 Apa yang sudah berjalan dengan baik ✅

| Aspek | Detail |
|-------|--------|
| **Mode Gate** | `batch_sanity` — satu LLM call untuk seluruh batch, bukan per-window (efisien token) |
| **Prompt Design** | Prompt ringkas, langsung ke policy pilihan, output JSON terstruktur |
| **Fail-Open** | Jika gate menghapus semua anomali → dikembalikan ke set original (L72-74) |
| **Annotasi Kaya** | 9 kolom anotasi (priority, rank, confidence, requested_context, dll.) |
| **Policy Normalization** | `_normalize_policy()` menolak nilai di luar `ALLOWED_POLICIES` |
| **High-Confidence Logic** | `_is_high_confidence()` multi-kriteria: score, strict flag, unknown_ratio, indicators |

### 2.2 Gap / Kelemahan yang Ditemukan ⚠️

#### GAP-F1: Hanya mengirim 12 anomali teratas ke LLM (bisa miss)
```python
# llm_filter.py L100
for _, anomaly in ranked_df.head(12).iterrows():
```
Jika ada 50+ anomali, 38+ tidak pernah dilihat LLM sebelum gate ditentukan. Policy `prioritize_critical` mungkin mengarahkan ke window ID yang tidak mewakili keseluruhan batch.

**Rekomendasi:** Naikkan ke 20-25 sample, atau tambahkan statistik distribusi score ke prompt.

---

#### GAP-F2: Prompt meminta penjelasan dalam Bahasa Indonesia, tapi LLM (Foundation-Sec-8B) lebih kuat dalam Bahasa Inggris
```python
# llm_filter.py L212
"reason": "Brief Indonesian explanation, max 40 words"
```
Model Ollama lokal (foundation-sec-8b) umumnya trained dominan English. Output reasoning berbahasa Indonesia bisa berkualitas rendah atau inconsistent.

**Rekomendasi:** Pisahkan language instruction dari content instruction. Biarkan reasoning dalam English, terjemahkan di level UI/report saja.

---

#### GAP-F3: `confidence` tidak digunakan dalam routing keputusan
```python
# llm_filter.py L153
"confidence": self._normalize_confidence(result.get("confidence")),
```
Nilai `confidence` direkam di annotasi tapi tidak mempengaruhi `_apply_gate_policy()` atau `_is_high_confidence()`.

**Rekomendasi (P3):** Gunakan `confidence < 0.4` sebagai trigger untuk fallback ke `keep_all`.

---

#### GAP-F4: Tidak ada retry jika LLM gagal parse JSON
```python
# llm_filter.py L156-163
except Exception as exc:
    return {
        "policy": "keep_all",
        ...
    }
```
Satu kegagalan LLM langsung fallback ke `keep_all`. Tidak ada retry mekanisme.

**Rekomendasi:** Tambahkan 1 retry dengan prompt yang lebih simpel (hanya minta `policy` tanpa `priority_window_ids`).

---

#### GAP-F5: `parsed_logs_df` parameter tidak digunakan sama sekali
```python
# llm_filter.py L51
del parsed_logs_df  # retained for compatibility with current call sites
```
Konteks log penuh tidak dibawa ke LLM, padahal bisa membantu dalam deteksi pola yang ambigu.

**Rekomendasi (P3/Future):** Pertimbangkan mengirim sample raw log untuk window dengan score tertinggi ke prompt.

---

## 3. Pilar 2: Tool Calls (`threat_intel.py` + `agent.py`)

### 3.1 Apa yang sudah berjalan dengan baik ✅

| Aspek | Detail |
|-------|--------|
| **6 API Terintegrasi** | ThreatFox, MalwareBazaar, URLHaus, AlienVault OTX, GreyNoise, VirusTotal |
| **Bounded LRU Cache** | 512-entry per-session cache dengan `OrderedDict` + threading lock (L27-51) |
| **ThreadPoolExecutor** | Tool calls paralel `max_workers = min(32, len(tool_calls))` (L608) |
| **Skip Validation** | `_get_tool_call_skip_reason()` validasi IOC type vs tool compatibility sebelum API call |
| **Deduplication** | `_dedupe_tool_calls()` + `_attempted_tool_call_keys()` cegah double-query |
| **Procedural Memory** | Learning dari performa tool runtime, fallback ke static playbook |
| **Fail-Safe per Tool** | Setiap tool punya `try/except` yang mengembalikan `{"status": "error"}` |
| **Exact IOC Match** | `_filter_exact_ioc_matches()` di ThreatFox filter false positive dari hasil wildcard |

### 3.2 Gap / Kelemahan yang Ditemukan ⚠️

#### GAP-T1: `aiohttp` diimport tapi tidak dipakai (dead import)
```python
# threat_intel.py L6
import aiohttp
```
`aiohttp` tidak digunakan di mana pun. Ini dependency yang tidak perlu dan bisa menyebabkan error jika tidak terinstall.

**Rekomendasi:** Hapus import `aiohttp`.

---

#### GAP-T2: VirusTotal tidak punya rate-limit handling
```python
# threat_intel.py L486-513
response = requests.get(url, headers=headers, timeout=10)
response.raise_for_status()
```
VT free tier: 4 req/min. Jika ada 10+ IOC, request ke VT akan di-429. Tidak ada exponential backoff.

**Rekomendasi:** Tambahkan `time.sleep(15)` setelah HTTP 429, atau retry dengan backoff (sesuai `procedural_memory.py` L312: `"backoff_strategy": "exponential"`). ProceduralMemory sudah mendokumentasikan ini tapi agent belum mengimplementasikannya.

---

#### GAP-T3: MalwareBazaar menggunakan `data=` (form) bukan `json=` untuk payload
```python
# threat_intel.py L223
response = requests.post(url, data=payload, headers=headers, timeout=10)
```
URLHaus menggunakan hal yang sama. Pastikan ini konsisten dengan dokumentasi API. ThreatFox menggunakan `json=payload` yang berbeda. Tidak ada masalah fungsional sekarang, tapi perlu dikonfirmasi.

---

#### GAP-T4: Timeout seragam 10 detik untuk semua API
Semua API menggunakan `timeout=10`. VirusTotal dan OTX bisa lambat (avg 2.5-3s). Pada kondisi jaringan buruk, 10s bisa terlalu pendek.

**Rekomendasi:** Buat timeout per-provider. Contoh: GreyNoise 5s, VT 20s, OTX 15s.

---

#### GAP-T5: `future.result(timeout=1)` sangat pendek di executor
```python
# agent.py L621
result, elapsed = future.result(timeout=1)
```
Timeout hanya 1 detik untuk `future.result()`. API call bisa memakan waktu 2-3 detik. Jika future belum selesai dalam 1 detik, akan masuk ke `except` dan dianggap error, padahal API call masih berjalan di background thread.

> [!CAUTION]
> Ini adalah bug potensial. Tool call bisa diklaim "error" padahal API masih sedang merespons. Thread pool masih menjalankan task tersebut, tapi hasilnya dibuang.

**Rekomendasi:** Naikkan ke `timeout=30` atau hapus timeout di `future.result()` karena API timeout sudah dihandle di level requests.

---

#### GAP-T6: Procedural memory `domain` strategy salah point ke URLHaus
```python
# procedural_memory.py L343-350
"domain": {
    "primary": "urlhaus",  # ← URLHaus hanya support URL, bukan domain bare
    ...
}
```
Dalam `TOOL_TO_IOC_TYPES` di agent.py: `"urlhaus_lookup": {"url"}` — hanya `url`, bukan `domain`. Jika memory menggunakan strategi ini dan merekomendasikan `urlhaus` untuk `domain` IOC, maka `_dedupe_tool_calls()` akan membuang call tersebut karena type mismatch.

**Rekomendasi:** Ubah `primary` untuk domain menjadi `"threatfox"` dan sesuaikan fallback.

---

#### GAP-T7: IOC extraction tidak capture domain dari URL
```python
# agent.py L1588-1625 (_identify_ioc_type)
if normalized_value.startswith(("http://", "https://")):
    ...
    return "url"
```
Jika URL malicious ditemukan, agent memperlakukannya hanya sebagai `url`. Tapi domain dalam URL tersebut tidak di-extract sebagai IOC terpisah. Investigasi domain bisa terlewat.

**Rekomendasi (P2):** Extract domain dari URL dan tambahkan sebagai IOC terpisah tipe `domain`.

---

## 4. Pilar 3: Generation (`agent.py` — prompt correlation & report)

### 4.1 Apa yang sudah berjalan dengan baik ✅

| Aspek | Detail |
|-------|--------|
| **Anti-Hallucination Guardrail** | Prompt report (L2160-2166) melarang LLM membuat log/IOC/timestamp fiktif secara eksplisit |
| **Evidence Anchoring** | Setiap claim diwajibkan menyebut window ID, IOC value, tool result |
| **ReAct Framework** | Correlation prompt menggunakan THOUGHT 1-3 untuk structured reasoning |
| **Bahasa Indonesia** | Output report dalam BI formal, sesuai konteks TNI AL |
| **Fallback Recommendations** | `_generate_default_recommendations()` menghasilkan rekomendasi evidence-based jika LLM gagal |
| **Minimal Hallucination** | Prompt `_create_report_prompt()` inject raw anomaly, timeline, tool result sebagai grounding |

### 4.2 Gap / Kelemahan yang Ditemukan ⚠️

#### GAP-G1: Correlation prompt hanya membawa 20 tool results
```python
# agent.py L1950
for result in relevant_tool_results[:20]:
```
Jika ada 30+ tool results (banyak IOC), 10+ results tidak dibawa ke correlation. Analisis bisa tidak komprehensif.

**Rekomendasi:** Naikan ke 30 atau terapkan filter — prioritaskan malicious/suspicious, lalu sisipkan sampel clean.

---

#### GAP-G2: Report prompt membawa `correlation_preview` hanya 500 karakter
```python
# agent.py L2108-2112
correlation_preview = (
    correlation_analysis[:500] + "..."
    if len(correlation_analysis) > 500
    else correlation_analysis
)
```
Correlation analysis bisa 1000-2000 karakter. Report generator hanya melihat separuhnya. Ini bisa menyebabkan rekomendasi yang tidak mencerminkan temuan correlation sepenuhnya.

**Rekomendasi:** Naikkan limit ke 1200-1500 karakter, atau kirim versi di-compress (bullet points summary, bukan raw text).

---

#### GAP-G3: `_extract_recommendations()` fragile — depends on exact header string
```python
# agent.py L1391-1393
if (
    "RECOMMENDATIONS" in llm_response.upper()
    or "REKOMENDASI" in llm_response.upper()
):
```
Jika LLM menggunakan variasi seperti "REKOMENDASI TINDAKAN" atau "LANGKAH PERBAIKAN", extraction gagal dan fallback ke default recommendations.

**Rekomendasi:** Gunakan regex yang lebih fleksibel:
```python
re.search(r"(REKOMENDASI|RECOMMENDATIONS?|TINDAKAN)\b", llm_response, re.IGNORECASE)
```

---

#### GAP-G4: Severity extraction bisa salah klasifikasi
```python
# agent.py L1574-1584
if "CRITICAL" in response_upper or "KRITIS" in response_upper:
    return "CRITICAL"
elif "HIGH" in response_upper or "TINGGI" in response_upper:
    return "HIGH"
```
Jika laporan mengandung kalimat "Tidak ada ancaman CRITICAL yang teridentifikasi", fungsi ini tetap akan mengembalikan `CRITICAL`.

**Rekomendasi:** Cari keyword dalam konteks section severity spesifik, bukan full text. Atau gunakan regex dengan negative lookahead:
```python
re.search(r'(?i)(?<!tidak ada )(?<!bukan )CRITICAL', response)
```

---

#### GAP-G5: Report prompt meng-inject `correlation_analysis` sebelum semua evidence, bisa confuse LLM
```python
# agent.py L2180-2190
### Correlation Analysis Summary
{correlation_preview}

### DeepLog Anomaly Evidence
{anomaly_evidence}
```
LLM mungkin "satisficed" dengan correlation analysis dan tidak memproses evidence baru di bawahnya. Lebih baik evidence dulu, baru synthesis.

**Rekomendasi:** Pindahkan `Correlation Analysis Summary` ke bagian bawah, setelah semua evidence dikumpulkan.

---

## 5. Aspek Cross-Cutting

### 5.1 LLM Provider Abstraction ✅
`llm_provider.py` sudah menangani Ollama, Gemini, dan OpenRouter dengan health check yang benar. Timeout API call ke provider menggunakan urllib (10 detik). Sudah bagus.

**Minor:** `GeminiRuntimeClient` dan `OpenRouterRuntimeClient` tidak support `system_prompt` parameter. Untuk model instruksi, ini bisa mempengaruhi output quality.

### 5.2 Procedural Memory ✅
Implementasi learning via exponential moving average (α=0.05 untuk success rate, α=0.1 untuk response time) sudah tepat. Persist ke JSON setiap update. Thread-safe (file write tidak di-lock — minor concern untuk concurrent sessions).

### 5.3 Gate Observations ✅
Logging komprehensif: per-window, dengan `utility_label_hint` yang bisa digunakan untuk future supervised learning gate. Desain ini sangat forward-thinking.

---

## 6. Tabel Prioritas Rekomendasi

| ID | Prioritas | Komponen | Masalah | Rekomendasi |
|----|-----------|----------|---------|-------------|
| T5 | 🔴 P1 | Tool Calls | `future.result(timeout=1)` terlalu pendek | Naikkan ke 30s atau hapus |
| T2 | 🔴 P1 | Tool Calls | VT rate limit tidak dihandle (429) | Tambah retry + backoff |
| T6 | 🟠 P2 | Tool Calls | Memory domain strategy salah → URLHaus | Ubah primary ke `threatfox` |
| G2 | 🟠 P2 | Generation | Correlation preview 500 char terlalu pendek | Naikkan ke 1200 char |
| G3 | 🟠 P2 | Generation | Recommendation extraction fragile | Gunakan regex fleksibel |
| T1 | 🟡 P2 | Tool Calls | `aiohttp` dead import | Hapus import |
| F1 | 🟡 P2 | LLM Filter | Hanya 12 anomali sample ke LLM | Naikkan ke 20-25 |
| G4 | 🟡 P2 | Generation | Severity extraction bisa false positive | Context-aware keyword search |
| F2 | 🟡 P3 | LLM Filter | Bahasa Indonesia di LLM lokal kurang optimal | Reasoning dalam English |
| T7 | 🟡 P3 | Tool Calls | Domain tidak di-extract dari URL | Extract domain sebagai IOC terpisah |
| G5 | 🟡 P3 | Generation | Urutan prompt: correlation sebelum evidence | Tukar urutan |
| G1 | 🟡 P3 | Generation | Hanya 20 tool results ke correlation | Naikkan ke 30 |
| F4 | 🟢 P3 | LLM Filter | Tidak ada retry LLM | Tambah 1 retry |
| T4 | 🟢 P3 | Tool Calls | Timeout seragam 10s | Per-provider timeout |
| F3 | 🟢 P3 | LLM Filter | Confidence tidak dipakai routing | Gunakan sebagai threshold |

---

## 7. Rekomendasi Kode — Fix Prioritas P1

### Fix T5: `future.result(timeout=1)` → Naikkan timeout
```python
# agent.py, line 621
# BEFORE:
result, elapsed = future.result(timeout=1)

# AFTER:
result, elapsed = future.result(timeout=35)  # API calls can take up to 30s
```

### Fix T2: VirusTotal Rate Limit Handling
```python
# threat_intel.py, tambahkan di virustotal_lookup:
for attempt in range(3):
    response = requests.get(url, headers=headers, timeout=20)
    if response.status_code == 429:
        wait = 15 * (attempt + 1)
        print(f"    VT rate limited, waiting {wait}s...")
        time.sleep(wait)
        continue
    response.raise_for_status()
    break
```

### Fix T6: Procedural Memory Domain Strategy
```python
# procedural_memory.py, tool_selection_rules.domain
"domain": {
    "primary": "threatfox",           # ← was: "urlhaus" (wrong, URLHaus = URL only)
    "reason": "ThreatFox covers domains and malware family associations",
    "fallback": ["alienvault_otx", "virustotal"],
    ...
}
```

### Fix G2: Correlation Preview Length
```python
# agent.py L2108-2112
# BEFORE: correlation_analysis[:500]
# AFTER:
correlation_preview = (
    correlation_analysis[:1400] + "..."
    if len(correlation_analysis) > 1400
    else correlation_analysis
)
```

### Fix G3: Recommendation Extraction — Flexible Regex
```python
# agent.py _extract_recommendations()
import re
RECO_HEADER = re.compile(
    r"(REKOMENDASI|RECOMMENDATIONS?|TINDAKAN\s+PERBAIKAN|LANGKAH\s+MITIGASI)",
    re.IGNORECASE
)
if RECO_HEADER.search(llm_response):
    ...
```

---

## 8. Gambaran Keseluruhan Kesiapan Sistem

```
Komponen              Kesiapan    Catatan
─────────────────────────────────────────────────────
Parsing (Drain)           ✅        Stabil
Anomaly Detection         ✅        DeepLog berfungsi baik
LLM Filter               🟡        Ada 5 gap, 1 kritis (retry)
IOC Extractor            ✅        Validasi ketat, false positive rendah
Planner                  ✅        Fail-open, bounded rounds
Tool Selector            ✅        Multi-tier fallback (reflection→plan→memory→LLM→static)
Tool Executor            🔴        future.result(timeout=1) BUG, VT rate limit
Correlator               ✅        Prompt ReAct solid
Post-Correlation         ✅        Gap-keyword detection + bounded loop
Timeline Builder         ✅        Chronological, no LLM needed
Report Generator         🟡        3 gap medium (preview, extraction, order)
Gate Observations        ✅        Komprehensif, future-ML ready
Procedural Memory        🟠        1 bug domain strategy
LLM Provider Abstraction ✅        Ollama + Gemini + OpenRouter
```

---

## 9. Rekomendasi Strategis (Jangka Menengah)

1. **Streaming Output** — Saat ini semua LLM call blocking. Implementasi streaming di report generation akan meningkatkan UX signifikan (user melihat laporan terbentuk real-time).

2. **Async Tool Executor** — Ganti `ThreadPoolExecutor` dengan `asyncio + aiohttp` di threat_intel.py untuk efisiensi lebih tinggi (hapus `import aiohttp` dummy dan implementasikan).

3. **LLM Tool Use (Function Calling)** — Jika pindah ke model yang support function calling (Gemini, GPT-4), ganti `_parse_tool_selections()` text-parsing menjadi structured function call. Ini akan menghilangkan GAP-T5 dan fragile text parsing.

4. **Gate Training Loop** — `gate_observations.py` sudah sangat siap untuk supervised learning. Langkah berikutnya: buat script untuk convert JSONL ke training dataset dengan `human_label`, lalu fine-tune filter/classifier lokal.

5. **Multi-LLM Role Specialization** — Pertimbangkan model berbeda untuk filter (ringan, cepat) vs. report (kuat, besar). Provider abstraction sudah mendukung ini via `role="filter"` vs `role="agent"`.
