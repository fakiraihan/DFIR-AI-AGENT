# Fast Gate Methodology and Execution Roadmap

## Purpose

Dokumen ini mendefinisikan rancangan **fast gating layer** untuk pipeline `FirstPrototype`.
Tujuannya bukan mengganti DeepLog atau mengganti SecFoundation, melainkan menambahkan lapisan keputusan ringan setelah DeepLog untuk menentukan anomaly window mana yang perlu diteruskan ke investigasi LLM penuh.

Target utama gate:

1. mengurangi noise sebelum masuk ke agent investigasi berat,
2. menjaga agar anomaly bernilai tinggi tidak terbuang,
3. menghemat RAM/VRAM dan latency dengan menunda pemakaian model besar,
4. menyediakan metodologi yang bisa dievaluasi secara defensible.

---

## Current Pipeline Context

Pipeline backend saat ini secara logis berjalan seperti ini:

```text
Raw log
  -> Drain parsing
  -> DeepLog anomaly detection
  -> LLMAnomalyFilter batch gate
  -> DFIRAgent investigation
  -> ReportGenerator
```

Komponen penting:

- `backend/main.py::run_investigation_pipeline(...)` sebagai orchestrator utama.
- `backend/modules/llm_filter.py::LLMAnomalyFilter.filter_anomalies(...)` sebagai gate LLM saat ini.
- `backend/modules/agent.py::DFIRAgent.investigate(...)` sebagai investigasi berat.
- `backend/modules/report.py::ReportGenerator.generate_report(...)` sebagai pembentuk laporan final.

Report generation tidak memanggil LLM secara langsung. Ia mengonsumsi `investigation_state` hasil agent.

---

## Problem With Naive Rule-Based Gating

Rule manual sederhana seperti `unknown_ratio tinggi = drop` atau `anomaly_score rendah = drop` lemah jika tidak dikalibrasi.

Kelemahan metodologisnya:

1. **Circularity**  
   Gate hanya membaca sinyal DeepLog untuk memvalidasi DeepLog sendiri.

2. **Arbitrary thresholds**  
   Ambang batas manual terlihat masuk akal, tetapi belum tentu benar secara empiris.

3. **No ground-truth anchor**  
   Tanpa label atau weak target, gate tidak bisa dibuktikan mengurangi noise tanpa membuang kasus penting.

4. **Parser/model bias**  
   Window yang terlihat noisy bisa saja akibat domain shift, parser mismatch, atau template yang belum dikenal, bukan benign event.

Karena itu, fast gate sebaiknya tidak diposisikan sebagai rule intuition layer, tetapi sebagai **calibrated routing layer**.

---

## Methodological Position

Fast gate bukan classifier malicious-vs-benign final.

Fast gate adalah **operational router** dengan tugas:

```text
DeepLog candidate anomaly -> route decision
```

Keputusan minimal:

- `drop_or_archive`  
  Window disimpan sebagai evidence mentah, tetapi tidak langsung memicu investigasi berat.

- `review_later`  
  Window memiliki sinyal lemah/sedang dan bisa masuk batch review atau sampled audit.

- `escalate_to_investigation`  
  Window cukup bernilai untuk diteruskan ke SecFoundation / DFIRAgent.

- `borderline_llm_gate`  
  Window tidak cukup jelas untuk diputuskan secara deterministic dan perlu gate LLM/SLM ringan.

Dengan framing ini, gate tidak mengklaim "benign" atau "malicious" secara definitif. Gate hanya mengoptimalkan routing operasional.

---

## Target Variable: Downstream Utility

Target gate sebaiknya berasal dari **nilai downstream**, bukan dari output DeepLog saja.

Contoh target weak label:

| Downstream result | Suggested target |
|---|---|
| Tidak ada IOC, tidak ada tool hit, summary low-quality, severity rendah | low_value |
| Ada IOC valid tetapi enrichment kosong/ambiguous | medium_value |
| Ada IOC prioritas, malicious/suspicious enrichment, timeline bermakna, severity medium/high | high_value |
| Human analyst menandai penting | high_value |
| Human analyst menandai false positive/noise | low_value |

Target ini menjawab pertanyaan:

> Apakah window ini layak menghabiskan biaya investigasi penuh?

Bukan:

> Apakah window ini pasti malicious?

---

## Candidate Features

Feature gate dapat berasal dari beberapa kelompok sinyal.

### 1. DeepLog Window Signals

- `anomaly_score`
- `strict_is_anomaly`
- `unknown_ratio`
- `actual_event`
- `predicted_event`
- rank/position of actual event if available
- top-k miss pattern
- window length / valid-token count

### 2. Parser and Source Signals

- selected profile: `general` / Windows-APT vs `sysmon`
- parser template strategy
- template count in file
- template rarity within session
- repeated template burst
- event-template entropy per window

### 3. Indicator Signals

- count of extracted IP/domain/URL/hash-like parameters
- executable/path/registry/service/process indicators
- presence of suspicious command-line fragments
- number of unique parameters in window

### 4. Contextual Aggregates

- anomaly density per file
- neighboring anomaly windows
- repeated same anomaly pattern count
- time proximity between candidate windows
- ratio of retained windows from same template family

### 5. Downstream Feedback Features

These are not available at first inference time, but useful for training/evaluation:

- whether investigation generated useful IOCs
- whether threat-intel tools returned suspicious/malicious hits
- final severity
- human analyst feedback

---

## Recommended Gate Architecture

### Stage A: DeepLog Recall-First Screening

DeepLog tetap menjadi detector awal. Untuk Windows Event branch, model Windows-APT diperlakukan sebagai recall-first sequence anomaly screener.

Output DeepLog tidak dianggap sebagai verdict, tetapi sebagai candidate anomaly windows.

### Stage B: Lightweight Calibrated Router

Router ringan mengambil feature dari candidate windows dan menghasilkan routing decision.

Model awal yang direkomendasikan:

1. logistic regression,
2. small decision tree,
3. gradient boosted tree kecil,
4. calibrated random forest jika data cukup.

Alasan memilih model klasik:

- inference sangat cepat,
- tidak perlu load LLM/SLM,
- mudah dievaluasi,
- lebih mudah dijelaskan di metodologi,
- bisa dikalibrasi dengan threshold recall-first.

### Stage C: Borderline LLM/SLM Gate

LLM/SLM kecil hanya digunakan untuk kasus borderline, bukan semua anomaly.

Contoh kondisi borderline:

- model confidence rendah,
- feature saling bertentangan,
- anomaly score sedang tetapi indikator cukup menarik,
- unknown ratio tinggi tetapi ada IOC kuat,
- source profile atau parser confidence rendah.

### Stage D: SecFoundation Investigation

Hanya window yang lolos gate atau borderline-escalated yang masuk ke `DFIRAgent`.

Di titik ini SecFoundation layak dipakai karena task-nya sudah berat:

- IOC extraction,
- threat-intel tool selection,
- enrichment,
- correlation,
- timeline,
- investigation summary.

---

## Evaluation Metrics

Accuracy biasa bukan metric utama.

Metric yang lebih sesuai:

### Safety Metrics

- **False dismiss rate**  
  Persentase high-value windows yang salah di-drop.

- **High-value recall**  
  Persentase high-value windows yang berhasil diteruskan ke investigasi.

- **Borderline recovery rate**  
  Seberapa sering borderline LLM/SLM menyelamatkan kasus bernilai tinggi.

### Efficiency Metrics

- **Investigation reduction rate**  
  Pengurangan jumlah windows yang masuk DFIRAgent.

- **LLM call reduction rate**  
  Pengurangan panggilan ke SecFoundation.

- **Latency saved**  
  Selisih waktu total investigasi sebelum dan sesudah gate.

- **Memory pressure improvement**  
  Apakah SecFoundation bisa ditunda sampai gate selesai.

### Quality Metrics

- jumlah IOC valid yang tetap ditemukan,
- severity distribution sebelum/sesudah gate,
- report usefulness,
- analyst acceptance rate.

---

## Data Collection Plan

Untuk membuat gate kuat secara metodologi, perlu log observasi dari pipeline.

Minimal yang perlu disimpan per candidate window:

```json
{
  "session_id": "...",
  "window_id": "...",
  "model_profile": "general|sysmon",
  "anomaly_score": 0.0,
  "strict_is_anomaly": true,
  "unknown_ratio": 0.0,
  "actual_event": "...",
  "predicted_event": "...",
  "key_indicators": [],
  "template_rarity": 0.0,
  "indicator_counts": {
    "ip": 0,
    "domain": 0,
    "url": 0,
    "hash": 0,
    "path": 0,
    "process": 0
  },
  "current_llm_gate_decision": "keep|drop|review",
  "investigation_result": {
    "ioc_count": 0,
    "malicious_hit_count": 0,
    "suspicious_hit_count": 0,
    "final_severity": "LOW|MEDIUM|HIGH|CRITICAL",
    "report_generated": true
  },
  "human_label": "optional"
}
```

---

## Execution Roadmap

### Phase 0 - Baseline Documentation

Goal: lock current behavior before changing it.

Tasks:

1. document current pipeline stages,
2. document current `LLMAnomalyFilter` prompt/input/output,
3. record current average runtime and anomaly counts,
4. record current memory behavior when SecFoundation is loaded.

Deliverable:

- baseline pipeline notes,
- representative sample outputs,
- runtime/memory baseline.

Success criteria:

- we can compare future gate changes against current behavior.

---

### Phase 1 - Instrumentation

Goal: collect enough data to calibrate a gate.

Tasks:

1. add structured logging for DeepLog anomaly windows,
2. persist current LLM gate decision,
3. persist downstream investigation summary metrics,
4. add optional analyst feedback field,
5. store records as JSONL or SQLite.

Deliverable:

- `gate_observations.jsonl` or equivalent dataset.

Success criteria:

- each anomaly window can be traced from DeepLog output to downstream investigation value.

---

### Phase 2 - Weak Label Definition

Goal: define operational labels.

Tasks:

1. define `low_value`, `medium_value`, `high_value`,
2. map downstream signals to these labels,
3. review a small sample manually,
4. adjust label rules to avoid overly aggressive drops.

Deliverable:

- weak labeling script/spec.

Success criteria:

- label distribution is explainable,
- high-value definition aligns with DFIR usefulness.

---

### Phase 3 - Feature Extraction

Goal: convert anomaly windows into model-ready features.

Tasks:

1. implement feature extraction from DeepLog output,
2. add parser/source features,
3. add indicator-count features,
4. add session-level aggregate features,
5. export tabular training data.

Deliverable:

- feature table for gate experiments.

Success criteria:

- all features are available before SecFoundation investigation starts.

---

### Phase 4 - Train Lightweight Router

Goal: build a calibrated non-LLM gate.

Tasks:

1. train simple baselines: logistic regression and decision tree,
2. optionally train XGBoost/LightGBM if dependencies are acceptable,
3. calibrate confidence threshold,
4. tune for high-value recall, not raw accuracy,
5. produce explainability output: top features / tree rules.

Deliverable:

- trained gate model,
- threshold config,
- evaluation report.

Success criteria:

- high-value recall remains high,
- meaningful reduction in windows sent to DFIRAgent,
- false dismiss rate is explicitly measured.

---

### Phase 5 - Borderline Policy

Goal: decide when to use LLM/SLM gate.

Tasks:

1. define confidence band for borderline cases,
2. test current LLM gate only on borderline windows,
3. optionally benchmark tiny SLM candidates for borderline only,
4. compare against no-LLM borderline handling.

Deliverable:

- borderline routing policy.

Success criteria:

- LLM calls drop significantly,
- high-value recall does not degrade materially.

---

### Phase 6 - Runtime Integration

Goal: integrate gate into current backend pipeline.

Target future flow:

```text
Drain parsing
  -> DeepLog
  -> Lightweight calibrated router
  -> optional borderline LLM/SLM gate
  -> SecFoundation DFIRAgent
  -> ReportGenerator
```

Tasks:

1. add a new gate module, e.g. `backend/modules/gate_router.py`,
2. keep `LLMAnomalyFilter` as optional fallback/borderline component,
3. update `main.py` orchestration,
4. store gate decision counts in session status,
5. ensure report includes gate summary metadata if useful.

Deliverable:

- working backend integration.

Success criteria:

- non-borderline windows do not require SLM/LLM,
- SecFoundation is only loaded after gate when investigation is needed,
- pipeline behavior is observable from session status.

---

### Phase 7 - Validation and Ablation

Goal: prove the gate helps.

Experiments:

1. no gate baseline,
2. current LLM batch gate,
3. lightweight router only,
4. lightweight router + borderline LLM,
5. lightweight router + borderline tiny SLM.

Compare:

- high-value recall,
- false dismiss rate,
- number of SecFoundation calls,
- total runtime,
- memory pressure,
- report usefulness.

Deliverable:

- validation report.

Success criteria:

- chosen design is justified empirically.

---

## Recommended Near-Term Direction

The strongest next step is not to immediately replace the current LLM gate with a tiny SLM.

Recommended direction:

```text
Instrument first -> collect downstream utility -> train lightweight router -> use LLM/SLM only for borderline cases
```

This is stronger than a pure rule-based gate and more resource-efficient than running an SLM for every anomaly.

---

## Open Questions

1. How many anomaly windows are produced per typical session after the Windows-APT model change?
2. How many of those windows produce useful downstream investigation output?
3. Is analyst feedback available, or should weak labels rely only on pipeline outputs?
4. What false dismiss rate is acceptable?
5. Should Sysmon and Windows-APT profiles share one gate or use profile-specific thresholds/models?
6. Should borderline LLM use the same SecFoundation model or a separately loaded tiny SLM?

---

## One-Line Summary

Fast gating should be treated as a calibrated operational routing problem trained against downstream investigation value, not as manual thresholding and not as a miniature final verdict model.
