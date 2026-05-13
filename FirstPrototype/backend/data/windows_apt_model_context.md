# Windows-APT DeepLog Model Context

## Purpose of This File

This document explains the trained Windows-APT anomaly detection model so downstream AI components in `FirstPrototype` can use it correctly during prompting, triage, reasoning, and report generation.

This file is **not** a generic README. It is an operational context file for AI-assisted DFIR workflows.

---

## What This Model Is

The model is a **DeepLog-based anomaly detector** trained on structured Windows telemetry derived from the local dataset:

- `D:\Dataset\Windows-APT 2025 A Dataset for APT-Inspired Attack`

DeepLog is an **unsupervised next-event prediction model** based on LSTM sequence modeling.

It does **not** classify malware families, threat actors, or incident severity directly.

What it actually does:

1. takes ordered event template sequences
2. predicts the next likely event
3. flags a window as anomalous if the actual next event is **not** inside the top-k predicted events

So the model output should be interpreted as:

> **sequence-level abnormality / suspicious behavioral deviation**

not as:

> confirmed compromise, confirmed malware, or confirmed actor attribution

---

## Intended Role Inside FirstPrototype

Within the PRD architecture, this model is best used as the **first screening layer** before downstream AI reasoning.

Recommended role:

- Drain-style log parsing converts raw Windows telemetry into event templates
- DeepLog identifies **candidate anomalous windows**
- AI agent receives those candidates and performs:
  - IOC extraction
  - context correlation
  - ATT&CK-aware reasoning
  - threat intelligence enrichment
  - report drafting

This model is therefore best treated as:

## **recall-first anomaly screening**, not final judgment

---

## Dataset and Training Context

### Source dataset

- Dataset family: Windows-APT 2025
- Telemetry source: Windows 10 + Wazuh + Sysmon + adversary emulation
- Nature of data: APT-inspired simulated attack telemetry mixed with benign/operational events

### Important dataset caveat

`combined.csv` does **not** expose a direct `Scenario_ID` per event row.

Because of that, event-level labels are not strong ground truth labels in the classical supervised sense.

The Windows-APT pipeline currently uses:

- weak anomaly signal from event-level MITRE fields
- metadata-aware enrichment from:
  - `scenario_manifest.csv`
  - `validation_summary.csv`

This means the dataset representation is:

## **weakly labeled / scenario-aware**, not hard-labeled per event

---

## Model Variants That Were Trained

Three Windows-APT variants were explored:

### 1. Baseline Windows-APT detector

- best raw anomaly detector among the Windows-APT variants tested
- strongest overall synthetic recall
- best choice when the main objective is recall-first screening before LLM gating

### 2. Refined Windows-APT detector

- preprocessing cleaned up noisy templates
- improved some harder anomaly classes (`reorder`, `repeat`)
- but did not beat the baseline overall

### 3. Metadata-aware Windows-APT V2

- adds scenario and validation context into the structured dataset
- best choice for DFIR interpretation and downstream reporting context
- not the strongest raw detector by itself

---

## Which Variant To Use For What

### If the task is **pure anomaly screening**

Prefer the **baseline Windows-APT detector**.

### If the task is **DFIR reasoning / ATT&CK-aligned analysis / report generation**

Prefer the **metadata-aware Windows-APT V2 dataset representation**.

### Recommended practical split

- use **baseline detection behavior** for anomaly candidate generation
- use **V2 metadata-enriched context** for agent reasoning, report generation, and scenario-aware explanation

This is the best current compromise between:

- detector strength
- DFIR interpretability
- PRD alignment

---

## Recommended Operating Points

The key operational tuning parameter is **top-k**.

Interpretation:

- lower `topk` = stricter detector = higher recall + higher false positive rate
- higher `topk` = more permissive detector = lower false positive rate + lower recall

### Baseline Windows-APT detector

Large synthetic benchmark results:

| Top-k | Clean FP rate | Overall synthetic detection |
|---:|---:|---:|
| 10 | 22.80% | 48.25% |
| 5 | 47.70% | 66.29% |

### Metadata-aware V2 detector

Large synthetic benchmark results:

| Top-k | Clean FP rate | Overall synthetic detection |
|---:|---:|---:|
| 10 | 26.60% | 46.53% |
| 5 | 46.20% | 63.60% |

### Operational recommendation

For a pipeline where false positives can be filtered downstream by an AI agent or analyst:

## **Recommended default: top-k = 5**

Reason:

- substantially stronger anomaly recall
- more suitable for recall-first DFIR triage
- acceptable when downstream reasoning exists

### Safer fallback

If alert volume becomes too noisy:

## **Fallback: top-k = 10**

---

## What the Model Output Means

The output should be interpreted as:

- suspicious event window
- unexpected sequence transition
- candidate anomalous behavior
- candidate malicious or non-baseline operational pattern

The output should **not** be interpreted as:

- confirmed intrusion
- confirmed malicious file execution
- confirmed exfiltration
- confirmed threat actor identity
- confirmed ATT&CK scenario membership

---

## Metadata-Aware V2 Fields Available for Reasoning

The metadata-aware V2 preprocessing adds these useful fields to structured outputs:

- `CandidateScenarioIDs`
- `CandidateScenarioCount`
- `ScenarioID`
- `ScenarioName`
- `ScenarioMitreGroups`
- `ScenarioReportedOrigin`
- `ScenarioTechniques`
- `ScenarioTactics`
- `ScenarioExpectedArtifacts`
- `ValidationTotalRuns`
- `ValidationAvgSuccessRatio`
- `ValidationSecondaryReviewed`
- `ValidationChecks`
- `ScenarioConfidence`

These fields are **investigation hints**, not definitive proof.

### Best interpretation rule

- `ScenarioConfidence = high` → strong scenario hint, still not hard ground truth
- `ScenarioConfidence = medium` → useful scenario hypothesis
- `ScenarioConfidence = candidate` → ambiguous multi-scenario candidate
- `ScenarioConfidence = none` → no usable scenario hypothesis available

---

## Weak Label Schema for Downstream AI Use

For prompting and internal reasoning, the following label interpretation is recommended:

### `benign`

- no MITRE anomaly signal
- no scenario candidate
- `ScenarioConfidence = none`

### `candidate_anomaly`

- anomaly-related signal exists
- scenario assignment is ambiguous
- `ScenarioConfidence = candidate`

### `scenario_anomaly_medium`

- unique scenario assignment exists
- confidence is not high enough to treat as strong scenario evidence

### `scenario_anomaly_high`

- unique scenario assignment exists
- validation-backed confidence is strong
- best available weak-label anomaly evidence in the dataset

This schema is more honest and operationally useful than forcing hard binary labels.

---

## Prompting Guidance for the AI Agent

When this model is used inside the DFIR agent pipeline, the downstream AI should follow these rules.

### The agent **should** say things like:

- "possible sequence anomaly"
- "candidate malicious behavioral deviation"
- "candidate ATT&CK-aligned activity"
- "this alert should be investigated further"
- "this window is suspicious because it deviates from the learned normal event order"

### The agent **should not** say things like:

- "confirmed compromise"
- "confirmed APT41"
- "confirmed lateral movement"
- "the host is definitely infected"
- "this event certainly belongs to scenario S34"

unless there is additional evidence beyond DeepLog output.

---

## Best Use Pattern in FirstPrototype

The best current workflow is:

1. parse raw logs into structured event templates
2. run DeepLog and flag anomalous windows
3. pass anomalous windows to the AI agent
4. enrich with:
   - IOC extraction
   - MITRE context
   - V2 scenario metadata
   - validation-derived confidence
5. generate a cautious DFIR narrative

### Recommended downstream logic

- if `topk=5` alert is triggered and `ScenarioConfidence` is high or medium:
  - prioritize for reasoning and reporting
- if alert is triggered but `ScenarioConfidence` is candidate or none:
  - still investigate, but phrase conclusions more cautiously

---

## Known Strengths

- works well as anomaly screening on Windows-APT synthetic benchmarks
- strongest when used before downstream AI triage
- scenario-aware V2 fields add DFIR context missing from plain anomaly scores
- useful for PRD-aligned incident narrative generation

---

## Known Limitations

1. The model is still an anomaly detector, not an attribution engine.
2. Windows-APT event labels are weak / metadata-derived, not strong per-event ground truth.
3. `ScenarioID` in V2 is heuristic unless uniquely inferred from technique metadata.
4. Synthetic anomaly results are useful stress tests, but they are not identical to real-world attack recall.
5. The strongest raw detector is still the baseline Windows-APT model, not the V2 metadata-aware variant.

---

## Practical Recommendation for Prompt Engineering

If this context is used in an LLM prompt, the safest policy is:

- treat DeepLog alerts as **suspicion signals**
- use scenario metadata as **investigation hints**
- use confidence-aware language
- escalate high-confidence windows first
- avoid definitive claims unless supported by additional IOC, correlation, or threat-intel evidence

---

## Source Artifacts

This context is grounded in the following local artifacts:

- `D:\FAKI\NEWMLMODL\output\windows_apt\windows_apt_training_report.md`
- `D:\FAKI\NEWMLMODL\output\windows_apt\sliding\W20_S1_CFalse_train0.8\topk_10_vs_5_large_seed42.md`
- `D:\FAKI\NEWMLMODL\output_windows_apt_refined\windows_apt_refinement_report.md`
- `D:\FAKI\NEWMLMODL\output_windows_apt_v2\windows_apt_metadata_v2_report.md`

---

## One-Line Summary

This Windows-APT DeepLog model should be used as a **recall-first sequence anomaly screener** whose alerts are then refined by DFIR reasoning, threat-intelligence enrichment, and scenario-aware metadata interpretation.
