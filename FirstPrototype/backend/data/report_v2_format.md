# Report V2 Format

Report V2 is the additive DFIR report contract emitted by `modules.report.ReportGenerator`. It keeps the original API/frontend fields intact while adding structured, standards-inspired sections for evidence provenance, methodology, limitations, impact defaults, and conservative MITRE ATT&CK mapping.

## Compatibility rule

Report V2 is appended to the existing report object. Current consumers can continue reading these legacy top-level keys:

- `metadata`
- `executive_summary`
- `technical_findings`
- `ioc_analysis`
- `attack_timeline`
- `recommendations`
- `evidence_references`

New consumers can additionally read the V2 keys listed below. JSON remains the source of truth; Markdown is rendered from these JSON fields and must not add richer claims than the JSON contains.

## V2 top-level sections

| Key | Purpose | Missing-data behavior |
| --- | --- | --- |
| `report_version` | Current additive schema version. | `"2.0"` |
| `standards_profile` | Names the standards-inspired profile and reference vocabulary. | References stay descriptive; no formal compliance claim. |
| `case_overview` | Session, log file, generation time, severity, status, analyst. | `Unknown` or `Not assessed`. |
| `objectives_scope` | Report objectives, included/excluded sources, time range, assumptions. | Empty lists or `Not available`. |
| `methodology` | Local processing approach, tools, and steps performed. | Steps record `No ... available` statuses where data is absent. |
| `evidence_provenance` | Local evidence sources and deterministic evidence items. | Empty `items`, `Not available` hashes, no invented acquisition details. |
| `detection_analysis` | Evidence-backed summary, counts, and findings. | `Not assessed` summary and empty/default counts. |
| `mitre_attack_mapping` | Conservative ATT&CK-lite techniques derived from local evidence. | `Not assessed`, `No supported mappings`, or empty `techniques`. |
| `impact_assessment` | CISA-inspired impact fields. | All impact claims default to `Not assessed` unless evidence supports them. |
| `limitations_confidence` | Missing data, unavailable enrichment, and confidence rationale. | Explicit limitations and `Low` confidence for low-evidence cases. |
| `appendices` | Structured tables copied from generated IOC, timeline, and reference data. | Empty arrays. |

## Evidence IDs

Evidence IDs are deterministic within a single report:

- `EV-LOG-###` for anomaly/log-window evidence.
- `EV-TOOL-###` for threat-intel/tool-enrichment evidence.

IDs are assigned by report order and are not random. Findings and ATT&CK mappings cite these IDs where available so analysts can trace claims back to local evidence items.

## Markdown section order

`ReportGenerator._to_markdown` renders the canonical Markdown order below from JSON only:

1. Metadata & Case Overview
2. Executive Summary
3. Objectives & Scope
4. Methodology & Tools
5. Evidence & Provenance
6. Detection & Analysis Findings
7. MITRE ATT&CK Mapping
8. Incident Timeline
9. Impact Assessment
10. Recommendations
11. Limitations & Confidence
12. Appendices

## Standards inspiration

Report V2 uses standards as vocabulary and structure guidance only:

- NIST SP 800-61 Rev. 2 incident response lifecycle: https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-61r2.pdf
- NIST SP 800-86 forensic process guidance: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-86.pdf
- CISA incident notification concepts for impact/timeline fields: https://www.cisa.gov/uscert/incident-notification-guidelines
- MITRE ATT&CK Enterprise technique taxonomy: https://attack.mitre.org/
- CASE/UCO, DFXML, and STIX vocabulary ideas are used only as lightweight naming inspiration.

## Non-goals and guardrails

- Do not add complete STIX, CASE/UCO, or DFXML export formats.
- Do not add external ATT&CK downloads or runtime lookups.
- Do not infer threat actor identity, malware family, compromise, data theft, exfiltration, recoverability, or business impact without supporting evidence.
- Do not present Report V2 as a formal forensic accreditation, court evidence statement, or custody validation workflow.
- Do not remove or rename legacy keys used by the current frontend/API.

## Safe defaults

When data is missing, use one of the approved neutral defaults: `Unknown`, `Not assessed`, `Not available`, an empty array, or an empty object. Failed enrichment tools should be represented as limitations such as unavailable/not configured enrichment, not as benign or malicious conclusions.
