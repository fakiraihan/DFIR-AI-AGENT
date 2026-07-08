# DeepLog Profile Baseline

DeepLog runtime profiles are owned by `backend/services/parsing_service.py` and settings in `backend/config.py`.

Parser template strategies are owned by `backend/modules/parsing.py` unless a reusable deterministic template helper is needed.

Dataset builders live under `backend/tools/` and emit structured CSVs compatible with `Timestamp`, `Label`, `EventId`, `EventTemplate`, `Content`, and optional `AgentName`.

Existing Windows/EVTX profiles must remain compatible when adding non-Windows profiles.
