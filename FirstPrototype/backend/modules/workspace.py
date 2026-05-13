from __future__ import annotations

import os
from pathlib import Path


WORKSPACE_ENV_VARS = (
    "DFIR_TRAINING_WORKSPACE",
    "TRAINING_WORKSPACE",
)
KNOWN_WORKSPACE_NAMES = (
    "NEWMLMODL",
    "LogADEmpirical-dev",
)


def _matches_markers(candidate: Path, markers: tuple[str, ...]) -> bool:
    return candidate.exists() and all((candidate / marker).exists() for marker in markers)


def resolve_training_workspace(current_file: str | Path, *markers: str) -> Path:
    required_markers = tuple(markers)

    for env_name in WORKSPACE_ENV_VARS:
        raw_value = os.getenv(env_name)
        if not raw_value:
            continue
        candidate = Path(raw_value).expanduser().resolve()
        if _matches_markers(candidate, required_markers):
            return candidate

    current_path = Path(current_file).resolve()
    search_roots = [current_path.parent, *current_path.parents]

    for root in search_roots:
        candidates = [root, *(root / name for name in KNOWN_WORKSPACE_NAMES)]
        for candidate in candidates:
            if _matches_markers(candidate, required_markers):
                return candidate

    raise FileNotFoundError(
        f"Unable to find training workspace for markers: {', '.join(required_markers)}"
    )
