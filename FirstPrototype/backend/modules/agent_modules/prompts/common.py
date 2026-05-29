"""Shared prompt-builder type aliases."""

from typing import Any, Callable, Dict


ToolResultPredicate = Callable[[Dict[str, Any]], bool]
PositiveCount = Callable[[Any], int]
AnomalySummarizer = Callable[[Dict[str, Any]], str]
