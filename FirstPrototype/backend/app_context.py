"""
Shared application context for paths, settings, and session storage.

This is the intentional singleton boundary for the prototype. Keeping runtime
state here makes audit/checking straightforward without introducing a full
dependency-injection container before the backend needs enterprise-style wiring.
"""

from pathlib import Path
from importlib import import_module

settings = import_module("config").settings
SessionStore = import_module("session_store").SessionStore


BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data" / "raw_logs"
OUTPUT_DIR = BASE_DIR / "output"
MODELS_DIR = BASE_DIR / "models"
SESSION_CACHE_DIR = BASE_DIR / settings.session_cache_path

DATA_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

session_store = SessionStore(
    cache_dir=SESSION_CACHE_DIR,
    raw_logs_dir=DATA_DIR,
    session_timeout_minutes=settings.session_timeout_minutes,
)
