"""
Configuration management for AI Agent DFIR
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=False,
        env_ignore_empty=True,
        extra="ignore",
    )

    # Ollama Configuration
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "foundation-sec-8b"

    # Additional LLM Provider Defaults
    gemini_model: str = "gemini-2.5-flash"
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    openrouter_model: str = "google/gemini-2.5-flash"
    llm_settings_path: str = "data/llm_settings.json"

    # Threat Intelligence API Keys
    abusech_api_key: Optional[str] = None
    alienvault_otx_api_key: Optional[str] = None
    greynoise_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None

    # Model Paths (default points to NEWMLMODL latest training artifacts)
    deeplog_model_path: str = (
        "../NEWMLMODL/output/eventlog/sliding/W20_S1_CFalse_train0.8/models/DeepLog.pt"
    )
    deeplog_vocab_path: str = (
        "../NEWMLMODL/output/eventlog/sliding/W20_S1_CFalse_train0.8/vocabs/DeepLog.pkl"
    )
    sysmon_deeplog_model_path: str = "../LogADEmpirical-dev/output/SysmonFastText/sliding/W10_S1_CTrue_train0.8/models/DeepLog.pt"
    sysmon_deeplog_vocab_path: str = "../LogADEmpirical-dev/output/SysmonFastText/sliding/W10_S1_CTrue_train0.8/vocabs/DeepLog.pkl"
    drain_config_path: str = "../models/drain/drain_config.ini"

    # Application Settings
    log_level: str = "INFO"
    max_upload_size_mb: int = 1000
    session_timeout_minutes: int = 60

    # Drain Parameters
    drain_depth: int = 4
    drain_sim_threshold: float = 0.5
    drain_max_children: int = 100
    parser_template_strategy: str = "drain"
    sysmon_parser_template_strategy: str = "provider_eventid"

    # DeepLog Parameters
    deeplog_window_size: int = 20
    deeplog_step_size: int = 1
    deeplog_topk: int = 10
    deeplog_embedding_dim: int = 300
    deeplog_hidden_size: int = 128
    deeplog_num_layers: int = 2
    deeplog_skip_unknown_windows: bool = True
    deeplog_max_unknown_ratio: float = 0.4
    sysmon_deeplog_window_size: int = 10


# Global settings instance
settings = Settings()
