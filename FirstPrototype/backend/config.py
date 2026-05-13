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
    gate_observations_path: str = "data/gate_observations.jsonl"
    procedural_memory_path: str = "data/procedural_memory.json"

    # Threat Intelligence API Keys
    abusech_api_key: Optional[str] = None
    alienvault_otx_api_key: Optional[str] = None
    greynoise_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None

    # Model Paths (runtime artifacts only; source code now lives in FirstPrototype)
    deeplog_model_path: str = (
        "D:\\FAKI\\NEWMLMODL\\output_lmd2023_2_3m_per_host\\lmd2023\\sliding\\W20_S20_CTrue_train0.8_per_host_chronological\\models\\DeepLog.pt"
    )
    deeplog_vocab_path: str = (
        "D:\\FAKI\\NEWMLMODL\\output_lmd2023_2_3m_per_host\\lmd2023\\sliding\\W20_S20_CTrue_train0.8_per_host_chronological\\vocabs\\DeepLog.pkl"
    )
    sysmon_deeplog_model_path: str = (
        "D:\\FAKI\\NEWMLMODL\\output_lmd2023_2_3m_per_host\\lmd2023\\sliding\\W20_S20_CTrue_train0.8_per_host_chronological\\models\\DeepLog.pt"
    )
    sysmon_deeplog_vocab_path: str = (
        "D:\\FAKI\\NEWMLMODL\\output_lmd2023_2_3m_per_host\\lmd2023\\sliding\\W20_S20_CTrue_train0.8_per_host_chronological\\vocabs\\DeepLog.pkl"
    )
    drain_config_path: str = "../models/drain/drain_config.ini"

    # Application Settings
    log_level: str = "INFO"
    max_upload_size_mb: int = 250
    # 0 means sessions are retained until explicitly cleared/deleted. This keeps
    # investigation history available across backend restarts, ChatGPT-style.
    session_timeout_minutes: int = 0

    # Drain Parameters
    drain_depth: int = 4
    drain_sim_threshold: float = 0.5
    drain_max_children: int = 100
    parser_template_strategy: str = "drain"
    sysmon_parser_template_strategy: str = "provider_eventid"

    # DeepLog Parameters
    deeplog_window_size: int = 10
    deeplog_step_size: int = 1
    deeplog_topk: int = 3
    deeplog_embedding_dim: int = 300
    deeplog_hidden_size: int = 128
    deeplog_num_layers: int = 2
    deeplog_skip_unknown_windows: bool = True
    deeplog_max_unknown_ratio: float = 0.4
    sysmon_deeplog_window_size: int = 10


# Global settings instance
settings = Settings()
