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
    ollama_model: str = "sec-foundation:8b-gpu"

    # Additional LLM Provider Defaults
    llm_forced_provider: str = "ollama"
    gemini_model: str = "gemini-2.5-flash"
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    openrouter_model: str = "google/gemini-2.5-flash"
    groq_base_url: str = "https://api.groq.com/openai/v1"
    groq_model: str = "groq/compound"
    groq_api_key: str = ""
    llm_groq_max_completion_tokens: int = 8192
    llm_groq_reasoning_effort: str = ""
    llm_settings_path: str = "data/llm_settings.json"
    llm_num_ctx: int = 16384
    llm_num_predict: int = 8192
    llm_max_output_tokens: int = 8192
    llm_openrouter_max_tokens: int = 65536
    gate_observations_path: str = "data/gate_observations.jsonl"
    procedural_memory_path: str = "data/procedural_memory.json"

    # Threat Intelligence API Keys
    abusech_api_key: Optional[str] = None
    alienvault_otx_api_key: Optional[str] = None
    # GreyNoise community API is no longer open; field kept for backward compat.
    greynoise_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None

    # Model Paths (runtime artifacts only; source code now lives in FirstPrototype)
    deeplog_model_path: str = (
        "D:\\FAKI\\NEWMLMODL\\output_lmd2023_2_3m_per_host\\lmd2023\\sliding\\W20_S20_CTrue_train0.8_per_host_chronological\\models\\DeepLog.pt"
    )
    deeplog_vocab_path: str = (
        "D:\\FAKI\\NEWMLMODL\\output_lmd2023_2_3m_per_host\\lmd2023\\sliding\\W20_S20_CTrue_train0.8_per_host_chronological\\vocabs\\DeepLog.pkl"
    )
    windows_sysmon_deeplog_model_path: str = (
        "D:\\FAKI\\NEWMLMODL\\output_lmd2023_2_3m_enriched_per_host\\lmd2023\\sliding\\W20_S20_CTrue_train0.8_per_host_chronological\\models\\DeepLog.pt"
    )
    windows_sysmon_deeplog_vocab_path: str = (
        "D:\\FAKI\\NEWMLMODL\\output_lmd2023_2_3m_enriched_per_host\\lmd2023\\sliding\\W20_S20_CTrue_train0.8_per_host_chronological\\vocabs\\DeepLog.pkl"
    )
    windows_evtx_deeplog_model_path: str = (
        "D:\\FAKI\\NEWMLMODL\\output_windows_evtx_bos_lowunk\\windows_apt\\sliding\\W30_S1_CTrue_train0.8_per_host_chronological\\models\\DeepLog.pt"
    )
    windows_evtx_deeplog_vocab_path: str = (
        "D:\\FAKI\\NEWMLMODL\\output_windows_evtx_bos_lowunk\\windows_apt\\sliding\\W30_S1_CTrue_train0.8_per_host_chronological\\vocabs\\DeepLog.pkl"
    )
    lmd_enriched_deeplog_model_path: str = (
        "D:\\FAKI\\NEWMLMODL\\output_lmd2023_2_3m_enriched_per_host\\lmd2023\\sliding\\W20_S20_CTrue_train0.8_per_host_chronological\\models\\DeepLog.pt"
    )
    lmd_enriched_deeplog_vocab_path: str = (
        "D:\\FAKI\\NEWMLMODL\\output_lmd2023_2_3m_enriched_per_host\\lmd2023\\sliding\\W20_S20_CTrue_train0.8_per_host_chronological\\vocabs\\DeepLog.pkl"
    )
    linux_log_deeplog_model_path: str = (
        "D:\\FAKI\\NEWMLMODL\\output_linux_ait_lds\\lmd2023\\sliding\\W20_S20_CTrue_train0.5_per_host_chronological\\models\\DeepLog.pt"
    )
    linux_log_deeplog_vocab_path: str = (
        "D:\\FAKI\\NEWMLMODL\\output_linux_ait_lds\\lmd2023\\sliding\\W20_S20_CTrue_train0.5_per_host_chronological\\vocabs\\DeepLog.pkl"
    )
    drain_config_path: str = "../models/drain/drain_config.ini"

    # Application Settings
    log_level: str = "INFO"
    max_upload_size_mb: int = 250
    session_cache_path: str = "data/session_store"
    auth_db_path: str = "data/dfir_app.sqlite3"
    # 0 means sessions are retained until explicitly cleared/deleted. This keeps
    # investigation history available across backend restarts, ChatGPT-style.
    session_timeout_minutes: int = 0

    # Drain Parameters
    drain_depth: int = 4
    drain_sim_threshold: float = 0.5
    drain_max_children: int = 100
    parser_template_strategy: str = "provider_eventid"
    windows_sysmon_parser_template_strategy: str = "provider_eventid"
    windows_evtx_parser_template_strategy: str = "windows_evtx_canonical"
    linux_log_parser_template_strategy: str = "linux_log"
    evtx_general_deeplog_profile: str = "windows_evtx"
    deeplog_template_enrichment: str = "none"
    windows_sysmon_deeplog_template_enrichment: str = "lmd_sysmon_v1"
    windows_evtx_deeplog_template_enrichment: str = "none"
    linux_log_deeplog_template_enrichment: str = "none"

    # DeepLog Parameters
    deeplog_window_size: int = 10
    deeplog_step_size: int = 1
    deeplog_topk: int = 3
    deeplog_embedding_dim: int = 300
    deeplog_hidden_size: int = 128
    deeplog_num_layers: int = 2
    deeplog_skip_unknown_windows: bool = False
    deeplog_max_unknown_ratio: float = 0.4
    deeplog_unknown_template_mode: str = "evaluate"
    deeplog_evtx_sparse_fallback_enabled: bool = False
    deeplog_evtx_sparse_fallback_threshold: float = 0.75
    deeplog_template_similarity_enabled: bool = False
    deeplog_template_similarity_threshold: float = 0.65
    deeplog_decision_policy: str = "topk"
    deeplog_score_threshold: float = 0.38495731353759766
    deeplog_medium_score_threshold: float = 0.70
    deeplog_target_recall: float = 0.80
    deeplog_optimization_metric: str = "f1"
    deeplog_calibration_min_precision: float = 0.65
    deeplog_calibration_max_fpr: float = 0.50
    deeplog_calibration_max_precision_recall_gap: float = 0.30
    deeplog_require_healthy_threshold: bool = True
    windows_sysmon_deeplog_window_size: int = 10
    windows_sysmon_deeplog_topk: int = 9
    windows_evtx_deeplog_window_size: int = 20
    windows_evtx_deeplog_topk: int = 5
    windows_evtx_deeplog_use_bos_context: bool = True
    windows_evtx_deeplog_bos_token: str = "<BOS>"
    windows_evtx_deeplog_bos_count: int = 20
    lmd_enriched_deeplog_window_size: int = 10
    lmd_enriched_deeplog_topk: int = 9
    lmd_enriched_deeplog_template_enrichment: str = "lmd_sysmon_v1"
    linux_log_deeplog_window_size: int = 10
    linux_log_deeplog_topk: int = 9


# Global settings instance
settings = Settings()
