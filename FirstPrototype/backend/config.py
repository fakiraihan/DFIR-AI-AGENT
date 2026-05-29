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
    llm_num_ctx: int = 16384
    llm_num_predict: int = 8192
    llm_max_output_tokens: int = 8192
    llm_openrouter_max_tokens: int = 65536
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
        "D:\\FAKI\\NEWMLMODL\\output_lmd2023_2_3m_enriched_per_host\\lmd2023\\sliding\\W20_S20_CTrue_train0.8_per_host_chronological\\models\\DeepLog.pt"
    )
    sysmon_deeplog_vocab_path: str = (
        "D:\\FAKI\\NEWMLMODL\\output_lmd2023_2_3m_enriched_per_host\\lmd2023\\sliding\\W20_S20_CTrue_train0.8_per_host_chronological\\vocabs\\DeepLog.pkl"
    )
    windows_loghub_deeplog_model_path: str = (
        "D:\\FAKI\\NEWMLMODL\\output_windows_loghub_stratified_1gb\\windows_loghub\\sliding\\W20_S5_CTrue_train0.7\\models\\DeepLog.pt"
    )
    windows_loghub_deeplog_vocab_path: str = (
        "D:\\FAKI\\NEWMLMODL\\output_windows_loghub_stratified_1gb\\windows_loghub\\sliding\\W20_S5_CTrue_train0.7\\vocabs\\DeepLog.pkl"
    )
    windows_apt_deeplog_model_path: str = (
        "D:\\FAKI\\NEWMLMODL\\output_windows_evtx_bos_lowunk\\windows_apt\\sliding\\W30_S1_CTrue_train0.8_per_host_chronological\\models\\DeepLog.pt"
    )
    windows_apt_deeplog_vocab_path: str = (
        "D:\\FAKI\\NEWMLMODL\\output_windows_evtx_bos_lowunk\\windows_apt\\sliding\\W30_S1_CTrue_train0.8_per_host_chronological\\vocabs\\DeepLog.pkl"
    )
    lmd_enriched_deeplog_model_path: str = (
        "D:\\FAKI\\NEWMLMODL\\output_lmd2023_2_3m_enriched_per_host\\lmd2023\\sliding\\W20_S20_CTrue_train0.8_per_host_chronological\\models\\DeepLog.pt"
    )
    lmd_enriched_deeplog_vocab_path: str = (
        "D:\\FAKI\\NEWMLMODL\\output_lmd2023_2_3m_enriched_per_host\\lmd2023\\sliding\\W20_S20_CTrue_train0.8_per_host_chronological\\vocabs\\DeepLog.pkl"
    )
    linux_ait_lds_deeplog_model_path: str = (
        "D:\\FAKI\\NEWMLMODL\\output_linux_ait_lds\\lmd2023\\sliding\\W20_S20_CTrue_train0.5_per_host_chronological\\models\\DeepLog.pt"
    )
    linux_ait_lds_deeplog_vocab_path: str = (
        "D:\\FAKI\\NEWMLMODL\\output_linux_ait_lds\\lmd2023\\sliding\\W20_S20_CTrue_train0.5_per_host_chronological\\vocabs\\DeepLog.pkl"
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
    parser_template_strategy: str = "provider_eventid"
    sysmon_parser_template_strategy: str = "provider_eventid"
    windows_loghub_parser_template_strategy: str = "windows_loghub_cbs"
    windows_apt_parser_template_strategy: str = "windows_evtx_canonical"
    linux_ait_lds_parser_template_strategy: str = "linux_ait_lds"
    evtx_general_deeplog_profile: str = "windows_apt"
    deeplog_template_enrichment: str = "none"
    sysmon_deeplog_template_enrichment: str = "lmd_sysmon_v1"
    windows_loghub_deeplog_template_enrichment: str = "none"
    windows_apt_deeplog_template_enrichment: str = "none"
    linux_ait_lds_deeplog_template_enrichment: str = "none"

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
    deeplog_llm_filter_mode: str = "annotate"
    deeplog_calibration_min_precision: float = 0.65
    deeplog_calibration_max_fpr: float = 0.50
    deeplog_calibration_max_precision_recall_gap: float = 0.30
    deeplog_require_healthy_threshold: bool = True
    sysmon_deeplog_window_size: int = 10
    sysmon_deeplog_topk: int = 9
    windows_loghub_deeplog_window_size: int = 20
    windows_apt_deeplog_window_size: int = 20
    windows_apt_deeplog_topk: int = 5
    windows_apt_deeplog_use_bos_context: bool = True
    windows_apt_deeplog_bos_token: str = "<BOS>"
    windows_apt_deeplog_bos_count: int = 20
    lmd_enriched_deeplog_window_size: int = 10
    lmd_enriched_deeplog_topk: int = 9
    lmd_enriched_deeplog_template_enrichment: str = "lmd_sysmon_v1"
    linux_ait_lds_deeplog_window_size: int = 10
    linux_ait_lds_deeplog_topk: int = 9


# Global settings instance
settings = Settings()
