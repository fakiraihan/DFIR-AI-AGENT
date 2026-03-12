"""
Configuration management for AI Agent DFIR
"""
from pydantic_settings import BaseSettings
from pathlib import Path
from typing import Optional


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""
    
    # Ollama Configuration
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "foundation-sec-8b"
    
    # Threat Intelligence API Keys
    # abuse.ch services (ThreatFox, MalwareBazaar, URLhaus) use same key
    abusech_api_key: Optional[str] = None
    alienvault_otx_api_key: Optional[str] = None
    greynoise_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    
    # Model Paths
    deeplog_model_path: str = "../models/deeplog/DeepLog.pt"
    deeplog_vocab_path: str = "../models/deeplog/DeepLog.pkl"
    drain_config_path: str = "../models/drain/drain_config.ini"
    
    # RSA Keys
    rsa_private_key_path: str = "../keys/private.pem"
    rsa_public_key_path: str = "../keys/public.pem"
    
    # Application Settings
    log_level: str = "INFO"
    max_upload_size_mb: int = 1000
    session_timeout_minutes: int = 60
    
    # Drain Parameters
    drain_depth: int = 4
    drain_sim_threshold: float = 0.5
    drain_max_children: int = 100
    
    # DeepLog Parameters
    deeplog_window_size: int = 10
    deeplog_step_size: int = 5
    deeplog_topk: int = 9
    deeplog_embedding_dim: int = 128
    deeplog_hidden_size: int = 128
    deeplog_num_layers: int = 2
    
    class Config:
        env_file = ".env"
        case_sensitive = False


# Global settings instance
settings = Settings()
