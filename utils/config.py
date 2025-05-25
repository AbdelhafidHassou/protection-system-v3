# utils/config.py
import os
from typing import Optional
from pydantic import BaseSettings, Field

class Settings(BaseSettings):
    """Application configuration settings"""
    
    # Application settings
    app_name: str = "Fraud Detection API"
    app_version: str = "1.0.0"
    debug: bool = Field(default=False, env="DEBUG")
    
    # Server settings
    host: str = Field(default="0.0.0.0", env="HOST")
    port: int = Field(default=8000, env="PORT")
    workers: int = Field(default=4, env="WORKERS")
    
    # MongoDB settings
    mongodb_uri: str = Field(
        default="mongodb://localhost:27017",
        env="MONGODB_URI"
    )
    mongodb_database: str = Field(
        default="fraud_detection",
        env="MONGODB_DATABASE"
    )
    
    # Redis settings
    redis_host: str = Field(default="localhost", env="REDIS_HOST")
    redis_port: int = Field(default=6379, env="REDIS_PORT")
    redis_password: Optional[str] = Field(default=None, env="REDIS_PASSWORD")
    redis_db: int = Field(default=0, env="REDIS_DB")
    
    # Security settings
    api_key_header: str = Field(default="X-API-Key", env="API_KEY_HEADER")
    cors_origins: list = Field(
        default=["*"],
        env="CORS_ORIGINS"
    )
    
    # ML Model settings
    model_dir: str = Field(default="saved_models", env="MODEL_DIR")
    model_update_interval: int = Field(
        default=3600,  # 1 hour in seconds
        env="MODEL_UPDATE_INTERVAL"
    )
    
    # Feature engineering settings
    max_historical_events: int = Field(default=1000, env="MAX_HISTORICAL_EVENTS")
    feature_cache_ttl: int = Field(default=300, env="FEATURE_CACHE_TTL")  # 5 minutes
    
    # Risk assessment settings
    risk_cache_ttl: int = Field(default=300, env="RISK_CACHE_TTL")  # 5 minutes
    risk_threshold_low: float = Field(default=0.3, env="RISK_THRESHOLD_LOW")
    risk_threshold_medium: float = Field(default=0.5, env="RISK_THRESHOLD_MEDIUM")
    risk_threshold_high: float = Field(default=0.7, env="RISK_THRESHOLD_HIGH")
    risk_threshold_critical: float = Field(default=0.85, env="RISK_THRESHOLD_CRITICAL")
    
    # Monitoring settings
    enable_metrics: bool = Field(default=True, env="ENABLE_METRICS")
    metrics_port: int = Field(default=9090, env="METRICS_PORT")
    
    # Logging settings
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    log_format: str = Field(default="json", env="LOG_FORMAT")
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False

# Create global settings instance
settings = Settings()