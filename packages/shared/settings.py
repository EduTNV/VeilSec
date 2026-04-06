from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", case_sensitive=False
    )

    environment: Literal["development", "staging", "production"] = "development"
    version: str = "0.1.0"
    lgpd_consent_version: str = "1.0"

    database_url: str = "postgresql+asyncpg://veilsec:veilsec@localhost:5432/veilsec"
    redis_url: str = "redis://localhost:6379/0"

    anthropic_api_key: str = Field(default="")
    anthropic_model: str = "claude-sonnet-4-5"
    openai_api_key: str = Field(default="")
    openai_fallback_model: str = "gpt-4o-mini"

    ownership_hmac_secret: str = Field(default="dev-secret-change-in-production-32chars!!")

    aws_s3_bucket: str = "veilsec-local"
    aws_endpoint_url: str | None = None
    aws_region: str = "us-east-1"

    ai_classifier_mode: Literal["mock", "local"] = "mock"
    ai_classifier_model_path: str = "./models/deberta-injection-detector"
    ai_classifier_threshold: float = 0.75

    sast_max_input_bytes: int = 500_000
    dast_ownership_ttl_hours: int = 24
    scan_retention_hours: int = 24

    dast_bucket_capacity: int = 10
    dast_refill_rate: float = 1.0
    dast_min_delay_ms: int = 800
    dast_degradation_multiplier: float = 2.0
    dast_max_consecutive_errors: int = 3

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def is_development(self) -> bool:
        return self.environment == "development"


@lru_cache
def get_settings() -> Settings:
    return Settings()
