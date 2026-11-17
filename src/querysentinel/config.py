from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class TargetConfig(BaseModel):
    id: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,62}$")
    engine: str
    dsn_env: str
    workload_dsn_env: str | None = None
    synthetic_workload_enabled: bool = False
    enabled: bool = True
    schedule: str | None = None
    error_log_dir: Path | None = None
    error_log_database: str | None = None

    @model_validator(mode="after")
    def check_error_log_source(self) -> TargetConfig:
        if (self.error_log_dir is None) != (self.error_log_database is None):
            raise ValueError("set both error_log_dir and error_log_database to collect errors")
        return self

    @field_validator("engine")
    @classmethod
    def postgresql_only(cls, value: str) -> str:
        if value != "postgresql":
            raise ValueError("only the postgresql engine is implemented")
        return value

    def dsn(self) -> str:
        value = os.getenv(self.dsn_env)
        if not value:
            raise ValueError(f"environment variable {self.dsn_env} is not configured")
        return value

    def workload_dsn(self) -> str:
        if not self.synthetic_workload_enabled or not self.workload_dsn_env:
            raise ValueError(f"synthetic workload is disabled for target {self.id}")
        value = os.getenv(self.workload_dsn_env)
        if not value:
            raise ValueError(f"environment variable {self.workload_dsn_env} is not configured")
        return value


class ScheduleConfig(BaseModel):
    cron: str = "*/15 * * * *"


class DetectionConfig(BaseModel):
    min_calls_per_interval: int = Field(default=10, ge=1)
    meaningful_latency_ms: float = Field(default=20.0, ge=0)
    latency_regression_factor: float = Field(default=3.0, gt=1)
    workload_regression_factor: float = Field(default=3.0, gt=1)
    expensive_query_mean_ms: float = Field(default=250.0, gt=0)
    temp_blocks_threshold: int = Field(default=100, ge=1)
    block_read_ratio_threshold: float = Field(default=0.35, gt=0, le=1)
    max_llm_investigations_per_scan: int = Field(default=3, ge=0, le=20)
    max_age_minutes: int = Field(default=1440, ge=1)


class NotificationConfig(BaseModel):
    console: bool = True
    webhook: bool = False


class RetentionConfig(BaseModel):
    interval_days: int = Field(default=30, ge=1)
    checkpoint_days: int = Field(default=7, ge=1)


class ProjectConfig(BaseModel):
    targets: list[TargetConfig]
    schedule: ScheduleConfig = ScheduleConfig()
    detection: DetectionConfig = DetectionConfig()
    notifications: NotificationConfig = NotificationConfig()
    retention: RetentionConfig = RetentionConfig()

    @model_validator(mode="after")
    def unique_target_ids(self) -> ProjectConfig:
        ids = [target.id for target in self.targets]
        if len(ids) != len(set(ids)):
            raise ValueError("target IDs must be unique")
        return self

    def target(self, target_id: str) -> TargetConfig | None:
        return next((target for target in self.targets if target.id == target_id), None)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    sentinel_database_url: str = "postgresql+psycopg://sentinel@localhost/sentinel"
    api_token: str = ""
    mcp_allowed_hosts: list[str] = [
        "127.0.0.1",
        "127.0.0.1:*",
        "localhost",
        "localhost:*",
        "[::1]",
        "[::1]:*",
    ]
    mcp_allowed_origins: list[str] = [
        "http://127.0.0.1",
        "http://127.0.0.1:*",
        "http://localhost",
        "http://localhost:*",
        "http://[::1]",
        "http://[::1]:*",
    ]
    ui_admin_password: str = ""
    ui_api_base_url: str = "http://127.0.0.1:8000"
    ai_model: str = "openai:gpt-5-mini"
    openai_api_key: str = ""
    anthropic_api_key: str = ""
    google_api_key: str = ""
    webhook_url: str = ""
    log_level: str = "INFO"
    config_path: Path = Path("config.yaml")
    statement_timeout_ms: int = 10_000
    lock_timeout_ms: int = 2_000
    llm_timeout_seconds: int = 60
    llm_max_tool_calls: int = 8
    llm_max_tokens: int = 8_000
    llm_max_output_tokens: int = 2_000
    llm_max_requests: int = 10
    job_lease_seconds: int = 120
    job_max_attempts: int = 3
    synthetic_workload_cache_dir: Path = Path(".cache/querysentinel")

    def model_credentials_configured(self) -> bool:
        provider = self.ai_model.partition(":")[0]
        if provider == "openai":
            return bool(self.openai_api_key)
        if provider == "anthropic":
            return bool(self.anthropic_api_key)
        if provider == "google":
            return bool(self.google_api_key)
        return provider == "test"


@lru_cache
def get_settings() -> Settings:
    return Settings()


@lru_cache
def load_project_config(path: str | Path | None = None) -> ProjectConfig:
    config_path = Path(path) if path else get_settings().config_path
    with config_path.open(encoding="utf-8") as handle:
        raw = yaml.safe_load(handle)
    return ProjectConfig.model_validate(raw)
