from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: str = "development"
    log_level: str = "INFO"
    cors_origins: str = "http://localhost:3000"
    aws_region: str = "ap-northeast-1"
    aws_endpoint_url: str | None = None
    aws_s3_presigned_endpoint_url: str | None = None
    raw_bucket: str = "workflow-helper-raw-dev"
    processed_bucket: str = "workflow-helper-processed-dev"
    processing_queue_url: str | None = None
    raw_retention_days: int = 14
    presigned_url_ttl_seconds: int = Field(default=900, gt=0, le=900)
    max_package_size_bytes: int = Field(default=512 * 1024 * 1024, gt=0, le=512 * 1024 * 1024)
    max_metadata_size_bytes: int = Field(default=1024 * 1024, gt=0)
    upload_stream_chunk_bytes: int = Field(default=1024 * 1024, gt=0)
    upload_spool_memory_bytes: int = Field(default=8 * 1024 * 1024, gt=0)

    @property
    def allowed_origins(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
