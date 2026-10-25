"""Configuración vía variables de entorno con prefijo SD_."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SD_")

    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    # Fuente 1 (tests/desarrollo local): clave directa por entorno.
    nvd_api_key: str | None = None
    # Fuente 2 (producción): ARN o nombre del secreto en AWS Secrets Manager.
    nvd_secret_id: str | None = None
    aws_region: str = "us-east-1"
    cache_ttl_seconds: int = 300
    cache_max_entries: int = 512
    http_timeout_seconds: float = 15.0
    max_results: int = 50


@lru_cache
def get_settings() -> Settings:
    return Settings()
