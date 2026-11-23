from functools import lru_cache
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "PRIORIS API"
    environment: str = "development"
    database_url: str | None = None
    cors_origins: str = "http://localhost:5173"
    log_level: str = "INFO"
    auth_secret_key: str | None = None
    access_token_expire_minutes: int = Field(default=60, gt=0, le=1440)

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @property
    def allowed_origins(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
