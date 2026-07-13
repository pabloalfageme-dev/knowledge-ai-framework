from pydantic_settings import BaseSettings, SettingsConfigDict


class AuthSettings(BaseSettings):
    JWT_SECRET: str
    ACCESS_TOKEN_EXPIRE_SECONDS: int = 900
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    LOCKOUT_ATTEMPT_THRESHOLD: int = 5
    LOCKOUT_DURATION_MINUTES: int = 15

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


auth_settings = AuthSettings()