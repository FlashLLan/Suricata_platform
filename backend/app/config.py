from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    secret_key: str = "dev-secret-key"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 10080  # 7 days
    database_url: str = "sqlite:///./suricata_platform.db"

    class Config:
        env_file = ".env"


settings = Settings()
