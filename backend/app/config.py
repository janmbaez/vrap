from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', extra='ignore')
    database_url: str = 'postgresql+psycopg://vrap:vrap@db/vrap'
    app_origin: str = 'http://localhost:5173'
    cookie_secure: bool = True
    tenable_access_key: str = ''
    tenable_secret_key: str = ''
    tenable_base_url: str = 'https://cloud.tenable.com'
    tenable_allowed_hosts: str = 'cloud.tenable.com'
    credential_encryption_key: str = ''
    session_hours: int = 8

@lru_cache
def settings():
    return Settings()
