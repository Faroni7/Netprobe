"""
BlackBox Recon Configuration
Phase 3: Reconnaissance Engine - Configuration and detection evasion settings
"""
from pydantic_settings import BaseSettings
from typing import Optional
import os


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Application
    APP_NAME: str = "BlackBox Recon"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = False
    
    # Database - Phase 7: Event Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./blackbox.db"
    
    # API Settings
    API_PREFIX: str = "/api"
    CORS_ORIGINS: list = ["http://localhost:3000", "http://localhost:5173"]
    
    # Reconnaissance Engine - Phase 3
    # Detection Evasion Settings
    
    # User-Agent rotation
    DEFAULT_USER_AGENT: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    USER_AGENTS: list = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "BlackBoxRecon/1.0 (Security Scanner)",
    ]
    
    # Rate Limiting - Security consideration
    REQUEST_DELAY: float = 0.5  # seconds between requests
    MAX_CONCURRENT: int = 5  # maximum parallel requests
    TIMEOUT: int = 10  # request timeout in seconds
    
    # Proxy Support - Phase 3
    PROXY_URL: Optional[str] = None  # e.g., "http://localhost:8080"
    
    # Scan Limits
    MAX_ENDPOINTS_PER_SCAN: int = 500
    MAX_DEPTH: int = 5
    SCAN_TIMEOUT: int = 3600  # 1 hour max scan time
    
    # Random delays for detection evasion
    RANDOM_DELAY_MIN: float = 0.1
    RANDOM_DELAY_MAX: float = 0.5
    
    class Config:
        env_file = ".env"
        case_sensitive = True


# Global settings instance
settings = Settings()


def get_settings() -> Settings:
    """Get the current application settings."""
    return settings
