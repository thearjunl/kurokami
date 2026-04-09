"""Centralized configuration management with environment variable support."""
import os
from pathlib import Path
from typing import Any


class Config:
    """Application configuration with environment variable support."""

    def __init__(self):
        """Initialize configuration from environment variables and defaults."""
        # Load .env file if it exists
        self._load_env_file()
        
        # Environment
        self.env = os.getenv("KUROKAMI_ENV", "development")
        self.is_production = self.env == "production"
        self.is_development = self.env == "development"
        
        # Database
        self.database_url = os.getenv("DATABASE_URL", "sqlite:///data/kurokami.db")
        
        # AI/LLM
        self.ollama_host = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")
        self.default_model = os.getenv("DEFAULT_MODEL", "qwen2.5:14b")
        self.fallback_model = os.getenv("FALLBACK_MODEL", "dolphin-mistral")
        
        # Security
        self.allow_exploits = self._parse_bool(os.getenv("ALLOW_EXPLOITS", "false"))
        self.workspace_encryption = self._parse_bool(os.getenv("WORKSPACE_ENCRYPTION", "false"))
        self.fernet_key = os.getenv("FERNET_KEY")
        self.api_key = os.getenv("API_KEY")
        self.jwt_secret = os.getenv("JWT_SECRET")
        
        # Logging
        self.log_level = os.getenv("LOG_LEVEL", "INFO")
        self.log_format = os.getenv("LOG_FORMAT", "json")
        self.log_dir = Path(os.getenv("LOG_DIR", "data/logs"))
        
        # Rate Limiting
        self.rate_limit_enabled = self._parse_bool(os.getenv("RATE_LIMIT_ENABLED", "true"))
        self.max_scans_per_hour = int(os.getenv("MAX_SCANS_PER_HOUR", "10"))
        self.max_concurrent_scans = int(os.getenv("MAX_CONCURRENT_SCANS", "3"))
        
        # Timeouts
        self.module_timeout = int(os.getenv("MODULE_TIMEOUT", "300"))
        self.scan_timeout = int(os.getenv("SCAN_TIMEOUT", "3600"))
        
        # Paths
        self.exports_dir = Path(os.getenv("EXPORTS_DIR", "data/exports"))
        self.vector_store_dir = Path(os.getenv("VECTOR_STORE_DIR", "data/vector_store"))
        
        # Monitoring
        self.enable_metrics = self._parse_bool(os.getenv("ENABLE_METRICS", "false"))
        self.metrics_port = int(os.getenv("METRICS_PORT", "9090"))
        
        # Email Notifications
        self.smtp_host = os.getenv("SMTP_HOST")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587")) if os.getenv("SMTP_PORT") else None
        self.smtp_user = os.getenv("SMTP_USER")
        self.smtp_password = os.getenv("SMTP_PASSWORD")
        self.notification_email = os.getenv("NOTIFICATION_EMAIL")
        
        # Validate critical settings in production
        if self.is_production:
            self._validate_production_config()

    def _load_env_file(self):
        """Load environment variables from .env file if it exists."""
        env_file = Path(".env")
        if not env_file.exists():
            return
        
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                
                if "=" in line:
                    key, value = line.split("=", 1)
                    key = key.strip()
                    value = value.strip()
                    
                    # Remove quotes if present
                    if value.startswith('"') and value.endswith('"'):
                        value = value[1:-1]
                    elif value.startswith("'") and value.endswith("'"):
                        value = value[1:-1]
                    
                    # Only set if not already in environment
                    if key not in os.environ:
                        os.environ[key] = value

    @staticmethod
    def _parse_bool(value: str) -> bool:
        """Parse boolean from string."""
        return value.lower() in ("true", "1", "yes", "on")

    def _validate_production_config(self):
        """Validate that critical settings are configured for production."""
        errors = []
        
        if not self.fernet_key and self.workspace_encryption:
            errors.append("FERNET_KEY must be set when WORKSPACE_ENCRYPTION is enabled")
        
        if not self.api_key and not self.jwt_secret:
            errors.append("API_KEY or JWT_SECRET should be set for production authentication")
        
        if self.database_url.startswith("sqlite:"):
            errors.append("SQLite is not recommended for production. Use PostgreSQL instead.")
        
        if self.log_level == "DEBUG":
            errors.append("LOG_LEVEL should not be DEBUG in production")
        
        if errors:
            raise ValueError(f"Production configuration errors:\n" + "\n".join(f"  - {e}" for e in errors))

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key."""
        return getattr(self, key, default)

    def to_dict(self) -> dict:
        """Convert configuration to dictionary (excluding sensitive values)."""
        sensitive_keys = {"fernet_key", "api_key", "jwt_secret", "smtp_password"}
        return {
            key: value
            for key, value in self.__dict__.items()
            if not key.startswith("_") and key not in sensitive_keys
        }


# Global configuration instance
config = Config()
