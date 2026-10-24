"""Typed runtime configuration.

Values come from environment variables prefixed ``CTI_`` or a local ``.env`` file.
Secrets have no defaults: code that needs one calls :meth:`Settings.require`, which
fails fast with every missing name instead of silently running half-configured.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class ConfigError(RuntimeError):
    """Raised when required configuration is missing."""


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CTI_", env_file=".env", extra="ignore")

    data_dir: Path = Path("data")
    s3_bucket: str | None = None
    s3_prefix: str = "snapshots"
    aws_profile: str | None = None
    abusech_auth_key: SecretStr | None = None
    contact: str | None = None

    def require(self, *names: str) -> None:
        missing = [n for n in names if getattr(self, n) in (None, "")]
        if missing:
            env = ", ".join(f"CTI_{n.upper()}" for n in missing)
            raise ConfigError(f"Missing required configuration: {env}")

    @property
    def user_agent(self) -> str:
        """Honest, identifiable User-Agent. Requires a contact address."""
        self.require("contact")
        return f"cti-pipeline/0.1 (+mailto:{self.contact})"
