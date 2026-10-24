import pytest

from cti.config import ConfigError, Settings


def test_require_lists_every_missing_name(monkeypatch):
    monkeypatch.delenv("CTI_S3_BUCKET", raising=False)
    monkeypatch.delenv("CTI_ABUSECH_AUTH_KEY", raising=False)
    settings = Settings(_env_file=None)
    with pytest.raises(ConfigError) as exc:
        settings.require("s3_bucket", "abusech_auth_key")
    assert "CTI_S3_BUCKET" in str(exc.value)
    assert "CTI_ABUSECH_AUTH_KEY" in str(exc.value)


def test_reads_env_and_hides_secrets(monkeypatch):
    monkeypatch.setenv("CTI_ABUSECH_AUTH_KEY", "sekrit")
    monkeypatch.setenv("CTI_S3_BUCKET", "bucket")
    settings = Settings(_env_file=None)
    settings.require("s3_bucket", "abusech_auth_key")
    assert "sekrit" not in repr(settings)
    assert settings.abusech_auth_key.get_secret_value() == "sekrit"


def test_user_agent_requires_contact(monkeypatch):
    monkeypatch.delenv("CTI_CONTACT", raising=False)
    with pytest.raises(ConfigError):
        _ = Settings(_env_file=None).user_agent
    monkeypatch.setenv("CTI_CONTACT", "me@example.com")
    assert "mailto:me@example.com" in Settings(_env_file=None).user_agent
