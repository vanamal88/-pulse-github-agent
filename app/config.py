
import base64
import re
from functools import lru_cache

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    github_app_id: str = Field(...)
    github_private_key_base64: str = Field(...)

    github_repository_owner: str = "vanamal88"
    github_allowed_repos: str = (
        "-pulse-github-agent,pulse-bridge"
    )
    github_installation_id: str | None = None

    pulse_agent_api_key: str = Field(...)

    max_request_body_bytes: int = Field(
        default=1_048_576,
        ge=1024,
    )
    github_api_timeout_seconds: float = Field(
        default=30.0,
        gt=0,
        le=120,
    )
    github_api_base_url: str = "https://api.github.com"

    @field_validator("github_app_id")
    @classmethod
    def validate_app_id(cls, value: str) -> str:
        value = value.strip()

        if not value.isdigit():
            raise ValueError("GITHUB_APP_ID must contain digits only")

        return value

    @field_validator("github_repository_owner")
    @classmethod
    def validate_owner(cls, value: str) -> str:
        value = value.strip()

        if not re.fullmatch(r"[A-Za-z0-9-]{1,39}", value):
            raise ValueError("Invalid GitHub repository owner")

        return value

    @field_validator("github_allowed_repos")
    @classmethod
    def validate_allowed_repos(cls, value: str) -> str:
        repos = [
            item.strip()
            for item in value.split(",")
            if item.strip()
        ]

        if not repos:
            raise ValueError("GITHUB_ALLOWED_REPOS cannot be empty")

        for repo in repos:
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", repo):
                raise ValueError(f"Invalid repository name: {repo}")

        normalized = [repo.lower() for repo in repos]

        if len(normalized) != len(set(normalized)):
            raise ValueError("Duplicate repository names")

        return ",".join(repos)

    @field_validator("pulse_agent_api_key")
    @classmethod
    def validate_api_key(cls, value: str) -> str:
        value = value.strip()

        if len(value) < 32:
            raise ValueError(
                "PULSE_AGENT_API_KEY must contain at least 32 characters"
            )

        return value

    @field_validator("github_installation_id")
    @classmethod
    def validate_installation_id(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None or not value.strip():
            return None

        value = value.strip()

        if not value.isdigit():
            raise ValueError("Invalid GITHUB_INSTALLATION_ID")

        return value

    @field_validator("github_api_base_url")
    @classmethod
    def validate_api_url(cls, value: str) -> str:
        value = value.rstrip("/")

        if not value.startswith("https://"):
            raise ValueError("GitHub API must use HTTPS")

        return value

    @property
    def allowed_repos_list(self) -> list[str]:
        return [
            repo.strip()
            for repo in self.github_allowed_repos.split(",")
            if repo.strip()
        ]

    @property
    def allowed_repos_set(self) -> set[str]:
        return {
            repo.lower()
            for repo in self.allowed_repos_list
        }

    @property
    def private_key_pem(self) -> str:
        try:
            decoded = base64.b64decode(
                self.github_private_key_base64,
                validate=True,
            )
            pem = decoded.decode("utf-8")

            private_key = serialization.load_pem_private_key(
                pem.encode("utf-8"),
                password=None,
            )

            if not isinstance(private_key, RSAPrivateKey):
                raise ValueError("GitHub App key must be RSA")

            if private_key.key_size < 2048:
                raise ValueError("RSA key must be at least 2048 bits")

            return pem

        except Exception as exc:
            raise ValueError(
                "Invalid GITHUB_PRIVATE_KEY_BASE64"
            ) from exc


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
