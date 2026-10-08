from pydantic_settings import (
    BaseSettings,
    SettingsConfigDict,
    EnvSettingsSource,
    DotEnvSettingsSource,
)
from pydantic import field_validator, Field, AliasChoices
from typing import Optional


class CleanEnvSource(EnvSettingsSource):
    """
    Reads OS and Docker environment variables.
    Strips quotes and whitespace. If an environment variable is set to empty/whitespace,
    it returns None so that OS environment overrides lower-precedence .env fallback.
    """
    def __call__(self):
        d = super().__call__()
        res = {}
        for k, v in d.items():
            if isinstance(v, str):
                cleaned = v.strip().strip("'").strip('"').strip()
                res[k] = cleaned if cleaned else None
            else:
                res[k] = v
        return res


class CleanDotEnvSource(DotEnvSettingsSource):
    """
    Reads local development .env fallback file.
    Strips quotes and whitespace. Empty values become None.
    """
    def __call__(self):
        d = super().__call__()
        res = {}
        for k, v in d.items():
            if isinstance(v, str):
                cleaned = v.strip().strip("'").strip('"').strip()
                res[k] = cleaned if cleaned else None
            else:
                res[k] = v
        return res


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
        env_file_encoding="utf-8",
    )

    PROJECT_NAME: str = "ThreatLens"
    ENVIRONMENT: str = "development"
    LOG_LEVEL: str = "INFO"
    PROVIDER_MODE: str = "live"  # "live" (default) or "mock" (tests only)
    
    # Database URL: SQLite for lightweight local / tests, Postgres for Docker / prod
    DATABASE_URL: str = "sqlite+aiosqlite:///./threatlens.db"
    
    # Pivot Engine Safety Guardrails
    MAX_PIVOT_DEPTH: int = 2
    MAX_PIVOT_NODES: int = 25
    MAX_PROVIDER_REQUESTS: int = 40
    CACHE_TTL: int = 3600
    
    # Provider API Keys
    VT_API_KEY: Optional[str] = None
    OTX_API_KEY: Optional[str] = None
    MALWAREBAZAAR_API_KEY: Optional[str] = None
    HYBRID_ANALYSIS_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    THREATFOX_API_KEY: Optional[str] = None
    URLHAUS_API_KEY: Optional[str] = None
    URLSCAN_API_KEY: Optional[str] = None
    CENSYS_API_KEY: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices(
            "CENSYS_API_KEY",
            "CENSYS_PAT",
            "CENSYS_TOKEN",
        ),
    )
    CENSYS_API_SECRET: Optional[str] = None
    CENSYS_API_ID: Optional[str] = None
    GREYNOISE_API_KEY: Optional[str] = None
    SHODAN_API_KEY: Optional[str] = None
    PULSEDIVE_API_KEY: Optional[str] = None
    CRIMINALIP_API_KEY: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices(
            "CRIMINALIP_API_KEY",
            "CRIMINAL_IP_API_KEY",
            "CRIMINAL_IP_KEY",
            "CIP_API_KEY",
        ),
    )
    PASSIVEDNS_API_KEY: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices(
            "PASSIVEDNS_API_KEY",
            "MNEMONIC_API_KEY",
            "MNEMONIC_PASSIVEDNS_API_KEY",
        ),
    )
    WEBCHECK_URL: Optional[str] = Field(
        default="http://web-check:3000",
        validation_alias=AliasChoices(
            "WEBCHECK_URL",
            "WEB_CHECK_URL",
            "WEBCHECK_API_URL",
        ),
    )

    @field_validator(
        "VT_API_KEY",
        "OTX_API_KEY",
        "MALWAREBAZAAR_API_KEY",
        "HYBRID_ANALYSIS_API_KEY",
        "ABUSEIPDB_API_KEY",
        "THREATFOX_API_KEY",
        "URLHAUS_API_KEY",
        "URLSCAN_API_KEY",
        "CENSYS_API_KEY",
        "CENSYS_API_SECRET",
        "CENSYS_API_ID",
        "GREYNOISE_API_KEY",
        "SHODAN_API_KEY",
        "PULSEDIVE_API_KEY",
        "CRIMINALIP_API_KEY",
        "PASSIVEDNS_API_KEY",
        "WEBCHECK_URL",
        mode="before",
    )
    @classmethod
    def empty_str_to_none(cls, v):
        if isinstance(v, str):
            v_stripped = v.strip()
            return v_stripped if v_stripped else None
        return v

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls,
        init_settings,
        env_settings,
        dotenv_settings,
        file_secret_settings,
    ):
        # Twelve-factor application precedence:
        # 1. Direct initialization kwargs
        # 2. Docker / OS environment variables (os.environ has highest external priority)
        # 3. Local development .env file (fallback only)
        # 4. File secrets
        return (
            init_settings,
            CleanEnvSource(settings_cls),
            CleanDotEnvSource(settings_cls, env_file=".env", env_file_encoding="utf-8"),
            file_secret_settings,
        )


settings = Settings()
