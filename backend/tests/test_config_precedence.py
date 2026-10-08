import os
import pytest
from httpx import AsyncClient
from app.config import Settings
from app.providers.router import ProviderRouter


def test_docker_env_precedence_over_dotenv(monkeypatch):
    # Simulate Docker injecting VT_API_KEY into os.environ
    monkeypatch.setenv("VT_API_KEY", "docker_injected_vt_key_999")
    monkeypatch.setenv("OTX_API_KEY", "docker_injected_otx_key_888")
    monkeypatch.setenv("CENSYS_API_ID", "docker_censys_id")
    monkeypatch.setenv("CENSYS_API_SECRET", "docker_censys_secret")

    # Instantiate fresh Settings
    fresh_settings = Settings()

    assert fresh_settings.VT_API_KEY == "docker_injected_vt_key_999"
    assert fresh_settings.OTX_API_KEY == "docker_injected_otx_key_888"
    assert fresh_settings.CENSYS_API_ID == "docker_censys_id"
    assert fresh_settings.CENSYS_API_SECRET == "docker_censys_secret"


def test_whitespace_and_empty_env_cleaned_to_none(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "   ")
    fresh_settings = Settings()
    assert fresh_settings.SHODAN_API_KEY is None or fresh_settings.SHODAN_API_KEY != "   "


def test_router_credentials_retrieval(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "VT_API_KEY", "test_router_key")
    monkeypatch.setattr(settings, "CENSYS_API_ID", "test_id")
    monkeypatch.setattr(settings, "CENSYS_API_SECRET", "test_secret")

    router = ProviderRouter()
    vt_key, vt_secret = router._get_credentials_for_provider("virustotal")
    assert vt_key == "test_router_key"
    assert vt_secret is None

    cid, csecret = router._get_credentials_for_provider("censys")
    assert cid == "test_id"
    assert csecret == "test_secret"


@pytest.mark.asyncio
async def test_safe_diagnostic_status_endpoint(client: AsyncClient, monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "secret_diagnostic_vt_key")
    resp = await client.get("/api/v1/providers/status")
    assert resp.status_code == 200
    data = resp.json()

    assert "virustotal" in data
    assert data["virustotal"]["configured"] is True
    assert data["virustotal"]["requires_auth"] is True

    # Critical security check: Ensure NO key values appear anywhere in the response
    raw_text = resp.text
    assert "secret_diagnostic_vt_key" not in raw_text
    assert "VT_API_KEY" not in raw_text
