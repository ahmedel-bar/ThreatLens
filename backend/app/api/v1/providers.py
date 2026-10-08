from fastapi import APIRouter
from typing import List
from app.schemas.provider import ProviderCapability
from app.providers.registry import registry

router = APIRouter(prefix="/providers", tags=["providers"])


@router.get("", response_model=List[ProviderCapability])
async def list_providers():
    """Returns capabilities, supported IOCs, and documentation links for all 11 providers."""
    return registry.get_capabilities_list()


@router.get("/status")
async def provider_configuration_status():
    """
    Safe diagnostic endpoint returning authentication status for all providers
    WITHOUT leaking or displaying key values.
    """
    from app.providers.router import ProviderRouter
    router = ProviderRouter()
    status = {}
    for name, provider in registry.get_all_providers().items():
        key, secret = router._get_credentials_for_provider(name)
        caps = provider.get_capabilities()
        if name == "censys":
            is_configured = bool(key or secret)
        else:
            is_configured = bool(key)
        status[name] = {
            "configured": is_configured,
            "requires_auth": caps.requires_auth,
            "display_name": caps.display_name,
        }
    return status
