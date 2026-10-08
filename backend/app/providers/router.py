import os
import asyncio
import httpx
from typing import List, Dict, Optional
from app.config import settings
from app.schemas.ioc import IOCType, ProviderStatus
from app.schemas.provider import ProviderResult
from app.providers.base import ProviderRequestContext
from app.providers.registry import registry


class ProviderRouter:
    def __init__(self, is_mock: Optional[bool] = None, max_concurrency: int = 6):
        self.is_mock = is_mock if is_mock is not None else (settings.PROVIDER_MODE.lower() == "mock")
        self.semaphore = asyncio.Semaphore(max_concurrency)

    def _get_credentials_for_provider(self, name: str) -> tuple[Optional[str], Optional[str]]:
        def _clean(val: Optional[str]) -> Optional[str]:
            if val and isinstance(val, str) and val.strip():
                return val.strip()
            return None

        if name == "virustotal":
            return _clean(os.environ.get("VT_API_KEY")) or _clean(settings.VT_API_KEY), None
        elif name == "otx":
            return _clean(settings.OTX_API_KEY), None
        elif name == "malwarebazaar":
            return _clean(settings.MALWAREBAZAAR_API_KEY), None
        elif name == "hybrid_analysis":
            return _clean(settings.HYBRID_ANALYSIS_API_KEY), None
        elif name == "abuseipdb":
            return _clean(settings.ABUSEIPDB_API_KEY), None
        elif name == "threatfox":
            return _clean(settings.THREATFOX_API_KEY), None
        elif name == "urlhaus":
            return _clean(settings.URLHAUS_API_KEY), None
        elif name == "urlscan":
            return _clean(settings.URLSCAN_API_KEY), None
        elif name == "censys":
            key_val = _clean(getattr(settings, "CENSYS_API_KEY", None))
            secret_val = _clean(getattr(settings, "CENSYS_API_SECRET", None))
            id_val = _clean(getattr(settings, "CENSYS_API_ID", None))

            # If both ID and SECRET are set (legacy Search v2 / test_router_credentials_retrieval)
            if id_val and secret_val:
                return id_val, secret_val
            # If CENSYS_API_KEY is configured (Platform v3 PAT)
            if key_val:
                return key_val, secret_val or key_val
            # If only CENSYS_API_SECRET is configured (Platform v3 PAT)
            if secret_val:
                return secret_val, secret_val
            # If only CENSYS_API_ID is configured
            if id_val:
                return id_val, None
            return None, None
        elif name == "greynoise":
            return _clean(settings.GREYNOISE_API_KEY), None
        elif name == "shodan":
            return _clean(settings.SHODAN_API_KEY), None
        elif name == "pulsedive":
            pulse_key = _clean(os.environ.get("PULSEDIVE_API_KEY")) or _clean(settings.PULSEDIVE_API_KEY)
            return pulse_key, None
        elif name == "criminalip":
            cip_key = (
                _clean(os.environ.get("CRIMINALIP_API_KEY"))
                or _clean(os.environ.get("CRIMINAL_IP_API_KEY"))
                or _clean(os.environ.get("CRIMINAL_IP_KEY"))
                or _clean(os.environ.get("CIP_API_KEY"))
                or _clean(settings.CRIMINALIP_API_KEY)
            )
            return cip_key, None
        elif name in ("mnemonic_passivedns", "passivedns"):
            pdns_key = (
                _clean(os.environ.get("PASSIVEDNS_API_KEY"))
                or _clean(os.environ.get("MNEMONIC_API_KEY"))
                or _clean(getattr(settings, "PASSIVEDNS_API_KEY", None))
                or _clean(getattr(settings, "MNEMONIC_API_KEY", None))
            )
            return pdns_key, None
        return None, None

    async def route_ioc(
        self,
        ioc_value: str,
        ioc_type: IOCType,
        provider_names: Optional[List[str]] = None,
    ) -> List[ProviderResult]:
        """
        Executes bounded concurrent queries against only capable providers for this IOC type.
        Unsupported providers are completely excluded from execution and display.
        """
        all_providers = registry.get_all_providers()
        selected_providers = []

        for name, provider in all_providers.items():
            if provider_names and name not in provider_names:
                continue
            if provider.is_ioc_supported(ioc_type):
                selected_providers.append(provider)

        async with httpx.AsyncClient(timeout=12.0) as http_client:
            tasks = []
            for prov in selected_providers:
                api_key, api_secret = self._get_credentials_for_provider(prov.name)
                ctx = ProviderRequestContext(
                    ioc_value=ioc_value,
                    ioc_type=ioc_type,
                    is_mock=self.is_mock,
                    api_key=api_key,
                    api_secret=api_secret,
                    timeout_seconds=10.0,
                    http_client=http_client,
                )
                tasks.append(self._execute_with_semaphore(prov, ctx))

            network_results = await asyncio.gather(*tasks, return_exceptions=False)
            return list(network_results)

    async def _execute_with_semaphore(self, provider, ctx: ProviderRequestContext) -> ProviderResult:
        async with self.semaphore:
            return await provider.execute(ctx)
