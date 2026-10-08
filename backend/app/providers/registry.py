from typing import Dict, List, Optional
from app.providers.base import BaseProvider
from app.schemas.provider import ProviderCapability

from app.providers.virustotal import VirusTotalProvider
from app.providers.otx import AlienVaultOTXProvider
from app.providers.malwarebazaar import MalwareBazaarProvider
from app.providers.hybrid_analysis import HybridAnalysisProvider
from app.providers.abuseipdb import AbuseIPDBProvider
from app.providers.threatfox import ThreatFoxProvider
from app.providers.urlhaus import URLhausProvider
from app.providers.urlscan import URLScanProvider
from app.providers.censys import CensysProvider
from app.providers.greynoise import GreyNoiseProvider
from app.providers.shodan import ShodanProvider
from app.providers.pulsedive import PulsediveProvider
from app.providers.criminalip import CriminalIPProvider
from app.providers.passivedns import PassiveDNSProvider
from app.providers.webcheck import WebCheckProvider


class ProviderRegistry:
    def __init__(self):
        self._providers: Dict[str, BaseProvider] = {}
        self._register_default_providers()

    def _register_default_providers(self):
        providers = [
            VirusTotalProvider(),
            AlienVaultOTXProvider(),
            MalwareBazaarProvider(),
            HybridAnalysisProvider(),
            AbuseIPDBProvider(),
            ThreatFoxProvider(),
            URLhausProvider(),
            URLScanProvider(),
            CensysProvider(),
            GreyNoiseProvider(),
            ShodanProvider(),
            PulsediveProvider(),
            CriminalIPProvider(),
            PassiveDNSProvider(),
            WebCheckProvider(),
        ]
        for p in providers:
            self._providers[p.name] = p

    def get_provider(self, name: str) -> Optional[BaseProvider]:
        if name == "passivedns":
            return self._providers.get("mnemonic_passivedns")
        return self._providers.get(name)

    def get_all_providers(self) -> Dict[str, BaseProvider]:
        return self._providers

    def get_capabilities_list(self) -> List[ProviderCapability]:
        return [p.get_capabilities() for p in self._providers.values()]


# Global registry singleton
registry = ProviderRegistry()
