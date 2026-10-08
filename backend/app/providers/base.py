import time
import httpx
from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any
from app.schemas.ioc import IOCType, ProviderStatus
from app.schemas.provider import (
    ProviderCapability,
    ProviderResult,
    InfrastructureData,
    DiscoveredIOC,
    ProviderEvidence,
)
from app.services.ioc import normalize_ioc
from app.config import settings


class ProviderRequestContext:
    def __init__(
        self,
        ioc_value: str,
        ioc_type: IOCType,
        is_mock: bool = False,
        api_key: Optional[str] = None,
        api_secret: Optional[str] = None,
        timeout_seconds: float = 10.0,
        http_client: Optional[httpx.AsyncClient] = None,
    ):
        self.ioc_value = ioc_value
        self.ioc_type = ioc_type
        self.is_mock = is_mock
        self.api_key = api_key
        self.api_secret = api_secret
        self.timeout_seconds = timeout_seconds
        self.http_client = http_client


class BaseProvider(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Machine identifier (e.g. virustotal, shodan)"""
        pass

    @property
    @abstractmethod
    def display_name(self) -> str:
        """Human readable name"""
        pass

    @abstractmethod
    def get_capabilities(self) -> ProviderCapability:
        """Returns the full declared capability descriptor"""
        pass

    def is_ioc_supported(self, ioc_type: IOCType) -> bool:
        caps = self.get_capabilities()
        return ioc_type in caps.supported_iocs

    async def execute(self, ctx: ProviderRequestContext) -> ProviderResult:
        """
        Public template method executing with full safety guardrails and status tracking.
        """
        start_time = time.perf_counter()

        # 1. Check capability
        if not self.is_ioc_supported(ctx.ioc_type):
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            return ProviderResult(
                provider_name=self.name,
                ioc_value=ctx.ioc_value,
                ioc_type=ctx.ioc_type,
                status=ProviderStatus.UNSUPPORTED,
                execution_time_ms=elapsed_ms,
                error_details=f"IOC type '{ctx.ioc_type.value}' is not supported by {self.display_name}.",
            )

        # 2. Check Mock vs Live (Mock strictly forbidden in production)
        if ctx.is_mock and settings.ENVIRONMENT.lower() != "production":
            try:
                res = await self._execute_mock(ctx)
                res.execution_time_ms = int((time.perf_counter() - start_time) * 1000)
                return res
            except Exception as e:
                elapsed_ms = int((time.perf_counter() - start_time) * 1000)
                return ProviderResult(
                    provider_name=self.name,
                    ioc_value=ctx.ioc_value,
                    ioc_type=ctx.ioc_type,
                    status=ProviderStatus.SERVER_ERROR,
                    execution_time_ms=elapsed_ms,
                    error_details=f"Mock execution error: {str(e)}",
                )

        # 3. Check Auth configuration for Live execution
        caps = self.get_capabilities()
        has_auth = bool(ctx.api_key and ctx.api_key.strip()) or bool(ctx.api_secret and ctx.api_secret.strip())
        if caps.requires_auth and not has_auth:
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            return ProviderResult(
                provider_name=self.name,
                ioc_value=ctx.ioc_value,
                ioc_type=ctx.ioc_type,
                status=ProviderStatus.NOT_CONFIGURED,
                execution_time_ms=elapsed_ms,
                error_details=f"API key not configured for {self.display_name}.",
                reputation_score=None,
                classification=None,
                malicious_count=0,
                suspicious_count=0,
                harmless_count=0,
                tags=[],
                threat_actors=[],
                malware_families=[],
                infrastructure=None,
                discovered_iocs=[],
                evidences=[],
                raw_data=None,
            )

        # 4. Live execution with HTTP error classification
        try:
            res = await self._execute_live(ctx)
            res.execution_time_ms = int((time.perf_counter() - start_time) * 1000)
            return res
        except httpx.TimeoutException:
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            return ProviderResult(
                provider_name=self.name,
                ioc_value=ctx.ioc_value,
                ioc_type=ctx.ioc_type,
                status=ProviderStatus.TIMEOUT,
                execution_time_ms=elapsed_ms,
                error_details="Request timed out.",
            )
        except httpx.HTTPStatusError as e:
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            status_code = e.response.status_code
            if status_code == 401:
                status = ProviderStatus.UNAUTHORIZED
            elif status_code == 403:
                status = ProviderStatus.FORBIDDEN
            elif status_code == 404:
                status = ProviderStatus.NOT_FOUND
            elif status_code == 429:
                status = ProviderStatus.RATE_LIMITED
            elif 500 <= status_code <= 599:
                status = ProviderStatus.SERVER_ERROR
            else:
                status = ProviderStatus.INVALID_RESPONSE

            return ProviderResult(
                provider_name=self.name,
                ioc_value=ctx.ioc_value,
                ioc_type=ctx.ioc_type,
                status=status,
                execution_time_ms=elapsed_ms,
                error_details=f"HTTP {status_code}: {e.response.text[:200]}",
            )
        except httpx.RequestError as e:
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            return ProviderResult(
                provider_name=self.name,
                ioc_value=ctx.ioc_value,
                ioc_type=ctx.ioc_type,
                status=ProviderStatus.NETWORK_ERROR,
                execution_time_ms=elapsed_ms,
                error_details=f"Network error: {str(e)}",
            )
        except Exception as e:
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            return ProviderResult(
                provider_name=self.name,
                ioc_value=ctx.ioc_value,
                ioc_type=ctx.ioc_type,
                status=ProviderStatus.SERVER_ERROR,
                execution_time_ms=elapsed_ms,
                error_details=f"Unexpected error: {str(e)}",
            )

    @abstractmethod
    async def _execute_live(self, ctx: ProviderRequestContext) -> ProviderResult:
        """Calls actual remote API and parses payload"""
        pass

    @abstractmethod
    async def _execute_mock(self, ctx: ProviderRequestContext) -> ProviderResult:
        """Returns realistic fixture-derived payload"""
        pass
