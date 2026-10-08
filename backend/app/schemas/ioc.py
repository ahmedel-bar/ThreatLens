from enum import Enum
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any


class IOCType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


class ProviderStatus(str, Enum):
    SUCCESS = "success"
    NOT_FOUND = "not_found"
    UNSUPPORTED = "unsupported"
    RATE_LIMITED = "rate_limited"
    UNAUTHORIZED = "unauthorized"
    FORBIDDEN = "forbidden"
    TIMEOUT = "timeout"
    SERVER_ERROR = "server_error"
    INVALID_RESPONSE = "invalid_response"
    DISABLED = "disabled"
    NOT_CONFIGURED = "not_configured"
    NETWORK_ERROR = "network_error"
    PARSE_ERROR = "parse_error"
    PLAN_RESTRICTED = "plan_restricted"


class NormalizedIOC(BaseModel):
    raw_value: str
    canonical_value: str
    ioc_type: IOCType
    is_valid: bool = True
    error: Optional[str] = None


class IOCDetectionResult(BaseModel):
    input_value: str
    detected_type: Optional[IOCType] = None
    canonical_value: Optional[str] = None
    is_valid: bool = False
    message: Optional[str] = None
