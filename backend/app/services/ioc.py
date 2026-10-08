import re
import ipaddress
from urllib.parse import urlparse, urlunparse
from typing import Tuple, Optional
from app.schemas.ioc import IOCType, NormalizedIOC, IOCDetectionResult


HEX_32_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$")
HEX_40_PATTERN = re.compile(r"^[a-fA-F0-9]{40}$")
HEX_64_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")

# Domain pattern: valid domain names with labels and standard TLD
DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)

URL_SCHEME_PATTERN = re.compile(r"^(https?|ftp)://", re.IGNORECASE)
IPV4_OCTET_PATTERN = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")


def detect_ioc_type(raw_value: str) -> Tuple[Optional[IOCType], Optional[str]]:
    """
    Automatically detects the IOC type from the raw input string.
    Returns (IOCType, None) on success or (None, error_message) on failure.
    """
    if not raw_value or not raw_value.strip():
        return None, "Empty input provided."

    value = raw_value.strip()

    # 1. Check IP Addresses
    # Check IPv4 (allow leading zeroes in octets for detection)
    m = IPV4_OCTET_PATTERN.match(value)
    if m:
        octets = [int(g) for g in m.groups()]
        if all(0 <= o <= 255 for o in octets):
            return IOCType.IPV4, None

    # Check IPv6
    try:
        ip = ipaddress.ip_address(value)
        if isinstance(ip, ipaddress.IPv6Address):
            return IOCType.IPV6, None
    except ValueError:
        pass

    # 2. Check Hashes (MD5, SHA1, SHA256)
    clean_hex = value.replace(":", "").replace("-", "").strip()
    if HEX_64_PATTERN.match(clean_hex):
        return IOCType.SHA256, None
    if HEX_40_PATTERN.match(clean_hex):
        return IOCType.SHA1, None
    if HEX_32_PATTERN.match(clean_hex):
        return IOCType.MD5, None

    # 3. Check URL
    if URL_SCHEME_PATTERN.match(value) or "://" in value:
        parsed = urlparse(value)
        if parsed.scheme and (parsed.netloc or parsed.path):
            return IOCType.URL, None

    # If it has a path or query string even without scheme, but starts with a domain
    if "/" in value and not value.endswith("/"):
        parts = value.split("/", 1)
        potential_domain = parts[0]
        if DOMAIN_PATTERN.match(potential_domain):
            return IOCType.URL, None

    # 4. Check Domain
    domain_candidate = value.rstrip(".")
    if DOMAIN_PATTERN.match(domain_candidate):
        return IOCType.DOMAIN, None

    return None, f"Unable to detect valid IOC type for: '{raw_value}'"


def normalize_ioc(raw_value: str, ioc_type: Optional[IOCType] = None) -> NormalizedIOC:
    """
    Validates and normalizes an IOC into its canonical representation.
    """
    if not raw_value or not raw_value.strip():
        return NormalizedIOC(
            raw_value=raw_value or "",
            canonical_value="",
            ioc_type=IOCType.DOMAIN,
            is_valid=False,
            error="Empty IOC value",
        )

    val = raw_value.strip()

    if ioc_type is None:
        detected, err = detect_ioc_type(val)
        if not detected:
            return NormalizedIOC(
                raw_value=raw_value,
                canonical_value=val,
                ioc_type=IOCType.DOMAIN,
                is_valid=False,
                error=err,
            )
        ioc_type = detected

    try:
        if ioc_type == IOCType.IPV4:
            # Handle potential leading zeroes in octets (e.g. 192.168.01.01 -> 192.168.1.1)
            m = IPV4_OCTET_PATTERN.match(val)
            if m:
                octets = [int(g) for g in m.groups()]
                if all(0 <= o <= 255 for o in octets):
                    canon_ip = ".".join(str(o) for o in octets)
                    return NormalizedIOC(
                        raw_value=raw_value,
                        canonical_value=canon_ip,
                        ioc_type=IOCType.IPV4,
                        is_valid=True,
                    )
            ip = ipaddress.IPv4Address(val)
            return NormalizedIOC(
                raw_value=raw_value,
                canonical_value=str(ip),
                ioc_type=IOCType.IPV4,
                is_valid=True,
            )

        elif ioc_type == IOCType.IPV6:
            ip = ipaddress.IPv6Address(val)
            return NormalizedIOC(
                raw_value=raw_value,
                canonical_value=ip.compressed.lower(),
                ioc_type=IOCType.IPV6,
                is_valid=True,
            )

        elif ioc_type == IOCType.MD5:
            clean = val.replace(":", "").replace("-", "").strip().lower()
            if not HEX_32_PATTERN.match(clean):
                return NormalizedIOC(
                    raw_value=raw_value,
                    canonical_value=clean,
                    ioc_type=IOCType.MD5,
                    is_valid=False,
                    error="Invalid MD5 length or non-hex characters",
                )
            return NormalizedIOC(
                raw_value=raw_value,
                canonical_value=clean,
                ioc_type=IOCType.MD5,
                is_valid=True,
            )

        elif ioc_type == IOCType.SHA1:
            clean = val.replace(":", "").replace("-", "").strip().lower()
            if not HEX_40_PATTERN.match(clean):
                return NormalizedIOC(
                    raw_value=raw_value,
                    canonical_value=clean,
                    ioc_type=IOCType.SHA1,
                    is_valid=False,
                    error="Invalid SHA1 length or non-hex characters",
                )
            return NormalizedIOC(
                raw_value=raw_value,
                canonical_value=clean,
                ioc_type=IOCType.SHA1,
                is_valid=True,
            )

        elif ioc_type == IOCType.SHA256:
            clean = val.replace(":", "").replace("-", "").strip().lower()
            if not HEX_64_PATTERN.match(clean):
                return NormalizedIOC(
                    raw_value=raw_value,
                    canonical_value=clean,
                    ioc_type=IOCType.SHA256,
                    is_valid=False,
                    error="Invalid SHA256 length or non-hex characters",
                )
            return NormalizedIOC(
                raw_value=raw_value,
                canonical_value=clean,
                ioc_type=IOCType.SHA256,
                is_valid=True,
            )

        elif ioc_type == IOCType.DOMAIN:
            clean = val.lower().rstrip(".")
            # Strip accidental http:// or https:// if present
            if clean.startswith("http://"):
                clean = clean[7:]
            elif clean.startswith("https://"):
                clean = clean[8:]
            clean = clean.split("/")[0].split(":")[0]  # strip any path or port
            if not DOMAIN_PATTERN.match(clean):
                return NormalizedIOC(
                    raw_value=raw_value,
                    canonical_value=clean,
                    ioc_type=IOCType.DOMAIN,
                    is_valid=False,
                    error="Invalid domain structure",
                )
            return NormalizedIOC(
                raw_value=raw_value,
                canonical_value=clean,
                ioc_type=IOCType.DOMAIN,
                is_valid=True,
            )

        elif ioc_type == IOCType.URL:
            # Case-insensitive scheme check
            target = val
            if not URL_SCHEME_PATTERN.match(target):
                target = "http://" + target

            parsed = urlparse(target)
            scheme = (parsed.scheme or "http").lower()
            netloc = parsed.netloc.lower()
            path = parsed.path
            # Deduplicate consecutive slashes in path
            path = re.sub(r"/+", "/", path) if path else "/"
            query = parsed.query
            fragment = parsed.fragment

            normalized_url = urlunparse((scheme, netloc, path, parsed.params, query, fragment))
            return NormalizedIOC(
                raw_value=raw_value,
                canonical_value=normalized_url,
                ioc_type=IOCType.URL,
                is_valid=True,
            )

    except Exception as e:
        return NormalizedIOC(
            raw_value=raw_value,
            canonical_value=val,
            ioc_type=ioc_type,
            is_valid=False,
            error=str(e),
        )

    return NormalizedIOC(
        raw_value=raw_value,
        canonical_value=val,
        ioc_type=ioc_type,
        is_valid=False,
        error="Unhandled IOC type",
    )


def process_ioc_input(raw_value: str) -> IOCDetectionResult:
    """
    Wrapper for API / UI detection.
    """
    detected_type, err = detect_ioc_type(raw_value)
    if not detected_type:
        return IOCDetectionResult(
            input_value=raw_value,
            detected_type=None,
            canonical_value=None,
            is_valid=False,
            message=err or "Invalid IOC",
        )

    norm = normalize_ioc(raw_value, detected_type)
    return IOCDetectionResult(
        input_value=raw_value,
        detected_type=norm.ioc_type,
        canonical_value=norm.canonical_value,
        is_valid=norm.is_valid,
        message=norm.error,
    )
