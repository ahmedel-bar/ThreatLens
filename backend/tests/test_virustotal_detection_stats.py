import pytest
from app.schemas.ioc import IOCType, ProviderStatus
from app.schemas.provider import VirusTotalDetectionStats
from app.providers.base import ProviderRequestContext
from app.providers.virustotal import VirusTotalProvider
from app.services.enrichment import build_layer1_reputation


def test_vt_stats_exact_case():
    """
    Exact case from user bug report:
    malicious: 55, suspicious: 0, undetected: 18 -> total: 73
    NOT 55 / 55
    """
    api_stats = {
        "malicious": 55,
        "suspicious": 0,
        "undetected": 18,
    }
    stats = VirusTotalDetectionStats.from_api_stats(api_stats)
    assert stats.malicious == 55
    assert stats.suspicious == 0
    assert stats.undetected == 18
    assert stats.total == 73

    d = stats.to_dict()
    assert d["malicious"] == 55
    assert d["suspicious"] == 0
    assert d["undetected"] == 18
    assert d["total"] == 73


def test_vt_stats_case_a():
    """
    Case A:
    malicious = 10, suspicious = 2, undetected = 80 -> total = 92
    """
    api_stats = {
        "malicious": 10,
        "suspicious": 2,
        "undetected": 80,
    }
    stats = VirusTotalDetectionStats.from_api_stats(api_stats)
    assert stats.malicious == 10
    assert stats.suspicious == 2
    assert stats.undetected == 80
    assert stats.total == 92


def test_vt_stats_case_b():
    """
    Case B:
    malicious = 0, suspicious = 0, undetected = 70 -> total = 70
    """
    api_stats = {
        "malicious": 0,
        "suspicious": 0,
        "undetected": 70,
    }
    stats = VirusTotalDetectionStats.from_api_stats(api_stats)
    assert stats.malicious == 0
    assert stats.suspicious == 0
    assert stats.undetected == 70
    assert stats.total == 70


def test_vt_stats_case_c():
    """
    Case C:
    malicious = 20, suspicious = 3, harmless = 40, undetected = 10 -> total = 73
    """
    api_stats = {
        "malicious": 20,
        "suspicious": 3,
        "harmless": 40,
        "undetected": 10,
    }
    stats = VirusTotalDetectionStats.from_api_stats(api_stats)
    assert stats.malicious == 20
    assert stats.suspicious == 3
    assert stats.harmless == 40
    assert stats.undetected == 10
    assert stats.total == 73


def test_vt_stats_case_d():
    """
    Case D:
    malicious = 20, suspicious = 3, undetected = 10, timeout = 2, type_unsupported = 1, failure = 1
    total = 37
    """
    api_stats = {
        "malicious": 20,
        "suspicious": 3,
        "undetected": 10,
        "timeout": 2,
        "type-unsupported": 1,
        "failure": 1,
    }
    stats = VirusTotalDetectionStats.from_api_stats(api_stats)
    assert stats.malicious == 20
    assert stats.suspicious == 3
    assert stats.undetected == 10
    assert stats.timeout == 2
    assert stats.type_unsupported == 1
    assert stats.failure == 1
    assert stats.total == 37


def test_virustotal_provider_parse_response_detection_stats():
    provider = VirusTotalProvider()
    ctx = ProviderRequestContext(
        ioc_value="44d88612fea8a8f36de82e1278abb02f",
        ioc_type=IOCType.MD5,
    )
    raw_data = {
        "data": {
            "id": ctx.ioc_value,
            "type": "file",
            "attributes": {
                "meaningful_name": "sample.exe",
                "size": 12345,
                "last_analysis_stats": {
                    "malicious": 55,
                    "suspicious": 0,
                    "undetected": 18,
                    "harmless": 0,
                    "timeout": 0,
                    "failure": 0,
                    "type-unsupported": 0,
                },
                "reputation": -85,
            },
        }
    }

    result = provider._parse_response(ctx, raw_data)
    assert result.status == ProviderStatus.SUCCESS
    assert result.malicious_count == 55
    assert result.suspicious_count == 0
    assert result.reputation_score == -85.0
    assert result.vt_engine_counts is not None
    assert result.vt_engine_counts["malicious"] == 55
    assert result.vt_engine_counts["suspicious"] == 0
    assert result.vt_engine_counts["undetected"] == 18
    assert result.vt_engine_counts["total"] == 73

    # Verify build_layer1_reputation preserves vt_engine_counts and does not collapse total to malicious
    layer1 = build_layer1_reputation(ctx.ioc_value, ctx.ioc_type, [result])
    assert layer1.vt_engine_counts is not None
    assert layer1.vt_engine_counts["total"] == 73
    assert layer1.vt_engine_counts["malicious"] == 55
    assert layer1.vt_engine_counts["undetected"] == 18

    # Ensure the ProviderResult inside provider_results also has vt_engine_counts
    vt_res = next(r for r in layer1.provider_results if r.provider_name.lower() == "virustotal")
    assert vt_res.vt_engine_counts is not None
    assert vt_res.vt_engine_counts["total"] == 73
    assert vt_res.vt_engine_counts["malicious"] == 55
    assert vt_res.vt_engine_counts["undetected"] == 18
