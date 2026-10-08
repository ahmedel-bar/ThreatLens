from app.services.confidence import calculate_ioc_confidence, get_confidence_tier


def test_confidence_tiers():
    assert get_confidence_tier(85.0) == "Very High"
    assert get_confidence_tier(65.0) == "High"
    assert get_confidence_tier(45.0) == "Medium"
    assert get_confidence_tier(15.0) == "Low"


def test_multi_provider_corroboration_increases_confidence():
    single_provider_conf = calculate_ioc_confidence(
        providers=["virustotal"],
        raw_confidences=[60.0],
        relationship_types=["related_to"],
    )

    multi_provider_conf = calculate_ioc_confidence(
        providers=["virustotal", "urlscan", "otx"],
        raw_confidences=[60.0, 60.0, 60.0],
        relationship_types=["related_to"],
    )

    assert multi_provider_conf > single_provider_conf
