from typing import List, Dict, Any


PROVIDER_WEIGHTS: Dict[str, float] = {
    "virustotal": 1.0,
    "otx": 0.85,
    "malwarebazaar": 0.95,
    "hybrid_analysis": 0.9,
    "abuseipdb": 0.85,
    "threatfox": 0.9,
    "urlhaus": 0.9,
    "urlscan": 0.85,
    "censys": 0.85,
    "greynoise": 0.85,
    "shodan": 0.85,
}


def calculate_ioc_confidence(
    providers: List[str],
    raw_confidences: List[float],
    relationship_types: List[str],
) -> float:
    """
    Calculates transparent application-derived confidence score (0-100).
    Considers:
    - Base confidence from providers
    - Weight of contributing providers
    - Number of independent providers agreeing
    - Relationship directness
    """
    if not providers:
        return 30.0

    # 1. Base average from provider signals
    base_avg = sum(raw_confidences) / len(raw_confidences) if raw_confidences else 50.0

    # 2. Provider reliability weighting
    weights = [PROVIDER_WEIGHTS.get(p.lower(), 0.7) for p in providers]
    weighted_factor = sum(weights) / len(weights)

    # 3. Independent corroboration bonus
    provider_count_bonus = min(25.0, (len(set(providers)) - 1) * 10.0)

    # 4. Direct relationship bonus (resolves_to, downloads > related_to)
    rel_bonus = 0.0
    direct_types = {"resolves_to", "downloads", "hosts", "shares_certificate"}
    if any(rt in direct_types for rt in relationship_types):
        rel_bonus = 10.0

    calculated = (base_avg * 0.6 * weighted_factor) + provider_count_bonus + rel_bonus
    # Bound to 0 - 100
    score = round(max(5.0, min(100.0, calculated)), 1)
    return score


def get_confidence_tier(score: float) -> str:
    """
    Returns the human-readable tier for SOC analysts:
    0-29: Low
    30-59: Medium
    60-79: High
    80-100: Very High
    """
    if score >= 80.0:
        return "Very High"
    elif score >= 60.0:
        return "High"
    elif score >= 30.0:
        return "Medium"
    else:
        return "Low"


def calculate_overall_risk(provider_results: List[Any]) -> tuple[float, str]:
    """
    Computes overall investigation risk score (0-100) and classification.
    """
    if not provider_results:
        return 0.0, "unknown"

    malicious_votes = 0
    suspicious_votes = 0
    benign_votes = 0
    total_reputation = 0.0
    count_valid = 0

    for res in provider_results:
        if getattr(res, "status", None) == "success":
            count_valid += 1
            classification = getattr(res, "classification", "unknown")
            if classification == "malicious":
                malicious_votes += 1
            elif classification == "suspicious":
                suspicious_votes += 1
            elif classification == "benign":
                benign_votes += 1

            rep = getattr(res, "reputation_score", None)
            if rep is not None:
                total_reputation += rep

    if count_valid == 0:
        return 0.0, "unknown"

    if malicious_votes >= 2 or (malicious_votes >= 1 and suspicious_votes >= 1):
        overall = "malicious"
        risk_score = min(100.0, 70.0 + (malicious_votes * 10.0))
    elif malicious_votes == 1 or suspicious_votes >= 1:
        overall = "suspicious"
        risk_score = 45.0 + (suspicious_votes * 10.0)
    elif benign_votes > 0 and malicious_votes == 0:
        overall = "benign"
        risk_score = 10.0
    else:
        overall = "unknown"
        risk_score = 20.0

    return round(min(100.0, max(0.0, risk_score)), 1), overall
