from ioc_inspector.models import IOCType, Severity
from ioc_inspector.risk import score_ioc


def test_https_domain_has_valid_score():
    score, severity, confidence, _ = score_ioc("https://example.org", IOCType.URL)
    assert 0 <= score <= 100
    assert severity in Severity
    assert confidence > 0


def test_threat_keyword_increases_risk():
    score, severity, _, reason = score_ioc("malware.example", IOCType.DOMAIN)
    assert score >= 65
    assert severity in {Severity.HIGH, Severity.CRITICAL}
    assert "threat-related" in reason
