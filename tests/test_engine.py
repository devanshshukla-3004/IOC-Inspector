from ioc_inspector.engine import analyze
from ioc_inspector.models import IOCType, Severity


def test_extracts_multiple_ioc_types():
    results = analyze("Contact 185.220.101.1 at analyst@example.org. SHA 0123456789abcdef0123456789abcdef")
    types = {item.ioc_type for item in results}
    assert IOCType.IP in types
    assert IOCType.EMAIL in types
    assert IOCType.HASH_MD5 in types


def test_invalid_ipv4_is_ignored():
    results = analyze("999.999.999.999")
    assert results == []


def test_deduplicates_case_insensitively():
    results = analyze("evil-example.test EVIL-EXAMPLE.TEST")
    assert len(results) == 1


def test_suspicious_token_raises_score():
    results = analyze("malware.example")
    assert results[0].score >= 65
    assert results[0].severity in {Severity.HIGH, Severity.CRITICAL}
