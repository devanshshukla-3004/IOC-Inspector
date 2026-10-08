from .models import IOCType, Severity

BASE_SCORES = {
    IOCType.IP: 55, IOCType.DOMAIN: 40, IOCType.URL: 50,
    IOCType.HASH_MD5: 45, IOCType.HASH_SHA1: 45, IOCType.HASH_SHA256: 45,
    IOCType.EMAIL: 25,
}
SUSPICIOUS_TERMS = ("malware", "phish", "evil", "payload", "botnet", "c2",
                    "command-control", "credential", "ransom", "trojan", "dropper",
                    "stealer", "exploit")
SUSPICIOUS_TLDS = (".top", ".xyz", ".click", ".zip", ".mov", ".tk", ".pw")


def score_ioc(value: str, ioc_type: IOCType) -> tuple[int, Severity, int, str]:
    score = BASE_SCORES[ioc_type]
    reasons = [f"{ioc_type.value.upper()} indicator"]
    lowered = value.lower()

    if any(term in lowered for term in SUSPICIOUS_TERMS):
        score += 25
        reasons.append("suspicious threat-related token")
    if ioc_type in {IOCType.DOMAIN, IOCType.URL} and any(
        tld in lowered.split("/")[0] for tld in SUSPICIOUS_TLDS
    ):
        score += 15
        reasons.append("higher-risk TLD")
    if ioc_type == IOCType.URL:
        if lowered.startswith("https://"):
            score -= 5
            reasons.append("HTTPS transport")
        authority = lowered.split("://", 1)[-1].split("/", 1)[0]
        if "@" in authority:
            score += 20
            reasons.append("userinfo in URL authority")
    if ioc_type == IOCType.DOMAIN and lowered.count(".") >= 4:
        score += 10
        reasons.append("deeply nested domain")

    score = max(0, min(score, 100))
    severity = (Severity.CRITICAL if score >= 85 else
                Severity.HIGH if score >= 65 else
                Severity.MEDIUM if score >= 40 else Severity.LOW)
    confidence = 95 if ioc_type in {
        IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256, IOCType.IP
    } else 85
    return score, severity, confidence, "; ".join(reasons)
