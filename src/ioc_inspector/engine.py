from .extractor import extract, unique
from .models import IOC
from .normalizer import defang, normalize
from .risk import score_ioc


def analyze(text: str) -> list[IOC]:
    indicators = []
    normalized_seen: set[tuple[str, object]] = set()
    for value, kind in unique(extract(defang(text))):
        canonical = normalize(value)
        key = (canonical, kind)
        if key in normalized_seen:
            continue
        normalized_seen.add(key)
        score, severity, confidence, reason = score_ioc(canonical, kind)
        indicators.append(IOC(canonical, kind, score, severity, confidence, reason))
    return sorted(indicators, key=lambda x: (-x.score, x.value))


def analyze_many(texts: list[str]) -> list[IOC]:
    return analyze("\n".join(texts))
