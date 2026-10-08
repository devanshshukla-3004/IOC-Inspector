from .extractor import extract, unique
from .models import IOC
from .risk import score_ioc


def analyze(text: str) -> list[IOC]:
    indicators = []
    for value, kind in unique(extract(text)):
        score, severity, confidence, reason = score_ioc(value, kind)
        indicators.append(IOC(value, kind, score, severity, confidence, reason))
    return sorted(indicators, key=lambda x: (-x.score, x.value.lower()))
