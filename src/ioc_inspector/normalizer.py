"""IOC normalization, including common defanged security-report formats."""

import re

DOT = re.compile(r"\s*\[\.\]\s*|\s*\(\.\)\s*|\s*\{\.\}\s*|\s+DOT\s+", re.I)
PROTO = re.compile(r"\b(hxxps?|hxxp)\s*:\s*//", re.I)


def defang(value: str) -> str:
    value = value.strip()
    value = DOT.sub(".", value)
    value = PROTO.sub(lambda m: "https://" if m.group(1).lower() == "hxxps" else "http://", value)
    value = re.sub(r"\s*(?:\[at\]|\(at\)|\{at\})\s*", "@", value, flags=re.I)
    return value.rstrip(".,;:)")


def normalize(value: str) -> str:
    return defang(value).strip().lower()
