import re
from typing import Iterable

from .models import IOCType

PATTERNS = {
    IOCType.URL: re.compile(r"https?://[^\s<>'"\]\[()]+", re.I),
    IOCType.EMAIL: re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+(?![\w-])", re.I),
    IOCType.HASH_MD5: re.compile(r"(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])", re.I),
    IOCType.HASH_SHA1: re.compile(r"(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])", re.I),
    IOCType.HASH_SHA256: re.compile(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", re.I),
    IOCType.IP: re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"),
    IOCType.DOMAIN: re.compile(r"(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w.-])", re.I),
}


def _valid_ipv4(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)


def extract(text: str) -> list[tuple[str, IOCType]]:
    found: list[tuple[str, IOCType]] = []
    for kind in [IOCType.URL, IOCType.EMAIL, IOCType.HASH_SHA256, IOCType.HASH_SHA1, IOCType.HASH_MD5, IOCType.IP, IOCType.DOMAIN]:
        for match in PATTERNS[kind].finditer(text):
            value = match.group(0).rstrip(".,;:)")
            if kind == IOCType.IP and not _valid_ipv4(value):
                continue
            found.append((value, kind))
    return found


def unique(items: Iterable[tuple[str, IOCType]]) -> list[tuple[str, IOCType]]:
    seen: set[tuple[str, IOCType]] = set()
    result = []
    for value, kind in items:
        key = (value.lower(), kind)
        if key not in seen:
            seen.add(key)
            result.append((value, kind))
    return result
