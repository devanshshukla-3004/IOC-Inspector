from dataclasses import dataclass
from enum import Enum


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "md5"
    HASH_SHA1 = "sha1"
    HASH_SHA256 = "sha256"
    EMAIL = "email"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class IOC:
    value: str
    ioc_type: IOCType
    score: int
    severity: Severity
    confidence: int
    reason: str
