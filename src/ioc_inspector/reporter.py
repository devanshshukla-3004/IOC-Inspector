"""Machine-readable reporting for IOC analysis."""

import csv
import json
from dataclasses import asdict
from pathlib import Path

from .models import IOC


def _record(item: IOC) -> dict:
    data = asdict(item)
    data["ioc_type"] = item.ioc_type.value
    data["severity"] = item.severity.value
    return data


def to_dict(results: list[IOC]) -> dict:
    counts: dict[str, int] = {}
    severities: dict[str, int] = {}
    for item in results:
        counts[item.ioc_type.value] = counts.get(item.ioc_type.value, 0) + 1
        severities[item.severity.value] = severities.get(item.severity.value, 0) + 1
    return {"summary": {"total": len(results), "by_type": counts, "by_severity": severities,
                        "max_score": max((x.score for x in results), default=0)},
            "indicators": [_record(x) for x in results]}


def write_json(results: list[IOC], path: str | Path) -> None:
    Path(path).write_text(json.dumps(to_dict(results), indent=2), encoding="utf-8")


def write_csv(results: list[IOC], path: str | Path) -> None:
    fields = ["value", "ioc_type", "score", "severity", "confidence", "reason"]
    with Path(path).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for item in results:
            writer.writerow(_record(item))
