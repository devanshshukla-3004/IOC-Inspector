import json

from ioc_inspector.engine import analyze
from ioc_inspector.reporter import to_dict, write_csv, write_json


def test_json_report(tmp_path):
    target = tmp_path / "report.json"
    write_json(analyze("8.8.8.8"), target)
    data = json.loads(target.read_text())
    assert data["summary"]["total"] == 1
    assert data["indicators"][0]["ioc_type"] == "ip"


def test_csv_report(tmp_path):
    target = tmp_path / "report.csv"
    write_csv(analyze("8.8.8.8"), target)
    assert "value,ioc_type,score" in target.read_text()


def test_summary_empty():
    assert to_dict([])["summary"]["total"] == 0
