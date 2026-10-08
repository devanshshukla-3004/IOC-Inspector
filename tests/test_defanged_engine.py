from ioc_inspector.engine import analyze


def test_defanged_iocs_are_analyzed():
    results = analyze("hxxps://malware[.]example[.]com/path analyst[at]example[.]org")
    values = {x.value for x in results}
    assert "https://malware.example.com/path" in values
    assert "analyst@example.org" in values
