from ioc_inspector.normalizer import defang, normalize


def test_defangs_url():
    assert defang("hxxps://evil[.]example[.]com/path") == "https://evil.example.com/path"


def test_defangs_email():
    assert defang("analyst[at]example[.]org") == "analyst@example.org"


def test_normalize_lowercases():
    assert normalize("HTTPS://EXAMPLE.ORG") == "https://example.org"
