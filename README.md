# 🔎 IOC Inspector

> **Day 06 — 100 Days, 100 Cybersecurity Projects**

IOC Inspector is an offline-first threat-intelligence utility for extracting, normalizing, classifying, and risk-scoring Indicators of Compromise from incident reports, logs, and analyst notes.

[![CI](https://github.com/devanshshukla-3004/IOC-Inspector/actions/workflows/ci.yml/badge.svg)](https://github.com/devanshshukla-3004/IOC-Inspector/actions/workflows/ci.yml)

## Features

- IPv4 detection and validation
- Domains, URLs, and email addresses
- MD5, SHA-1, and SHA-256 detection
- Defanged IOC restoration such as `hxxps://evil[.]example[.]com`
- Case-insensitive normalization and deduplication
- Deterministic heuristic risk scoring
- LOW / MEDIUM / HIGH / CRITICAL severity
- Confidence scoring
- JSON and CSV reports
- Single-file and recursive directory analysis
- Automated tests and GitHub Actions CI
- No commercial intelligence API required

## Detection pipeline

```text
Raw Report
    ↓
Defang / Clean
    ↓
IOC Extraction
    ↓
Normalization
    ↓
Classification
    ↓
Risk Engine
    ↓
Terminal + JSON/CSV
```

## Quick start

Requires Python 3.10+.

```bash
git clone https://github.com/devanshshukla-3004/IOC-Inspector.git
cd IOC-Inspector
python -m venv .venv
pip install -r requirements.txt
```

Windows activation:

```powershell
.venv\Scripts\Activate.ps1
```

## Usage

Analyze raw text:

```bash
python -m ioc_inspector.cli --text "185.220.101.1 hxxps://malware[.]example[.]com analyst[at]example[.]org"
```

Analyze a report:

```bash
python -m ioc_inspector.cli --file samples/threat_report.txt
```

Batch-analyze all `.txt` and `.log` files recursively:

```bash
python -m ioc_inspector.cli --directory ./samples
```

Export reports:

```bash
python -m ioc_inspector.cli --file samples/threat_report.txt --json report.json --csv report.csv
```

## Example output

```text
IOC INSPECTOR
────────────────────────────────────────────────────────────────────────────────────────
TYPE       INDICATOR                                      SCORE  SEVERITY  CONF
────────────────────────────────────────────────────────────────────────────────────────
URL        https://malware.example/download                  70  HIGH      85%
IP         185.220.101.1                                     55  MEDIUM    95%
DOMAIN     malware.example                                   65  HIGH      85%
EMAIL      security@example.org                              25  LOW       85%
────────────────────────────────────────────────────────────────────────────────────────
4 indicator(s) detected
```

## Risk model

The score is a heuristic prioritization signal, not proof that an IOC is malicious.

Signals include IOC type, suspicious threat-related keywords, higher-risk TLD patterns, URL transport, URL userinfo, and domain nesting depth.

| Score | Severity |
|---:|---|
| 0–39 | LOW |
| 40–64 | MEDIUM |
| 65–84 | HIGH |
| 85–100 | CRITICAL |

## Project structure

```text
IOC-Inspector/
├── .github/workflows/ci.yml
├── samples/
│   └── threat_report.txt
├── src/ioc_inspector/
│   ├── cli.py
│   ├── engine.py
│   ├── extractor.py
│   ├── models.py
│   ├── normalizer.py
│   ├── reporter.py
│   └── risk.py
├── tests/
├── pyproject.toml
├── requirements.txt
└── LICENSE
```

## Testing

```bash
python -m pytest -q
```

CI validates Python 3.10 through 3.13.

## Roadmap

- [x] IOC extraction
- [x] Defanged IOC restoration
- [x] Normalization and deduplication
- [x] Heuristic risk scoring
- [x] JSON / CSV reporting
- [x] Batch analysis
- [x] Automated testing + CI
- [ ] Optional VirusTotal / AbuseIPDB enrichment adapters
- [ ] STIX 2.1 export
- [ ] Streamlit analyst dashboard
- [ ] IOC relationship graph

## Security note

IOC Inspector is offline-first and does not contact or probe indicators. It is intended for defensive triage of copied reports and logs.

## Disclaimer

For defensive security research, education, incident-response preparation, and authorized analysis only. The risk score is heuristic and should not be treated as proof of maliciousness.
