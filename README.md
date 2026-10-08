# 🔎 IOC Inspector

> **Day 06 — 100 Days, 100 Cybersecurity Projects**

**IOC Inspector** is an offline-first cybersecurity utility for extracting **Indicators of Compromise (IOCs)** from incident reports, logs, and analyst notes, normalizing both plain-text and defanged indicators, classifying them, and assigning a transparent heuristic risk score.

It is designed as a compact **threat-intelligence triage engine**: fast enough for local analysis, deterministic enough to test, and structured enough to produce machine-readable reports.

[![CI](https://github.com/devanshshukla-3004/IOC-Inspector/actions/workflows/ci.yml/badge.svg)](https://github.com/devanshshukla-3004/IOC-Inspector/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Mode-Offline--First-111827)](#-security-and-privacy)

---

## 🎯 What problem does it solve?

During incident response, threat reports and logs often contain indicators such as:

- IP addresses
- domains
- URLs
- email addresses
- MD5 / SHA-1 / SHA-256 hashes

Analysts frequently encounter **defanged IOCs** such as:

```text
hxxps://malware[.]example[.]com
analyst[at]example[.]org
```

These indicators are intentionally altered so they are safer to copy and share, but they are less convenient to process automatically.

IOC Inspector turns this raw material into structured records:

```text
Raw report
   │
   ▼
Defang restoration
   │
   ▼
IOC extraction
   │
   ▼
Normalization + deduplication
   │
   ▼
Classification
   │
   ▼
Heuristic risk scoring
   │
   ├──► Terminal table
   ├──► JSON report
   └──► CSV report
```

---

## ✨ Key capabilities

| Capability | What it does |
|---|---|
| **IOC extraction** | Detects IPv4 addresses, domains, URLs, emails, and common cryptographic hashes |
| **Defanged IOC support** | Restores `[.]`, `(.)`, `{.}`, `[at]`, `hxxp`, and similar representations before extraction |
| **Normalization** | Trims and lowercases indicators for consistent analysis |
| **Deduplication** | Prevents repeated indicators from producing duplicate findings |
| **IOC classification** | Separates indicators into IP, domain, URL, email, MD5, SHA-1, and SHA-256 |
| **Risk scoring** | Produces a deterministic 0–100 heuristic score |
| **Severity** | Maps scores to LOW, MEDIUM, HIGH, or CRITICAL |
| **Confidence** | Reports extraction confidence based on IOC type |
| **Reasoning** | Records why an indicator received its score |
| **Batch analysis** | Recursively scans `.txt` and `.log` files |
| **Reporting** | Exports structured JSON and CSV results |
| **Testing** | Includes unit/integration coverage for core functionality |
| **CI** | GitHub Actions validates the test suite across supported Python versions |
| **Offline-first design** | No external threat-intelligence service is required |

---

## 🧩 Supported indicators

### IP addresses
Detects IPv4 indicators such as:

```text
185.220.101.1
10.10.20.15
```

### Domains

```text
malware.example.com
cdn.example.org
```

### URLs

```text
https://malware.example/download
http://example.org/login
```

### Email addresses

```text
security@example.org
analyst@example.org
```

### File hashes

Supported formats:

- **MD5** — 32 hexadecimal characters
- **SHA-1** — 40 hexadecimal characters
- **SHA-256** — 64 hexadecimal characters

Example:

```text
44d88612fea8a8f36de82e1278abb02f
0123456789abcdef0123456789abcdef01234567
0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

> Hashes are identified by format only. IOC Inspector does **not** claim that a hash is malicious simply because it matches a hash pattern.

---

## 🛡️ Defanged IOC handling

IOC Inspector restores common analyst-safe representations **before extraction**.

Examples:

| Defanged | Normalized |
|---|---|
| `hxxp://evil[.]example` | `http://evil.example` |
| `hxxps://evil(.)example` | `https://evil.example` |
| `evil{.}example` | `evil.example` |
| `analyst[at]example.org` | `analyst@example.org` |
| `ADMIN AT EXAMPLE DOT ORG` | `admin@example.org` |

The order is important:

```text
Defang → Extract → Normalize → Deduplicate → Score
```

Restoring defanged indicators **after** extraction would miss many intentionally obfuscated IOCs.

---

## 🧠 Risk scoring engine

The risk engine is deliberately **transparent and deterministic** rather than pretending to provide a definitive maliciousness verdict.

### Base scores

| IOC type | Base score |
|---|---:|
| IPv4 | 55 |
| Domain | 40 |
| URL | 50 |
| MD5 / SHA-1 / SHA-256 | 45 |
| Email | 25 |

Additional heuristic signals can increase or decrease the score.

### Signals considered

**Threat-related terms**

Examples include:

```text
malware
phish
evil
payload
botnet
c2
credential
ransom
trojan
dropper
stealer
exploit
```

**Higher-risk TLD patterns**

```text
.top
.xyz
.click
.zip
.mov
.tk
.pw
```

**URL characteristics**

- HTTPS receives a small transport adjustment.
- Userinfo in the URL authority increases the score.

**Domain structure**

- Deeply nested domains receive an additional heuristic adjustment.

### Severity bands

| Score | Severity | Interpretation |
|---:|---|---|
| **0–39** | 🟢 LOW | Lower-priority indicator |
| **40–64** | 🟡 MEDIUM | Worth analyst review |
| **65–84** | 🟠 HIGH | Higher-priority triage candidate |
| **85–100** | 🔴 CRITICAL | Highest-priority heuristic signal |

> **Important:** A score is a prioritization signal, **not proof of maliciousness**. A legitimate domain can receive a high score, and a malicious IOC can receive a lower score.

---

## 📊 Example analysis

Input:

```text
Incident note:
The workstation contacted hxxps://malware[.]example/download
from 185.220.101.1.
Contact: analyst[at]example.org
```

Conceptual output:

```text
IOC INSPECTOR
────────────────────────────────────────────────────────────────────────────────────────
TYPE       INDICATOR                                      SCORE  SEVERITY  CONF
────────────────────────────────────────────────────────────────────────────────────────
URL        https://malware.example/download                  70  HIGH      85%
IP         185.220.101.1                                     55  MEDIUM    95%
DOMAIN     malware.example                                   65  HIGH      85%
EMAIL      analyst@example.org                               25  LOW       85%
────────────────────────────────────────────────────────────────────────────────────────
4 indicator(s) detected
```

The exact findings depend on the input and the deterministic rules implemented in the current release.

---

## 🚀 Quick start

### Requirements

- Python **3.10+**
- Git

No commercial threat-intelligence API is required for the core workflow.

### 1. Clone

```bash
git clone https://github.com/devanshshukla-3004/IOC-Inspector.git
cd IOC-Inspector
```

### 2. Create a virtual environment

Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

macOS / Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the analyzer

```bash
python -m ioc_inspector.cli --text "185.220.101.1 hxxps://malware[.]example[.]com analyst[at]example[.]org"
```

---

## 💻 CLI usage

### Analyze raw text

```bash
python -m ioc_inspector.cli --text "Suspicious host: 185.220.101.1"
```

### Analyze one file

```bash
python -m ioc_inspector.cli --file samples/threat_report.txt
```

### Recursively analyze a directory

Only `.txt` and `.log` files are included:

```bash
python -m ioc_inspector.cli --directory ./samples
```

### Export JSON

```bash
python -m ioc_inspector.cli \
  --file samples/threat_report.txt \
  --json report.json
```

### Export CSV

```bash
python -m ioc_inspector.cli \
  --file samples/threat_report.txt \
  --csv report.csv
```

### Export both

```bash
python -m ioc_inspector.cli \
  --file samples/threat_report.txt \
  --json report.json \
  --csv report.csv
```

### Quiet / automation-friendly mode

Suppress the terminal table while still generating requested reports:

```bash
python -m ioc_inspector.cli \
  --file samples/threat_report.txt \
  --json report.json \
  --quiet
```

### CLI options

| Option | Purpose |
|---|---|
| `--text` | Analyze an inline text string |
| `--file` | Analyze one text file |
| `--directory` | Recursively analyze `.txt` / `.log` files |
| `--json` | Write a JSON report |
| `--csv` | Write a CSV report |
| `--quiet` | Suppress terminal result table |

Exactly one source option is required.

---

## 📦 Machine-readable output

JSON output contains both a summary and the individual indicators.

Example structure:

```json
{
  "summary": {
    "total": 2,
    "by_type": {
      "ip": 1,
      "domain": 1
    },
    "by_severity": {
      "medium": 1,
      "high": 1
    },
    "max_score": 65
  },
  "indicators": [
    {
      "value": "185.220.101.1",
      "ioc_type": "ip",
      "score": 55,
      "severity": "medium",
      "confidence": 95,
      "reason": "IP indicator"
    }
  ]
}
```

CSV output contains:

```text
value,ioc_type,score,severity,confidence,reason
```

This makes the project useful as a preprocessing component for a larger SOC, SIEM, threat-hunting, or analytics workflow.

---

## 🐍 Python API

The core engine can also be used directly from Python:

```python
from ioc_inspector.engine import analyze, analyze_many

text = """
Suspicious host: hxxps://malware[.]example/download
Source IP: 185.220.101.1
"""

results = analyze(text)

for item in results:
    print(
        item.ioc_type.value,
        item.value,
        item.score,
        item.severity.value,
    )
```

For multiple documents:

```python
from ioc_inspector.engine import analyze_many

documents = [
    "Host: 10.10.10.10",
    "URL: hxxps://example[.]org/login",
]

results = analyze_many(documents)
```

---

## 🏗️ Architecture

```text
                         ┌─────────────────────┐
                         │   Input Sources     │
                         │ text / file / batch │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │     Normalizer      │
                         │ defang + normalize  │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │     Extractor       │
                         │ IP / URL / domain   │
                         │ email / hashes      │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │   Analysis Engine   │
                         │ dedupe + classify   │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │     Risk Engine     │
                         │ score + severity    │
                         │ + explanation       │
                         └──────────┬──────────┘
                                    │
                     ┌──────────────┼──────────────┐
                     ▼              ▼              ▼
                 Terminal         JSON           CSV
```

### Design principles

- **Offline-first** — core analysis does not need network access.
- **Deterministic** — the same input and rules produce repeatable results.
- **Explainable** — scores include human-readable reasons.
- **Modular** — extraction, normalization, scoring, reporting, and CLI concerns are separated.
- **Testable** — core behavior is covered by automated tests.
- **Extensible** — enrichment providers and additional export formats can be added without replacing the core engine.

---

## 📁 Project structure

```text
IOC-Inspector/
│
├── .github/
│   └── workflows/
│       └── ci.yml
│
├── samples/
│   └── threat_report.txt
│
├── src/
│   └── ioc_inspector/
│       ├── __init__.py
│       ├── cli.py
│       ├── engine.py
│       ├── extractor.py
│       ├── models.py
│       ├── normalizer.py
│       ├── reporter.py
│       └── risk.py
│
├── tests/
│   ├── test_defanged_engine.py
│   ├── test_engine.py
│   ├── test_normalizer.py
│   ├── test_reporter.py
│   └── test_risk.py
│
├── .gitignore
├── LICENSE
├── pyproject.toml
├── README.md
└── requirements.txt
```

---

## 🧪 Testing

Run the complete test suite:

```bash
python -m pytest -q
```

The test suite covers areas including:

- IOC extraction
- IOC classification
- normalization
- defanged indicator handling
- risk scoring
- severity mapping
- report generation
- engine behavior

GitHub Actions is configured to test the project across:

```text
Python 3.10
Python 3.11
Python 3.12
Python 3.13
```

The CI badge at the top of this README reflects the current GitHub Actions state.

---

## 🔐 Security and privacy

IOC Inspector is intentionally **offline-first**.

The core analyzer:

- does not make requests to extracted domains;
- does not connect to IP addresses;
- does not query external reputation services;
- does not execute downloaded content;
- does not require API keys for local analysis.

This makes it suitable for safely inspecting copied threat reports and log excerpts without automatically interacting with potentially hostile infrastructure.

> **Note:** The project is an analysis utility, not a sandbox or malware execution environment.

---

## ⚠️ Limitations

The current release is intentionally lightweight.

It does **not**:

- prove that an IOC is malicious;
- perform live reputation lookups;
- execute or detonate files;
- perform network scanning;
- resolve domains or contact remote infrastructure;
- provide a full SIEM/SOC backend;
- replace professional threat-intelligence platforms.

Its risk engine is heuristic and should be treated as a **triage/prioritization layer**.

---

## 🗺️ Roadmap

### Current release

- [x] IPv4 extraction
- [x] Domain extraction
- [x] URL extraction
- [x] Email extraction
- [x] MD5 / SHA-1 / SHA-256 extraction
- [x] Defanged IOC restoration
- [x] Normalization
- [x] Deduplication
- [x] Explainable heuristic risk scoring
- [x] Severity classification
- [x] Confidence scoring
- [x] JSON reporting
- [x] CSV reporting
- [x] Recursive batch analysis
- [x] Automated testing
- [x] GitHub Actions CI

### Planned

- [ ] Optional VirusTotal / AbuseIPDB enrichment adapters
- [ ] STIX 2.1 export
- [ ] Streamlit analyst dashboard
- [ ] IOC relationship graph
- [ ] YARA/Sigma-oriented workflow integrations
- [ ] Additional IOC types such as IPv6 and MAC addresses
- [ ] Configurable scoring profiles
- [ ] Analyst-friendly filtering and severity views

---

## 📚 Learning outcomes

This project was built as **Day 06** of my **100 Days, 100 Cybersecurity Projects** challenge.

The project focuses on practical cybersecurity engineering concepts:

- threat-intelligence fundamentals
- IOC lifecycle and normalization
- defensive parsing of security data
- deterministic risk modeling
- explainable security heuristics
- CLI application design
- structured reporting
- automated testing
- CI/CD fundamentals
- modular Python architecture

---


## 📄 License

This project is released under the **MIT License**. See [LICENSE](LICENSE) for details.

---

## 👨‍💻 Author

**Devansh Shukla**

BTech CSE student • Cybersecurity • AI/Data Science

- GitHub: [@devanshshukla-3004](https://github.com/devanshshukla-3004)
- LinkedIn: [Devansh Shukla](https://www.linkedin.com/in/devansh-shukla-22b7a7429/)

---

## ⭐ Support the project

If this project is useful for your cybersecurity learning or portfolio:

- ⭐ Star the repository
- 🐛 Open an issue with improvements or bug reports
- 🔀 Submit a pull request
- 📢 Share the project with other security learners

> Built as part of **100 Days, 100 Cybersecurity Projects** — one practical security project at a time.

---

### ⚖️ Disclaimer

This project is intended for **defensive security research, education, incident-response preparation, and authorized analysis only**. Do not use it to interact with systems or infrastructure without appropriate authorization.

