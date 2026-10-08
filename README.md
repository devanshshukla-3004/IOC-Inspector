# IOC Inspector

**IOC Inspector** is a lightweight threat-intelligence engine for extracting, classifying, normalizing, and risk-scoring Indicators of Compromise (IOCs).

> Day 06 of the **100 Days, 100 Cybersecurity Projects** challenge.

## What it does

IOC Inspector accepts raw security text and identifies:

- IPv4 and IPv6 addresses
- Domains
- URLs
- MD5, SHA-1, and SHA-256 hashes
- Email addresses

It then normalizes indicators, removes duplicates, classifies them, and produces a deterministic risk assessment.

## Architecture

```
Raw Text
   │
   ▼
Extractor → Normalizer → Classifier → Risk Engine → Report
```

## Quick start

```bash
python -m pip install -r requirements.txt
python -m ioc_inspector.cli --text "Failed connection to 185.220.101.1 from evil-example.test"
```

## Example

```text
IOC INSPECTOR
────────────────────────────────────────
IP       185.220.101.1       HIGH
DOMAIN   evil-example.test   MEDIUM
────────────────────────────────────────
2 indicators detected
```

## Project status

Day 06 implementation is intentionally offline-first: no commercial threat-intelligence API is required for the core engine.

## Disclaimer

This project is for defensive security research, education, and authorized analysis only.
