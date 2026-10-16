# Phishing Scanner

A phishing URL discovery and detection tool for URL intelligence, page analysis, brand impersonation detection, and evidence-based risk scoring.

[简体中文](README.zh-CN.md)

## Features

- Discover candidate URLs through multiple search engines.
- Route URLs through a local malicious URL database and whitelist before deeper analysis.
- Analyze URL, domain, page content, forms, links, scripts, redirects, downloads, and external requests.
- Detect brand impersonation, homoglyphs, mixed scripts, Punycode, and fake official subdomains.
- Detect collection of passwords, OTPs, payment-card data, identity data, private keys, and seed phrases.
- Detect sensitive form submissions, cross-domain exfiltration, external iframes, redirects, and dangerous downloads.
- Integrate WHOIS, RDAP, DNS, ASN, certificate-transparency, and ICP filing signals.
- Correlate suspicious domains with known malicious infrastructure.
- Produce explainable results through the V2 evidence engine.

## Quick Start

Python 3.9 or later is recommended.

```bash
python -m pip install -r requirements.txt
```

Run the CLI:

```bash
python phishing_detector.py [query] [options]
```

The default search workflow reads `keywords.json`. The file can be a JSON array or an object with a `keywords` field:

```json
{
  "keywords": [
    "bank login",
    "account verification",
    "online customer service"
  ]
}
```

Use `--keywords-config` if your keyword file has another name or location.


### CLI options

| Option | Description |
| --- | --- |
| `query` | Search keyword by default; URL or URL-file path in `--icp` mode. |
| `--search`, `-k` | Search all keywords when used without a value, or search the specified keyword. |
| `--list-keywords` | List configured keywords. |
| `-e`, `--engine` | Select one or more search engines. |
| `-j`, `--json` | Print JSON output. |
| `-o`, `--output` | Save results under `output/`. |
| `--keywords-config` | Keyword configuration file; default: `keywords.json`. |
| `--providers-config` | Provider and runtime configuration; default: `providers.py`. |
| `--icp` | Run standalone ICP filing lookup. |
| `--url`, `-u` | Scan one URL or a file containing URLs. |
| `--evaluate DATASET` | Calculate Precision, Recall, FPR, FNR, and a confusion matrix. |
| `--build-infra` | Derive `infra_knowledge.json` from the local malicious URL database. |

`--url` and `--icp` automatically handle UTF-8 BOM when reading URL files.

## Detection Pipeline

For a normal URL scan, the detector:

1. Normalizes the URL and extracts the registered domain.
2. Checks the local malicious URL database. A match is classified as blocked.
3. Checks the whitelist. A match is classified as whitelisted.
4. Fetches public targets through a controlled HTTP client and validates redirect targets.
5. Runs domain, brand, page, link, registration, Logo, and infrastructure analysis.
6. Looks up ICP filing information and uses it as trust context.
7. Combines the collected signals through the legacy scoring layer and the V2 evidence engine.

The V2 evidence engine groups signals into:

- `G1`: Reputation and blocklists
- `G2`: Domain and URL signals
- `G3`: Brand impersonation
- `G4`: Page content
- `G5`: Credential and sensitive-data collection
- `G6`: Exfiltration, redirects, and downloads
- `G7`: Infrastructure and registration information

The main verdicts are:

- `SAFE`
- `UNKNOWN`
- `SUSPICIOUS`
- `HIGH_RISK`
- `PHISHING`
- `MALWARE`
- `SCAM`

The direct URL CLI additionally groups results into `blocked`, `whitelisted`, and `unblocked`. Brand similarity alone does not directly trigger blocking; direct evidence such as local blocklist matches, sensitive-data collection, and cross-domain submission has higher priority.

## Configuration

The main configuration files are:

| File | Purpose |
| --- | --- |
| `providers.py` | Search engines, URL database, ICP, cache, infrastructure, and Logo settings. |
| `brands.json` | Brand aliases and official domains. |
| `evidence_rules.json` | V2 evidence rules. |
| `risk_rules.json` | Legacy risk weights and thresholds. |
| `whitelist.txt` | Whitelisted domains and URLs. |
| `infra_knowledge.json` | Known malicious infrastructure. |
| `keywords.json` | Search keywords, usually kept as local runtime configuration. |

### ICP lookup

The project supports a local ICP lookup service and can use the 4759.cn API as a fallback. The fallback API key is configured at:

```text
ICP_SERVICE.fallback_api.api_key
```

### Local URL database

The local URL database is configured in `providers.py` and commonly points to an external `urldb` directory. If it is unavailable, the remaining analyses can still run, but local blocklist routing will not be available.

`URL_DATABASE.subdirs` accepts both directories and individual files. Use `URL_DATABASE.files` when you want to list selected files explicitly:


### Infrastructure knowledge base

Build or update the infrastructure knowledge base with:

```bash
python phishing_detector.py --build-infra
```

The derivation process builds IP and ASN associations from clusters of malicious domains and filters private, loopback, and common large-cloud ASNs to reduce shared-hosting false positives.

## Output

JSON results may include:

- `requested_url` and `final_url`
- `requested_domain` and `final_domain`
- `verdict`, `risk_level`, and `confidence`
- V2 evidence items, groups, and summaries
- Legacy dimension scores and hard rules
- ICP and WHOIS/RDAP information
- Discovery sources and error details

When `--output` is used, result files are written to the `output/` directory in the current working directory.

## Network Safety Boundaries

By default, URL scanning rejects loopback, private, link-local, unassigned, and other non-public addresses. HTTP fetching follows at most five redirects and validates every redirect target again. Response bodies are limited to 512 KiB and primarily parsed as HTML/XHTML. TLS certificate failures are recorded as risk signals.

Only scan URLs and data that you are authorized to inspect.

## Project Structure

```text
phishing-scanner/
├── phishing_detector.py       # CLI entry point
├── providers.py               # Runtime and provider configuration
├── brands.json                # Brand definitions
├── evidence_rules.json        # V2 evidence rules
├── risk_rules.json            # Legacy scoring rules
├── requirements.txt           # Python dependencies
├── tools/                     # Data-generation utilities
├── tests/                     # Regression tests
└── detector/
    ├── core.py                # Main detection workflow
    ├── config.py              # Configuration loading
    ├── analyzers/             # URL, page, brand, link, and infrastructure analysis
    ├── cli/                   # CLI commands and reporting
    ├── discovery/             # URL discovery
    ├── engines/               # Search-engine adapters
    ├── integrations/          # External service integrations
    ├── policy/                # Whitelist and URL database policy
    ├── scoring/               # Risk and evidence scoring
    └── utils/                 # Shared utilities
```