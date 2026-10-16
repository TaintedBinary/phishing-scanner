# Phishing Scanner

A phishing URL discovery and detection tool for URL intelligence, page analysis, brand impersonation detection, and evidence-based risk scoring.

[中文文档](#中文文档)

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

## Usage

```bash
# Search all configured keywords
python phishing_detector.py

# Search for a specific keyword
python phishing_detector.py -k "bank login"

# Select search engines
python phishing_detector.py -k "account verification" -e bing baidu

# Look up ICP filing information for one URL
python phishing_detector.py --icp https://example.com

# Look up URLs from a file
python phishing_detector.py --icp urls.txt

# Scan one URL directly
python phishing_detector.py --url https://example.com

# Scan URLs from a file and save results under output/
python phishing_detector.py --url urls.txt --output

# Print JSON output
python phishing_detector.py --url https://example.com --json

# Evaluate a labeled dataset
python phishing_detector.py --evaluate labeled_urls.json

# Build the infrastructure knowledge base
python phishing_detector.py --build-infra
```

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

Do not commit a real API key to a public repository. The current implementation does not automatically read this key from an environment variable.

### Local URL database

The local URL database is configured in `providers.py` and commonly points to an external `urldb` directory. If it is unavailable, the remaining analyses can still run, but local blocklist routing will not be available.

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

## Development and Testing

Check Python syntax:

```bash
python -m compileall -q phishing_detector.py providers.py detector tools
```

Run the regression tests:

```bash
python -m pytest tests -q
```

An evaluation dataset can be a JSON array or an object containing a `samples` array. Each record must contain `url` and `label`. Supported labels include `phishing`/`safe`, `malicious`/`benign`, `true`/`false`, and `1`/`0`.

Before pushing changes, run the syntax check and test suite, then review the diff for credentials and local-only files.

---

## 中文文档

钓鱼网址发现与检测工具，支持搜索引擎发现、URL 检测、页面分析、品牌仿冒识别、ICP 备案查询、恶意基础设施关联和基于证据的风险评分。

### 功能

- 从多个搜索引擎发现待检测 URL。
- 使用本地恶意网址库和白名单进行前置分流。
- 分析域名、URL、页面内容、表单、链接、脚本、跳转和下载行为。
- 检测品牌仿冒、同形字符、混合脚本、Punycode 和伪造官方子域。
- 识别密码、验证码、支付卡、身份信息、私钥和助记词采集。
- 检测敏感表单外传、外域请求、外部 iframe、动态跳转和危险下载。
- 集成 WHOIS、RDAP、DNS、ASN、证书透明度和 ICP 备案信息。
- 使用 V2 证据引擎生成可解释的风险结论。

### 快速开始

建议使用 Python 3.9 或更高版本：

```bash
python -m pip install -r requirements.txt
```

默认搜索模式需要 `keywords.json`。配置文件可以是数组，也可以是包含 `keywords` 字段的对象：

```json
{
  "keywords": [
    "银行登录",
    "账号验证",
    "在线客服"
  ]
}
```

如果关键词文件名称或路径不同，可以使用 `--keywords-config` 指定。

### 常用命令

```bash
# 搜索全部关键词
python phishing_detector.py

# 搜索指定关键词
python phishing_detector.py -k "银行登录"

# 指定搜索引擎
python phishing_detector.py -k "账号验证" -e bing baidu

# 查询单个 URL 的 ICP 备案
python phishing_detector.py --icp https://example.com

# 检测单个 URL
python phishing_detector.py --url https://example.com

# 检测 URL 文件并保存结果
python phishing_detector.py --url urls.txt --output

# 输出 JSON
python phishing_detector.py --url https://example.com --json

# 评估标注数据集
python phishing_detector.py --evaluate labeled_urls.json

# 构建基础设施知识库
python phishing_detector.py --build-infra
```

### 风险结论

V2 证据引擎将信号归入以下证据组：

- `G1`：信誉和黑名单
- `G2`：域名和 URL
- `G3`：品牌仿冒
- `G4`：页面内容
- `G5`：凭据和敏感信息采集
- `G6`：外传、跳转和下载行为
- `G7`：基础设施和注册信息

主要 verdict 包括：`SAFE`、`UNKNOWN`、`SUSPICIOUS`、`HIGH_RISK`、`PHISHING`、`MALWARE` 和 `SCAM`。直接检测模式还会按“已拦截”“白名单”“未拦截”分类输出。

品牌相似度本身不会直接构成拦截；本地恶意库命中、敏感信息采集和外域提交等直接证据优先级更高。

### 配置和注意事项

主要配置文件是 `providers.py`、`brands.json`、`evidence_rules.json`、`risk_rules.json`、`whitelist.txt`、`infra_knowledge.json` 和 `keywords.json`。

ICP fallback API key 配置项为：

```text
ICP_SERVICE.fallback_api.api_key
```

不要把真实 API key 提交到公开仓库。当前实现不会自动从环境变量读取该 key。

本地恶意 URL 库通常位于项目外部的 `urldb` 目录，由 `providers.py` 配置。缺少该目录时，其他分析仍可运行，但本地黑名单前置分流不会生效。

URL 检测默认拒绝回环、私有、链路本地、未分配和其他非公网地址；最多跟随 5 次重定向，每次都会重新校验目标地址；响应正文最多读取 512 KiB，主要解析 HTML/XHTML。

### 开发与测试

```bash
# 检查 Python 语法
python -m compileall -q phishing_detector.py providers.py detector tools

# 运行回归测试
python -m pytest tests -q
```

评估数据集可以是 JSON 数组，也可以是包含 `samples` 数组的对象。每条记录需要包含 `url` 和 `label`，支持 `phishing`/`safe`、`malicious`/`benign`、`true`/`false` 和 `1`/`0`。
