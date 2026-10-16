# Phishing Scanner

钓鱼网址发现与检测工具，支持搜索引擎发现、URL 检测、页面特征分析、品牌仿冒识别、备案查询、基础设施关联和风险证据评分。

A phishing URL discovery and detection tool with search-engine discovery, URL analysis, page inspection, brand impersonation detection, ICP filing lookup, infrastructure correlation, and evidence-based risk scoring.

## 功能概览 / Features

- 从多个搜索引擎发现待检测 URL。
- Discover candidate URLs from multiple search engines.
- 使用本地恶意 URL 库和白名单进行前置分流。
- Route URLs through a local blocklist and whitelist before network analysis.
- 分析域名、URL、页面内容、链接、表单、脚本和下载行为。
- Analyze domains, URLs, page content, links, forms, scripts, and download behavior.
- 检测品牌仿冒、同形字符、混合脚本、Punycode 和伪造官方子域。
- Detect brand impersonation, homoglyphs, mixed scripts, Punycode, and fake official subdomains.
- 识别密码、验证码、支付卡、身份证、私钥和助记词等敏感信息采集。
- Detect collection of passwords, OTPs, payment card data, identity data, private keys, and seed phrases.
- 检测敏感表单外传、外域请求、外部 iframe、动态跳转和危险下载。
- Detect sensitive form exfiltration, cross-domain requests, external iframes, redirects, and dangerous downloads.
- 集成 WHOIS、RDAP、DNS、ASN、证书透明度和 ICP 备案信息。
- Integrate WHOIS, RDAP, DNS, ASN, certificate transparency, and ICP filing information.
- 使用 V2 证据引擎输出可解释的风险结论。
- Produce explainable verdicts through the V2 evidence engine.

## 工作流程 / Workflow

默认 URL 检测流程如下：

The default URL detection workflow is:

1. 规范化 URL 并提取注册域名。
   Normalize the URL and extract its registered domain.
2. 查询本地恶意 URL 库；命中后直接归类为已拦截。
   Check the local malicious URL database; matches are immediately classified as blocked.
3. 查询统一白名单；命中后归类为白名单。
   Check the unified whitelist; matches are classified as whitelisted.
4. 对公网目标执行受控 HTTP 抓取和重定向检查。
   Fetch public targets through a controlled HTTP client with redirect validation.
5. 分析域名、品牌、页面、链接、注册信息和基础设施信号。
   Analyze domain, brand, page, link, registration, and infrastructure signals.
6. 查询 ICP 备案，并将结果作为信任上下文使用。
   Query ICP filing information and use it as trust context.
7. 通过旧版风险评分和 V2 证据规则生成最终 verdict。
   Generate the final verdict with the legacy score and V2 evidence rules.

## 快速开始 / Quick Start

建议使用 Python 3.9 或更高版本。

Python 3.9 or later is recommended.

```bash
python -m pip install -r requirements.txt
```

运行命令行入口：

Run the CLI entry point:

```bash
python phishing_detector.py [query] [options]
```

默认搜索模式需要 `keywords.json`。配置文件可以是数组，也可以是包含 `keywords` 字段的对象：

The default search mode requires `keywords.json`. The file can be either a JSON array or an object containing a `keywords` field:

```json
{
  "keywords": [
    "银行登录",
    "在线客服",
    "账号验证"
  ]
}
```

`keywords.json` 可能属于本地运行配置，当前仓库可能不会提交它。也可以通过 `--keywords-config` 指定其他文件。

`keywords.json` may be treated as a local runtime configuration and may not be committed to the repository. Use `--keywords-config` to select another file.

## 命令行参数 / CLI Options

| 参数 / Option | 说明 / Description |
| --- | --- |
| `query` | 默认模式下是搜索关键词；`--icp` 模式下是 URL 或包含 URL 的文件路径。 / A search keyword by default, or a URL/file path in `--icp` mode. |
| `--search`, `-k` | 兼容旧用法；不带值时搜索全部关键词。 / Legacy search option; without a value, searches all configured keywords. |
| `--list-keywords` | 列出关键词配置。 / List configured keywords. |
| `-e`, `--engine` | 指定一个或多个搜索引擎。 / Select one or more search engines. |
| `-j`, `--json` | 以 JSON 格式输出。 / Print JSON output. |
| `-o`, `--output` | 将结果保存到 `output/`。 / Save results under `output/`. |
| `--keywords-config` | 指定关键词配置文件，默认是 `keywords.json`。 / Select the keyword configuration file; default: `keywords.json`. |
| `--providers-config` | 指定服务和运行配置文件，默认是 `providers.py`。 / Select the provider and runtime configuration; default: `providers.py`. |
| `--icp` | 启用独立 ICP 备案查询模式。 / Enable standalone ICP filing lookup. |
| `--url`, `-u` | 直接检测单个 URL 或 URL 文件。 / Directly scan a URL or a file containing URLs. |
| `--evaluate DATASET` | 对标注数据集计算 Precision、Recall、FPR、FNR 和混淆矩阵。 / Evaluate a labeled dataset with Precision, Recall, FPR, FNR, and a confusion matrix. |
| `--build-infra` | 从本地恶意 URL 库派生 `infra_knowledge.json`。 / Build `infra_knowledge.json` from the local malicious URL database. |

读取 URL 文件时，`--url` 和 `--icp` 会自动处理 UTF-8 BOM。

When reading URL files, `--url` and `--icp` automatically handle a UTF-8 BOM.

## 使用示例 / Examples

```bash
# 搜索全部关键词 / Search all configured keywords
python phishing_detector.py

# 搜索指定关键词 / Search for a specific keyword
python phishing_detector.py -k "银行登录"

# 指定搜索引擎 / Select search engines
python phishing_detector.py -k "账号验证" -e bing baidu

# 查询单个 URL 的 ICP 备案 / Look up ICP filing for one URL
python phishing_detector.py --icp https://example.com

# 查询文件中的 URL / Look up URLs from a file
python phishing_detector.py --icp urls.txt

# 直接检测单个 URL / Scan one URL directly
python phishing_detector.py --url https://example.com

# 检测 URL 文件并保存结果 / Scan a URL file and save results
python phishing_detector.py --url urls.txt --output

# 输出 JSON / Print JSON
python phishing_detector.py --url https://example.com --json

# 评估标注数据集 / Evaluate a labeled dataset
python phishing_detector.py --evaluate labeled_urls.json

# 构建基础设施知识库 / Build the infrastructure knowledge base
python phishing_detector.py --build-infra
```

## 风险判定 / Risk Verdicts

V2 证据引擎的规则目录位于 `evidence_rules.json`，当前规则版本由代码中的 `RULE_VERSION` 定义。引擎会综合以下证据组：

The V2 evidence rules are defined in `evidence_rules.json`. The active rule version is defined by `RULE_VERSION` in the code. The engine combines these evidence groups:

- `G1`：信誉和黑名单 / Reputation and blocklists
- `G2`：域名和 URL / Domain and URL signals
- `G3`：品牌仿冒 / Brand impersonation
- `G4`：页面内容 / Page content
- `G5`：凭据和敏感信息采集 / Credential and sensitive-data collection
- `G6`：外传、跳转和下载行为 / Exfiltration, redirect, and download behavior
- `G7`：基础设施和注册信息 / Infrastructure and registration information

主要 verdict 包括：

The main verdicts include:

- `SAFE`：安全 / Safe
- `UNKNOWN`：证据不足或无法判断 / Insufficient or unavailable evidence
- `SUSPICIOUS`：可疑 / Suspicious
- `HIGH_RISK`：高风险 / High risk
- `PHISHING`：钓鱼 / Phishing
- `MALWARE`：恶意软件相关 / Malware-related
- `SCAM`：诈骗相关 / Scam-related

命令行 URL 检测结果还会按 `已拦截`、`白名单` 和 `未拦截` 三类输出。品牌相似度本身不会直接构成拦截；敏感信息采集、外域提交、本地恶意库命中等直接证据具有更高优先级。

The CLI also groups URL scan results into `blocked`, `whitelisted`, and `unblocked`. Brand similarity alone does not directly trigger blocking; direct evidence such as sensitive-data collection, cross-domain submission, and local blocklist matches has higher priority.

## 配置 / Configuration

主要配置文件如下：

The main configuration files are:

- `providers.py`：搜索引擎、URL 库、ICP、缓存、基础设施和 Logo 配置。 / Search engines, URL database, ICP, cache, infrastructure, and logo settings.
- `brands.json`：品牌、别名和官方域名。 / Brands, aliases, and official domains.
- `evidence_rules.json`：V2 证据规则。 / V2 evidence rules.
- `risk_rules.json`：旧版风险权重和阈值。 / Legacy risk weights and thresholds.
- `whitelist.txt`：白名单。 / Whitelist.
- `infra_knowledge.json`：基础设施知识库。 / Infrastructure knowledge base.
- `keywords.json`：搜索关键词，通常作为本地配置使用。 / Search keywords, usually treated as local configuration.

### ICP API

项目支持本地 ICP 查询服务，并可使用 4759.cn API 作为 fallback。当前 API key 配置项位于 `providers.py` 的 `ICP_SERVICE.fallback_api.api_key`。

The project supports a local ICP lookup service and can use the 4759.cn API as a fallback. The current API key setting is `ICP_SERVICE.fallback_api.api_key` in `providers.py`.

请勿将真实 API key 提交到公开 Git 仓库。提交前应检查配置文件、提交历史和差异内容；当前实现不会自动从环境变量读取该 key。

Do not commit a real API key to a public Git repository. Check configuration files, commit history, and diffs before pushing; the current implementation does not automatically read this key from an environment variable.

### 本地恶意 URL 库 / Local URL Database

本地 URL 库默认由 `providers.py` 配置，通常指向项目外部的 `urldb` 目录。若本地库不可用，程序仍可执行其他分析，但本地黑名单前置分流不会生效。

The local URL database is configured in `providers.py` and commonly points to an external `urldb` directory. If it is unavailable, other analyses can still run, but local blocklist routing will not be available.

### 基础设施知识库 / Infrastructure Knowledge Base

执行以下命令可以从本地恶意 URL 库派生 `infra_knowledge.json`：

Run the following command to derive `infra_knowledge.json` from the local malicious URL database:

```bash
python phishing_detector.py --build-infra
```

派生过程会按多个恶意域名聚集情况建立 IP 和 ASN 关联，并过滤私有地址、回环地址和常见大型云服务 ASN，以降低共享主机误报。

The derivation process builds IP and ASN associations from clusters of malicious domains and filters private, loopback, and common large-cloud ASNs to reduce shared-hosting false positives.

## 网络安全边界 / Network Safety Boundaries

URL 检测默认拒绝回环、私有、链路本地、未分配和其他非公网地址。HTTP 抓取最多跟随 5 次重定向，并对每次重定向重新执行目标地址校验；正文最多读取 512 KiB，主要解析 HTML/XHTML。TLS 证书校验失败会作为风险信号记录。

By default, URL scanning rejects loopback, private, link-local, unassigned, and other non-public addresses. HTTP fetching follows at most five redirects and validates each redirect target again; response bodies are limited to 512 KiB and primarily parsed as HTML/XHTML. TLS certificate failures are recorded as risk signals.

请只对你有权检查的 URL 和数据运行扫描。

Only scan URLs and data that you are authorized to inspect.

## 输出字段 / Output Fields

结果通常包含以下信息：

Results commonly include:

- 请求 URL 和最终落地 URL：`requested_url`、`final_url`；
- Requested and final URLs: `requested_url`, `final_url`;
- 请求域名和最终域名：`requested_domain`、`final_domain`；
- Requested and final domains: `requested_domain`, `final_domain`;
- `verdict`、`risk_level`、`confidence`；
- `verdict`, `risk_level`, and `confidence`;
- V2 证据、证据组和证据摘要；
- V2 evidence items, evidence groups, and evidence summaries;
- 维度分数、Hard Rule 和兼容字段；
- Dimension scores, hard rules, and compatibility fields;
- ICP、WHOIS/RDAP、发现来源和错误信息。
- ICP, WHOIS/RDAP, discovery sources, and error information.

JSON 输出可以用于后续审查、评估和批量处理。运行 `--output` 时，结果会写入当前目录的 `output/` 文件夹。

JSON output can be used for review, evaluation, and batch processing. With `--output`, result files are written to the `output/` directory in the current working directory.

## 项目结构 / Project Structure

```text
phishing-scanner/
├── phishing_detector.py       # CLI entry point / 命令行入口
├── providers.py               # Runtime and provider configuration / 运行和服务配置
├── brands.json                # Brand definitions / 品牌定义
├── evidence_rules.json        # V2 evidence rules / V2 证据规则
├── risk_rules.json            # Legacy scoring rules / 旧版评分规则
├── requirements.txt           # Python dependencies / Python 依赖
├── tools/                     # Data-generation utilities / 数据生成工具
├── tests/                     # Regression tests / 回归测试
└── detector/
    ├── core.py                # Main detection workflow / 主检测流程
    ├── config.py              # Configuration loading / 配置加载
    ├── analyzers/             # URL, page, brand, link, and infrastructure analysis
    ├── cli/                   # CLI commands and reporting / 命令行和输出
    ├── discovery/             # URL discovery / URL 发现
    ├── engines/               # Search-engine adapters / 搜索引擎适配器
    ├── integrations/          # External service integrations / 外部服务集成
    ├── policy/                # Whitelist and URL database policy / 白名单和 URL 库策略
    ├── scoring/               # Risk and evidence scoring / 风险和证据评分
    └── utils/                 # Shared utilities / 通用工具
```

## 当前状态 / Current Status

核心检测流程、V2 证据规则、页面敏感信息识别、品牌仿冒分析、ICP 查询和基础设施分析已经集成到主流程中。实际扫描结果仍会受到搜索引擎、DNS、WHOIS/RDAP、ICP 服务和本地 URL 库可用性的影响。

The main detection workflow, V2 evidence rules, sensitive-data detection, brand impersonation analysis, ICP lookup, and infrastructure analysis are integrated. Actual scan results still depend on the availability of search engines, DNS, WHOIS/RDAP, ICP services, and the local URL database.
