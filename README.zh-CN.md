# Phishing Scanner

钓鱼网址发现与检测工具，支持搜索引擎发现、URL 检测、页面分析、品牌仿冒识别、ICP 备案查询、恶意基础设施关联和基于证据的风险评分。

[English](README.md)

## 功能概览

- 从多个搜索引擎发现待检测 URL。
- 使用本地恶意网址库和白名单进行前置分流。
- 分析域名、URL、页面内容、表单、链接、脚本、跳转和下载行为。
- 检测品牌仿冒、同形字符、混合脚本、Punycode 和伪造官方子域。
- 识别密码、验证码、支付卡、身份信息、私钥和助记词采集。
- 检测敏感表单外传、外域请求、外部 iframe、动态跳转和危险下载。
- 集成 WHOIS、RDAP、DNS、ASN、证书透明度和 ICP 备案信息。
- 使用 V2 证据引擎生成可解释的风险结论。

## 快速开始

建议使用 Python 3.9 或更高版本：

```bash
python -m pip install -r requirements.txt
```

运行命令行入口：

```bash
python phishing_detector.py [query] [options]
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


### 命令行参数

| 参数 | 说明 |
| --- | --- |
| `query` | 默认模式下是搜索关键词；`--icp` 模式下是 URL 或包含 URL 的文件路径。 |
| `--search`, `-k` | 不带值时搜索全部关键词，带值时搜索指定关键词。 |
| `--list-keywords` | 列出已配置的关键词。 |
| `-e`, `--engine` | 指定一个或多个搜索引擎。 |
| `-j`, `--json` | 输出 JSON。 |
| `-o`, `--output` | 将结果保存到 `output/`。 |
| `--keywords-config` | 关键词配置文件，默认是 `keywords.json`。 |
| `--providers-config` | 服务和运行配置文件，默认是 `providers.py`。 |
| `--icp` | 启用独立 ICP 备案查询。 |
| `--url`, `-u` | 直接检测单个 URL 或 URL 文件。 |
| `--evaluate DATASET` | 计算 Precision、Recall、FPR、FNR 和混淆矩阵。 |
| `--build-infra` | 从本地恶意 URL 库派生 `infra_knowledge.json`。 |

读取 URL 文件时，`--url` 和 `--icp` 会自动处理 UTF-8 BOM。

## 检测流程

普通 URL 检测会按以下顺序执行：

1. 规范化 URL 并提取注册域名。
2. 查询本地恶意 URL 库，命中后归类为已拦截。
3. 查询白名单，命中后归类为白名单。
4. 通过受控 HTTP 客户端抓取公网目标，并校验重定向目标。
5. 执行域名、品牌、页面、链接、注册信息、Logo 和基础设施分析。
6. 查询 ICP 备案，并将结果作为信任上下文使用。
7. 通过旧版评分层和 V2 证据引擎生成最终结论。

V2 证据引擎将信号归入以下证据组：

- `G1`：信誉和黑名单
- `G2`：域名和 URL
- `G3`：品牌仿冒
- `G4`：页面内容
- `G5`：凭据和敏感信息采集
- `G6`：外传、跳转和下载行为
- `G7`：基础设施和注册信息

主要 verdict 包括：

- `SAFE`：安全
- `UNKNOWN`：证据不足或无法判断
- `SUSPICIOUS`：可疑
- `HIGH_RISK`：高风险
- `PHISHING`：钓鱼
- `MALWARE`：恶意软件相关
- `SCAM`：诈骗相关

直接检测模式还会按“已拦截”“白名单”和“未拦截”分类输出。品牌相似度本身不会直接构成拦截；本地恶意库命中、敏感信息采集和外域提交等直接证据优先级更高。

## 配置

主要配置文件如下：

| 文件 | 用途 |
| --- | --- |
| `providers.py` | 搜索引擎、URL 库、ICP、缓存、基础设施和 Logo 配置。 |
| `brands.json` | 品牌、别名和官方域名。 |
| `evidence_rules.json` | V2 证据规则。 |
| `risk_rules.json` | 旧版风险权重和阈值。 |
| `whitelist.txt` | 白名单。 |
| `infra_knowledge.json` | 已知恶意基础设施。 |
| `keywords.json` | 搜索关键词，通常作为本地运行配置。 |

### ICP 查询

项目支持本地 ICP 查询服务，也可以使用 4759.cn API 作为 fallback。API key 配置项为：

```text
ICP_SERVICE.fallback_api.api_key
```

### 本地 URL 库

本地 URL 库由 `providers.py` 配置，通常位于项目外部的 `urldb` 目录。缺少该目录时，其他分析仍可运行，但本地黑名单前置分流不会生效。

`URL_DATABASE.subdirs` 同时支持目录和单个文件，仅用于扫描时的本地黑名单前置分流。如果需要单独指定文件供 `--build-infra` 派生基础设施知识库使用，可以配置 `URL_DATABASE.files`（相对于 root，也支持绝对路径）：

### 基础设施知识库

使用以下命令构建或更新基础设施知识库：

```bash
python phishing_detector.py --build-infra
```

派生过程会根据多个恶意域名的 IP 和 ASN 聚集情况建立关联，并过滤私有地址、回环地址和常见大型云服务 ASN，以降低共享主机误报。

## 输出结果

JSON 结果可能包含：

- `requested_url` 和 `final_url`
- `requested_domain` 和 `final_domain`
- `verdict`、`risk_level` 和 `confidence`
- V2 证据、证据组和证据摘要
- 旧版维度分数和 Hard Rule
- ICP、WHOIS/RDAP 信息
- 发现来源和错误信息

使用 `--output` 时，结果会写入当前工作目录的 `output/` 文件夹。

## 网络安全边界

URL 检测默认拒绝回环、私有、链路本地、未分配和其他非公网地址。HTTP 抓取最多跟随 5 次重定向，并对每次重定向重新校验目标地址；响应正文最多读取 512 KiB，主要解析 HTML/XHTML。TLS 证书校验失败会作为风险信号记录。

请只对你有权检查的 URL 和数据运行扫描。

## 项目结构

```text
phishing-scanner/
├── phishing_detector.py       # 命令行入口
├── providers.py               # 运行和服务配置
├── brands.json                # 品牌定义
├── evidence_rules.json        # V2 证据规则
├── risk_rules.json            # 旧版评分规则
├── requirements.txt           # Python 依赖
├── tools/                     # 数据生成工具
├── tests/                     # 回归测试
└── detector/
    ├── core.py                # 主检测流程
    ├── config.py              # 配置加载
    ├── analyzers/             # URL、页面、品牌、链接和基础设施分析
    ├── cli/                   # 命令行和结果输出
    ├── discovery/             # URL 发现
    ├── engines/               # 搜索引擎适配器
    ├── integrations/          # 外部服务集成
    ├── policy/                # 白名单和 URL 库策略
    ├── scoring/               # 风险和证据评分
    └── utils/                 # 通用工具
```
