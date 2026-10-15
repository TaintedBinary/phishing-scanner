# Phishing Scanner

钓鱼网址发现与检测工具。当前默认工作流是：

1. 读取关键字。
2. 调用搜索引擎发现 URL。
3. 对发现的 URL 先做本地网址库分流。
4. 未被本地库拦截的 URL 再进入白名单、页面、链接、注册信息和启发式特征检测。
5. 按风险等级输出结果。

## API 获取

```
获取网址：https://4759.cn/

在 `providers.py` 的 `ICP_SERVICE.fallback_api.api_key` 中配置 API key。该密钥不会从环境变量读取。
```
## 快速开始

安装依赖：

```bash
pip install -r requirements.txt
```


## 命令行参数

```bash
python phishing_detector.py [query] [options]
```

| 参数 | 说明 |
| --- | --- |
| `query` | 默认搜索模式下表示搜索关键字；`--icp` 模式下表示 URL 或包含 URL 的文件路径 |
| `--search`, `-k` | 兼容旧用法。不带参数时搜索全部关键字，带参数时搜索指定关键字 |
| `--list-keywords` | 列出 `keywords.json` 中配置的关键字 |
| `-e`, `--engine` | 指定搜索引擎，可传多个 |
| `-j`, `--json` | 以 JSON 格式输出 |
| `-o`, `--output` | 保存结果到 `output/` 目录 |
| `--keywords-config` | 指定关键字配置文件，默认 `keywords.json` |
| `--providers-config` | 指定服务配置文件，默认 `providers.py` |
| `--icp` | 启用独立 ICP 查询模式 |
| `--url`, `-u` | 直接检测指定 URL 或包含 URL 的文件路径，按已拦截/白名单/未拦截三类输出 |
| `--evaluate` | 检测标注 JSON 数据集并输出 Precision、Recall、FPR、FNR 和混淆矩阵 |
| `--build-infra` | 从本地恶意网址库解析 DNS/ASN，自动派生基础设施知识库 `infra_knowledge.json` 后退出 |

> **注意**：`--url` 和 `--icp` 模式读取文件时会自动处理 UTF-8 BOM（`\ufeff`），无需手动去除。



## 使用示例

```bash
# 搜索模式：搜索全部关键字
python phishing_detector.py

# 搜索模式：搜索指定关键字
python phishing_detector.py -k "银行登录"

# ICP 备案查询：查询单个 URL
python phishing_detector.py --icp https://example.com

# ICP 备案查询：查询文件中的 URL
python phishing_detector.py --icp urls.txt

# URL 检测：检测单个 URL，按三类输出
python phishing_detector.py --url https://example.com

# URL 检测：检测文件中的 URL，保存结果到文件
python phishing_detector.py --url urls.txt -o

# URL 检测：JSON 格式输出
python phishing_detector.py --url https://example.com -j

# 评估标注数据集
python phishing_detector.py --evaluate labeled_urls.json

# 从本地恶意网址库派生基础设施知识库（需真实 DNS，大库耗时数分钟）
python phishing_detector.py --build-infra
```

## 检测逻辑

普通检测会按下面顺序处理 URL：

1. 规范化 URL，提取主域名。
2. 查询本地 `urldb`，命中则标记为 `已拦截` 并结束。
3. 查询统一白名单，命中则标记为 `白名单` 并结束。
4. 通过受控 HTTP 客户端抓取页面：限制公网目标、逐跳重定向、响应类型和正文大小。
5. 独立查询 WHOIS 和 RDAP，并合并为统一注册信息；结果按 TTL 缓存。
6. 执行域名、品牌（UTS#39 skeleton 同形异义字/混脚本检测）、页面、链接、注册信息等启发式特征；比对页面 favicon 与品牌官方 favicon 的感知哈希（pHash）。
7. 基础设施层分析：解析 DNS A/AAAA/NS/MX/PTR、Cymru ASN、证书透明度（默认关闭），与本地知识库 `infra_knowledge.json` 比对。
8. 查询 ICP 备案；主域名存在官方备案则记录为信任上下文（不影响风险分）。
9. 按 Domain、Brand、Content、Behavior 四个维度计算最高 17 分并执行 Hard Rule（HR-01~HR-07）。
10. V2 证据引擎（`evidence_rules.json`，规则版本 2.1.0）将全部信号归入 G1~G7 证据组并产出最终判定。

**正式判定以 V2 verdict 为准**：`PHISHING`（钓鱼）、`MALWARE`（恶意软件，仿冒上下文诱导下载）、`SCAM`（诈骗，中奖/解冻话术配合支付或个人信息采集）。四维风险分和旧字段仅作为对照保留。

判定优先级：E4 直接证据（本地库、助记词采集、外域提交敏感表单、带 verdict 的 Hard Rule）> 多强组融合（≥2 个强组且含攻击组 → PHISHING）> 弱证据组合。**品牌相似单独不构成拦截**；ICP 备案仅降级启发式组合（PHISHING/HIGH_RISK → SUSPICIOUS），不能覆盖直接攻击证据。

最终输出按 verdict 映射为风险等级：

- `安全`
- `可疑`
- `高风险`
- `高置信钓鱼`
- `恶意软件`
- `诈骗`

本地库命中的结果会单独归类为：

- `已拦截`

白名单命中的结果会在普通输出前被过滤，不作为风险结果展示。

## 基础设施知识库（infra_knowledge.json）

本地恶意网址库回答"这个域名是否已知恶意"，而基础设施知识库捕获**换域名不换基础设施**的攻击：新注册域名解析到已知恶意 IP 或托管在滥用 ASN 时，产生 INFRA-502~505 证据（E3 融合级，不单独拦截）。

知识库无需手工维护，由本地恶意网址库自动派生：

```bash
python phishing_detector.py --build-infra
```

派生规则（`providers.py` 的 `INFRASTRUCTURE` 段可调）：

- 一个 IP 上聚集 ≥2 个恶意域名才进入 `bad_ips`（防共享主机误伤）；
- 一个 ASN 聚集 ≥3 个恶意域名才进入 `bad_asns`；
- Cloudflare/AWS/阿里云/腾讯云/国内运营商等大型 ASN 永不进入 `bad_asns`；
- 私有/回环地址自动过滤，单个域名解析失败不中断；
- 与现有知识库**合并写入**，手工添加的条目永不丢失。

## 项目结构

```text
phishing-scanner/
├── phishing_detector.py       # CLI 启动器
├── brands.json                # 品牌、别名与官方注册域配置
├── evidence_rules.json        # V2 证据规则目录（规则版本 2.1.0）
├── risk_rules.json            # 四维上限、等级阈值和特征权重
├── keywords.json              # 搜索关键字配置
├── providers.py               # 搜索、分流、ICP、缓存、基础设施、Logo 配置
├── icp_records.json           # ICP 备案信息缓存
├── infra_knowledge.json       # 恶意基础设施知识库（--build-infra 自动派生）
├── whitelist.txt              # 白名单
├── requirements.txt           # Python 依赖
├── README.md
├── tools/                     # 数据生成脚本（confusables 表等）
├── tests/                     # pytest 回归测试（139 条，全离线）
└── detector/
    ├── __init__.py
    ├── core.py                # PhishingDetector 主检测流程
    ├── config.py              # 配置加载和路径解析
    ├── analyzers/             # 本地特征分析（含 infra/logo 分析器）
    ├── cli/                   # 命令行应用层
    ├── discovery/             # URL 发现入口
    ├── engines/               # 搜索引擎实现
    ├── integrations/          # ICP、WHOIS、RDAP、DNS、ASN、CT、infra_mining 等外部服务集成
    ├── policy/                # 白名单、本地 URL 库等策略
    ├── scoring/               # V2 证据引擎与评分策略
    └── utils/                 # 通用工具（缓存、UTS#39 skeleton、解码）
```

注意：`urldb` 当前是外部库目录，默认位于 `D:/hr_repositories/urldb`，不要求放在当前项目目录中。品牌官方资产维护在 `brands.json`，评分权重和阈值维护在 `risk_rules.json`。

## 网络安全边界

URL 检测默认拒绝回环、私有、链路本地、未分配和其他非公网地址；最多跟随 5 次重定向，每次重定向都会重新进行 DNS 和公网地址校验；仅解析 HTML/XHTML，并最多读取 512 KiB 页面内容。TLS 证书校验失败会记录为中风险信号，不会关闭证书校验。

## 结果字段

结果同时保存 `requested_url`/`requested_domain` 和最终 `final_url`/`final_domain`。跨注册域重定向会进入证据链，并对最终域名重新执行本地网址库和白名单检查。评分输出包含四维分数、封顶后的风险分、Hard Rule 编号和可解释证据。

## 开发与测试

评估数据集可以是 JSON 数组，也可以是包含 `samples` 数组的对象。每项必须包含 `url` 和 `label`；`label` 可使用 `phishing`/`safe`、`malicious`/`benign`、`true`/`false` 或 `1`/`0`。正样本风险等级包含 `高风险`、`钓鱼`、`高置信钓鱼`、`恶意软件`、`诈骗`、`已拦截`。
