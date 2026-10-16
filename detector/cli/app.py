"""Command-line application entry point."""
import argparse
import json
import logging
import os
import re
import sys
from datetime import datetime

from detector import PhishingDetector
from detector.config import load_string_list
from detector.cli.icp import run_icp_query
from detector.cli.reporting import format_brief_results, sort_results
from detector.cli.search import run_keyword_search
from detector.evaluation import evaluate_detector, load_labeled_dataset


BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_WHITELIST_PATH = os.path.join(BASE_DIR, 'whitelist.txt')

URL_CHECK_CATEGORIES = ('已拦截', '白名单', '未拦截')
# 输出文件名一律使用 ASCII，避免 Windows 控制台编码把中文文件名写成乱码
OUTPUT_FILENAMES = {
    '已拦截': 'blocked',
    '白名单': 'whitelisted',
    '未拦截': 'unblocked',
}
URL_REGEX = re.compile(r'(?:https?://|www\.)[^\s<>"\']+')
DOMAIN_REGEX = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}(?:/.*)?$')


def build_parser():
    parser = argparse.ArgumentParser(description='钓鱼网址检测工具')
    parser.add_argument('query', nargs='?', help='搜索关键词，或 --icp 模式下的 URL/文件路径')
    parser.add_argument('-o', '--output', nargs='?', const=True, default=False,
                        help='保存检测结果到当前目录下的 output 文件夹')
    parser.add_argument('--search', '-k', nargs='?', const='__all__', default=None,
                        help='兼容旧用法：不带参数时搜索全部关键词，带参数时搜索指定关键词')
    parser.add_argument('--list-keywords', action='store_true', help='列出关键词配置文件中的关键词')
    parser.add_argument('-e', '--engine', nargs='+', default=None,
                        help='搜索引擎 (google bing baidu duckduckgo sogou)')
    parser.add_argument('--icp', action='store_true',
                        help='通过本地 ICP_Query 服务查询指定URL或文件中的URL')
    parser.add_argument('--keywords-config', default='keywords.json',
                        help='关键词配置文件路径')
    parser.add_argument('--providers-config', default='providers.py',
                        help='搜索、反向WHOIS接口配置文件路径')
    parser.add_argument('--url', '-u', default=None,
                        help='直接检测指定URL或包含URL的文件路径，按已拦截/白名单/未拦截三类输出')
    parser.add_argument('--evaluate', metavar='DATASET',
                        help='检测标注 JSON 数据集并输出 Precision/Recall/FPR/FNR')
    parser.add_argument('--build-infra', action='store_true',
                        help='从本地恶意网址库解析 DNS/ASN 派生基础设施知识库 '
                             '(infra_knowledge.json) 后退出')
    return parser


def main(argv=None):
    _configure_console_encoding()
    logging.getLogger().setLevel(logging.ERROR)
    args = build_parser().parse_args(argv)

    if args.list_keywords:
        list_keywords(args.keywords_config)
        return

    if args.icp:
        if not args.query:
            print("错误: --icp 模式需要提供URL或文件路径")
            return
        run_icp_query(args.query, args, BASE_DIR)
        return

    if args.build_infra:
        try:
            run_build_infra(args.providers_config)
        except ValueError as exc:
            print(f'错误: {exc}')
        return

    with PhishingDetector(
            DEFAULT_WHITELIST_PATH, providers_path=args.providers_config) as detector:
        if args.evaluate:
            try:
                samples = load_labeled_dataset(args.evaluate)
                report = evaluate_detector(detector, samples)
            except (OSError, ValueError) as exc:
                print(f'评估失败: {exc}')
                return
            print(json.dumps(report, ensure_ascii=False, indent=2))
            return

        if args.url:
            urls = load_urls_from_input(args.url)
            if not urls:
                print("错误: 未找到有效URL")
                return
            results = detector.batch_detect(urls)
            output_url_check_results(results, args, BASE_DIR)
            return

        try:
            results = run_keyword_search(detector, args.query, args.search, args)
        except ValueError as exc:
            print(f"读取搜索配置失败: {exc}")
            return

        output_detection_results(results, args, BASE_DIR)


def _configure_console_encoding():
    if os.name != 'nt':
        return
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, 'reconfigure', None)
        if callable(reconfigure):
            reconfigure(encoding='utf-8', errors='replace')


def list_keywords(config_path):
    try:
        keywords = load_string_list(config_path, 'keywords')
    except ValueError as exc:
        print(f"读取关键词配置失败: {exc}")
        return

    print(f"\n配置文件中的关键词 ({len(keywords)} 个):")
    for keyword in keywords:
        print(f"  - {keyword}")


def output_detection_results(results, args, base_dir):
    filtered_results = [
        r for r in results
        if not r.get('whitelisted') and r.get('risk_level') != '白名单'
    ]

    if args.output:
        try:
            output_dir = os.path.join(os.getcwd(), 'output')
            os.makedirs(output_dir, exist_ok=True)
            saved_paths = save_split_detection_results(filtered_results, output_dir)
            if saved_paths:
                print("结果已保存到:")
                for path in saved_paths:
                    print(f"  {path}")
            else:
                print("本次无检测结果，未生成文件")
        except Exception as exc:
            print(f"错误: 保存文件失败 - {exc}")
        return

    output = render_detection_results(filtered_results)
    print(output)


def render_detection_results(results):
    return format_brief_results(sort_results(results))


def save_split_detection_results(results, output_dir=None):
    output_dir = output_dir or os.path.join(os.getcwd(), 'output')
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    blocked_results, unblocked_results = split_blocked_results(results)
    files = [
        (f'blocked_{timestamp}.txt', blocked_results),
        (f'unblocked_{timestamp}.txt', unblocked_results),
    ]

    saved_paths = []
    for filename, subset in files:
        if not subset:
            continue
        filepath = os.path.join(output_dir, filename)
        with open(filepath, 'w', encoding='utf-8') as handle:
            handle.write(render_detection_results(subset))
        saved_paths.append(filepath)
    return saved_paths


def split_blocked_results(results):
    """Split search output using the formal V2 interception decision."""
    from detector.cli.reporting import BLOCKING_VERDICTS

    blocked = []
    unblocked = []
    for result in results:
        if (result.get('blocked')
                or result.get('risk_level') == '已拦截'
                or result.get('verdict') in BLOCKING_VERDICTS):
            blocked.append(result)
        else:
            unblocked.append(result)
    return blocked, unblocked


def run_build_infra(providers_config, dns_lookup=None, asn_lookup=None):
    """Derive infra_knowledge.json from the local malicious URL database.

    Resolves every URL-database domain (DNS A/AAAA + Cymru ASN) and
    aggregates shared infrastructure into the knowledge base used by G7
    evidence.  Lookups are injectable for offline testing.
    """
    from detector.analyzers.infra import load_knowledge_base
    from detector.config import (
        load_infrastructure_config, load_url_database_config,
    )
    from detector.integrations import infra_mining
    from detector.integrations.asn import ASNLookup
    from detector.integrations.dns_records import DNSRecordLookup
    from detector.policy.url_database import URLBlocklist

    url_config = load_url_database_config(providers_config)
    database = URLBlocklist(
        url_config.get('file_paths', []), enabled=url_config.get('enabled', True))
    domains = sorted(database.entries)
    if not domains:
        print('错误: 本地恶意网址库为空，无法派生基础设施知识库')
        for path in url_config.get('file_paths', []):
            print(f'  已配置文件: {path}')
        return

    infra_config = load_infrastructure_config(providers_config)
    dns_lookup = dns_lookup or DNSRecordLookup(
        timeout=infra_config['dns_timeout'])
    asn_lookup = asn_lookup or ASNLookup(timeout=infra_config['asn_timeout'])

    print(f'恶意域名 {len(domains)} 个，开始解析 DNS/ASN（可能需要数分钟）...')
    result = infra_mining.derive_knowledge(
        domains, dns_lookup, asn_lookup,
        min_domains_per_ip=infra_config['derive_min_domains_per_ip'],
        min_domains_per_asn=infra_config['derive_min_domains_per_asn'],
        excluded_asns=infra_config['derive_excluded_asns'],
    )
    stats = result['stats']
    output_path = infra_config['knowledge_base_path']
    existing = load_knowledge_base(output_path)
    merged = infra_mining.merge_knowledge(existing, result['knowledge'])
    infra_mining.write_knowledge(output_path, merged)

    holders = stats.get('asn_holders') or {}
    print(f'\n派生完成，已写入 {output_path}')
    print(f'  解析成功域名:   {stats["resolved_domains"]}/{stats["total_domains"]}')
    print(f'  独立 IP:        {stats["distinct_addresses"]}')
    print(f'  bad_ips:        {stats["bad_ips"]} 个'
          f'（≥{infra_config["derive_min_domains_per_ip"]} 个恶意域名聚集）')
    print(f'  bad_asns:       {stats["bad_asns"]} 个'
          f'（≥{infra_config["derive_min_domains_per_asn"]} 个恶意域名聚集）')
    for asn in merged['bad_asns']:
        print(f'    AS{asn} {holders.get(asn, "")}'.rstrip())
    excluded = stats.get('excluded_asns') or []
    if excluded:
        print(f'  已排除大型 CDN/云 ASN: {", ".join("AS" + a for a in excluded)}')
    print(f'  bad_domains:    {len(merged["bad_domains"])} 个（含原有条目）')
    return merged


def load_urls_from_input(input_value):
    """Load URLs from a URL string or a file containing URLs."""
    input_value = str(input_value).strip()
    if not input_value:
        return []

    if input_value.startswith(('http://', 'https://', 'www.')):
        return [input_value]

    if os.path.isfile(input_value):
        with open(input_value, 'r', encoding='utf-8-sig', errors='ignore') as handle:
            content = handle.read()
        urls = []
        for match in URL_REGEX.findall(content):
            url = match.rstrip('.,;:!?')
            if url.startswith('www.'):
                url = 'http://' + url
            urls.append(url)
        if not urls:
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith('#') and '://' not in line and DOMAIN_REGEX.match(line):
                    urls.append(line)
        return urls

    return [input_value]


def url_check_category(result):
    """Categorize by the V2 decision, preserving whitelist compatibility.

    ``blocked`` records are always intercepted.  V2 PHISHING/MALWARE/SCAM
    are also interception decisions even when they were inferred from page
    evidence rather than a local blocklist.  HIGH_RISK/SUSPICIOUS remain
    review results.
    """
    from detector.cli.reporting import BLOCKING_VERDICTS

    if result.get('blocked') or result.get('risk_level') == '已拦截':
        return '已拦截'
    if result.get('whitelisted') or result.get('risk_level') == '白名单':
        return '白名单'
    if result.get('verdict') in BLOCKING_VERDICTS:
        return '已拦截'
    return '未拦截'


def group_url_check_results(results):
    groups = {cat: [] for cat in URL_CHECK_CATEGORIES}
    for result in results:
        groups[url_check_category(result)].append(result)
    return groups


def format_url_check_categories(results):
    """Group results into 已拦截/白名单/未拦截 and render each as brief lines."""
    groups = group_url_check_results(results)
    sections = []
    for category in URL_CHECK_CATEGORIES:
        subset = sort_results(groups[category])
        if not subset:
            continue
        lines = [f"# {category}网址 ({len(subset)})"]
        lines.extend(format_brief_result(r) for r in subset)
        sections.append('\n'.join(lines))
    return '\n'.join(sections)


def format_url_check_results(results):
    return format_brief_results(sort_results(results))


def output_url_check_results(results, args, base_dir):
    if args.output:
        try:
            output_dir = os.path.join(os.getcwd(), 'output')
            os.makedirs(output_dir, exist_ok=True)
            saved_paths = save_url_check_results(results, output_dir)
            if saved_paths:
                print("结果已保存到:")
                for path in saved_paths:
                    print(f"  {path}")
            else:
                print("本次无检测结果，未生成文件")
        except Exception as exc:
            print(f"错误: 保存文件失败 - {exc}")
        return

    output = format_url_check_categories(results)
    print(output)


def save_url_check_results(results, output_dir=None):
    """Save URL check results split into 已拦截/白名单/未拦截 files.

    Each file contains a single flat sorted brief-line list.  Filenames use
    ASCII (blocked_/whitelisted_/unblocked_) to stay robust against Windows
    console encoding issues.  Empty categories produce no file.
    """
    output_dir = output_dir or os.path.join(os.getcwd(), 'output')
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    groups = group_url_check_results(results)

    saved_paths = []
    for category in URL_CHECK_CATEGORIES:
        if not groups[category]:
            continue
        filename = f'{OUTPUT_FILENAMES[category]}_{timestamp}.txt'
        filepath = os.path.join(output_dir, filename)
        content = format_url_check_results(groups[category])
        with open(filepath, 'w', encoding='utf-8') as handle:
            handle.write(content)
        saved_paths.append(filepath)
    return saved_paths
