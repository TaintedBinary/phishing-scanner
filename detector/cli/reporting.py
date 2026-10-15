"""Format and normalize detector results for CLI output."""
from urllib.parse import urlparse


CATEGORY_ORDER = (
    '已拦截', '高置信钓鱼', '钓鱼', '恶意软件', '诈骗', '高风险', '可疑', '安全'
)

# Verdicts that constitute a formal interception decision.
BLOCKING_VERDICTS = frozenset({'PHISHING', 'MALWARE', 'SCAM'})


def result_category(result):
    level = result.get('risk_level', '未知')
    if level == '已拦截' or result.get('blocked'):
        return CATEGORY_ORDER[0]
    if result.get('verdict') in BLOCKING_VERDICTS:
        return {
            'PHISHING': '钓鱼',
            'MALWARE': '恶意软件',
            'SCAM': '诈骗',
        }[result['verdict']]
    if level in ('白名单', '安全'):
        return CATEGORY_ORDER[-1]
    if level in CATEGORY_ORDER:
        return level
    if level == '恶意':
        return '钓鱼'
    return '可疑'


def group_results(results):
    groups = {category: [] for category in CATEGORY_ORDER}
    for result in results:
        groups[result_category(result)].append(result)
    return groups


def serialize_categories(results, categories=None):
    categories = categories or CATEGORY_ORDER
    groups = group_results(results)
    return {
        category: [compact_result(result) for result in groups[category]]
        for category in categories
    }


def compact_result(result):
    compact = {
        'url': result.get('url', ''),
        'domain': result.get('domain', ''),
        'risk_level': result.get('risk_level', '未知'),
        'score': result.get('total_score', 0),
    }
    if result.get('requested_url'):
        compact['requested_url'] = result['requested_url']
    if result.get('final_url'):
        compact['final_url'] = result['final_url']
    if result.get('requested_domain'):
        compact['requested_domain'] = result['requested_domain']
    if result.get('final_domain'):
        compact['final_domain'] = result['final_domain']
    if result.get('dimension_scores'):
        compact['dimension_scores'] = result['dimension_scores']
    if result.get('hard_rules'):
        compact['hard_rules'] = result['hard_rules']
    if result.get('risk_evidence'):
        compact['risk_evidence'] = result['risk_evidence']
    if result.get('trust_signals'):
        compact['trust_signals'] = result['trust_signals']

    if result.get('blocked'):
        compact['blocked'] = True
        compact['blocklist'] = result.get('blocklist', {})

    keywords = []
    sources = []
    for source in result.get('discovery_sources', []):
        if source.get('type') == 'keyword':
            keyword = source.get('value', '')
            if keyword and keyword not in keywords:
                keywords.append(keyword)
            sources.append({
                'keyword': keyword,
                'engine': source.get('engine', ''),
            })
        else:
            sources.append({
                'identifier_type': source.get('identifier_type', ''),
                'value': source.get('value', ''),
            })
    if keywords:
        compact['keywords'] = keywords
    if sources:
        compact['sources'] = sources

    deformation_match = result.get('deformation_match')
    if deformation_match:
        compact['deformation_match'] = deformation_match

    icp_filing = result.get('icp_filing')
    if icp_filing:
        compact['icp_filing'] = {
            'has_filing': bool(icp_filing.get('has_filing')),
            'source': icp_filing.get('source', ''),
            'from_cache': bool(icp_filing.get('from_cache')),
        }
        filing_info = extract_icp_filing_info(icp_filing)
        if filing_info:
            compact['icp_filing']['filing_info'] = filing_info

    whois_info = result.get('whois', {})
    if whois_info.get('available'):
        compact['whois'] = {
            'registrar': whois_info.get('registrar', ''),
            'registrant_name': whois_info.get('registrant_name', ''),
            'registrant_org': whois_info.get('registrant_org', ''),
            'registrant_email': ', '.join(whois_info.get('registrant_emails', [])),
            'creation_date': whois_info.get('creation_date', ''),
            'expiration_date': whois_info.get('expiration_date', ''),
            'name_servers': whois_info.get('name_servers', ''),
        }

    if result.get('error'):
        compact['error'] = result['error']
    return compact


def format_simple(results, categories=None):
    results = [r for r in results if r.get('risk_level') != '白名单']
    groups = group_results(results)
    categories = categories or CATEGORY_ORDER
    lines = []
    for category in categories:
        category_results = groups[category]
        lines.append(f"# {category}网址 ({len(category_results)})")
        for result in category_results:
            lines.append(_format_result_line(result))
        lines.append("")
    return '\n'.join(lines).rstrip()


def _format_result_line(result):
    url = result.get('url', '')
    parts = [f"  {url}"]
    final_url = result.get('final_url', '')
    if final_url and final_url != url:
        parts.append(f'[最终落地: {final_url}]')

    keywords = []
    for source in result.get('discovery_sources', []):
        if source.get('type') == 'keyword':
            keyword = source.get('value', '')
            if keyword and keyword not in keywords:
                keywords.append(keyword)
    if keywords:
        parts.append(f"[关键词: {', '.join(keywords)}]")

    if result.get('blocked'):
        blocklist = result.get('blocklist', {})
        parts.append(f"[本地库: {blocklist.get('matched', '')}]")

    deformation_match = result.get('deformation_match')
    if deformation_match:
        observed_domain = result.get('full_domain') or result.get('domain') or extract_host(url)
        parts.append(f"[域名变形: {observed_domain} 疑似仿冒 {deformation_match}]")

    icp_filing = result.get('icp_filing')
    if icp_filing and icp_filing.get('has_filing'):
        summary = format_icp_filing_summary(icp_filing)
        if summary:
            parts.append(f"[ICP备案: {summary}]")

    whois_info = result.get('whois', {})
    if whois_info.get('available'):
        whois_parts = []
        if whois_info.get('registrar'):
            whois_parts.append(f"注册商: {whois_info['registrar']}")
        if whois_info.get('registrant_org'):
            whois_parts.append(f"注册组织: {whois_info['registrant_org']}")
        if whois_info.get('registrant_emails'):
            whois_parts.append(f"注册邮箱: {', '.join(whois_info['registrant_emails'])}")
        if whois_info.get('creation_date'):
            whois_parts.append(f"注册日期: {whois_info['creation_date']}")
        if whois_parts:
            parts.append(f"| WHOIS: {'; '.join(whois_parts)}")

    return ' '.join(parts)


def extract_host(url):
    value = str(url or '').strip()
    if '://' not in value:
        value = f'http://{value}'
    return (urlparse(value).hostname or '').strip('.').lower()


def extract_icp_filing_info(icp_filing):
    record = _pick_first_record(icp_filing.get('records', []))
    if not record:
        return {}
    return {
        '主办单位': record.get('unitName') or record.get('mainUnitName') or '',
        '网站备案号': (
            record.get('serviceLicence') or record.get('siteLicense') or
            record.get('serviceLicense') or ''
        ),
        '主体备案号': record.get('mainLicence') or '',
        '更新时间': record.get('updateRecordTime') or '',
    }


def format_icp_filing_summary(icp_filing):
    filing_info = extract_icp_filing_info(icp_filing)
    if not filing_info:
        return ''
    parts = []
    for label in ('主办单位', '网站备案号', '主体备案号', '更新时间'):
        value = filing_info.get(label)
        if value:
            parts.append(f'{label}: {value}')
    source = icp_filing.get('source')
    if source:
        parts.append(f'来源: {source}')
    return '; '.join(parts)


def _pick_first_record(records):
    if not records:
        return {}
    return records[0] if isinstance(records[0], dict) else {}


RISK_LEVEL_EN = {
    '安全': 'SAFE',
    '可疑': 'SUSPICIOUS',
    '高风险': 'HIGH_RISK',
    '钓鱼': 'PHISHING',
    '高置信钓鱼': 'PHISHING',
    '恶意软件': 'MALWARE',
    '诈骗': 'SCAM',
    '已拦截': 'PHISHING',
    '白名单': 'SAFE',
    '检测失败': 'FAILED',
    '未知': 'UNKNOWN',
}


def sort_results(results):
    def _key(r):
        if (r.get('blocked') or r.get('risk_level') == '已拦截'
                or r.get('verdict') in BLOCKING_VERDICTS):
            return float('inf')
        return r.get('total_score', 0)
    return sorted(results, key=_key, reverse=True)


def compact_v2(result):
    """Return the stable JSON representation for the V2 evidence engine.

    ``score_shadow`` is deliberately retained as a compatibility field; it is
    not the source of the final verdict.
    """
    verdict = result.get('verdict') or RISK_LEVEL_EN.get(
        result.get('risk_level', '未知'), 'UNKNOWN'
    )
    compact = {
        'url': result.get('url', ''),
        'verdict': verdict,
        'risk_level': result.get('risk_level', '未知'),
        'confidence': result.get('confidence', 0.0),
        'engine_version': result.get('engine_version', ''),
        'score_shadow': result.get('total_score', 0),
        'evidence_summary': result.get('evidence_summary', {}),
        'evidence_groups': result.get('evidence_groups', {}),
        'group_strength': result.get('group_strength', {}),
        'strong_groups': result.get('strong_groups', []),
        'evidence': result.get('v2_evidence', []),
    }
    for key in ('domain', 'final_url', 'final_domain', 'requested_url',
                'requested_domain', 'blocked', 'blocklist', 'error'):
        if result.get(key):
            compact[key] = result[key]
    hard_rules = result.get('hard_rules') or []
    if hard_rules:
        compact['hard_rules'] = hard_rules
    if result.get('risk_evidence'):
        compact['risk_evidence'] = result['risk_evidence']
    if result.get('dimension_scores'):
        compact['dimension_scores'] = result['dimension_scores']
    icp = result.get('icp_filing')
    if icp and icp.get('has_filing'):
        record = _pick_first_record(icp.get('records', []))
        if record:
            filing = {}
            unit = record.get('unitName') or record.get('mainUnitName')
            if unit:
                filing['主办单位'] = unit
            licence = (record.get('serviceLicence') or record.get('siteLicense')
                       or record.get('serviceLicense'))
            if licence:
                filing['网站备案号'] = licence
            if record.get('mainLicence'):
                filing['主体备案号'] = record['mainLicence']
            if filing:
                compact['备案信息'] = filing
    return compact