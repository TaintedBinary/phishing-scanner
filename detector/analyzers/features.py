import tldextract


TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

FEATURE_LABELS = {
    'batch_registration': '批量注册关联证据',
    'unnecessary_hyphens': '不必要横杠',
    'unreachable_domain': '域名不可达',
    'whois_unavailable': 'WHOIS不可用',
    'redirect_count': '重定向次数',
    'tls_mismatch': 'TLS证书异常',
    'ip_host': 'IP地址主机',
}


def batch_registration(whois_data):
    """Return a weak signal only when WHOIS contains association evidence."""
    if not isinstance(whois_data, dict) or not whois_data:
        return 0
    registrar = str(whois_data.get('registrar', '')).lower()
    registrant_org = str(whois_data.get('registrant_org', '')).lower()
    registrant_name = str(whois_data.get('registrant_name', '')).lower()
    emails = whois_data.get('registrant_emails', [])
    if isinstance(emails, (str, bytes)):
        emails = [emails]
    elif not isinstance(emails, (list, tuple, set)):
        emails = []
    email_text = ','.join(str(value) for value in emails).lower()
    combined = ' '.join((registrar, registrant_org, registrant_name, email_text))
    if any(marker in combined for marker in (
        'bulk', 'wholesale', 'reseller', 'portfolio',
        'domain portfolio', 'same registrant',
    )):
        return -1
    return 0


def unnecessary_hyphens(hostname):
    """Return a weak signal for unusually placed or excessive hyphens."""
    domain = TLD_EXTRACTOR(str(hostname or '')).domain
    hyphen_count = domain.count('-')
    if hyphen_count > 2 or domain.startswith('-') or domain.endswith('-'):
        return -1
    if '--' in domain:
        return -1
    parts = domain.split('-')
    if len(parts) > 3 and all(len(part) <= 3 for part in parts):
        return -1
    return 0


def describe_feature(name, score):
    label = FEATURE_LABELS.get(name, name)
    if score < 0:
        return f'{label}命中可疑特征'
    if score > 0:
        return f'{label}未发现可疑特征'
    return f'{label}无法判断或证据不足'
