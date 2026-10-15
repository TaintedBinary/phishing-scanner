from collections import defaultdict
import json
from pathlib import Path


RULE_CONFIG_PATH = Path(__file__).resolve().parents[2] / 'risk_rules.json'
REQUIRED_WEIGHTS = frozenset({
    'domain_age_lt_7', 'domain_age_lt_30', 'domain_age_lt_183',
    'unnecessary_hyphens', 'unreachable_domain', 'whois_unavailable',
    'tls_mismatch', 'ip_host', 'whois_privacy', 'batch_registration', 'userinfo',
    'non_standard_port', 'long_query', 'brand_match',
    'official_domain_mismatch', 'domain_similarity',
    'character_substitution', 'homograph', 'brand_deformation_cap',
    'multiple_brands', 'fake_official_subdomain', 'content_mismatch',
    'page_impersonation', 'credential_collection', 'otp_collection',
    'payment_collection', 'wallet_seed', 'external_form_action',
    'redirect_count', 'dangerous_download', 'external_download',
    'dynamic_redirect', 'fake_footer', 'suspicious_redirect_param',
    'link_analysis',
})


def load_rule_config(path=RULE_CONFIG_PATH):
    try:
        with Path(path).open('r', encoding='utf-8-sig') as handle:
            config = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f'评分规则加载失败 {path}: {exc}') from exc
    required = {'dimension_caps', 'risk_thresholds', 'weights'}
    if not isinstance(config, dict) or not required.issubset(config):
        raise ValueError(f'评分规则必须包含: {", ".join(sorted(required))}')
    if set(config['dimension_caps']) != {'domain', 'brand', 'content', 'behavior'}:
        raise ValueError('dimension_caps 必须且只能包含四个标准维度')
    if not REQUIRED_WEIGHTS.issubset(config['weights']):
        missing = REQUIRED_WEIGHTS.difference(config['weights'])
        raise ValueError(f'评分规则缺少权重: {", ".join(sorted(missing))}')
    thresholds = config['risk_thresholds']
    threshold_names = ('suspicious', 'high_risk', 'phishing', 'high_confidence')
    try:
        threshold_values = [float(thresholds[name]) for name in threshold_names]
        numeric_values = [
            float(value) for section in ('dimension_caps', 'weights')
            for value in config[section].values()
        ]
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError('评分上限、阈值和权重必须是有效数字') from exc
    if threshold_values != sorted(threshold_values) or len(set(threshold_values)) != 4:
        raise ValueError('风险等级阈值必须严格递增')
    if any(value < 0 for value in numeric_values):
        raise ValueError('评分上限和权重不能为负数')
    return config


RULE_CONFIG = load_rule_config()
DIMENSION_CAPS = {
    name: float(RULE_CONFIG['dimension_caps'][name])
    for name in ('domain', 'brand', 'content', 'behavior')
}
WEIGHTS = {name: float(value) for name, value in RULE_CONFIG['weights'].items()}
THRESHOLDS = {
    name: float(value) for name, value in RULE_CONFIG['risk_thresholds'].items()
}

RISK_LEVELS = (
    ('安全', 0.0, THRESHOLDS['suspicious']),
    ('可疑', THRESHOLDS['suspicious'], THRESHOLDS['high_risk']),
    ('高风险', THRESHOLDS['high_risk'], THRESHOLDS['phishing']),
    ('钓鱼', THRESHOLDS['phishing'], THRESHOLDS['high_confidence']),
    ('高置信钓鱼', THRESHOLDS['high_confidence'], float('inf')),
)


def _weight(name):
    try:
        return WEIGHTS[name]
    except KeyError as exc:
        raise ValueError(f'评分规则缺少权重: {name}') from exc


def _add(scores, dimension, rule_id, feature, value, detail, severity='weak'):
    if value:
        scores[dimension].append({
            'rule_id': rule_id,
            'feature': feature,
            'score': float(value),
            'severity': severity,
            'detail': detail,
        })


def evaluate_hard_rules(brand, page, has_punycode=False, homograph=False):
    """Evaluate high-confidence combinations before ordinary scoring."""
    brand = brand or {}
    page = page or {}
    non_official = bool(brand.get('brand_name') and not brand.get('is_official'))
    high_similarity = bool(brand.get('high_similarity'))
    credential = bool(page.get('credential_collection'))
    sensitive = (
        credential or page.get('otp_collection') or page.get('payment_collection')
        or page.get('wallet_seed') or page.get('personal_info_collection')
    )
    rules = []

    if (has_punycode or homograph) and non_official and high_similarity:
        rules.append({
            'id': 'HR-01',
            'level': '钓鱼',
            'detail': '检测到 Punycode/异体字符、品牌高度相似且注册域不是官方域',
        })
    if non_official and high_similarity and credential:
        rules.append({
            'id': 'HR-02',
            'level': '钓鱼',
            'detail': '品牌高度相似、非官方注册域，并检测到账号或密码采集',
        })
    if brand.get('multiple_brands') and non_official and sensitive:
        rules.append({
            'id': 'HR-03',
            'level': '钓鱼',
            'detail': '非官方域组合多个品牌，并存在登录、验证码或支付操作',
        })
    if non_official and brand.get('brand_name') and page.get('dangerous_download'):
        if credential:
            rules.append({
                'id': 'HR-04',
                'level': '钓鱼',
                'detail': '品牌仿冒非官方域提供可执行文件下载并采集凭据',
            })
        elif page.get('page_impersonation'):
            # Report HR-006: malware delivery requires an impersonation
            # context; ordinary software download sites stay unblocked.
            rules.append({
                'id': 'HR-06',
                'level': '恶意软件',
                'verdict': 'MALWARE',
                'detail': '品牌仿冒上下文提供可执行文件或安装包下载',
            })
    if (
        brand.get('brand_name')
        and non_official
        and page.get('page_impersonation')
        and sensitive
    ):
        rules.append({
            'id': 'HR-05',
            'level': '钓鱼',
            'detail': '页面冒用品牌官方身份并采集敏感信息',
        })
    rules.append(_evaluate_scam_rule(page, non_official))
    return [rule for rule in rules if rule]


def _evaluate_scam_rule(page, non_official):
    """HR-07: prize/freeze scam templates collecting payment or PII."""
    strong_scam = page.get('scam_strong') or []
    scam_total = len(page.get('scam_keywords') or [])
    collects = bool(
        page.get('payment_collection') or page.get('personal_info_collection')
    )
    if not collects or not strong_scam:
        return None
    if len(strong_scam) >= 2 or (len(strong_scam) >= 1 and scam_total >= 3) or (
            len(strong_scam) >= 1 and (non_official or page.get('page_impersonation'))):
        return {
            'id': 'HR-07',
            'level': '诈骗',
            'verdict': 'SCAM',
            'detail': (
                '诈骗话术模板（中奖/账户异常/解冻）配合支付或个人信息采集: '
                + ', '.join(strong_scam[:4])
            ),
        }
    return None


def score_result(signals, brand=None, page=None, link_analysis=None,
                 age_days=None, has_punycode=False, icp_filing=None,
                 whois_data=None, url_signals=None):
    """Map current detector signals to capped four-dimension scores."""
    signals = signals or {}
    brand = brand or {}
    page = page or {}
    link_analysis = link_analysis or {}
    whois_data = whois_data or {}
    url_signals = url_signals or {}
    scores = defaultdict(list)

    if age_days is not None:
        if age_days < 7:
            _add(scores, 'domain', 'DM-01', 'domain_age', _weight('domain_age_lt_7'),
                 '域名注册时间小于 7 天')
        elif age_days < 30:
            _add(scores, 'domain', 'DM-01', 'domain_age', _weight('domain_age_lt_30'),
                 '域名注册时间小于 30 天')
        elif age_days < 183:
            _add(scores, 'domain', 'DM-01', 'domain_age', _weight('domain_age_lt_183'),
                 '域名注册时间小于 6 个月')

    mapping = {
        'unnecessary_hyphens': ('DM-03', _weight('unnecessary_hyphens'), '域名横杠数量或位置异常', 'weak'),
        'unreachable_domain': ('DM-04', _weight('unreachable_domain'), '目标域名当前不可达', 'weak'),
        'whois_unavailable': ('DM-05', _weight('whois_unavailable'), 'WHOIS 信息不可用', 'weak'),
        'tls_mismatch': ('DM-06', _weight('tls_mismatch'), 'TLS 证书校验失败', 'medium'),
        'ip_host': ('DM-10', _weight('ip_host'), 'URL 直接使用 IP 地址作为主机', 'medium'),
    }
    for name, (rule_id, value, detail, severity) in mapping.items():
        if signals.get(name) == -1:
            _add(scores, 'domain', rule_id, name, value, detail, severity)

    whois_blob = ' '.join(
        str(whois_data.get(field, '')) for field in (
            'registrar', 'registrant_org', 'registrant_name',
            'registrant_email', 'registrant_emails',
        )
    ).lower()
    privacy_markers = (
        'privacy', 'protected', 'redacted', 'whoisguard',
        'domains by proxy', 'contact privacy', 'private registration',
    )
    if any(marker in whois_blob for marker in privacy_markers):
        _add(scores, 'domain', 'DM-02', 'whois_privacy', _weight('whois_privacy'),
             'WHOIS 使用隐私保护服务', 'weak')
    elif signals.get('batch_registration') == -1:
        _add(scores, 'domain', 'DM-02', 'batch_registration', _weight('batch_registration'),
             '存在批量注册或关联注册证据', 'medium')

    if url_signals.get('userinfo'):
        _add(scores, 'domain', 'DM-07', 'userinfo', _weight('userinfo'),
             'URL 包含 username/password 等 userinfo 组件', 'medium')
    if url_signals.get('non_standard_port'):
        _add(scores, 'domain', 'DM-08', 'non_standard_port', _weight('non_standard_port'),
             'URL 使用非标准 HTTP/HTTPS 端口', 'weak')
    if url_signals.get('long_query'):
        _add(scores, 'domain', 'DM-09', 'long_query', _weight('long_query'),
             'URL 查询参数过长', 'weak')

    high_similarity = bool(brand.get('high_similarity'))
    if brand.get('brand_name') and not brand.get('is_official'):
        _add(scores, 'brand', 'BR-01', 'brand_match', _weight('brand_match'),
             f"命中品牌 {brand['brand_name']}", 'medium')
        _add(scores, 'brand', 'BR-02', 'official_domain_mismatch', _weight('official_domain_mismatch'),
             '命中品牌但注册域不是官方域', 'high')
    deformation_candidates = []
    if high_similarity and not brand.get('is_official'):
        deformation_candidates.append(
            ('BR-03', 'domain_similarity', _weight('domain_similarity'), '域名主体与品牌高度相似')
        )
    if brand.get('character_substitution') and not brand.get('is_official'):
        deformation_candidates.append(
            ('BR-04', 'character_substitution', _weight('character_substitution'), '检测到数字或字符替换仿冒')
        )
    if ((brand.get('homograph') or (has_punycode and high_similarity))
            and not brand.get('is_official')):
        deformation_candidates.append(
            ('BR-05', 'homograph', _weight('homograph'), '检测到 Unicode/Punycode 同形字符仿冒')
        )
    if brand.get('deformation'):
        deformation_candidates.append((
            'BR-06', 'brand_deformation',
            min(_weight('brand_deformation_cap'), max(.5, brand.get('deformation_score', 1))),
            '检测到品牌域名变形',
        ))
    if deformation_candidates:
        rule_id, feature, value, detail = max(
            deformation_candidates, key=lambda item: item[2]
        )
        _add(scores, 'brand', rule_id, feature,
             min(_weight('brand_deformation_cap'), value), detail, 'high')
    if brand.get('multiple_brands'):
        _add(scores, 'brand', 'BR-07', 'multiple_brands', _weight('multiple_brands'),
             '非官方域组合多个知名品牌', 'high')
    if brand.get('fake_official_subdomain'):
        _add(scores, 'brand', 'BR-08', 'fake_official_subdomain', _weight('fake_official_subdomain'),
             '子域名伪造官方域名层级', 'high')

    if page.get('content_mismatch'):
        _add(scores, 'content', 'CT-01', 'content_mismatch', _weight('content_mismatch'),
             '页面品牌身份与当前注册域不一致', 'high')
    if page.get('page_impersonation'):
        _add(scores, 'content', 'CT-02', 'page_impersonation', _weight('page_impersonation'),
             '页面内容疑似冒用品牌官方身份', 'medium')
    if page.get('credential_collection'):
        _add(scores, 'content', 'CT-03', 'credential_collection', _weight('credential_collection'),
             '页面检测到账号/密码采集', 'high')
    if page.get('otp_collection'):
        _add(scores, 'content', 'CT-04', 'otp_collection', _weight('otp_collection'),
             '页面检测到验证码采集', 'high')
    if page.get('payment_collection'):
        _add(scores, 'content', 'CT-05', 'payment_collection', _weight('payment_collection'),
             '页面检测到支付或银行卡信息采集', 'high')
    if page.get('wallet_seed'):
        _add(scores, 'content', 'CT-06', 'wallet_seed', _weight('wallet_seed'),
             '页面检测到助记词或私钥采集', 'critical')
    if page.get('external_form_actions'):
        _add(scores, 'content', 'CT-07', 'external_form_action', _weight('external_form_action'),
             '表单提交到外部域名', 'medium')

    if signals.get('redirect_count') == -1:
        _add(scores, 'behavior', 'BH-01', 'redirect_count', _weight('redirect_count'),
             '重定向次数超过 2 次', 'medium')
    if page.get('dangerous_download'):
        _add(scores, 'behavior', 'BH-03', 'dangerous_download', _weight('dangerous_download'),
             '页面包含可执行文件或安装包下载', 'high')
    elif page.get('external_download'):
        _add(scores, 'behavior', 'BH-02', 'external_download', _weight('external_download'),
             '页面下载链接指向外部注册域', 'medium')
    if page.get('dynamic_redirect'):
        _add(scores, 'behavior', 'BH-04', 'dynamic_redirect', _weight('dynamic_redirect'),
             '页面包含动态跳转行为', 'medium')
    if page.get('fake_footer'):
        _add(scores, 'behavior', 'BH-06', 'fake_footer', _weight('fake_footer'),
             '页脚链接大部分为空或无效跳转', 'weak')
    if url_signals.get('suspicious_redirect_param'):
        _add(scores, 'behavior', 'BH-05', 'suspicious_redirect_param', _weight('suspicious_redirect_param'),
             'URL 包含可疑跳转参数', 'weak')
    if link_analysis.get('score') == -1:
        _add(scores, 'behavior', 'BH-07', 'link_analysis', _weight('link_analysis'),
             '页面存在较多可疑外链、短链接或隐藏链接', 'medium')

    dimension_scores = {}
    evidence = []
    for dimension, cap in DIMENSION_CAPS.items():
        raw = sum(item['score'] for item in scores[dimension])
        dimension_scores[dimension] = min(cap, round(raw, 2))
        evidence.extend(scores[dimension])

    total = round(sum(dimension_scores.values()), 2)
    level = next(
        name for name, lower, upper in RISK_LEVELS
        if lower <= total < upper
    )
    trust_signals = []
    if icp_filing and icp_filing.get('has_filing'):
        trust_signals.append({
            'type': 'icp_filing',
            'source': icp_filing.get('source', ''),
            'effect': 'context_only',
            'detail': 'ICP备案作为信任上下文记录，不抵消风险分且不覆盖 Hard Rule',
        })
    return {
        'total_score': total,
        'risk_level': level,
        'dimension_scores': dimension_scores,
        'evidence': evidence,
        'trust_signals': trust_signals,
        'max_score': sum(DIMENSION_CAPS.values()),
    }
