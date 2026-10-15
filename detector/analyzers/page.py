"""Static page content and behavior analysis."""

import re
from urllib.parse import urljoin, urlparse

from ..utils.tld import TLD_EXTRACTOR
from ..utils.domain import registered_domain

PASSWORD_FIELD_PATTERN = re.compile(
    r'(?:pass(?:word)?|passwd|pwd|密码)',
    re.IGNORECASE,
)
OTP_FIELD_PATTERN = re.compile(
    r'(?:otp|2fa|mfa|verification(?:\s+code)?|verify(?:\s+code)?|'
    r'security(?:\s+code)?|one[-\s]?time|passcode|验证码|校验码|动态码|短信验证码)',
    re.IGNORECASE,
)
PAYMENT_FIELD_PATTERN = re.compile(
    r'(?:credit[\s_-]*card|debit[\s_-]*card|card[\s_-]*number|'
    r'card[_-]?number|'
    r'bank[\s_-]*account|'
    r'cvv|cvc|iban|payment|银行卡|信用卡|卡号|支付|付款)',
    re.IGNORECASE,
)
WALLET_FIELD_PATTERN = re.compile(
    r'(?:private\s+key|secret\s+key|seed(?:\s+phrase)?|recovery'
    r'(?:\s+phrase)?|mnemonic|助记词|恢复短语|私钥)',
    re.IGNORECASE,
)
OFFICIAL_CLAIM_PATTERN = re.compile(
    r'(?:official\s+(?:site|website|account)|official|官方网站|官方登录|官方客服|官方账号)',
    re.IGNORECASE,
)
PERSONAL_INFO_FIELD_PATTERN = re.compile(
    r'(?:real.?name|full.?name|identity|id.?card|passport|social.?security|身份证|姓名|真实姓名|护照)',
    re.IGNORECASE,
)
SCAM_KEYWORDS = (
    '客服', '中奖', '领奖', '退款', '包裹', '快递',
    '账户异常', '账号异常', '立即验证', '安全验证',
    '解冻账户', '限时', 'customer service', 'refund',
    'parcel', 'delivery', 'prize', 'winner',
    'account suspended', 'verify now',
)
# High-specificity scam markers (prize claims, account freezes, urgent
# unfreeze flows).  Two or more of these combined with information or
# payment collection is a direct SCAM scenario per the V2 report (HR-007).
STRONG_SCAM_KEYWORDS = (
    '中奖', '领奖', '兑奖', '账户异常', '账号异常',
    '解冻', '冻结', '限时领取', '清空',
    'prize', 'winner', 'account suspended', 'account locked',
)
SENSITIVE_TEXT_KEYWORDS = (
    '登录', '登陆', '密码', '验证码', '安全码',
    '付款', '支付', '账单', '核实', '验证身份',
    'sign in', 'login', 'password', 'otp',
    'verification', 'payment', 'billing',
)
DOWNLOAD_EXTENSIONS = {
    '.exe': 'executable',
    '.msi': 'installer',
    '.apk': 'installer',
    '.dmg': 'installer',
    '.pkg': 'installer',
    '.zip': 'archive',
    '.rar': 'archive',
    '.7z': 'archive',
}
DANGEROUS_DOWNLOAD_TYPES = frozenset({'executable', 'installer'})


def _text(soup):
    if not soup:
        return ''
    return ' '.join(soup.stripped_strings).lower()


def _field_value(tag):
    return ' '.join(
        str(tag.get(attribute, ''))
        for attribute in ('name', 'id', 'type', 'placeholder', 'autocomplete', 'aria-label')
    )


def _has_field(tags, pattern):
    return any(pattern.search(_field_value(tag)) for tag in tags)


def _unique(values):
    return list(dict.fromkeys(value for value in values if value))


def _download_target(tag, page_url):
    attribute = 'href' if tag.name in ('a', 'area', 'link') else 'src'
    value = str(tag.get(attribute, '')).strip()
    if not value:
        return None
    target = urljoin(page_url, value)
    path = urlparse(target).path.lower()
    for extension, kind in DOWNLOAD_EXTENSIONS.items():
        if path.endswith(extension):
            return {'url': target, 'type': kind, 'extension': extension}
    return None


def analyze_page(soup, page_url, page_domain):
    """Return explainable content and behavior signals.

    The sensitive-information flags require fields/forms rather than merely
    matching words in ordinary prose. This avoids treating a help article
    mentioning "password" as credential collection.
    """
    result = {
        'credential_collection': False,
        'otp_collection': False,
        'payment_collection': False,
        'wallet_seed': False,
        'personal_info_collection': False,
        'login_form': False,
        'external_form_actions': [],
        'same_domain_sensitive_form': False,
        'external_script_targets': [],
        'external_iframes': [],
        'scam_keywords': [],
        'scam_strong': [],
        'sensitive_keywords': [],
        'download_targets': [],
        'external_download': False,
        'dangerous_download': False,
        'dynamic_redirect': False,
        'official_claim': False,
        'fake_footer': False,
        'page_brand_text': [],
        'page_text': '',
    }
    if not soup:
        return result

    page_text = _text(soup)
    result['page_text'] = page_text[:20000]
    result['scam_keywords'] = _unique([keyword for keyword in SCAM_KEYWORDS if keyword.lower() in page_text])
    result['scam_strong'] = _unique([
        keyword for keyword in STRONG_SCAM_KEYWORDS
        if keyword.lower() in page_text
    ])
    result['sensitive_keywords'] = _unique([keyword for keyword in SENSITIVE_TEXT_KEYWORDS if keyword.lower() in page_text])
    forms = soup.find_all('form')
    for form in forms:
        inputs = form.find_all(['input', 'textarea'])
        password_field = _has_field(inputs, PASSWORD_FIELD_PATTERN) or any(
            str(tag.get('type', '')).lower() == 'password' for tag in inputs
        )
        result['login_form'] |= password_field
        result['credential_collection'] |= password_field
        result['otp_collection'] |= _has_field(inputs, OTP_FIELD_PATTERN)
        result['payment_collection'] |= _has_field(inputs, PAYMENT_FIELD_PATTERN)
        result['wallet_seed'] |= _has_field(inputs, WALLET_FIELD_PATTERN)
        result['personal_info_collection'] |= _has_field(inputs, PERSONAL_INFO_FIELD_PATTERN)
    result['official_claim'] = bool(OFFICIAL_CLAIM_PATTERN.search(page_text))
    footer_links = [
        str(tag.get('href', '')).strip().lower()
        for footer in soup.find_all('footer')
        for tag in footer.find_all('a')
    ]
    invalid_footer_links = [
        href for href in footer_links
        if not href or href == '#' or href.startswith('javascript:')
    ]
    result['fake_footer'] = bool(
        len(footer_links) >= 3
        and len(invalid_footer_links) / len(footer_links) >= 0.75
    )

    page_registered = registered_domain(
        urlparse(page_url).hostname or page_domain, TLD_EXTRACTOR
    )
    for form in forms:
        inputs = form.find_all(['input', 'textarea'])
        password_field = _has_field(inputs, PASSWORD_FIELD_PATTERN) or any(
            str(tag.get('type', '')).lower() == 'password' for tag in inputs
        )
        action = urljoin(page_url, str(form.get('action', '')).strip())
        action_host = (urlparse(action).hostname or '').lower()
        action_domain = registered_domain(action_host, TLD_EXTRACTOR) if action_host else page_registered
        if action_host and action_domain != page_registered:
            result['external_form_actions'].append(action)
        elif password_field or _has_field(inputs, OTP_FIELD_PATTERN) or _has_field(inputs, PAYMENT_FIELD_PATTERN) or _has_field(inputs, WALLET_FIELD_PATTERN):
            result['same_domain_sensitive_form'] = True
    result['external_form_actions'] = _unique(result['external_form_actions'])

    for tag in soup.find_all(['a', 'area', 'link', 'script']):
        target = _download_target(tag, page_url)
        if target:
            result['download_targets'].append(target)
    result['download_targets'] = _unique_dicts(result['download_targets'])
    result['external_download'] = any(
        registered_domain(urlparse(target['url']).hostname or '', TLD_EXTRACTOR)
        != page_registered
        for target in result['download_targets']
    )
    result['dangerous_download'] = any(
        target['type'] in DANGEROUS_DOWNLOAD_TYPES
        for target in result['download_targets']
    )
    dynamic_script = ' '.join(
        tag.get_text(' ', strip=True) for tag in soup.find_all('script')
    )
    script_targets = []
    for match in re.finditer(r"(?:fetch|XMLHttpRequest|sendBeacon)\s*\([^)]*?['\"](https?://[^'\"]+)", dynamic_script, re.IGNORECASE):
        target = match.group(1)
        if registered_domain(urlparse(target).hostname or '', TLD_EXTRACTOR) != page_registered:
            script_targets.append(target)
    result['external_script_targets'] = _unique(script_targets)
    iframe_targets = []
    for iframe in soup.find_all('iframe', src=True):
        target = urljoin(page_url, str(iframe.get('src', '')).strip())
        if registered_domain(urlparse(target).hostname or '', TLD_EXTRACTOR) != page_registered:
            iframe_targets.append(target)
    result['external_iframes'] = _unique(iframe_targets)
    dynamic_attributes = ' '.join(
        str(tag.get('onclick', '')) for tag in soup.find_all(onclick=True)
    )
    dynamic_meta = any(
        str(tag.get('http-equiv', '')).lower() == 'refresh'
        for tag in soup.find_all('meta')
    )
    result['dynamic_redirect'] = bool(
        dynamic_meta or re.search(
            r'(?:window\s*\.\s*location|document\s*\.\s*location|location\s*\.(?:href|assign|replace)|window\s*\.\s*open)',
            f'{dynamic_script} {dynamic_attributes}',
            re.IGNORECASE,
        )
    )

    for tag in soup.find_all(['title', 'h1', 'meta', 'img']):
        if tag.name == 'meta':
            value = tag.get('content', '')
        elif tag.name == 'img':
            value = tag.get('alt', '')
        else:
            value = tag.get_text(' ', strip=True)
        if value:
            result['page_brand_text'].append(str(value)[:200])
    result['page_brand_text'] = _unique(result['page_brand_text'])
    return result


def _unique_dicts(values):
    result = []
    seen = set()
    for value in values:
        key = (value.get('url'), value.get('type'), value.get('extension'))
        if key not in seen:
            seen.add(key)
            result.append(value)
    return result




