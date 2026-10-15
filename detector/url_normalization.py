"""URL normalization and registrable-domain identity."""

from dataclasses import dataclass
import ipaddress
from typing import Dict
from urllib.parse import parse_qsl, urlparse, urlunsplit

from .utils.domain import ascii_hostname, unicode_hostname
from .utils.tld import TLD_EXTRACTOR


class URLValidationError(ValueError):
    """Raised when an input cannot be represented as a safe scan target."""


@dataclass(frozen=True)
class NormalizedURL:
    original_url: str
    url: str
    hostname_ascii: str
    hostname_unicode: str
    registered_domain: str
    full_domain: str
    has_punycode: bool
    is_ip: bool
    signals: Dict[str, bool]


def normalize_url(value, require_registered_domain=True) -> NormalizedURL:
    original = str(value or '').strip()
    candidate = original if '://' in original else f'https://{original}'
    if len(candidate) > 8192:
        raise URLValidationError('URL 长度超过 8192 字符')
    try:
        parsed = urlparse(candidate)
    except ValueError as exc:
        raise URLValidationError(f'URL 格式无效: {exc}') from exc
    if parsed.scheme.lower() not in ('http', 'https') or not parsed.hostname:
        raise URLValidationError('URL 格式无效，仅支持包含有效主机名的 HTTP/HTTPS URL')

    hostname_ascii = ascii_hostname(parsed.hostname.lower().rstrip('.'))
    if not hostname_ascii:
        raise URLValidationError('URL 主机名格式无效')
    hostname_unicode = unicode_hostname(hostname_ascii)
    signals = _url_signals(parsed)
    try:
        ipaddress.ip_address(hostname_ascii)
        is_ip = True
    except ValueError:
        is_ip = False
    signals['ip_host'] = is_ip
    netloc = _normalized_netloc(parsed, hostname_ascii)
    normalized = urlunsplit((
        parsed.scheme.lower(), netloc, parsed.path, parsed.query, ''
    ))
    redacted_original = urlunsplit((
        parsed.scheme.lower(), netloc, parsed.path, parsed.query, parsed.fragment
    ))

    extracted = TLD_EXTRACTOR(hostname_ascii)
    if extracted.domain and extracted.suffix:
        registered = f'{extracted.domain}.{extracted.suffix}'.lower()
        full_domain = (
            f'{extracted.subdomain}.{registered}'
            if extracted.subdomain else registered
        )
    elif is_ip:
        registered = hostname_ascii
        full_domain = hostname_ascii
    elif require_registered_domain:
        raise URLValidationError('无法从 URL 提取有效注册域名')
    else:
        registered = hostname_ascii
        full_domain = hostname_ascii

    return NormalizedURL(
        original_url=redacted_original,
        url=normalized,
        hostname_ascii=hostname_ascii,
        hostname_unicode=hostname_unicode,
        registered_domain=registered,
        full_domain=full_domain,
        has_punycode='xn--' in hostname_ascii,
        is_ip=is_ip,
        signals=signals,
    )


def _normalized_netloc(parsed_url, hostname_ascii):
    host = hostname_ascii
    if ':' in host and not host.startswith('['):
        host = f'[{host}]'
    try:
        port = parsed_url.port
    except ValueError as exc:
        raise URLValidationError('URL 端口格式无效') from exc
    default_port = (
        (parsed_url.scheme.lower() == 'http' and port == 80)
        or (parsed_url.scheme.lower() == 'https' and port == 443)
    )
    return host + ('' if not port or default_port else f':{port}')


def _url_signals(parsed_url):
    redirect_keys = {
        'url', 'uri', 'redirect', 'redirect_url', 'redirect_uri', 'next',
        'return', 'return_url', 'continue', 'target', 'dest', 'destination',
    }
    try:
        port = parsed_url.port
    except ValueError as exc:
        raise URLValidationError('URL 端口格式无效') from exc
    return {
        'userinfo': parsed_url.username is not None or parsed_url.password is not None,
        'non_standard_port': bool(
            port and not (
                (parsed_url.scheme.lower() == 'http' and port == 80)
                or (parsed_url.scheme.lower() == 'https' and port == 443)
            )
        ),
        'long_query': len(parsed_url.query) > 256,
        'suspicious_redirect_param': any(
            str(key).lower() in redirect_keys
            and ('://' in str(item) or '%2f' in str(item).lower()
                 or '%3a' in str(item).lower())
            for key, item in parse_qsl(parsed_url.query, keep_blank_values=True)
        ),
    }
