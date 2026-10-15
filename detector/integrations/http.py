"""Controlled HTTP fetching for untrusted scan targets."""

from dataclasses import dataclass, field
import ipaddress
import socket
import threading
import time
from typing import Callable, Dict, List, Optional
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests


class FetchError(RuntimeError):
    """Raised when a target cannot be fetched within the scanner policy."""


class UnsafeTargetError(FetchError):
    """Raised when a URL resolves to a non-public network address."""


class TLSVerificationError(FetchError):
    """Raised when HTTPS certificate verification fails."""


@dataclass
class FetchResult:
    requested_url: str
    final_url: str
    status_code: int
    headers: Dict[str, str]
    content: bytes
    redirect_chain: List[Dict[str, object]] = field(default_factory=list)
    truncated: bool = False
    redirect_userinfo: bool = False

    @property
    def redirects(self) -> int:
        return max(0, len(self.redirect_chain) - 1)


class NetworkSafetyPolicy:
    """Reject targets that resolve outside the public Internet.

    DNS answers are cached in memory for a short TTL (default 300s) so
    multi-hop redirect validation does not re-query the resolver for the
    same hostname; expiry keeps validation correct across longer scans.
    """

    DNS_CACHE_TTL = 300.0

    def __init__(self, resolver: Callable = socket.getaddrinfo,
                 dns_cache_ttl: float = DNS_CACHE_TTL):
        self._resolver = resolver
        self._dns_cache_ttl = float(dns_cache_ttl)
        self._dns_cache: Dict[str, object] = {}
        self._dns_lock = threading.Lock()

    def _resolve_addresses(self, hostname: str, port: int) -> set:
        if self._dns_cache_ttl <= 0:
            return self._resolve_now(hostname, port)
        with self._dns_lock:
            entry = self._dns_cache.get(hostname)
            if entry and time.monotonic() - entry[0] <= self._dns_cache_ttl:
                return entry[1]
        addresses = self._resolve_now(hostname, port)
        with self._dns_lock:
            self._dns_cache[hostname] = (time.monotonic(), addresses)
        return addresses

    def _resolve_now(self, hostname: str, port: int) -> set:
        return {
            item[4][0].split('%', 1)[0]
            for item in self._resolver(hostname, port, type=socket.SOCK_STREAM)
        }

    def validate(self, url: str) -> None:
        parsed = urlsplit(url)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname:
            raise UnsafeTargetError('仅允许访问有效的 HTTP/HTTPS URL')
        try:
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        except ValueError as exc:
            raise UnsafeTargetError('URL 端口格式无效') from exc
        try:
            addresses = self._resolve_addresses(parsed.hostname, port)
        except OSError as exc:
            raise FetchError(f'DNS 解析失败: {exc}') from exc
        if not addresses:
            raise FetchError('DNS 未返回可用地址')
        for value in addresses:
            try:
                address = ipaddress.ip_address(value)
            except ValueError as exc:
                raise UnsafeTargetError(f'DNS 返回了无效地址: {value}') from exc
            if not address.is_global:
                raise UnsafeTargetError(f'拒绝访问非公网地址: {address}')


class HttpFetcher:
    """Fetch a bounded HTML response and validate every redirect hop."""

    REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})

    def __init__(self, safety_policy: Optional[NetworkSafetyPolicy] = None,
                 session_factory=requests.Session, max_redirects: int = 5,
                 max_bytes: int = 512 * 1024):
        self.safety_policy = safety_policy or NetworkSafetyPolicy()
        self.session_factory = session_factory
        self.max_redirects = max_redirects
        self.max_bytes = max_bytes

    def fetch(self, url: str) -> FetchResult:
        requested_url = url
        current_url = url
        chain = []
        redirect_userinfo = False
        with self.session_factory() as session:
            for redirect_index in range(self.max_redirects + 1):
                self.safety_policy.validate(current_url)
                try:
                    response = session.get(
                        current_url,
                        timeout=(3, 5),
                        allow_redirects=False,
                        stream=True,
                        headers={
                            'User-Agent': (
                                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                                'AppleWebKit/537.36 PhishingScanner/1.0'
                            )
                        },
                    )
                except requests.exceptions.SSLError as exc:
                    raise TLSVerificationError('TLS 证书校验失败') from exc
                chain.append({'url': current_url, 'status_code': response.status_code})
                if response.status_code in self.REDIRECT_CODES:
                    location = response.headers.get('location')
                    response.close()
                    if not location:
                        raise FetchError('重定向响应缺少 Location')
                    if redirect_index >= self.max_redirects:
                        raise FetchError(f'重定向次数超过上限 {self.max_redirects}')
                    current_url = urljoin(current_url, location)
                    parsed_redirect = urlsplit(current_url)
                    if parsed_redirect.username is not None or parsed_redirect.password is not None:
                        redirect_userinfo = True
                        current_url = _strip_userinfo(parsed_redirect)
                    continue

                content_type = response.headers.get('content-type', '').lower()
                if content_type and not any(
                        kind in content_type for kind in ('text/html', 'application/xhtml+xml')):
                    response.close()
                    raise FetchError(f'不支持的响应类型: {content_type.split(";", 1)[0]}')

                content = bytearray()
                truncated = False
                headers = {
                    str(key).lower(): str(value) for key, value in response.headers.items()
                }
                try:
                    for chunk in response.iter_content(chunk_size=8192):
                        remaining = self.max_bytes - len(content)
                        if remaining <= 0:
                            truncated = True
                            break
                        content.extend(chunk[:remaining])
                        if len(chunk) > remaining:
                            truncated = True
                            break
                finally:
                    response.close()
                return FetchResult(
                    requested_url=requested_url,
                    final_url=current_url,
                    status_code=response.status_code,
                    headers=headers,
                    content=bytes(content),
                    redirect_chain=chain,
                    truncated=truncated,
                    redirect_userinfo=redirect_userinfo,
                )
        raise FetchError('无法获取目标页面')


def _strip_userinfo(parsed_url) -> str:
    hostname = parsed_url.hostname or ''
    if ':' in hostname and not hostname.startswith('['):
        hostname = f'[{hostname}]'
    port = parsed_url.port
    netloc = hostname + (f':{port}' if port else '')
    return urlunsplit((
        parsed_url.scheme, netloc, parsed_url.path, parsed_url.query,
        parsed_url.fragment,
    ))
