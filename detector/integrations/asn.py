"""ASN ownership lookup through Cymru's DNS TXT service.

Uses only plain DNS queries (``origin.asn.cymru.com`` /
````asNNNN.asn.cymru.com````) so no HTTP API keys are required.  Results
are cached for long TTLs: ASN ownership changes rarely.
"""
from typing import Callable, Dict, Optional

try:  # pragma: no cover
    import dns.resolver
    import dns.exception
except ImportError:  # pragma: no cover
    dns = None

from ..utils.cache import TTLFileCache, null_cache


DEFAULT_TIMEOUT = 3.0


class ASNLookup:
    """Resolve the autonomous system owning an IP address."""

    def __init__(self, cache: Optional[TTLFileCache] = None,
                 timeout: float = DEFAULT_TIMEOUT,
                 resolver_factory: Optional[Callable] = None):
        self.cache = cache or null_cache()
        self.timeout = float(timeout)
        self._resolver_factory = resolver_factory
        self._resolver = None

    def lookup(self, address: str) -> Dict[str, object]:
        address = str(address or '').strip()
        if not address:
            return {}
        cached = self.cache.get(f'asn:{address}')
        if isinstance(cached, dict):
            return cached
        result = self._query(address)
        if result:
            self.cache.set(f'asn:{address}', result)
        return result

    def _query(self, address: str) -> Dict[str, object]:
        if dns is None or self._resolver_factory is False:
            return {}
        try:
            if self._resolver is None:
                if self._resolver_factory is not None:
                    self._resolver = self._resolver_factory()
                else:
                    self._resolver = dns.resolver.Resolver()
                    self._resolver.lifetime = self.timeout
                    self._resolver.timeout = self.timeout
            origin = self._origin_query(self._resolver, address)
            if not origin:
                return {}
            asn = origin.get('asn') or ''
            return {
                'asn': asn,
                'prefix': origin.get('prefix', ''),
                'holder': self._holder_query(self._resolver, asn),
            }
        except Exception:
            return {}

    @staticmethod
    def _origin_query(resolver, address: str) -> Dict[str, str]:
        try:
            if ':' in address:  # IPv6 is stored as a nibble-reversed hex name
                exploded = address.split(':')
                hex_name = '.'.join(
                    char for segment in exploded for char in segment.zfill(4)[::-1]
                )
                query = f'{hex_name}.origin6.asn.cymru.com'
            else:
                octets = address.split('.')
                query = f'{".".join(reversed(octets))}.origin.asn.cymru.com'
            answer = str(resolver.resolve(query, 'TXT')[0])
            parts = [field.strip().strip('"') for field in answer.split('|')]
            if len(parts) >= 3:
                return {
                    'asn': parts[0].replace('AS', '', 1),
                    'prefix': parts[1],
                    'country': parts[2],
                }
        except Exception:
            return {}
        return {}

    @staticmethod
    def _holder_query(resolver, asn: str) -> str:
        if not asn:
            return ''
        try:
            answer = str(resolver.resolve(f'as{asn}.asn.cymru.com', 'TXT')[0])
            parts = [field.strip().strip('"') for field in answer.split('|')]
            if len(parts) >= 5:
                return parts[4]
        except Exception:
            return ''
        return ''
