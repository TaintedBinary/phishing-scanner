"""DNS record queries for the infrastructure layer (L2).

Resolves A/AAAA/NS/MX and PTR records through dnspython when available.
Every query is exception-guarded and cached so a failed or slow resolver
never breaks the scan pipeline.  The resolver callable is injectable for
offline testing.
"""
from typing import Callable, Dict, List, Optional

try:  # pragma: no cover - exercised only when dnspython is installed
    import dns.resolver
    import dns.reversename
    import dns.exception
except ImportError:  # pragma: no cover
    dns = None

from ..utils.cache import TTLFileCache, null_cache


DEFAULT_TIMEOUT = 3.0


class DNSRecordLookup:
    """Query the DNS records used for infrastructure analysis."""

    def __init__(self, cache: Optional[TTLFileCache] = None,
                 timeout: float = DEFAULT_TIMEOUT,
                 resolver_factory: Optional[Callable] = None):
        self.cache = cache or null_cache()
        self.timeout = float(timeout)
        self._resolver_factory = resolver_factory
        self._resolver = None

    def lookup(self, domain: str) -> Dict[str, object]:
        domain = str(domain or '').strip().lower().rstrip('.')
        if not domain:
            return {}
        cached = self.cache.get(f'dns:{domain}')
        if isinstance(cached, dict):
            return cached
        result = self._query(domain)
        if result:
            self.cache.set(f'dns:{domain}', result)
        return result

    def _query(self, domain: str) -> Dict[str, object]:
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
            return {
                'addresses': self._resolve(self._resolver, domain, 'A'),
                'addresses_v6': self._resolve(self._resolver, domain, 'AAAA'),
                'name_servers': self._resolve(self._resolver, domain, 'NS'),
                'mail_servers': self._resolve(self._resolver, domain, 'MX'),
                'ptr': self._reverse(self._resolver, domain),
            }
        except Exception:
            return {}

    @staticmethod
    def _resolve(resolver, domain: str, record_type: str) -> List[str]:
        try:
            answers = resolver.resolve(domain, record_type)
            return [str(answer).strip().rstrip('.') for answer in answers]
        except Exception:
            return []

    @staticmethod
    def _reverse(resolver, domain: str) -> str:
        """PTR for the first A record, used as hosting context."""
        try:
            addresses = resolver.resolve(domain, 'A')
            if not addresses:
                return ''
            reversed_name = dns.reversename.from_address(str(addresses[0]))
            return str(resolver.resolve(reversed_name, 'PTR')[0]).strip().rstrip('.')
        except Exception:
            return ''
