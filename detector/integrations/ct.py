"""Certificate Transparency log lookups via crt.sh.

Queries the public crt.sh JSON API for certificates issued for a domain.
The lookup is optional (disabled by default because crt.sh is slow and
rate-limited) and fully cached.  It supports the G7 infrastructure group:
certificates whose SANs span protected brand names or known-suspicious
domains are strong correlation signals.
"""
import json
from typing import Callable, Dict, List, Optional

import requests

from ..utils.cache import TTLFileCache, null_cache
from ..utils.domain import registered_domain
from ..utils.tld import TLD_EXTRACTOR


CRT_SH_URL = 'https://crt.sh/'
DEFAULT_TIMEOUT = 10.0
DEFAULT_MAX_ENTRIES = 500


class CTLookup:
    """Fetch certificate transparency entries for a domain from crt.sh."""

    def __init__(self, cache: Optional[TTLFileCache] = None,
                 timeout: float = DEFAULT_TIMEOUT,
                 max_entries: int = DEFAULT_MAX_ENTRIES,
                 http_get: Optional[Callable] = None):
        self.cache = cache or null_cache()
        self.timeout = float(timeout)
        self.max_entries = int(max_entries)
        self._http_get = http_get or self._default_get

    def lookup(self, domain: str) -> Dict[str, object]:
        domain = str(domain or '').strip().lower().rstrip('.')
        if not domain:
            return {}
        cached = self.cache.get(f'ct:{domain}')
        if isinstance(cached, dict):
            return cached
        result = self._query(domain)
        if result:
            self.cache.set(f'ct:{domain}', result)
        return result

    def _query(self, domain: str) -> Dict[str, object]:
        try:
            response = self._http_get(domain)
            if not response:
                return {}
            entries = response[: self.max_entries]
        except Exception:
            return {}
        if not isinstance(entries, list):
            return {}
        return {
            'certificate_count': len(entries),
            'san_domains': _unique_domains(
                _iter_name_values(entries), limit=self.max_entries,
            ),
        }

    def _default_get(self, domain: str):
        response = requests.get(
            CRT_SH_URL,
            params={'q': domain, 'output': 'json'},
            timeout=self.timeout,
            headers={'User-Agent': 'PhishingScanner/2.1'},
        )
        response.raise_for_status()
        return response.json()


def _iter_name_values(entries: List[dict]):
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for key in ('name_value', 'common_name'):
            value = entry.get(key)
            if value:
                for name in str(value).split('\n'):
                    name = name.strip().lstrip('*.').lower()
                    if name:
                        yield name


def _unique_domains(names, limit: int) -> List[str]:
    result = []
    seen = set()
    for name in names:
        registered = registered_domain(name, TLD_EXTRACTOR)
        key = registered or name
        if key and key not in seen:
            seen.add(key)
            result.append(key)
        if len(result) >= limit:
            break
    return result
