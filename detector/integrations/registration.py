"""Unified WHOIS and RDAP registration-data lookup."""

from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Dict, List, Optional

from .rdap import extract_dates, get_domain_status, get_registrar, query_rdap
from .whois import query_whois
from ..utils.cache import TTLFileCache, null_cache


@dataclass
class RegistrationResult:
    data: Dict[str, object]
    rdap: Optional[Dict[str, object]] = None
    warnings: List[str] = field(default_factory=list)


class RegistrationLookup:
    """Query WHOIS and RDAP independently, then merge their useful fields.

    When a TTLFileCache is provided, merged results are cached per domain
    so repeated scans do not re-query WHOIS/RDAP servers (the report's
    caching recommendation for RDAP-level data).
    """

    def __init__(self, whois_query: Callable = query_whois,
                 rdap_query: Callable = query_rdap,
                 cache: Optional[TTLFileCache] = None,
                 cache_ttl: float = 7 * 24 * 3600):
        self._whois_query = whois_query
        self._rdap_query = rdap_query
        self._cache = cache or null_cache()
        self._cache_ttl = float(cache_ttl)

    def lookup(self, domain: str) -> RegistrationResult:
        cached = self._cache.get(f'registration:{domain}')
        if isinstance(cached, dict) and cached.get('data'):
            return RegistrationResult(
                data=cached['data'],
                rdap=cached.get('rdap'),
                warnings=list(cached.get('warnings') or []),
            )
        result = self._query(domain)
        self._cache.set(f'registration:{domain}', {
            'data': result.data,
            'rdap': result.rdap,
            'warnings': result.warnings,
        })
        return result

    def _query(self, domain: str) -> RegistrationResult:
        warnings = []
        whois_data = None
        rdap_data = None
        with ThreadPoolExecutor(max_workers=2, thread_name_prefix='registration') as executor:
            whois_future = executor.submit(self._whois_query, domain, timeout=4)
            rdap_future = executor.submit(self._rdap_query, domain, timeout=5)
            try:
                whois_data = whois_future.result()
            except Exception as exc:
                warnings.append(f'WHOIS 查询失败: {exc}')
            try:
                rdap_data = rdap_future.result()
            except Exception as exc:
                warnings.append(f'RDAP 查询失败: {exc}')

        data = _normalize_whois(whois_data)
        if rdap_data:
            dates = extract_dates(rdap_data)
            data['creation_date'] = data.get('creation_date') or dates.get('created') or ''
            data['expiration_date'] = data.get('expiration_date') or dates.get('expires') or ''
            data['updated_date'] = data.get('updated_date') or dates.get('updated') or ''
            data['registrar'] = data.get('registrar') or get_registrar(rdap_data) or ''
            data['status'] = data.get('status') or get_domain_status(rdap_data)
            data['available'] = True
            data['sources'] = ['whois', 'rdap'] if whois_data else ['rdap']
        elif whois_data:
            data['sources'] = ['whois']
        return RegistrationResult(data=data, rdap=rdap_data, warnings=warnings)


def _normalize_whois(value) -> Dict[str, object]:
    value = value if isinstance(value, dict) else {}
    email_value = value.get('registrant_email') or value.get('registrant_emails') or []
    if isinstance(email_value, str):
        emails = [item.strip() for item in email_value.split(',') if item.strip()]
    elif isinstance(email_value, (list, tuple, set)):
        emails = [str(item).strip() for item in email_value if str(item).strip()]
    else:
        emails = []
    fields = (
        'registrar', 'registrant_name', 'registrant_org', 'creation_date',
        'expiration_date', 'updated_date', 'name_servers', 'status',
        'registrant_phone', 'registrant_address', 'country', 'city', 'state',
        'zipcode',
    )
    result = {field: value.get(field, '') for field in fields}
    result['registrant_emails'] = list(dict.fromkeys(emails))
    result['available'] = bool(value)
    result['sources'] = []
    return result
