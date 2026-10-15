"""Infrastructure-layer (L2) evidence analysis.

Combines DNS records, ASN ownership, and certificate transparency data
with a local knowledge base into explainable G7 infrastructure signals:

- shared IP with known-bad infrastructure  (INFRA-502, strong)
- certificate linked to suspicious domains or brand SANs (INFRA-503)
- hosting in a known abusive ASN           (INFRA-504, medium)
- free/dynamic DNS name servers            (INFRA-505, weak)

All network lookups are injectable and exception-guarded, so the analyzer
degrades to an empty result (no evidence) when offline.  Nothing here can
produce a verdict on its own; the evidence engine combines G7 with other
groups per the standard fusion rules.
"""
import ipaddress
import json
import os
from typing import Dict, Optional

from ..integrations.asn import ASNLookup
from ..integrations.ct import CTLookup
from ..integrations.dns_records import DNSRecordLookup

DEFAULT_FREE_DNS_PROVIDERS = (
    'afraid.org', 'duckdns.org', 'no-ip.com', 'no-ip.org', 'ddns.net',
    'hopto.org', 'zapto.org', 'serveo.org', 'ngrok.io', 'dynu.com',
    'freedns.zone', 'changeip.com', 'dnsdynamic.org', 'strangled.net',
)


def load_knowledge_base(path) -> dict:
    """Load the local known-bad infrastructure knowledge base."""
    default = {
        'bad_ips': [],
        'bad_asns': [],
        'bad_domains': [],
        'suspicious_cert_domains': [],
    }
    if not path or not os.path.isfile(path):
        return default
    try:
        with open(path, 'r', encoding='utf-8-sig') as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return default
    if not isinstance(data, dict):
        return default
    result = dict(default)
    for key in default:
        value = data.get(key)
        if isinstance(value, list):
            result[key] = [str(item).strip().lower() for item in value
                           if str(item).strip()]
    return result


class InfrastructureAnalyzer:
    """Assemble infrastructure context and G7 evidence signals."""

    def __init__(self, dns_lookup: Optional[DNSRecordLookup] = None,
                 asn_lookup: Optional[ASNLookup] = None,
                 ct_lookup: Optional[CTLookup] = None,
                 knowledge_base: Optional[dict] = None,
                 knowledge_base_path: str = '',
                 free_dns_providers=DEFAULT_FREE_DNS_PROVIDERS,
                 brand_aliases=None):
        self.dns_lookup = dns_lookup if dns_lookup is not None else DNSRecordLookup()
        self.asn_lookup = asn_lookup if asn_lookup is not None else ASNLookup()
        self.ct_lookup = ct_lookup  # None disables CT (crt.sh is slow)
        self.knowledge_base = (
            knowledge_base if knowledge_base is not None
            else load_knowledge_base(knowledge_base_path)
        )
        self.free_dns_providers = {
            str(provider).lower() for provider in (free_dns_providers or ())
        }
        self.brand_aliases = {
            str(alias).lower() for alias in (brand_aliases or ())
        }

    def analyze(self, domain: str, registered_domain: str = '') -> Dict[str, object]:
        """Return raw infrastructure data plus derived evidence signals."""
        domain = str(domain or '').strip().lower().rstrip('.')
        if not domain:
            return {}
        dns_data = self._safe(self.dns_lookup.lookup, domain) or {}
        addresses = list(dns_data.get('addresses') or [])
        asn_data = self._asn_for(addresses)
        ct_data = (
            self._safe(self.ct_lookup.lookup, registered_domain or domain) or {}
            if self.ct_lookup is not None else {}
        )
        signals = self._signals(
            domain, registered_domain or domain, dns_data, asn_data, ct_data,
        )
        return {
            'dns': dns_data or None,
            'asn': asn_data or None,
            'ct': ct_data or None,
            'signals': signals,
        }

    # ------------------------------------------------------------------
    def _asn_for(self, addresses: list) -> dict:
        for address in addresses:
            asn_data = self._safe(self.asn_lookup.lookup, address)
            if asn_data:
                return asn_data
        return {}

    def _signals(self, domain: str, registered: str,
                 dns_data: dict, asn_data: dict, ct_data: dict) -> Dict[str, object]:
        signals: Dict[str, object] = {}

        matched_ip = self._match_bad_ip(dns_data.get('addresses') or [])
        if matched_ip:
            signals['shared_ip_with_known_bad'] = True
            signals['shared_ip_detail'] = matched_ip

        asn = str(asn_data.get('asn') or '')
        if asn and asn in {str(item).replace('as', '', 1).lower()
                           for item in self.knowledge_base.get('bad_asns', [])}:
            signals['abusive_asn'] = True
            signals['abusive_asn_detail'] = (
                f"AS{asn} {asn_data.get('holder', '')}".strip()
            )

        san_domains = list(ct_data.get('san_domains') or [])
        if san_domains:
            suspicious_hits = [
                item for item in san_domains
                if item in set(self.knowledge_base.get(
                    'suspicious_cert_domains', []))
                or item in set(self.knowledge_base.get('bad_domains', []))
            ]
            brand_hits = [
                item for item in san_domains
                if self._contains_brand(item) and item != registered
            ]
            if suspicious_hits:
                signals['cert_shared_with_suspicious'] = True
                signals['cert_suspicious_domains'] = suspicious_hits
            if brand_hits:
                signals['cert_brand_san'] = True
                signals['cert_brand_domains'] = brand_hits

        free_ns = [
            ns for ns in (dns_data.get('name_servers') or [])
            if any(ns == provider or ns.endswith('.' + provider)
                   for provider in self.free_dns_providers)
        ]
        if free_ns:
            signals['free_dns_provider'] = True
            signals['free_dns_detail'] = ', '.join(free_ns[:3])

        return signals

    def _match_bad_ip(self, addresses: list) -> str:
        bad_entries = self.knowledge_base.get('bad_ips', [])
        if not bad_entries:
            return ''
        networks = []
        for entry in bad_entries:
            try:
                networks.append((entry, ipaddress.ip_network(entry, strict=False)))
            except ValueError:
                continue
        for address in addresses:
            try:
                value = ipaddress.ip_address(address)
            except ValueError:
                continue
            for entry, network in networks:
                if value in network:
                    return f'{address} in {entry}'
        return ''

    def _contains_brand(self, domain: str) -> bool:
        if not self.brand_aliases:
            return False
        label = domain.split('.')[0]
        return any(alias in label for alias in self.brand_aliases if len(alias) >= 5)

    @staticmethod
    def _safe(func, *args):
        try:
            return func(*args)
        except Exception:
            return {}
