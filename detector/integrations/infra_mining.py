"""Derive the infrastructure knowledge base from the local URL database.

The URL database (URLBlocklist) answers one question: "is this exact domain
known-bad?"  Attackers register fresh domains daily, so that list alone goes
stale.  What stays stable is the infrastructure behind the domains: the same
server IPs, the same abusive ASNs, the same certificates.

This module turns the URL database into those derived indicators:

- ``bad_ips``    addresses hosting >= N distinct malicious domains
- ``bad_asns``   autonomous systems hosting >= M distinct malicious domains
- ``bad_domains`` the source malicious domains (certificate SAN correlation)

Shared-infrastructure false positives are the main hazard: a phishing site on
Cloudflare shares an IP with millions of legitimate sites.  Therefore major
CDN / cloud / carrier ASNs are excluded by default (configurable), and single-
domain IPs never enter ``bad_ips``.  Derived evidence is E3 (fusion), never a
direct verdict, for exactly this reason.

All lookups are injectable and exception-guarded.  The CLI entry point is
``phishing_detector.py --build-infra``.
"""
import ipaddress
import json
import os
from collections import defaultdict

# Major CDN / cloud / carrier ASNs.  They host millions of legitimate sites,
# so "many malicious domains here" is expected background noise, not signal.
EXCLUDED_ASN_DEFAULTS = frozenset({
    '13335',  # Cloudflare
    '16509', '14618',  # Amazon AWS
    '15169', '396982',  # Google
    '8075', '8068', '8069', '8070', '8071', '8072', '8073', '8074',  # Microsoft / Azure
    '20940', '16625', '20944',  # Akamai
    '54113',  # Fastly
    '14061',  # DigitalOcean
    '20473',  # Vultr
    '24940',  # Hetzner
    '16276',  # OVH
    '45102', '37963',  # Alibaba Cloud
    '132203', '45090',  # Tencent Cloud
    '4134', '4814', '4837', '9808', '58466',  # CN carriers (Chinatelecom / Unicom / Mobile)
    '6939',  # Hurricane Electric (transit)
    '174', '1299', '2914', '3257', '3356', '6461',  # Tier-1 transit
})

KNOWLEDGE_KEYS = ('bad_ips', 'bad_asns', 'bad_domains', 'suspicious_cert_domains')


def normalize_asn(value) -> str:
    """Normalize 'AS13335' / 'as13335' / 13335 to the bare numeric string."""
    value = str(value or '').strip().lower()
    if value.startswith('as') and value[2:].isdigit():
        value = value[2:]
    return value


def _is_global_address(address) -> bool:
    try:
        return ipaddress.ip_address(str(address).strip()).is_global
    except ValueError:
        return False


def derive_knowledge(domains, dns_lookup, asn_lookup, *,
                     min_domains_per_ip=2, min_domains_per_asn=3,
                     excluded_asns=EXCLUDED_ASN_DEFAULTS):
    """Resolve malicious domains and aggregate shared infrastructure.

    Returns ``{'knowledge': {...}, 'stats': {...}}``.  Never raises on
    individual lookup failures; failing domains are simply counted.
    """
    domains = [normalize_domain(d) for d in domains]
    domains = sorted({d for d in domains if d})
    excluded = {normalize_asn(a) for a in (excluded_asns or ())}

    ip_domains = defaultdict(set)
    resolved = 0
    for domain in domains:
        data = _safe_lookup(dns_lookup, domain)
        addresses = [
            address for address in
            list(data.get('addresses') or []) + list(data.get('addresses_v6') or [])
            if _is_global_address(address)
        ]
        if not addresses:
            continue
        resolved += 1
        for address in addresses:
            ip_domains[str(address).strip()].add(domain)

    asn_domains = defaultdict(set)
    asn_holders = {}
    for address, address_domains in ip_domains.items():
        info = _safe_lookup(asn_lookup, address)
        asn = normalize_asn(info.get('asn'))
        if not asn:
            continue
        asn_domains[asn] |= address_domains
        if info.get('holder'):
            asn_holders.setdefault(asn, str(info['holder']).strip())

    bad_ips = sorted(
        address for address, address_domains in ip_domains.items()
        if len(address_domains) >= min_domains_per_ip
    )
    bad_asns = sorted(
        asn for asn, asn_domains_set in asn_domains.items()
        if len(asn_domains_set) >= min_domains_per_asn and asn not in excluded
    )

    knowledge = {
        'bad_ips': bad_ips,
        'bad_asns': bad_asns,
        'bad_domains': list(domains),
        'suspicious_cert_domains': [],
    }
    stats = {
        'total_domains': len(domains),
        'resolved_domains': resolved,
        'distinct_addresses': len(ip_domains),
        'distinct_asns': len(asn_domains),
        'bad_ips': len(bad_ips),
        'bad_asns': len(bad_asns),
        'excluded_asns': sorted(
            asn for asn, asn_domains_set in asn_domains.items()
            if len(asn_domains_set) >= min_domains_per_asn and asn in excluded
        ),
        'asn_holders': {asn: asn_holders.get(asn, '') for asn in bad_asns},
    }
    return {'knowledge': knowledge, 'stats': stats}


def merge_knowledge(existing, derived):
    """Union derived indicators into the existing knowledge base.

    Manual additions are never lost: entries only accumulate.  Re-running the
    derivation refreshes the derived sets from the current URL database while
    keeping anything added by hand (e.g. suspicious_cert_domains).
    """
    existing = existing or {}
    derived = derived or {}
    merged = {}
    for key in KNOWLEDGE_KEYS:
        values = list(existing.get(key) or []) + list(derived.get(key) or [])
        merged[key] = sorted({
            str(value).strip().lower() for value in values if str(value).strip()
        })
    return merged


def write_knowledge(path, knowledge):
    """Write the knowledge base atomically (UTF-8 JSON)."""
    path = str(path)
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    tmp_path = path + '.tmp'
    with open(tmp_path, 'w', encoding='utf-8') as handle:
        json.dump(knowledge, handle, ensure_ascii=False, indent=2)
        handle.write('\n')
    os.replace(tmp_path, path)
    return path


def normalize_domain(domain) -> str:
    domain = str(domain or '').strip().lower().rstrip('.')
    if domain.startswith('www.'):
        domain = domain[4:]
    return domain


def _safe_lookup(lookup, key):
    try:
        result = lookup.lookup(key)
    except Exception:
        return {}
    return result if isinstance(result, dict) else {}
