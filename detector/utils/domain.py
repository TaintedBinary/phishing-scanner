"""Shared domain utilities used across multiple modules.

Provides hostname normalization, domain normalization, and other
common domain-related helpers to eliminate code duplication.
"""

import re


def ascii_hostname(hostname: str) -> str:
    """Convert a Unicode hostname to its ASCII (IDNA) representation."""
    labels = []
    for label in str(hostname or '').strip('.').lower().split('.'):
        if not label:
            continue
        try:
            labels.append(label.encode('idna').decode('ascii'))
        except (UnicodeError, ValueError):
            return ''
    result = '.'.join(labels)
    if len(result) > 253 or any(
            len(label) > 63 or not re.fullmatch(r'[a-z0-9-]+', label)
            or label.startswith('-') or label.endswith('-')
            for label in labels):
        return ''
    return result


def unicode_hostname(hostname: str) -> str:
    """Decode an ASCII (IDNA) hostname back to Unicode."""
    labels = []
    for label in str(hostname or '').strip('.').lower().split('.'):
        if not label:
            continue
        try:
            labels.append(label.encode('ascii').decode('idna'))
        except (UnicodeError, ValueError):
            labels.append(label)
    return '.'.join(labels)


def normalize_domain(domain: str) -> str:
    """Normalize a domain: lowercase, strip dots, remove www. prefix."""
    domain = str(domain or '').strip().strip('.').lower()
    if domain.startswith('www.'):
        domain = domain[4:]
    return domain


def registered_domain(hostname: str, tld_extractor) -> str:
    """Extract the registered domain from a hostname using a TLD extractor."""
    hostname = str(hostname or '').strip('.').lower()
    extracted = tld_extractor(hostname)
    if extracted.domain and extracted.suffix:
        return f'{extracted.domain}.{extracted.suffix}'
    return hostname
