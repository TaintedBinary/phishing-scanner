"""Local URL database checks used before heuristic analysis."""
import os
import re
from typing import Dict, Iterable, List, Optional


class URLBlocklist:
    """Check domains against local URL database files.

    The detector checks the extracted registrable domain against domains found
    in the local database files. Subdomains in the database do not imply their
    parent domain is blocked.
    """

    def __init__(self, paths: Iterable[str], enabled: bool = True):
        self.paths = list(paths or [])
        self.enabled = enabled
        entries = self._load_entries() if enabled else []
        self.entries = {entry['domain']: entry for entry in entries}

    def check(self, domain: str) -> Optional[Dict[str, str]]:
        if not self.enabled:
            return None

        domain = normalize_domain(domain)
        if not domain:
            return None

        entry = self.entries.get(domain)
        if not entry:
            return None
        return {
            'domain': domain,
            'matched': entry['domain'],
            'raw': entry['value'],
            'source': entry['source'],
        }

    def _load_entries(self) -> List[Dict[str, str]]:
        entries = []
        for path in self.paths:
            if not path:
                continue
            if os.path.isdir(path):
                entries.extend(self._load_directory(path))
            elif os.path.isfile(path):
                entries.extend(self._load_file(path))
        return entries

    def _load_directory(self, directory: str) -> List[Dict[str, str]]:
        entries = []
        for root, _, files in os.walk(directory):
            for filename in files:
                entries.extend(self._load_file(os.path.join(root, filename)))
        return entries

    def _load_file(self, path: str) -> List[Dict[str, str]]:
        entries = []
        try:
            with open(path, 'r', encoding='utf-8-sig', errors='ignore') as handle:
                for line in handle:
                    value = normalize_line(line)
                    if not value:
                        continue
                    for domain in extract_domains_from_line(value):
                        entries.append({
                            'value': value,
                            'domain': domain,
                            'source': path,
                        })
        except OSError:
            return []
        return entries


def normalize_line(line: str) -> str:
    line = str(line or '').strip()
    if not line or line.startswith('#'):
        return ''
    return line.lower()


def normalize_domain(domain: str) -> str:
    domain = str(domain or '').strip().strip('.').lower()
    if domain.startswith('www.'):
        domain = domain[4:]
    return domain


def extract_domains_from_line(line: str) -> List[str]:
    line = normalize_line(line)
    if not line or '//' in line:
        return []

    domains = []
    seen = set()
    for token in re.findall(r'[a-z0-9][a-z0-9._~:/?#\[\]@!$&\'()*+,;=%-]*', line):
        domain = extract_domain_from_token(token)
        if domain and domain not in seen:
            seen.add(domain)
            domains.append(domain)
    return domains


def extract_domain_from_token(token: str) -> str:
    token = str(token or '').strip().strip('\'"`“”‘’，,;()[]{}<>')
    if not token:
        return ''
    if '//' in token:
        return ''
    hostname = token.split('/')[0].split(':')[0]
    hostname = normalize_domain(hostname)
    if not is_domain_name(hostname):
        return ''
    return hostname


def is_domain_name(value: str) -> bool:
    if not value or '.' not in value:
        return False
    if re.fullmatch(r'\d+(?:\.\d+){3}', value):
        return False
    labels = value.split('.')
    return all(re.fullmatch(r'[a-z0-9-]+', label) for label in labels)
