"""Local ICP filing record cache."""
import json
import os
import tempfile
import threading
from typing import Any, Dict, Optional


FIELD_DOMAIN = '域名'
FIELD_UNIT = '主办单位'
FIELD_SITE_LICENSE = '网站备案号'
FIELD_MAIN_LICENSE = '主体备案号'
FIELD_UPDATED_AT = '更新时间'


class ICPRecordStore:
    """Store ICP filing records by domain in a JSON file.

    Thread-safe: all reads and writes are protected by a lock to prevent
    concurrent access from corrupting the JSON cache file.
    """

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self.records = self._load()

    def get(self, domain: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self.records.get(normalize_domain(domain))

    def put_record(self, domain: str, record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        filing = extract_filing_record(domain, record)
        if not filing:
            return None

        with self._lock:
            self.records[filing[FIELD_DOMAIN]] = filing
            self.save()
        return filing

    def save(self) -> None:
        directory = os.path.dirname(os.path.abspath(self.path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        descriptor, temporary_path = tempfile.mkstemp(
            prefix='.icp-records-', suffix='.tmp', dir=directory, text=True
        )
        try:
            with os.fdopen(descriptor, 'w', encoding='utf-8') as handle:
                json.dump(self.records, handle, ensure_ascii=False, indent=2)
                handle.write('\n')
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, self.path)
        except Exception:
            try:
                os.unlink(temporary_path)
            except OSError:
                pass
            raise

    def _load(self) -> Dict[str, Dict[str, Any]]:
        if not os.path.isfile(self.path):
            return {}
        try:
            with open(self.path, 'r', encoding='utf-8-sig') as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return {}

        if not isinstance(data, dict):
            return {}

        records = {}
        for key, value in data.items():
            if not isinstance(value, dict):
                continue
            domain = normalize_domain(value.get(FIELD_DOMAIN) or key)
            if not domain:
                continue
            records[domain] = {
                FIELD_DOMAIN: domain,
                FIELD_UNIT: str(value.get(FIELD_UNIT, '')).strip(),
                FIELD_SITE_LICENSE: str(value.get(FIELD_SITE_LICENSE, '')).strip(),
                FIELD_MAIN_LICENSE: str(value.get(FIELD_MAIN_LICENSE, '')).strip(),
                FIELD_UPDATED_AT: str(value.get(FIELD_UPDATED_AT, '')).strip(),
            }
        return records


def normalize_domain(domain: str) -> str:
    domain = str(domain or '').strip().strip('.').lower()
    if domain.startswith('www.'):
        domain = domain[4:]
    return domain


def extract_filing_record(domain: str, record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not isinstance(record, dict):
        return None

    normalized_domain = normalize_domain(record.get('domain') or domain)
    if not normalized_domain:
        return None

    filing = {
        FIELD_DOMAIN: normalized_domain,
        FIELD_UNIT: _first(record, 'unitName', 'mainUnitName'),
        FIELD_SITE_LICENSE: _first(record, 'serviceLicence', 'siteLicense', 'serviceLicense'),
        FIELD_MAIN_LICENSE: _first(record, 'mainLicence'),
        FIELD_UPDATED_AT: _first(record, 'updateRecordTime'),
    }
    if not any(filing[field] for field in (
            FIELD_UNIT, FIELD_SITE_LICENSE, FIELD_MAIN_LICENSE, FIELD_UPDATED_AT)):
        return None
    return filing


def cached_record_to_provider_record(record: Dict[str, Any]) -> Dict[str, Any]:
    return {
        'domain': record.get(FIELD_DOMAIN, ''),
        'unitName': record.get(FIELD_UNIT, ''),
        'mainUnitName': record.get(FIELD_UNIT, ''),
        'serviceLicence': record.get(FIELD_SITE_LICENSE, ''),
        'siteLicense': record.get(FIELD_SITE_LICENSE, ''),
        'serviceLicense': record.get(FIELD_SITE_LICENSE, ''),
        'mainLicence': record.get(FIELD_MAIN_LICENSE, ''),
        'updateRecordTime': record.get(FIELD_UPDATED_AT, ''),
    }


def _first(record: Dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = str(record.get(key, '')).strip()
        if value:
            return value
    return ''
