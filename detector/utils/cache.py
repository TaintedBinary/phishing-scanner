"""Generic TTL JSON file cache shared by network integrations.

All scanner lookups (WHOIS/RDAP, DNS records, ASN, CT logs, favicon
hashes) funnel through this store so repeated scans avoid redundant
external queries.  Writes are atomic (temp file + ``os.replace``) and
all operations are guarded by a lock, matching the safety guarantees
of :mod:`detector.integrations.icp_cache`.
"""
import json
import os
import tempfile
import threading
import time
from typing import Any, Optional


DEFAULT_TTL = 7 * 24 * 3600  # one week


class TTLFileCache:
    """Persist JSON values keyed by string with per-entry timestamps."""

    def __init__(self, path: str, default_ttl: float = DEFAULT_TTL):
        self.path = str(path)
        self.default_ttl = float(default_ttl)
        self._lock = threading.Lock()
        self._entries = self._load()

    def get(self, key: str, max_age: Optional[float] = None) -> Any:
        """Return the cached value or None when missing/expired."""
        max_age = self.default_ttl if max_age is None else float(max_age)
        with self._lock:
            entry = self._entries.get(str(key))
            if not isinstance(entry, dict):
                return None
            timestamp = float(entry.get('t', 0))
            value = entry.get('v')
            if max_age <= 0 or time.time() - timestamp > max_age:
                return None
            return value

    def set(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        """Store *value* under *key* and persist atomically.

        ``ttl`` is accepted for API symmetry; expiry is evaluated at read
        time via ``get(max_age=...)`` using the reader's policy.
        """
        entry = {'t': time.time(), 'v': value}
        with self._lock:
            self._entries[str(key)] = entry
            self._save()

    def clear(self) -> None:
        with self._lock:
            self._entries = {}
            self._save()

    def _load(self) -> dict:
        if not os.path.isfile(self.path):
            return {}
        try:
            with open(self.path, 'r', encoding='utf-8-sig') as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    def _save(self) -> None:
        directory = os.path.dirname(os.path.abspath(self.path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        descriptor, temporary_path = tempfile.mkstemp(
            prefix='.cache-', suffix='.tmp', dir=directory, text=True
        )
        try:
            with os.fdopen(descriptor, 'w', encoding='utf-8') as handle:
                json.dump(self._entries, handle, ensure_ascii=False, indent=2)
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


def null_cache() -> 'TTLFileCache':
    """Return a disabled cache handle (never persists, never returns data)."""
    return _NullCache()


class _NullCache(TTLFileCache):
    def __init__(self):  # pylint: disable=super-init-not-called
        self.path = ''
        self.default_ttl = 0
        self._lock = threading.Lock()

    def get(self, key, max_age=None):
        return None

    def set(self, key, value, ttl=None):
        return None

    def clear(self):
        return None

    def _save(self):
        return None
