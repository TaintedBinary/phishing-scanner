"""ICP filing query integrations."""
import os
import re
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional, Sequence

import requests
import tldextract

from .icp_cache import cached_record_to_provider_record

TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
ASCII_DOMAIN_RE = re.compile(r'^[a-z0-9.-]+$')


class ICPServiceError(RuntimeError):
    """Raised when an ICP provider cannot be started or queried."""


class ICPService:
    """Manage a local ICP_Query service and query website filing records."""

    source_name = 'ICP_Query/MIIT'

    def __init__(self, base_url: str,
                 exe_path: str,
                 auto_start: bool = True,
                 startup_timeout: float = 20,
                 request_timeout: float = 20):
        self.base_url = base_url.rstrip('/')
        self.exe_path = os.path.abspath(exe_path)
        self.auto_start = auto_start
        self.startup_timeout = startup_timeout
        self.request_timeout = request_timeout
        self.process: Optional[subprocess.Popen] = None
        self._start_lock = threading.Lock()

    def _is_ready(self) -> bool:
        try:
            response = requests.get(self.base_url, timeout=2)
            return response.status_code < 500
        except requests.RequestException:
            return False

    def ensure_started(self) -> bool:
        """Reuse an existing service, or start the configured executable."""
        with self._start_lock:
            return self._ensure_started_locked()

    def _ensure_started_locked(self) -> bool:
        if self._is_ready():
            return False

        if not self.auto_start:
            raise ICPServiceError(f'ICP service is not running: {self.base_url}')

        if not os.path.isfile(self.exe_path):
            raise ICPServiceError(f'ICP executable not found: {self.exe_path}')

        exe_dir = os.path.dirname(self.exe_path)
        creationflags = 0
        startupinfo = None
        if os.name == 'nt':
            creationflags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = 0

        try:
            self.process = subprocess.Popen(
                [self.exe_path],
                cwd=exe_dir,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=creationflags,
                startupinfo=startupinfo,
            )
        except OSError as exc:
            raise ICPServiceError(f'Failed to start ICP service: {exc}') from exc

        deadline = time.monotonic() + self.startup_timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise ICPServiceError(
                    f'ICP service exited early with code: {self.process.returncode}'
                )
            if self._is_ready():
                return True
            time.sleep(0.25)

        self.stop()
        raise ICPServiceError(
            f'ICP service was not ready within {self.startup_timeout:g}s: {self.base_url}'
        )

    def query_web(self, domain: str, page_num: int = 1,
                  page_size: int = 10) -> Dict[str, Any]:
        self.ensure_started()
        response = requests.get(
            f'{self.base_url}/query/web',
            params={
                'search': domain,
                'pageNum': page_num,
                'pageSize': page_size,
            },
            timeout=self.request_timeout,
        )
        response.raise_for_status()
        try:
            data = response.json()
        except ValueError as exc:
            raise ICPServiceError('ICP service did not return valid JSON') from exc
        if not isinstance(data, dict):
            raise ICPServiceError('ICP service returned an unexpected payload')
        return data

    def stop(self) -> None:
        """Stop only the service process started by this client instance."""
        if self.process is None or self.process.poll() is not None:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=3)


class ICP4759API:
    """Query ping.4759.cn and normalize the response to ICP_Query shape."""

    source_name = '4759.cn/MIIT'

    def __init__(self, api_url: str, api_key: str, request_timeout: float = 20):
        self.api_url = api_url
        self.api_key = api_key
        self.request_timeout = request_timeout

    def query_web(self, domain: str) -> Dict[str, Any]:
        if not self.api_key:
            raise ICPServiceError('4759 ICP API key is not configured')

        try:
            response = requests.get(
                self.api_url,
                params={'key': self.api_key, 'domain': domain},
                timeout=self.request_timeout,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            raise ICPServiceError(f'4759 ICP API request failed: {exc.__class__.__name__}') from exc

        try:
            data = response.json()
        except ValueError as exc:
            raise ICPServiceError('4759 ICP API did not return valid JSON') from exc
        if not isinstance(data, dict):
            raise ICPServiceError('4759 ICP API returned an unexpected payload')
        return normalize_4759_response(data)


def normalize_4759_response(data: Dict[str, Any]) -> Dict[str, Any]:
    """Convert 4759.cn response fields to the record format used by the CLI."""
    if data.get('code') != 200:
        return data

    record = data.get('data') or {}
    if not isinstance(record, dict) or not record:
        return {
            'code': 200,
            'msg': data.get('msg', ''),
            'params': {'list': []},
            'call_stats': data.get('call_stats'),
            'used_api': data.get('used_api'),
            'raw': data,
        }

    normalized = {
        'domain': record.get('domain', ''),
        'unitName': record.get('company', ''),
        'mainUnitName': record.get('company', ''),
        'unitType': record.get('type', ''),
        'mainLicence': record.get('icp_main', ''),
        'serviceLicence': record.get('icp', ''),
        'siteLicense': record.get('icp', ''),
        'serviceLicense': record.get('icp', ''),
        'updateRecordTime': record.get('icp_time', ''),
    }
    return {
        'code': 200,
        'msg': data.get('msg', ''),
        'params': {'list': [normalized] if any(normalized.values()) else []},
        'call_stats': data.get('call_stats'),
        'used_api': data.get('used_api'),
        'raw': data,
    }


def extract_domain(input_str: str) -> str:
    from urllib.parse import urlparse

    value = (input_str or '').strip().lstrip('\ufeff')
    if '://' not in value:
        value = 'http://' + value
    hostname = (urlparse(value).hostname or '').strip('.').lower()
    if hostname.startswith('www.'):
        hostname = hostname[4:]

    # ICP 查询只接受可直接作为主机名使用的 ASCII 域名。
    # 这能把混杂中文、标点或其他异常字符的输入挡在查询前面，
    # 避免把“看起来像域名”的字符串误送去查备案。
    if not hostname or not ASCII_DOMAIN_RE.fullmatch(hostname):
        return ''

    extracted = TLD_EXTRACTOR(hostname)
    if extracted.domain and extracted.suffix:
        return f'{extracted.domain}.{extracted.suffix}'
    return ''


def read_urls(input_str: str) -> List[str]:
    value = (input_str or '').strip()
    if os.path.isfile(value):
        with open(value, 'r', encoding='utf-8-sig', errors='ignore') as handle:
            return [line.strip() for line in handle
                    if line.strip() and not line.lstrip().startswith('#')]
    return [value]


def query_urls(input_str: str, service, fallback_services: Sequence = None,
               record_store=None) -> List[Dict[str, Any]]:
    services = normalize_services(service, fallback_services)
    results = []

    for url in read_urls(input_str):
        domain = extract_domain(url)
        if not domain:
            results.append({'url': url, 'domain': '', 'error': '无法提取域名'})
            continue

        if record_store is not None:
            cached = record_store.get(domain)
            if cached:
                results.append(build_cached_result(url, domain, cached))
                continue

        if not services:
            results.append({'url': url, 'domain': domain, 'error': '没有可用的 ICP 查询服务'})
            continue

        result = query_domain_with_fallback(url, domain, services)
        if record_store is not None and result.get('has_filing'):
            records = result.get('records') or []
            if records:
                result['cached_record'] = record_store.put_record(domain, records[0])
        results.append(result)

    return results


def normalize_services(service, fallback_services: Sequence = None) -> List[Any]:
    if isinstance(service, Sequence) and not isinstance(service, (str, bytes)):
        return [s for s in service if s is not None]
    return [s for s in [service] + list(fallback_services or []) if s is not None]


def build_cached_result(url: str, domain: str, cached_record: Dict[str, Any]) -> Dict[str, Any]:
    record = cached_record_to_provider_record(cached_record)
    return {
        'url': url,
        'domain': domain,
        'has_filing': True,
        'data': {
            'code': 200,
            'params': {'list': [record]},
            'cached': True,
        },
        'records': [record],
        'source': 'ICP_RECORD_CACHE',
        'from_cache': True,
        'fallback_errors': [],
    }


def query_domain_with_fallback(url: str, domain: str, services: Sequence) -> Dict[str, Any]:
    errors = []
    for service in services:
        source = service_source(service)
        try:
            data = service.query_web(domain)
        except Exception as exc:
            errors.append(f'{source}: {exc}')
            continue

        if data.get('code') != 200:
            message = data.get('message') or data.get('msg') or 'ICP 查询失败'
            errors.append(f'{source}: {message}')
            continue

        params = data.get('params') or {}
        items = params.get('list', []) if isinstance(params, dict) else []
        return {
            'url': url,
            'domain': domain,
            'has_filing': bool(items),
            'data': data,
            'records': items,
            'source': source,
            'fallback_errors': errors,
        }

    return {
        'url': url,
        'domain': domain,
        'error': '; '.join(errors) if errors else 'ICP 查询失败',
    }


def service_source(service) -> str:
    source_name = getattr(service, 'source_name', '')
    if isinstance(source_name, str) and source_name:
        return source_name
    return service.__class__.__name__
