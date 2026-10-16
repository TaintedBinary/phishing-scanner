import importlib.util
import json
import os

from .integrations.infra_mining import EXCLUDED_ASN_DEFAULTS, normalize_asn


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


DEFAULT_URL_DATABASE_CONFIG = {
    'enabled': True,
    'root': os.environ.get('PHISHING_SCANNER_URLDATA_ROOT', ''),
    'subdirs': [
        os.path.join('urldb', 'malurl'),
        os.path.join('urldb', 'urlcls'),
    ],
    # Optional files can be listed separately from directory paths.
    'files': [],
}


DEFAULT_ICP_SERVICE_CONFIG = {
    'enabled': True,
    'base_url': os.environ.get('ICP_SERVICE_BASE_URL', 'http://127.0.0.1:16181'),
    'exe_path': os.environ.get('ICP_API_EXE_PATH', os.path.join('ymicp-windows-amd64-rs', 'icpApi-rs.exe')),
    'auto_start': True,
    'startup_timeout': 20,
    'request_timeout': 20,
    'cache': {
        'enabled': True,
        'path': 'icp_records.json',
    },
    'fallback_api': {
        'enabled': True,
        'url': os.environ.get('ICP_FALLBACK_API_URL', 'https://ping.4759.cn/api/icp_api.php'),
        'api_key': '',
        'request_timeout': 20,
    },
}


def load_json(path, default=None):
    """Load a UTF-8 JSON file and return a useful error to the CLI."""
    if not os.path.isabs(path):
        path = os.path.join(BASE_DIR, path)
    try:
        with open(path, 'r', encoding='utf-8-sig') as handle:
            return json.load(handle)
    except FileNotFoundError:
        if default is not None:
            return default
        raise ValueError(f"配置文件不存在: {path}")
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"配置文件格式错误 {path}: 第 {exc.lineno} 行第 {exc.colno} 列"
        ) from exc


def load_python_config(path):
    """Load a Python config file and return the PROVIDERS variable."""
    if not os.path.isabs(path):
        path = os.path.join(BASE_DIR, path)
    if not os.path.exists(path):
        raise ValueError(f"配置文件不存在: {path}")
    try:
        spec = importlib.util.spec_from_file_location("providers_config", path)
        if spec is None or spec.loader is None:
            raise ValueError(f"无法加载配置文件: {path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if not hasattr(module, 'PROVIDERS'):
            raise ValueError(f"配置文件 {path} 缺少 PROVIDERS 变量")
        return module.PROVIDERS
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"配置文件格式错误 {path}: {exc}") from exc


def load_config(path, default=None):
    """Load a config file (JSON or Python) and return the data."""
    if path.endswith('.py'):
        return load_python_config(path)
    return load_json(path, default=default)


def load_string_list(path, key):
    data = load_json(path)
    values = data.get(key) if isinstance(data, dict) else data

    # Compatible with grouped config: {"keywords": {"group": ["kw1", "kw2"]}}.
    if isinstance(values, dict):
        values = [item for sublist in values.values() for item in sublist]

    if not isinstance(values, list):
        raise ValueError(f"配置文件 {path} 中的 {key} 必须是数组或分类对象")

    result = []
    seen = set()
    for value in values:
        value = str(value).strip()
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def resolve_project_path(path):
    path = str(path or '').strip()
    if not path:
        return path
    if os.path.isabs(path):
        return path
    return os.path.join(BASE_DIR, path)


DEFAULT_CACHE_CONFIG = {
    'enabled': True,
    'dir': 'cache/cache.json',
    'registration_ttl': 7 * 24 * 3600,
}

DEFAULT_INFRASTRUCTURE_CONFIG = {
    'enabled': True,
    'dns': True,
    'asn': True,
    'ct': False,
    'dns_timeout': 3,
    'asn_timeout': 3,
    'ct_timeout': 10,
    'knowledge_base_path': 'infra_knowledge.json',
    # --build-infra derivation thresholds.  Shared hosting is the false
    # positive hazard, so an IP/ASN only becomes "known-bad" when several
    # distinct malicious domains actually sit on it.
    'derive_min_domains_per_ip': 2,
    'derive_min_domains_per_asn': 3,
    'derive_excluded_asns': sorted(EXCLUDED_ASN_DEFAULTS),
}

DEFAULT_LOGO_CONFIG = {
    'enabled': True,
    'threshold': 10,
}


def load_cache_config(path):
    data = load_config(path, default={})
    section = data.get('cache', {}) if isinstance(data, dict) else {}
    config = dict(DEFAULT_CACHE_CONFIG)
    if isinstance(section, dict):
        config.update({k: v for k, v in section.items() if v is not None})
    config['enabled'] = bool(config.get('enabled', True))
    config['dir'] = resolve_project_path(config.get('dir', 'cache/cache.json'))
    config['registration_ttl'] = float(config.get('registration_ttl', 604800))
    return config


def load_infrastructure_config(path):
    data = load_config(path, default={})
    section = data.get('infrastructure', {}) if isinstance(data, dict) else {}
    config = dict(DEFAULT_INFRASTRUCTURE_CONFIG)
    if isinstance(section, dict):
        config.update({k: v for k, v in section.items() if v is not None})
    config['enabled'] = bool(config.get('enabled', True))
    for key in ('dns', 'asn', 'ct'):
        config[key] = bool(config.get(key, DEFAULT_INFRASTRUCTURE_CONFIG[key]))
    for key in ('dns_timeout', 'asn_timeout', 'ct_timeout'):
        config[key] = float(config.get(key, DEFAULT_INFRASTRUCTURE_CONFIG[key]))
    for key in ('derive_min_domains_per_ip', 'derive_min_domains_per_asn'):
        config[key] = int(config.get(key, DEFAULT_INFRASTRUCTURE_CONFIG[key]))
    excluded = config.get('derive_excluded_asns')
    if not isinstance(excluded, (list, tuple, set, frozenset)):
        excluded = DEFAULT_INFRASTRUCTURE_CONFIG['derive_excluded_asns']
    config['derive_excluded_asns'] = {
        asn for asn in (normalize_asn(item) for item in excluded) if asn
    }
    config['knowledge_base_path'] = resolve_project_path(
        config.get('knowledge_base_path', 'infra_knowledge.json')
    )
    return config


def load_logo_config(path):
    data = load_config(path, default={})
    section = data.get('logo', {}) if isinstance(data, dict) else {}
    config = dict(DEFAULT_LOGO_CONFIG)
    if isinstance(section, dict):
        config.update({k: v for k, v in section.items() if v is not None})
    config['enabled'] = bool(config.get('enabled', True))
    config['threshold'] = int(config.get('threshold', 10))
    return config


def load_icp_service_config(path):
    data = load_config(path, default={})
    section = data.get('icp_service', {}) if isinstance(data, dict) else {}
    config = dict(DEFAULT_ICP_SERVICE_CONFIG)
    config['cache'] = dict(DEFAULT_ICP_SERVICE_CONFIG['cache'])
    config['fallback_api'] = dict(DEFAULT_ICP_SERVICE_CONFIG['fallback_api'])

    if isinstance(section, dict):
        for key, value in section.items():
            if value is None:
                continue
            if key == 'cache' and isinstance(value, dict):
                config['cache'].update({k: v for k, v in value.items() if v is not None})
            elif key == 'fallback_api' and isinstance(value, dict):
                config['fallback_api'].update({k: v for k, v in value.items() if v is not None})
            else:
                config[key] = value

    config['base_url'] = str(config.get('base_url', '')).rstrip('/')
    config['exe_path'] = resolve_project_path(config.get('exe_path', ''))
    config['enabled'] = bool(config.get('enabled', True))
    config['auto_start'] = bool(config.get('auto_start', True))
    config['startup_timeout'] = float(config.get('startup_timeout', 20))
    config['request_timeout'] = float(config.get('request_timeout', 20))

    cache = config['cache']
    cache['enabled'] = bool(cache.get('enabled', True))
    cache['path'] = resolve_project_path(cache.get('path', 'icp_records.json'))

    fallback_api = config['fallback_api']
    fallback_api['enabled'] = bool(fallback_api.get('enabled', True))
    fallback_api['url'] = str(fallback_api.get('url', '')).strip()
    fallback_api['api_key'] = str(fallback_api.get('api_key', '')).strip()
    fallback_api['request_timeout'] = float(fallback_api.get('request_timeout', 20))
    return config


def load_url_database_config(path):
    data = load_config(path, default={})
    section = data.get('url_database', {}) if isinstance(data, dict) else {}
    config = dict(DEFAULT_URL_DATABASE_CONFIG)
    config['subdirs'] = list(DEFAULT_URL_DATABASE_CONFIG['subdirs'])
    config['files'] = list(DEFAULT_URL_DATABASE_CONFIG.get('files', []))
    if isinstance(section, dict):
        config.update({k: v for k, v in section.items() if v is not None})
    config['enabled'] = bool(config.get('enabled', True))

    # Backward compatible: an older config may still provide explicit paths.
    explicit_paths = config.get('paths')
    if explicit_paths is not None:
        if isinstance(explicit_paths, str):
            explicit_paths = [explicit_paths]
        config['paths'] = [resolve_project_path(item) for item in explicit_paths]
        return config

    root = resolve_project_path(config.get('root', ''))
    subdirs = config.get('subdirs', [])
    files = config.get('files', [])
    if isinstance(subdirs, str):
        subdirs = [subdirs]
    if isinstance(files, str):
        files = [files]

    # Both `subdirs` and `files` may contain relative paths under `root` or
    # absolute paths. URLBlocklist handles either a directory or a file.
    configured_paths = list(subdirs or []) + list(files or [])
    paths = []
    seen = set()
    for item in configured_paths:
        item = str(item or '').strip()
        if not item:
            continue
        resolved = item if os.path.isabs(item) else os.path.join(root, item)
        resolved = os.path.normpath(resolved)
        if resolved not in seen:
            seen.add(resolved)
            paths.append(resolved)

    config['root'] = root
    config['subdirs'] = subdirs
    config['files'] = files
    config['paths'] = paths
    return config
