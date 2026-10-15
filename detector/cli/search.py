"""Keyword search command-line workflow."""
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import json
import math
import os
import threading
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

from ..config import load_config, load_string_list
from ..utils.domain import ascii_hostname


def resolve_search_targets(query, search_arg, keywords_config):
    keywords = load_string_list(keywords_config, 'keywords')
    requested = search_arg if search_arg is not None else query

    if requested in (None, '', '__all__'):
        return keywords
    return [str(requested).strip()]


def run_keyword_search(detector, query, search_arg, args):
    providers = load_config(args.providers_config)
    search_config = providers.get('search', {})
    workflow_config = providers.get('workflow', {})
    engines = args.engine or search_config.get('engines', ['baidu'])
    max_results = int(search_config.get('max_results', 20))
    results_per_page = max(1, int(search_config.get('results_per_page', 10)))
    configured_pages = max(1, int(search_config.get('pages', 1)))
    diagnostics_enabled = bool(search_config.get('diagnostics', True))
    if max_results > 0:
        pages = min(configured_pages, max(1, math.ceil(max_results / max(1, results_per_page))))
    else:
        pages = configured_pages
    search_threads = max(1, int(search_config.get('threads', 4)))
    detect_threads = max(1, int(workflow_config.get('threads', 2)))
    max_urls = int(workflow_config.get('max_urls', 0) or 0)

    targets = resolve_search_targets(query, search_arg, args.keywords_config)
    diagnostics = _create_diagnostics_logger(diagnostics_enabled)
    if diagnostics:
        print(f"搜索诊断日志: {diagnostics.path}")

    discovered = _discover_urls(
        targets,
        engines,
        max_results,
        results_per_page,
        pages,
        search_threads,
        diagnostics=diagnostics,
    )
    urls = _rank_urls(discovered)
    if max_urls > 0:
        urls = urls[:max_urls]

    if diagnostics:
        diagnostics.write({
            'event': 'summary',
            'keywords': targets,
            'engines': engines,
            'configured_pages': configured_pages,
            'used_pages': pages,
            'results_per_page': results_per_page,
            'discovered_urls': len(discovered),
            'queued_detection_urls': len(urls),
        })

    if not urls:
        return []

    results = detector.batch_detect(urls, max_workers=detect_threads)
    for result in results:
        result['discovery_sources'] = discovered.get(_normalize_url(result.get('url')), [])
    return results


def _discover_urls(keywords, engines, max_results, results_per_page, pages, workers, diagnostics=None):
    from ..discovery.search import print_search_status, search as search_web

    discovered = defaultdict(list)

    def search_one(keyword, engine, page):
        return keyword, engine, page, search_web(
            keyword,
            engine=engine,
            max_results=results_per_page,
            page=page,
        )

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(search_one, keyword, engine, page): (keyword, engine, page)
            for keyword in keywords
            for engine in engines
            for page in range(1, pages + 1)
        }
        for future in as_completed(futures):
            keyword, engine, page = futures[future]
            try:
                _, _, _, urls = future.result()
                print_search_status(keyword, engine, page, "ok" if urls else "empty")
            except Exception:
                diagnostics and diagnostics.write({
                    'event': 'search',
                    'keyword': keyword,
                    'engine': engine,
                    'page': page,
                    'status': 'failed',
                    'error': _format_exception(),
                    'requested_results': results_per_page,
                    'returned_urls': 0,
                    'normalized_urls': 0,
                    'new_urls': 0,
                    'duplicate_urls': 0,
                })
                print_search_status(keyword, engine, page, "failed")
                continue

            normalized_urls = []
            new_urls = 0
            duplicate_urls = 0
            for url in urls:
                normalized = _normalize_url(url)
                if not normalized:
                    continue
                normalized_urls.append(normalized)
                was_seen = normalized in discovered
                if was_seen:
                    duplicate_urls += 1
                else:
                    new_urls += 1
                discovered[normalized].append({
                    'type': 'keyword',
                    'value': keyword,
                    'engine': engine,
                    'page': page,
                    'url': url,
                })

            diagnostics and diagnostics.write({
                'event': 'search',
                'keyword': keyword,
                'engine': engine,
                'page': page,
                'status': 'ok' if urls else 'empty',
                'requested_results': results_per_page,
                'returned_urls': len(urls),
                'normalized_urls': len(set(normalized_urls)),
                'new_urls': new_urls,
                'duplicate_urls': duplicate_urls,
                'sample_urls': normalized_urls[:5],
            })

    return dict(discovered)


def _format_exception():
    import sys

    exc = sys.exc_info()[1]
    return f"{exc.__class__.__name__}: {exc}"


def _create_diagnostics_logger(enabled):
    if not enabled:
        return None
    output_dir = os.path.join(os.getcwd(), 'output')
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    path = os.path.join(output_dir, f'search_diagnostics_{timestamp}.jsonl')
    return SearchDiagnosticsLogger(path)


class SearchDiagnosticsLogger:
    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()

    def write(self, event):
        payload = dict(event)
        payload.setdefault('timestamp', datetime.now().isoformat(timespec='seconds'))
        line = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        with self._lock:
            with open(self.path, 'a', encoding='utf-8') as handle:
                handle.write(line + '\n')


def _normalize_url(url):
    value = str(url or '').strip()
    if not value:
        return ''

    parsed = urlsplit(value)
    scheme = parsed.scheme.lower() or 'http'
    hostname = (parsed.hostname or '').lower().rstrip('.')
    if not hostname:
        return value
    # IDNA-encode so discovery keys match analyze_url's canonical normalize_url output.
    encoded = ascii_hostname(hostname)
    if encoded:
        hostname = encoded

    port = parsed.port
    if port and not ((scheme == 'http' and port == 80) or (scheme == 'https' and port == 443)):
        netloc = f"{hostname}:{port}"
    else:
        netloc = hostname

    path = parsed.path or '/'
    if path != '/':
        path = path.rstrip('/') or '/'

    query_items = [
        (key, val)
        for key, val in parse_qsl(parsed.query, keep_blank_values=True)
        if key.lower() not in {'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content', 'spm', 'from'}
    ]
    query = urlencode(query_items, doseq=True)
    return urlunsplit((scheme, netloc, path, query, ''))


def _rank_urls(discovered):
    scored = []
    for url, sources in discovered.items():
        score = len(sources)
        score += len({source.get('engine') for source in sources if source.get('engine')})
        score += len({source.get('value') for source in sources if source.get('value')})
        scored.append((score, url, sources))

    scored.sort(key=lambda item: (-item[0], item[1]))
    return [url for _, url, _ in scored]
