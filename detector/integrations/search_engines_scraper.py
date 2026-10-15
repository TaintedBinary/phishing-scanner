"""Optional adapter for the Search-Engines-Scraper project.

This adapter is intentionally defensive:
- It imports the third-party package lazily.
- It accepts both sync and async search implementations.
- It normalizes several result shapes to a flat URL list.

The main search pipeline can prefer this backend when it is available,
and fall back to the built-in engine implementations otherwise.
"""

from __future__ import annotations

import asyncio
import importlib
import inspect
import math
from collections.abc import Iterable
from typing import Any, Dict, List


class SearchEnginesScraperUnavailable(RuntimeError):
    """Raised when the third-party scraper package cannot be used."""


SUPPORTED_ENGINES: Dict[str, str] = {
    'google': 'Google',
    'bing': 'Bing',
    'yahoo': 'Yahoo',
    'duckduckgo': 'DuckDuckGo',
    'ddg': 'DuckDuckGo',
    'aol': 'Aol',
    'mojeek': 'Mojeek',
    'torch': 'Torch',
}


def is_supported_engine(engine: str) -> bool:
    return normalize_engine_name(engine) in SUPPORTED_ENGINES


def normalize_engine_name(engine: str) -> str:
    return str(engine or '').strip().lower()


def search_urls(query: str, engine: str = 'google', max_results: int = 20) -> List[str]:
    module = _import_search_engines_module()
    engine_class = _resolve_engine_class(module, engine)
    if engine_class is None:
        raise SearchEnginesScraperUnavailable(
            f'Search-Engines-Scraper does not provide engine: {engine}'
        )

    engine_obj = _instantiate_engine(engine_class)
    results = _run_search(engine_obj, query, max_results)
    urls = _extract_urls(results)
    return _dedupe_and_trim(urls, max_results)


def _import_search_engines_module():
    try:
        return importlib.import_module('search_engines')
    except ModuleNotFoundError as exc:
        raise SearchEnginesScraperUnavailable(
            'Search-Engines-Scraper package is not installed'
        ) from exc


def _resolve_engine_class(module, engine: str):
    engine_name = normalize_engine_name(engine)
    class_name = SUPPORTED_ENGINES.get(engine_name)
    if not class_name:
        return None

    engine_map = getattr(module, 'search_engines_dict', None)
    if isinstance(engine_map, dict):
        candidate = engine_map.get(engine_name) or engine_map.get(class_name)
        if inspect.isclass(candidate):
            return candidate

    candidate = getattr(module, class_name, None)
    if inspect.isclass(candidate):
        return candidate
    return None


def _instantiate_engine(engine_class):
    try:
        return engine_class()
    except TypeError as exc:
        raise SearchEnginesScraperUnavailable(
            f'Cannot instantiate scraper engine {engine_class!r}: {exc}'
        ) from exc


def _run_search(engine_obj, query: str, max_results: int):
    search_method = getattr(engine_obj, 'search', None)
    if not callable(search_method):
        raise SearchEnginesScraperUnavailable(
            f'Scraper engine {engine_obj.__class__.__name__} has no search() method'
        )

    kwargs = _build_search_kwargs(search_method, max_results)
    result = search_method(query, **kwargs)
    if inspect.isawaitable(result):
        result = asyncio.run(result)
    return result


def _build_search_kwargs(search_method, max_results: int) -> Dict[str, Any]:
    try:
        signature = inspect.signature(search_method)
    except (TypeError, ValueError):
        return {}

    params = signature.parameters
    kwargs: Dict[str, Any] = {}

    # The upstream library has used both page-based and limit-based search APIs
    # across different forks. We only pass a keyword when the callable accepts it.
    if 'max_results' in params:
        kwargs['max_results'] = max_results
    elif 'limit' in params:
        kwargs['limit'] = max_results
    elif 'pages' in params:
        kwargs['pages'] = max(1, math.ceil(max_results / 10))
    elif 'page' in params:
        kwargs['page'] = 1

    return kwargs


def _extract_urls(results) -> List[str]:
    if results is None:
        return []

    links_method = getattr(results, 'links', None)
    if callable(links_method):
        try:
            links = links_method()
        except Exception:
            links = []
        else:
            if isinstance(links, Iterable) and not isinstance(links, (str, bytes)):
                return [str(url).strip() for url in links if str(url).strip()]

    if isinstance(results, dict):
        for key in ('links', 'results', 'items', 'data'):
            value = results.get(key)
            if value is not None:
                extracted = _extract_urls(value)
                if extracted:
                    return extracted
        return []

    if isinstance(results, Iterable) and not isinstance(results, (str, bytes)):
        urls = []
        for item in results:
            if isinstance(item, str):
                value = item.strip()
                if value:
                    urls.append(value)
                continue

            if isinstance(item, dict):
                for key in ('link', 'url', 'href'):
                    value = str(item.get(key, '') or '').strip()
                    if value:
                        urls.append(value)
                        break
                else:
                    nested = item.get('links') or item.get('results') or item.get('items')
                    if nested is not None:
                        urls.extend(_extract_urls(nested))
        return urls

    return []


def _dedupe_and_trim(urls: List[str], max_results: int) -> List[str]:
    seen = set()
    result = []
    for url in urls:
        value = str(url or '').strip()
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
        if len(result) >= max_results:
            break
    return result
