"""搜索引擎入口层。

所有搜索引擎实现都在 detector/engines/ 包中。
本模块只负责：
- 导入引擎注册表
- 执行搜索并过滤搜索引擎自身域名
- 打印搜索状态
"""

import urllib.parse
import re

from ..engines import ENGINES
from ..integrations.search_engines_scraper import (
    SearchEnginesScraperUnavailable,
    is_supported_engine as scraper_supports_engine,
    search_urls as scraper_search_urls,
)

SEARCH_ENGINE_DOMAINS = (
    'baidu.com',
    'bing.com',
    'duckduckgo.com',
    'google.com',
    'sogou.com',
    'so.com',
    'chinaso.com',
    'quark.sm.cn',
    'startpage.com',
)


def search(keywords, engine='google', max_results=20, page=1):
    """执行搜索并返回 URL 列表。

    Args:
        keywords: 搜索关键词（字符串或列表）
        engine: 搜索引擎名称
        max_results: 最大结果数

    Returns:
        URL 字符串列表（已过滤搜索引擎自身域名）

    Raises:
        ValueError: 不支持的搜索引擎
    """
    if isinstance(keywords, list):
        query = ' '.join(keywords)
    else:
        query = keywords

    urls = []
    engine_name = str(engine or '').strip().lower()

    page = max(1, int(page or 1))

    if page == 1 and scraper_supports_engine(engine_name):
        try:
            urls = scraper_search_urls(query, engine=engine_name, max_results=max_results)
        except SearchEnginesScraperUnavailable:
            urls = []
        except Exception:
            urls = []

    if not urls:
        engine_instance = ENGINES.get(engine_name)
        if not engine_instance:
            available = list(ENGINES.keys())
            raise ValueError(f"不支持的搜索引擎: {engine}，可选: {available}")
        urls = engine_instance.search(query, max_results, page=page)

    return [url for url in urls if not _is_search_engine_url(url)]


def print_search_status(keyword, engine, page_or_status, status=None):
    """打印搜索状态：有结果 / 无结果 / 失败"""
    if status is None:
        print(f"关键词: {keyword} | 搜索引擎: {engine} | 状态: {page_or_status}")
        return
    print(f"关键词: {keyword} | 搜索引擎: {engine} | 页码: {page_or_status} | 状态: {status}")


def _is_search_engine_url(url):
    """判断 URL 是否属于搜索引擎自身域名。"""
    hostname = (urllib.parse.urlparse(str(url or '')).hostname or '').strip('.').lower()
    if not hostname:
        return False
    if any(
            hostname == domain or hostname.endswith('.' + domain)
            for domain in SEARCH_ENGINE_DOMAINS):
        return True
    return bool(re.fullmatch(
        r'(?:[^.]+\.)*google\.(?:com|[a-z]{2}|(?:com|co)\.[a-z]{2})',
        hostname,
    ))


def list_engines():
    """列出所有可用引擎。"""
    return list(ENGINES.keys())
