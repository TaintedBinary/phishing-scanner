"""DuckDuckGo 搜索引擎适配器。

使用 ddgs (duckduckgo-search) 库执行搜索。
由于该库直接返回结果列表，重写 search() 方法。
"""

import threading
from .base import BaseEngine, register


class _SearchTimeout(Exception):
    """搜索超时异常。"""
    pass


def _run_in_thread(target, args=(), timeout=20):
    """在子线程中执行 target，超时后抛出 _SearchTimeout。"""
    result = []
    exception = []

    def _worker():
        try:
            result.append(target(*args))
        except Exception as e:
            exception.append(e)

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    t.join(timeout=timeout)
    if t.is_alive():
        raise _SearchTimeout(f"搜索超时 ({timeout}s)")
    if exception:
        raise exception[0]
    return result[0] if result else []


@register("duckduckgo")
class DuckDuckGoEngine(BaseEngine):
    """DuckDuckGo 搜索引擎。"""

    name = "duckduckgo"
    _TIMEOUT = 20  # 秒

    def search(self, query: str, max_results: int = 20, page: int = 1) -> list[str]:
        """执行搜索并返回 URL 列表。"""
        if page > 1:
            return []
        try:
            from ddgs import DDGS

            def _do_search():
                with DDGS() as ddgs:
                    results = list(ddgs.text(query, max_results=max_results))
                    urls = [r.get("href", "") for r in results if r.get("href")]
                    return urls[:max_results]

            urls = _run_in_thread(_do_search, timeout=self._TIMEOUT)
            return urls
        except _SearchTimeout:
            raise RuntimeError(f"DuckDuckGo 搜索超时 ({self._TIMEOUT}s)")
        except Exception as e:
            raise RuntimeError(f"DuckDuckGo 搜索失败: {e}") from e
