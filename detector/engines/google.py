"""Google search engine adapter."""

import threading
import urllib.parse

import requests

from .base import BaseEngine, register


class _SearchTimeout(Exception):
    """Raised when the library search does not finish in time."""


def _run_in_thread(target, args=(), timeout=20):
    result = []
    exception = []

    def _worker():
        try:
            result.append(target(*args))
        except Exception as e:
            exception.append(e)

    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()
    thread.join(timeout=timeout)
    if thread.is_alive():
        raise _SearchTimeout(f"search timeout ({timeout}s)")
    if exception:
        raise exception[0]
    return result[0] if result else []


@register("google")
class GoogleEngine(BaseEngine):
    """Google search engine."""

    name = "google"
    supports_pagination = True
    _TIMEOUT = 20

    def search(self, query: str, max_results: int = 20, page: int = 1) -> list[str]:
        page = max(1, int(page or 1))
        if page == 1:
            urls = self._search_with_library(query, max_results)
            if urls:
                return urls[:max_results]

        return self._search_with_html(query, max_results, page)

    def _search_with_library(self, query: str, max_results: int) -> list[str]:
        try:
            from googlesearch import search as gs

            def _do_search():
                return list(gs(query, num_results=max_results))

            return _run_in_thread(_do_search, timeout=self._TIMEOUT)[:max_results]
        except Exception:
            return []

    def _search_with_html(self, query: str, max_results: int, page: int) -> list[str]:
        per_page = max(1, min(int(max_results or 10), 10))
        start = (max(1, int(page)) - 1) * per_page
        params = {
            "q": query,
            "num": per_page,
            "start": start,
            "hl": "zh-CN",
            "gl": "cn",
            "pws": "0",
        }
        url = f"https://www.google.com/search?{urllib.parse.urlencode(params)}"
        headers = dict(self.default_headers)
        headers["Referer"] = "https://www.google.com/"

        try:
            resp = requests.get(url, headers=headers, timeout=15, allow_redirects=True)
            resp.raise_for_status()
            return _extract_google_urls(resp.text)[:max_results]
        except requests.RequestException as e:
            raise RuntimeError(f"Google search failed: {e}") from e
        except Exception as e:
            raise RuntimeError(f"Google parse failed: {e}") from e


def _extract_google_urls(html: str) -> list[str]:
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html, "html.parser")
    urls = []

    for h3 in soup.select("h3"):
        link = h3.find_parent("a")
        if not link:
            continue
        url = _resolve_google_url(link.get("href", ""))
        if url:
            urls.append(url)

    if not urls:
        for link in soup.select("a[href]"):
            url = _resolve_google_url(link.get("href", ""))
            if url:
                urls.append(url)

    return _dedupe(urls)


def _resolve_google_url(href: str) -> str:
    href = str(href or "").strip()
    if not href:
        return ""

    if href.startswith("/url?"):
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(href).query)
        href = (query.get("q") or query.get("url") or [""])[0]
        href = urllib.parse.unquote(href)

    parsed = urllib.parse.urlsplit(href)
    hostname = (parsed.hostname or "").lower()
    if not href.startswith("http"):
        return ""
    if hostname.endswith("google.com") or hostname.endswith("googleusercontent.com"):
        return ""
    return href


def _dedupe(urls: list[str]) -> list[str]:
    seen = set()
    result = []
    for url in urls:
        if url in seen:
            continue
        seen.add(url)
        result.append(url)
    return result
