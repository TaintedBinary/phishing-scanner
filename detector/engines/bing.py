"""Bing 搜索引擎适配器。

使用 requests + BeautifulSoup 解析 Bing 搜索结果页面。
"""

import base64
import urllib.parse

from .base import BaseEngine, register


@register("bing")
class BingEngine(BaseEngine):
    """Bing 搜索引擎。"""

    name = "bing"
    supports_pagination = True

    def request(self, query: str, max_results: int = 20, page: int = 1) -> dict:
        """构建搜索请求。"""
        per_page = max(1, min(int(max_results or 20), 50))
        first = max(1, (max(1, int(page)) - 1) * per_page + 1)
        return {
            "url": (
                "https://www.bing.com/search?"
                f"q={urllib.parse.quote(query)}&count={per_page}&first={first}"
            ),
            "headers": self.default_headers,
        }

    def parse(self, resp) -> list[str]:
        """解析响应，提取 URL 列表。"""
        from bs4 import BeautifulSoup
        from ..utils.html import decode_response

        soup = BeautifulSoup(decode_response(resp), "html.parser")
        urls = []
        for a in soup.select("li.b_algo h2 a, ol#b_results li h2 a"):
            href = a.get("href")
            url = _resolve_bing_url(href)
            if url:
                urls.append(url)
        return urls


def _resolve_bing_url(href: str) -> str:
    """Return the real result URL from Bing click-tracking links."""
    href = str(href or "").strip()
    if not href:
        return ""

    parsed = urllib.parse.urlsplit(href)
    hostname = (parsed.hostname or "").lower()
    if not hostname.endswith("bing.com"):
        return href if href.startswith("http") else ""

    query = urllib.parse.parse_qs(parsed.query)
    encoded_url = (query.get("u") or [""])[0]
    if encoded_url.startswith("a1"):
        decoded = _decode_bing_a1_url(encoded_url)
        if decoded.startswith("http"):
            return decoded

    direct_url = (query.get("url") or [""])[0]
    direct_url = urllib.parse.unquote(direct_url)
    if direct_url.startswith("http"):
        return direct_url
    return ""


def _decode_bing_a1_url(value: str) -> str:
    payload = value[2:]
    payload += "=" * ((4 - len(payload) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(payload).decode("utf-8", errors="ignore")
    except Exception:
        return ""
