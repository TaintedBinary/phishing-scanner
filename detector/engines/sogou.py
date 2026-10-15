"""Sogou 搜索引擎适配器。

使用 requests + BeautifulSoup 解析搜狗搜索结果页面。
"""

import urllib.parse

from .base import BaseEngine, register, resolve_redirect_url


@register("sogou")
class SogouEngine(BaseEngine):
    """Sogou 搜索引擎。"""

    name = "sogou"
    supports_pagination = True

    def request(self, query: str, max_results: int = 20, page: int = 1) -> dict:
        """构建搜索请求。"""
        page_index = max(1, int(page))
        return {
            "url": (
                "https://www.sogou.com/web?"
                f"query={urllib.parse.quote(query)}&page={page_index}"
            ),
            "headers": self.default_headers,
        }

    def parse(self, resp) -> list[str]:
        """解析响应，提取 URL 列表。"""
        from bs4 import BeautifulSoup
        from ..utils.html import decode_response

        soup = BeautifulSoup(decode_response(resp), "html.parser")
        urls = []
        for a in soup.select(".vrwrap h3 a, h3.vr-title a"):
            href = a.get("href", "")
            if href.startswith("http"):
                urls.append(resolve_redirect_url(href, headers=self.default_headers))
        return urls
