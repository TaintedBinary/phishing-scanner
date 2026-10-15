"""360Search (so.com) 搜索引擎适配器。

移植自 SearXNG 的 360search.py 引擎。
使用 lxml XPath 解析 HTML 响应。
"""

import requests
from lxml import html

from .base import BaseEngine, register, resolve_redirect_url


@register("so360")
class So360Engine(BaseEngine):
    """360 搜索 (so.com) 引擎。"""

    name = "360Search"
    base_url = "https://www.so.com"
    supports_pagination = True

    # Cookie 缓存（内存级，进程内复用）
    _cookie_cache: str = ""

    def request(self, query: str, max_results: int = 20, page: int = 1) -> dict:
        """构建 360 搜索请求。"""
        from urllib.parse import urlencode

        query_params = {"q": query, "pn": max(1, int(page))}
        url = f"{self.base_url}/s?{urlencode(query_params)}"

        # 获取 Cookie（首次访问首页获取 set-cookie）
        cookie = self._get_cookie()

        headers = dict(self.default_headers)
        headers["Cookie"] = cookie
        headers["Referer"] = self.base_url + "/"

        return {
            "url": url,
            "headers": headers,
            "cookies": {},
            "method": "GET",
        }

    def _get_cookie(self) -> str:
        """获取 360 搜索的 Cookie。

        360 搜索需要在请求时携带 Cookie，否则可能返回空结果。
        首次访问首页获取 set-cookie，后续复用。
        """
        if self._cookie_cache:
            return self._cookie_cache

        try:
            resp = requests.get(
                self.base_url,
                headers=self.default_headers,
                timeout=10,
                allow_redirects=False,
            )
            set_cookie = resp.headers.get("set-cookie", "")
            if set_cookie:
                # 提取第一个 cookie（通常是关键的那个）
                cookie = set_cookie.split(";")[0].strip()
                self._cookie_cache = cookie
                return cookie
        except requests.RequestException:
            pass

        return ""

    def parse(self, resp: requests.Response) -> list[str]:
        """解析 360 搜索 HTML 响应，提取 URL 列表。"""
        text = resp.text
        if not text or not text.strip():
            return []

        try:
            dom = html.fromstring(text)
        except Exception:
            return []

        urls = []
        # XPath: 匹配搜索结果列表项
        for item in dom.xpath('//li[contains(@class, "res-list")]'):
            # 提取标题链接
            title_links = item.xpath('.//h3[contains(@class, "res-title")]/a')
            if not title_links:
                continue

            link = title_links[0]
            # 优先使用 data-mdurl 属性（真实 URL）
            url = link.get("data-mdurl") or link.get("href", "")

            # 过滤无效 URL
            if url and url.startswith("http"):
                urls.append(resolve_redirect_url(url, headers=self.default_headers))

        return urls
