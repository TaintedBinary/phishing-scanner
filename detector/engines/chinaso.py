"""ChinaSo (chinaso.com) 搜索引擎适配器。

移植自 SearXNG 的 chinaso.py 引擎。
使用官方 JSON API，返回结构化数据。
"""

import base64
import secrets
import requests
from urllib.parse import urlencode

from .base import BaseEngine, register


@register("chinaso")
class ChinaSoEngine(BaseEngine):
    """ChinaSo 搜索引擎。"""

    name = "ChinaSo"
    base_url = "https://www.chinaso.com"
    results_per_page = 10
    supports_pagination = True

    def request(self, query: str, max_results: int = 20, page: int = 1) -> dict:
        """构建 ChinaSo 搜索请求。

        ChinaSo 使用 JSON API，需要携带随机 uid cookie。
        """
        per_page = max(1, min(int(max_results or self.results_per_page), 50))
        page_index = max(1, int(page))
        query_params = {
            "q": query,
            "pn": page_index,
            "ps": per_page,
        }

        url = f"{self.base_url}/v5/general/v1/web/search?{urlencode(query_params)}"

        # 生成随机 uid cookie（SearXNG 的做法）
        uid = base64.b64encode(secrets.token_bytes(16)).decode("utf-8")
        cookies = {"uid": uid}

        headers = dict(self.default_headers)
        headers["Accept"] = "application/json, text/plain, */*"
        headers["Referer"] = self.base_url + "/"

        return {
            "url": url,
            "headers": headers,
            "cookies": cookies,
            "method": "GET",
        }

    def parse(self, resp: requests.Response) -> list[str]:
        """解析 ChinaSo JSON 响应，提取 URL 列表。"""
        try:
            data = resp.json()
        except Exception:
            return []

        # 检查响应结构
        if not isinstance(data, dict) or "data" not in data:
            return []

        inner_data = data.get("data")
        if not inner_data or not isinstance(inner_data, dict):
            return []

        items = inner_data.get("data", [])
        if not items:
            return []

        urls = []
        for entry in items:
            url = entry.get("url", "")
            if url and url.startswith("http"):
                urls.append(url)

        return urls
