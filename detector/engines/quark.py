"""Quark (quark.sm.cn) 搜索引擎适配器。

移植自 SearXNG 的 quark.py 引擎。
Quark 返回 HTML 页面，其中嵌入 JSON 数据，需要正则提取后解析。
"""

import json
import re
import requests
from urllib.parse import urlencode

from .base import BaseEngine, register


@register("quark")
class QuarkEngine(BaseEngine):
    """Quark (神马) 搜索引擎。"""

    name = "Quark"
    base_url = "https://quark.sm.cn"
    results_per_page = 10
    supports_pagination = True

    # 阿里云 CAPTCHA 检测模式
    CAPTCHA_PATTERN = re.compile(
        r'\{[^{]*?"action"\s*:\s*"captcha"\s*,\s*"url"\s*:\s*"([^"]+)"[^{]*?\}'
    )

    def request(self, query: str, max_results: int = 20, page: int = 1) -> dict:
        """构建 Quark 搜索请求。"""
        query_params = {
            "q": query,
            "layout": "html",
            "page": max(1, int(page)),
        }

        url = f"{self.base_url}/s?{urlencode(query_params)}"

        headers = dict(self.default_headers)
        headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        headers["Referer"] = self.base_url + "/"

        return {
            "url": url,
            "headers": headers,
            "cookies": {},
            "method": "GET",
        }

    def parse(self, resp: requests.Response) -> list[str]:
        """解析 Quark HTML 响应，提取 URL 列表。

        Quark 将搜索结果以 JSON 形式嵌入在 HTML 的 script 标签中：
        <script type="application/json" id="s-data-xxx" data-used-by="hydrate">...</script>

        我们需要提取这些 JSON 数据，然后从中解析出 URL。
        """
        text = resp.text

        # 检测 CAPTCHA
        if self.CAPTCHA_PATTERN.search(text):
            raise RuntimeError("Quark 返回 CAPTCHA 验证页面，请稍后重试")

        urls = []
        # 提取所有嵌入的 JSON 数据
        pattern = re.compile(
            r'<script\s+type="application/json"\s+id="s-data-[^"]+"\s+'
            r'data-used-by="hydrate">(.*?)</script>',
            re.DOTALL,
        )
        matches = pattern.findall(text)

        for match in matches:
            try:
                data = json.loads(match)
            except json.JSONDecodeError:
                continue

            # 从 initialData 中提取 URL
            initial_data = data.get("data", {}).get("initialData", {})
            urls.extend(self._extract_urls_from_data(initial_data))

        return urls

    def _extract_urls_from_data(self, data: dict) -> list[str]:
        """递归从 Quark 的 JSON 数据中提取 URL。

        Quark 的数据结构复杂多变，使用多种解析策略。
        """
        urls = []

        if not isinstance(data, dict):
            return urls

        # 策略 1: 直接提取 sourceProps.dest_url
        source_props = data.get("sourceProps", {})
        dest_url = source_props.get("dest_url")
        if dest_url and dest_url.startswith("http"):
            urls.append(dest_url)

        # 策略 2: 提取 normal_url
        normal_url = data.get("normal_url")
        if normal_url and normal_url.startswith("http"):
            urls.append(normal_url)

        # 策略 3: 提取 url 字段
        url = data.get("url")
        if url and url.startswith("http"):
            urls.append(url)

        # 策略 4: 提取 source.url
        source = data.get("source", {})
        if isinstance(source, dict):
            src_url = source.get("url") or source.get("dest_url")
            if src_url and src_url.startswith("http"):
                urls.append(src_url)

        # 策略 5: 提取 title_url
        title_url = data.get("title_url")
        if title_url and title_url.startswith("http"):
            urls.append(title_url)

        # 策略 6: 提取 baike_url
        baike_url = data.get("baike_url")
        if baike_url and baike_url.startswith("http"):
            urls.append(baike_url)

        # 策略 7: 提取 play_url
        play_url = data.get("play_url")
        if play_url and play_url.startswith("http"):
            urls.append(play_url)

        # 策略 8: 提取 imgUrl
        img_url = data.get("imgUrl")
        if img_url and img_url.startswith("http"):
            urls.append(img_url)

        # 策略 9: 递归遍历 list 数组
        item_list = data.get("list", []) or data.get("feed", []) or data.get("image", [])
        for item in item_list:
            if isinstance(item, dict):
                urls.extend(self._extract_urls_from_data(item))

        # 策略 10: 递归遍历 list_container
        list_container = data.get("list_container", [])
        for section in list_container:
            if isinstance(section, dict):
                urls.extend(self._extract_urls_from_data(section))

        # 策略 11: 递归遍历 data 子对象
        inner_data = data.get("data", {})
        if isinstance(inner_data, dict):
            urls.extend(self._extract_urls_from_data(inner_data))

        # 策略 12: 递归遍历 strong 子对象
        strong = data.get("strong", {})
        if isinstance(strong, dict):
            urls.extend(self._extract_urls_from_data(strong))

        # 策略 13: 递归遍历 message 子对象
        message = data.get("message", {})
        if isinstance(message, dict):
            urls.extend(self._extract_urls_from_data(message))

        # 去重
        seen = set()
        unique_urls = []
        for u in urls:
            if u not in seen:
                seen.add(u)
                unique_urls.append(u)

        return unique_urls
