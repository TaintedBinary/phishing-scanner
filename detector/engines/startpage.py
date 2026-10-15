"""Startpage (startpage.com) 搜索引擎适配器。

移植自 SearXNG 的 startpage.py 引擎。
Startpage 需要先从首页获取 sc 代码，然后发送 POST 请求。
返回的 HTML 中嵌入 JSON 数据，需要正则提取后解析。
"""

import json
import re
import requests

from .base import BaseEngine, register


@register("startpage")
class StartpageEngine(BaseEngine):
    """Startpage 搜索引擎。"""

    name = "Startpage"
    base_url = "https://www.startpage.com"
    search_url = "https://www.startpage.com/sp/search"

    # sc 代码缓存
    _sc_code_cache: str = ""

    def request(self, query: str) -> dict:
        """构建 Startpage 搜索请求。

        Startpage 需要：
        1. 从首页获取 sc 代码（反爬令牌）
        2. 发送 POST 请求，携带 sc 代码和特定 cookie
        """
        sc_code = self._get_sc_code()

        # POST 表单数据
        data = {
            "query": query,
            "cat": "web",
            "t": "device",
            "sc": sc_code,
            "with_date": "",
            "abd": "1",
            "abe": "1",
            "qsr": "all",
            "qadf": "none",
            "language": "en",
            "lui": "en",
        }

        headers = dict(self.default_headers)
        headers["Origin"] = self.base_url
        headers["Referer"] = self.base_url + "/"
        headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

        # 构建 cookie
        cookie = self._build_cookie()

        return {
            "url": self.search_url,
            "headers": headers,
            "cookies": {"preferences": cookie},
            "data": data,
            "method": "POST",
        }

    def _get_sc_code(self) -> str:
        """从 Startpage 首页获取 sc 代码。

        Startpage 在每个搜索表单中嵌入一个 sc 参数，
        没有这个参数会被认为是机器人请求。
        """
        if self._sc_code_cache:
            return self._sc_code_cache

        try:
            resp = requests.get(
                self.base_url,
                headers=self.default_headers,
                timeout=10,
                allow_redirects=True,
            )
            resp.raise_for_status()

            # 检测是否被重定向到 CAPTCHA
            if "captcha" in resp.url.lower():
                raise RuntimeError("Startpage 返回 CAPTCHA 验证页面")

            # 从 HTML 中提取 sc 代码
            # <input type="hidden" name="sc" value="...">
            match = re.search(r'<input[^>]+name="sc"[^>]+value="([^"]+)"', resp.text)
            if match:
                sc_code = match.group(1)
                self._sc_code_cache = sc_code
                return sc_code

            # 备用模式：value 在 name 之前
            match = re.search(r'<input[^>]+value="([^"]+)"[^>]+name="sc"', resp.text)
            if match:
                sc_code = match.group(1)
                self._sc_code_cache = sc_code
                return sc_code

            raise RuntimeError("无法从 Startpage 首页提取 sc 代码")

        except requests.RequestException as e:
            raise RuntimeError(f"获取 Startpage sc 代码失败: {e}") from e

    def _build_cookie(self) -> str:
        """构建 Startpage 搜索所需的 cookie。

        Startpage 使用特殊的 cookie 格式来传递用户偏好设置。
        """
        items = [
            ("date_time", "world"),
            ("disable_family_filter", "none"),
            ("disable_open_in_new_window", "0"),
            ("enable_post_method", "1"),
            ("enable_proxy_safety_suggest", "1"),
            ("enable_stay_control", "1"),
            ("instant_answers", "1"),
            ("lang_homepage", "s/device/en/"),
            ("num_of_results", "10"),
            ("suggestions", "1"),
            ("wt_unit", "celsius"),
            ("language", "en"),
            ("language_ui", "en"),
            ("search_results_region", "all"),
        ]

        # Startpage 的 cookie 格式：keyEEEvalueN1NkeyEEEvalue...
        parts = []
        for key, value in items:
            parts.append(f"{key}EEE{value}")
        return "N1N".join(parts)

    def parse(self, resp: requests.Response) -> list[str]:
        """解析 Startpage HTML 响应，提取 URL 列表。

        Startpage 将搜索结果以 JSON 形式嵌入在 HTML 中：
        React.createElement(UIStartpage.AppSerpWeb, {...})
        """
        text = resp.text

        # 检测 CAPTCHA
        if resp.headers.get("Location", "").startswith("https://www.startpage.com/sp/captcha"):
            raise RuntimeError("Startpage 返回 CAPTCHA 验证页面")

        # 提取嵌入的 JSON 数据
        # 格式：React.createElement(UIStartpage.AppSerpWeb, {{...}})
        pattern = re.compile(
            r'React\.createElement\(UIStartpage\.AppSerpWeb,\s*\{(.*?)\}\)',
            re.DOTALL,
        )
        match = pattern.search(text)
        if not match:
            return []

        # 修复 JSON 格式（包裹成完整 JSON 对象）
        json_str = "{" + match.group(1) + "}"
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError:
            return []

        # 从 JSON 中提取 URL
        urls = []
        results_obj = data.get("render", {}).get("presenter", {}).get("regions", {})

        for results_categ in results_obj.get("mainline", []):
            for item in results_categ.get("results", []):
                # 只处理 web-google 类型的结果
                if results_categ.get("display_type") == "web-google":
                    url = item.get("clickUrl", "")
                    if url and url.startswith("http"):
                        urls.append(url)

        return urls
