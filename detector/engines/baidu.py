"""Baidu 搜索引擎适配器。

使用 requests + BeautifulSoup 解析百度搜索结果页面。
需要先访问首页获取 Cookie。
"""

import urllib.parse

from .base import BaseEngine, register, resolve_redirect_url


@register("baidu")
class BaiduEngine(BaseEngine):
    """Baidu 搜索引擎。"""

    name = "baidu"
    supports_pagination = True

    def search(self, query: str, max_results: int = 20, page: int = 1) -> list[str]:
        """执行搜索并返回 URL 列表。

        重写 search() 以先获取首页 Cookie。
        """
        import requests
        from bs4 import BeautifulSoup
        from ..utils.html import decode_response

        session = requests.Session()
        session.headers.update(self.default_headers)

        # 先访问首页获取 Cookie
        try:
            session.get("https://www.baidu.com/", timeout=10)
        except Exception:
            pass  # Cookie 获取失败不影响搜索

        per_page = max(1, min(int(max_results or 20), 50))
        page_index = max(1, int(page))
        pn = (page_index - 1) * per_page
        url = (
            "https://www.baidu.com/s?"
            f"wd={urllib.parse.quote(query)}&rn={per_page}&pn={pn}"
        )
        try:
            resp = session.get(url, timeout=15)
            resp.raise_for_status()
            soup = BeautifulSoup(decode_response(resp), "html.parser")
            urls = []
            for a in soup.select("h3.t a, .c-title a"):
                href = a.get("href", "")
                if href.startswith("http"):
                    urls.append(resolve_redirect_url(
                        href,
                        headers=self.default_headers,
                        session=session,
                    ))
            return urls[:max_results]
        except Exception as e:
            raise RuntimeError(f"Baidu 搜索失败: {e}") from e
