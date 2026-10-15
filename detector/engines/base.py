"""搜索引擎适配器基类。

定义统一的引擎接口：
- request(query: str) -> dict: 构建搜索请求（返回 url, headers, cookies, data, method）
- parse(resp: requests.Response) -> list[str]: 解析响应提取 URL 列表

使用 register() 装饰器或子类化 BaseEngine 来注册新引擎。
"""

import inspect
import requests
from urllib.parse import urljoin

from ..integrations.http import NetworkSafetyPolicy, UnsafeTargetError


# 全局引擎注册表
ENGINES: dict[str, "BaseEngine"] = {}


def register(name: str):
    """注册引擎到全局 ENGINES 字典。

    用法：
        @register("so360")
        class So360Engine(BaseEngine):
            ...
    """
    def wrapper(cls):
        ENGINES[name] = cls()
        return cls
    return wrapper


class BaseEngine:
    """搜索引擎适配器基类。

    子类必须实现 request() 和 parse() 方法。
    """

    # 引擎名称（用于日志和错误信息）
    name: str = "base"
    supports_pagination: bool = False

    # 默认请求头
    default_headers: dict[str, str] = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    }

    def request(self, query: str, max_results: int = 20, page: int = 1) -> dict:
        """构建搜索请求。

        返回字典包含以下键：
        - url (str): 请求 URL
        - headers (dict): 请求头
        - cookies (dict): Cookie
        - data (dict): POST 数据（可选）
        - method (str): HTTP 方法，默认 GET

        Raises:
            NotImplementedError: 子类必须实现此方法
        """
        raise NotImplementedError

    def parse(self, resp: requests.Response) -> list[str]:
        """解析响应，提取 URL 列表。

        Args:
            resp: requests.Response 对象

        Returns:
            URL 字符串列表

        Raises:
            NotImplementedError: 子类必须实现此方法
        """
        raise NotImplementedError

    def search(self, query: str, max_results: int = 20, page: int = 1) -> list[str]:
        """执行搜索并返回 URL 列表。

        这是对外暴露的统一接口，内部调用 request() 和 parse()。

        Args:
            query: 搜索关键词
            max_results: 最大结果数

        Returns:
            URL 字符串列表
        """
        if page > 1 and not self.supports_pagination:
            return []

        req = self._build_request(query, max_results=max_results, page=page)
        url = req.get("url", "")
        headers = req.get("headers", self.default_headers)
        cookies = req.get("cookies", {})
        data = req.get("data")
        method = req.get("method", "GET")

        try:
            if method.upper() == "POST":
                resp = requests.post(
                    url, headers=headers, cookies=cookies,
                    data=data, timeout=15, allow_redirects=True,
                )
            else:
                resp = requests.get(
                    url, headers=headers, cookies=cookies,
                    timeout=15, allow_redirects=True,
                )
            resp.raise_for_status()
            return self.parse(resp)[:max_results]
        except requests.RequestException as e:
            raise RuntimeError(f"{self.name} 搜索失败: {e}") from e
        except Exception as e:
            raise RuntimeError(f"{self.name} 解析失败: {e}") from e

    def _build_request(self, query: str, max_results: int, page: int) -> dict:
        signature = inspect.signature(self.request)
        kwargs = {}
        if "max_results" in signature.parameters:
            kwargs["max_results"] = max_results
        if "page" in signature.parameters:
            kwargs["page"] = page
        return self.request(query, **kwargs)


def resolve_redirect_url(url: str, headers=None, session=None, timeout: int = 8,
                         safety_policy=None, max_redirects: int = 5) -> str:
    """Resolve a search click URL while validating every redirect target."""
    value = str(url or "").strip()
    if not value.startswith("http"):
        return ""

    client = session or requests
    safety_policy = safety_policy or NetworkSafetyPolicy()
    current = value
    try:
        for redirect_index in range(max_redirects + 1):
            safety_policy.validate(current)
            response = client.get(
                current,
                headers=headers,
                timeout=timeout,
                allow_redirects=False,
                stream=True,
            )
            try:
                if response.status_code not in {301, 302, 303, 307, 308}:
                    return current
                location = response.headers.get('location')
                if not location or redirect_index >= max_redirects:
                    return current
                current = urljoin(current, location)
            finally:
                response.close()
    except UnsafeTargetError:
        return ''
    except Exception:
        return value
    return current
