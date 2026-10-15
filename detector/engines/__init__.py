"""搜索引擎适配器模块。

每个引擎实现两个方法：
- request(query: str) -> dict: 构建搜索请求
- parse(resp: requests.Response) -> list[str]: 解析响应提取 URL

引擎通过 register() 注册到全局 ENGINES 字典。
"""

from .base import BaseEngine, register, ENGINES

# 导入所有引擎以触发自动注册
from .so360 import So360Engine
from .chinaso import ChinaSoEngine
from .quark import QuarkEngine
from .startpage import StartpageEngine
from .google import GoogleEngine
from .bing import BingEngine
from .baidu import BaiduEngine
from .sogou import SogouEngine
from .duckduckgo import DuckDuckGoEngine

__all__ = [
    "BaseEngine",
    "register",
    "ENGINES",
    "So360Engine",
    "ChinaSoEngine",
    "QuarkEngine",
    "StartpageEngine",
    "GoogleEngine",
    "BingEngine",
    "BaiduEngine",
    "SogouEngine",
    "DuckDuckGoEngine",
]
