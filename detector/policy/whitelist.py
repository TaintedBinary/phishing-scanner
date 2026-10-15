"""Single, label-boundary-aware whitelist policy."""

import logging
import os
import re
from typing import Optional, Tuple


SYSTEM_DOMAINS = frozenset({
    '163.com', '126.com', 'alibaba.com', 'alipay.com', 'aliyun.com',
    'amazon.com', 'apple.com', 'baidu.com', 'bilibili.com', 'bing.com',
    'caixin.com', 'dianping.com', 'douban.com', 'douyin.com', 'facebook.com',
    'github.com', 'google.com', 'huawei.com', 'huorong.cn', 'ifeng.com',
    'jd.com', 'jdcloud.com', 'kuaishou.com', 'lenovo.com', 'meituan.com',
    'microsoft.com', 'netease.com', 'paypal.com', 'pinduoduo.com', 'qq.com',
    'sina.com.cn', 'sogou.com', 'sohu.com', 'taobao.com', 'tencent.com',
    'tmall.com', 'twitter.com', 'wechat.com', 'weibo.com', 'xiaomi.com',
    'ximalaya.com', 'youdao.com', 'zhihu.com', '360.cn',
})


class WhitelistManager:
    """Match exact domains, their subdomains, or explicitly marked regex rules."""

    def __init__(self, whitelist_path: str):
        self.whitelist_path = whitelist_path
        self.domains = set(SYSTEM_DOMAINS)
        self.patterns = []
        self._load_file()

    def _load_file(self) -> None:
        if not os.path.exists(self.whitelist_path):
            logging.warning('白名单文件 %s 不存在，仅使用内置白名单', self.whitelist_path)
            return
        try:
            with open(self.whitelist_path, 'r', encoding='utf-8-sig') as handle:
                for raw_line in handle:
                    value = raw_line.strip()
                    if not value or value.startswith('#'):
                        continue
                    if value.startswith('/') and value.endswith('/') and len(value) > 2:
                        try:
                            self.patterns.append(re.compile(value[1:-1], re.IGNORECASE))
                        except re.error as exc:
                            logging.warning('忽略无效白名单正则 %r: %s', value, exc)
                        continue
                    domain = _normalize_rule(value.split()[0])
                    if domain:
                        self.domains.add(domain)
        except OSError as exc:
            logging.warning('加载白名单文件失败: %s', exc)

    def check(self, hostname: str) -> Tuple[bool, Optional[str]]:
        hostname = _normalize_hostname(hostname)
        if not hostname:
            return False, None
        for domain in self.domains:
            if hostname == domain or hostname.endswith('.' + domain):
                source = 'system' if domain in SYSTEM_DOMAINS else 'file'
                return True, f'{source}:{domain}'
        for pattern in self.patterns:
            if pattern.fullmatch(hostname):
                return True, f'file-regex:/{pattern.pattern}/'
        return False, None


def _normalize_rule(value: str) -> str:
    value = value.strip().lower().rstrip('.')
    if value.startswith('*.'):
        value = value[2:]
    if '*' in value or not _is_hostname(value):
        return ''
    return value


def _normalize_hostname(value: str) -> str:
    value = str(value or '').strip().lower().rstrip('.')
    try:
        return value.encode('idna').decode('ascii')
    except UnicodeError:
        return ''


def _is_hostname(value: str) -> bool:
    labels = value.split('.')
    return bool(
        len(labels) >= 2
        and all(label and len(label) <= 63 and re.fullmatch(r'[a-z0-9-]+', label)
                and not label.startswith('-') and not label.endswith('-') for label in labels)
    )
