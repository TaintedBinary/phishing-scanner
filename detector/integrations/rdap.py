"""
RDAP 客户端 — 增强域名年龄检测

RDAP (Registration Data Access Protocol) 是 WHOIS 的现代化替代方案，
提供结构化的 JSON 响应，包含域名注册信息。

支持：
  - 查询域名注册日期、过期日期
  - 查询注册商信息
  - 查询域名状态
"""

import logging
from typing import Optional, Dict, Any

import requests

logger = logging.getLogger(__name__)

# 主要 RDAP 服务器
RDAP_SERVERS = [
    'https://rdap.org',
    'https://rdap.arin.net',
    'https://rdap.apnic.net',
    'https://rdap.lacnic.net',
    'https://rdap.regrois.ac.za',
    'https://rdap.ripe.net',
]

# TLD → RDAP 服务器映射
TLD_RDAP_MAP = {
    'com': 'https://rdap.verisign.com/com/v1/domain/',
    'net': 'https://rdap.verisign.com/net/v1/domain/',
    'org': 'https://rdap.pir.org/v1/domain/',
    'cn': 'https://rdap.cnnic.cn/v1/domain/',
    'io': 'https://rdap.nic.io/v1/domain/',
    'co': 'https://rdap.verisign.com/co/v1/domain/',
    'us': 'https://rdap.nic.us/v1/domain/',
    'info': 'https://rdap.afilias.net/v1/domain/',
    'biz': 'https://rdap.afilias.net/v1/domain/',
    'xyz': 'https://rdap.afilias.net/v1/domain/',
    'online': 'https://rdap.afilias.net/v1/domain/',
    'site': 'https://rdap.afilias.net/v1/domain/',
    'store': 'https://rdap.afilias.net/v1/domain/',
    'tech': 'https://rdap.afilias.net/v1/domain/',
    'app': 'https://rdap.afilias.net/v1/domain/',
    'dev': 'https://rdap.afilias.net/v1/domain/',
    'ai': 'https://rdap.nic.ai/v1/domain/',
    'gg': 'https://rdap.gg/v1/domain/',
    'tk': 'https://rdap.nic.tk/v1/domain/',
    'ml': 'https://rdap.nic.ml/v1/domain/',
    'ga': 'https://rdap.nic.ga/v1/domain/',
    'cf': 'https://rdap.nic.cf/v1/domain/',
}


def get_rdap_server(domain: str) -> Optional[str]:
    """根据域名 TLD 获取对应的 RDAP 服务器"""
    parts = domain.split('.')
    if len(parts) < 2:
        return None
    tld = parts[-1].lower()
    return TLD_RDAP_MAP.get(tld)


def query_rdap(domain: str, timeout: int = 15) -> Optional[Dict[str, Any]]:
    """
    通过 RDAP 查询域名注册信息
    
    Args:
        domain: 要查询的域名
        timeout: 请求超时时间
    
    Returns:
        RDAP 响应数据，失败返回 None
    """
    rdap_url = get_rdap_server(domain)
    
    if rdap_url:
        try:
            url = f'{rdap_url}{domain}'
            resp = requests.get(url, timeout=timeout, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'application/json',
            })
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            logger.debug(f'RDAP 查询失败 ({rdap_url}): {e}')
    
    # 回退到通用 RDAP 服务器
    try:
        url = f'https://rdap.org/domain/{domain}'
        resp = requests.get(url, timeout=timeout, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json',
        })
        if resp.status_code == 200:
            return resp.json()
    except Exception as e:
        logger.debug(f'通用 RDAP 查询失败: {e}')
    
    return None


def extract_dates(rdap_data: Dict[str, Any]) -> Dict[str, Optional[str]]:
    """
    从 RDAP 响应中提取日期信息
    
    Args:
        rdap_data: RDAP 响应数据
    
    Returns:
        {
            'created': str,      # 注册日期
            'updated': str,      # 更新日期
            'expires': str,      # 过期日期
        }
    """
    result = {
        'created': None,
        'updated': None,
        'expires': None,
    }
    
    if not rdap_data:
        return result
    
    # 查找 events 数组
    events = rdap_data.get('events', [])
    if isinstance(events, list):
        for event in events:
            event_type = event.get('eventAction', '').lower()
            event_date = event.get('eventDate')
            if event_date:
                if 'creation' in event_type or 'registration' in event_type:
                    result['created'] = event_date
                elif 'expiration' in event_type:
                    result['expires'] = event_date
                elif 'last changed' in event_type or 'update' in event_type:
                    result['updated'] = event_date
    
    return result


def get_registrar(rdap_data: Dict[str, Any]) -> Optional[str]:
    """
    从 RDAP 数据中提取注册商信息
    
    Args:
        rdap_data: RDAP 响应数据
    
    Returns:
        注册商名称，失败返回 None
    """
    if not rdap_data:
        return None
    
    # 查找 entities 数组
    entities = rdap_data.get('entities', [])
    if isinstance(entities, list):
        for entity in entities:
            roles = entity.get('roles', [])
            if 'registrar' in roles:
                vcard = entity.get('vcardArray') or []
                properties = vcard[1] if len(vcard) > 1 and isinstance(vcard[1], list) else []
                for property_item in properties:
                    if (isinstance(property_item, list) and len(property_item) >= 4
                            and property_item[0] == 'fn'):
                        return str(property_item[3])
    
    return None


def get_domain_status(rdap_data: Dict[str, Any]) -> list:
    """
    从 RDAP 数据中提取域名状态
    
    Args:
        rdap_data: RDAP 响应数据
    
    Returns:
        域名状态列表
    """
    if not rdap_data:
        return []
    
    statuses = rdap_data.get('status', [])
    if isinstance(statuses, list):
        return statuses
    
    return []
