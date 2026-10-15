#!/usr/bin/env python3
"""
增强版 WHOIS 查询模块
多策略查询：python-whois → 原始 WHOIS 协议
"""

import socket
import re
import logging
import time
import datetime

logger = logging.getLogger(__name__)

# ── 日期解析 ──

_DATE_FORMATS = [
    "%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S%z", "%Y/%m/%d", "%d-%b-%Y", "%d %b %Y",
    "%b %d %Y", "%Y%m%d", "%Y-%m-%dT%H:%M:%S.%fZ",
]


def _parse_date(date_str):
    if not date_str or date_str == 'N/A':
        return ""
    date_str = str(date_str).strip()
    for fmt in _DATE_FORMATS:
        try:
            dt = datetime.datetime.strptime(date_str, fmt)
            return dt.strftime("%Y-%m-%d")
        except (ValueError, TypeError):
            continue
    m = re.search(r'(\d{4}-\d{2}-\d{2})', date_str)
    if m:
        try:
            return datetime.datetime.strptime(m.group(1), "%Y-%m-%d").strftime("%Y-%m-%d")
        except (ValueError, TypeError):
            pass
    return date_str[:20]


# ── 策略 1: python-whois ──

def _query_primary(domain, timeout=12):
    """使用 python-whois 库查询"""
    try:
        import whois as _whois_mod
        whois_query = getattr(_whois_mod, 'whois', None)
        if not whois_query:
            return None
        w = whois_query(domain, timeout=timeout)
        if not w:
            return None

        email_val = (
            getattr(w, 'email', '') or getattr(w, 'emails', '')
            or getattr(w, 'registrant_email', '')
        )
        if isinstance(email_val, list):
            email_val = email_val[0] if email_val else ''
        email_val = str(email_val).strip()

        def _val(name, *fallbacks):
            for key in (name,) + fallbacks:
                v = getattr(w, key, None)
                if v:
                    return v
            return ''

        ns = getattr(w, 'name_servers', None)
        if isinstance(ns, list):
            ns_str = ", ".join([str(x) for x in ns[:3]])
        elif ns:
            ns_str = str(ns)
        else:
            ns_str = ""

        return {
            "creation_date": _parse_date(_val('creation_date')),
            "expiration_date": _parse_date(_val('expiration_date')),
            "updated_date": _parse_date(_val('updated_date')),
            "registrar": str(_val('registrar') or '').strip(),
            "name_servers": ns_str,
            "status": str(_val('status') or '').strip(),
            "registrant_name": str(_val('name', 'registrant_name') or '').strip(),
            "registrant_org": str(_val('org', 'organization', 'registrant_org') or '').strip(),
            "registrant_email": email_val,
            "registrant_phone": str(_val('phone', 'registrant_phone') or '').strip(),
            "registrant_address": str(_val('address', 'registrant_address') or '').strip(),
            "country": str(_val('country') or '').strip(),
            "city": str(_val('city') or '').strip(),
            "state": str(_val('state') or '').strip(),
            "zipcode": str(_val('zipcode', 'postal_code') or '').strip(),
        }
    except Exception as e:
        logger.debug(f"whois primary failed for {domain}: {e}")
        return None


# ── 策略 2: 原始 WHOIS 协议 ──

_TLD_SERVERS = {
    'com': 'whois.verisign-grs.com',
    'net': 'whois.verisign-grs.com',
    'org': 'whois.pir.org',
    'cn': 'whois.cnnic.cn',
    'io': 'whois.nic.io',
    'co': 'whois.nic.co',
    'info': 'whois.afilias.net',
    'biz': 'whois.nic.biz',
    'xyz': 'whois.nic.xyz',
    'online': 'whois.nic.online',
    'site': 'whois.nic.site',
    'store': 'whois.nic.store',
    'tech': 'whois.nic.tech',
    'app': 'whois.nic.app',
    'dev': 'whois.nic.dev',
    'ai': 'whois.nic.ai',
    'gg': 'whois.nic.gg',
    'ru': 'whois.tcinet.ru',
    'top': 'whois.nic.top',
    'cc': 'whois.nic.cc',
    'me': 'whois.nic.me',
    'tv': 'whois.nic.tv',
    'pw': 'whois.nic.pw',
    'ltd': 'whois.nic.ltd',
    'inc': 'whois.nic.inc',
    'global': 'whois.nic.global',
    'club': 'whois.nic.club',
    'pro': 'whois.nic.pro',
    'mobi': 'whois.nic.mobi',
    'name': 'whois.nic.name',
    'tel': 'whois.nic.tel',
    'asia': 'whois.nic.asia',
    'travel': 'whois.nic.travel',
    'jobs': 'whois.nic.jobs',
    'museum': 'whois.nic.museum',
    'coop': 'whois.nic.coop',
    'cat': 'whois.nic.cat',
    'edu': 'whois.educause.net',
    'gov': 'whois.nic.gov',
    'mil': 'whois.nic.mil',
    'int': 'whois.iana.org',
}

_CNNIC_KEYWORDS = ["China Internet Network Information Center", "cnnic.cn", "CNNIC"]


def _is_cnnic(val):
    val_lower = str(val).lower()
    return any(kw.lower() in val_lower for kw in _CNNIC_KEYWORDS)


def _query_raw(domain, timeout=12):
    """通过原始 WHOIS 协议查询"""
    tld = domain.split('.')[-1]
    servers = []
    if tld in _TLD_SERVERS:
        servers.append(_TLD_SERVERS[tld])
    servers.extend(['whois.iana.org', 'whois.internic.net'])

    for server in servers:
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((server, 43))
            s.sendall(f"{domain}\r\n".encode())
            s.shutdown(socket.SHUT_WR)
            data = b""
            while True:
                try:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                except socket.timeout:
                    break
            text = data.decode('utf-8', errors='ignore')
            if len(text) > 50:
                return _parse_raw_whois(text)
        except Exception as e:
            logger.debug(f"whois raw failed for {domain} via {server}: {e}")
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass
        continue
    return None


_RAW_PATTERNS = {
    "creation_date": [
        r'[Cc]reation\s*[Dd]ate:\s*([\d\-/]{8,20})',
        r'[Rr]egistered\s*on:\s*([\d\-/]{8,20})',
        r'[Rr]egistratio[n]?\s*[Dd]ate:\s*([\d\-/]{8,20})',
    ],
    "expiration_date": [
        r'[Ee]xpir[a]?tion\s*[Dd]ate:\s*([\d\-/]{8,20})',
        r'[Ee]xpires\s*on:\s*([\d\-/]{8,20})',
        r'[Ee]xpiry\s*[Dd]ate:\s*([\d\-/]{8,20})',
    ],
    "updated_date": [
        r'[Uu]pdated\s*[Dd]ate:\s*([\d\-/]{8,20})',
        r'[Ll]ast\s*[Mm]odified:\s*([\d\-/]{8,20})',
    ],
    "registrar": [
        r'[Rr]egistrar:\s*(.+?)$',
        r'[Ss]ponsoring\s*[Rr]egistrar:\s*(.+?)$',
    ],
    "status": [
        r'[Dd]omain\s*[Ss]tatus:\s*(.+?)$',
    ],
    "registrant_name": [
        r'[Rr]egistrant\s*[Nn]ame:\s*(.+?)$',
        r'[Rr]egistrant\s*[Cc]ontact\s*[Nn]ame:\s*(.+?)$',
    ],
    "registrant_org": [
        r'[Rr]egistrant\s*[Oo]rgani[sz]ation:\s*(.+?)$',
        r'[Rr]egistrant\s*[Cc]ompany:\s*(.+?)$',
    ],
    "registrant_email": [
        r'[Rr]egistrant\s*[Ee]mail:\s*(.+?)$',
        r'[Rr]egistrant\s*[Cc]ontact\s*[Ee]mail:\s*(.+?)$',
    ],
    "registrant_phone": [
        r'[Rr]egistrant\s*[Pp]hone:\s*(.+?)$',
    ],
    "registrant_address": [
        r'[Rr]egistrant\s*[Aa]ddress:\s*(.+?)$',
    ],
    "country": [
        r'[Rr]egistrant\s*[Cc]ountry:\s*(.+?)$',
    ],
    "city": [
        r'[Rr]egistrant\s*[Cc]ity:\s*(.+?)$',
    ],
    "state": [
        r'[Rr]egistrant\s*[Ss]tate/[Pp]rovince:\s*(.+?)$',
    ],
    "zipcode": [
        r'[Rr]egistrant\s*[Pp]ostal\s*[Cc]ode:\s*(.+?)$',
    ],
}


def _parse_raw_whois(text):
    result = {
        "creation_date": "", "expiration_date": "", "updated_date": "",
        "registrar": "", "name_servers": "", "status": "",
        "registrant_name": "", "registrant_org": "", "registrant_email": "",
        "registrant_phone": "", "registrant_address": "",
        "country": "", "city": "", "state": "", "zipcode": "",
    }

    for field, pats in _RAW_PATTERNS.items():
        for pat in pats:
            m = re.search(pat, text, re.MULTILINE)
            if m:
                val = m.group(1).strip().rstrip('\r')
                if field in ("creation_date", "expiration_date", "updated_date"):
                    result[field] = _parse_date(val)
                elif _is_cnnic(val) and field.startswith('registrant_'):
                    continue
                else:
                    result[field] = val[:80]
                break

    ns_matches = re.findall(r'[Nn]ame\s*[Ss]erver:\s*([\w\.\-]+)', text)
    if ns_matches:
        result["name_servers"] = ", ".join(ns_matches[:3])

    if not result["registrant_email"]:
        email_match = re.search(r'([^\s@]+@[^\s@]+\.[^\s@]+)', text)
        if email_match:
            email_val = email_match.group(1)
            if not _is_cnnic(email_val):
                result["registrant_email"] = email_val[:80]

    return result


# ── 统一查询入口 ──

def query_whois(domain, timeout=4, max_retry=1):
    """
    多策略 WHOIS 查询，返回合并后的注册信息字典。
    策略顺序：python-whois → 原始 WHOIS 协议。
    RDAP 由 RegistrationLookup 独立查询和合并。
    """
    strategies = [
        ("primary", _query_primary),
        ("raw", _query_raw),
    ]

    merged = {}
    best = None

    for attempt in range(max_retry):
        for name, func in strategies:
            try:
                result = func(domain, timeout)
                if result and not result.get("_error"):
                    if result.get("creation_date") and not best:
                        best = result.copy()
                    for key, value in result.items():
                        if key != "_error" and value and not merged.get(key):
                            merged[key] = value
                    if merged.get("creation_date"):
                        logger.debug(f"WHOIS success via {name} for {domain}")
                        return merged
            except Exception as e:
                logger.debug(f"WHOIS {name} failed (attempt {attempt+1}): {e}")
        if attempt < max_retry - 1:
            time.sleep(1)

    if best:
        return best
    return None
