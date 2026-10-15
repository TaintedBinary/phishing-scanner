"""链接分析规则"""
from urllib.parse import urljoin, urlparse

from ..utils.domain import registered_domain
from ..utils.tld import TLD_EXTRACTOR

SHORT_URL_DOMAINS = [
    'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 'cli.gs',
    'yfrog.com', 'migre.me', 'ff.im', 'tiny.cc', 'url4.eu', 'twit.ac',
    'su.pr', 'twurl.nl', 'snipurl.com', 'short.to', 'budurl.com', 'ping.fm',
    'post.ly', 'just.as', 'bkite.com', 'snipr.com', 'fic.kr', 'loopt.us',
    'doiop.com', 'short.ie', 'kl.am', 'wp.me', 'rubyurl.com', 'om.ly',
    'to.ly', 'bit.do', 'lnkd.in', 'db.tt', 'qr.ae', 'adf.ly', 'bitly.com',
    'cur.lv', 'ity.im', 'q.gs', 'po.st', 'bc.vc', 'twitthis.com', 'u.to',
    'j.mp', 'buzurl.com', 'cutt.us', 'u.bb', 'yourls.org', 'prettylinkpro.com',
    'scrnch.me', 'filoops.info', 'vzturl.com', 'qr.net', '1url.com',
    'tweez.me', 'v.gd', 'tr.im', 'link.zip.net',
]

SUSPICIOUS_LINK_KEYWORDS = ['download', 'update', 'install', 'setup', 'get', '安装', '下载', '更新', '升级']

def analyze_links(soup, page_domain):
    result = {'total_links': 0, 'external_links': 0, 'external_ratio': 0.0,
              'short_url_count': 0, 'hidden_links': 0, 'suspicious_links': [], 'score': 1}
    if not soup:
        return result
    links = soup.find_all('a', href=True)
    result['total_links'] = len(links)
    if not links:
        return result
    page_registered = registered_domain(page_domain, TLD_EXTRACTOR)
    external_count = 0
    short_url_count = 0
    hidden_count = 0
    suspicious = []
    for link in links:
        href = link.get('href', '').strip()
        if not href or href.startswith('#') or href.startswith('javascript:'):
            continue
        try:
            parsed = urlparse(urljoin(f'https://{page_domain}/', href))
            link_domain = (parsed.hostname or '').lower()
        except Exception:
            continue
        if (link_domain and
                registered_domain(link_domain, TLD_EXTRACTOR) != page_registered):
            external_count += 1
            if link_domain in SHORT_URL_DOMAINS:
                short_url_count += 1
                suspicious.append({'href': href, 'reason': '短链接服务'})
            link_text = (link.get_text() or '').strip().lower()
            if any(kw in link_text for kw in SUSPICIOUS_LINK_KEYWORDS):
                suspicious.append({'href': href, 'text': link_text, 'reason': '可疑链接文本'})
        style = link.get('style', '')
        if style and ('display:none' in style.lower() or 'visibility:hidden' in style.lower()):
            hidden_count += 1
            suspicious.append({'href': href, 'reason': '隐藏链接'})
    result['external_links'] = external_count
    result['external_ratio'] = external_count / len(links) if links else 0.0
    result['short_url_count'] = short_url_count
    result['hidden_links'] = hidden_count
    result['suspicious_links'] = suspicious
    if result['external_ratio'] > 0.8 or result['short_url_count'] > 3 or result['hidden_links'] > 0 or len(suspicious) > 5:
        result['score'] = -1
    return result
