import os
from bs4 import BeautifulSoup

from .utils.html import decode_content
from .config import (
    load_cache_config,
    load_infrastructure_config,
    load_icp_service_config,
    load_logo_config,
    load_url_database_config,
)
from .integrations.asn import ASNLookup
from .integrations.ct import CTLookup
from .integrations.dns_records import DNSRecordLookup
from .integrations.icp import ICP4759API, ICPService, query_urls as query_icp_urls
from .integrations.icp_cache import ICPRecordStore
from .integrations.http import HttpFetcher, TLSVerificationError, UnsafeTargetError
from .integrations.registration import RegistrationLookup
from .policy.whitelist import WhitelistManager
from .policy.url_database import URLBlocklist
from .analyzers import features
from .analyzers.brand import (
    analyze_domain as analyze_brand_domain,
    find_page_brands,
    page_claim_brand_result,
)
from .analyzers.infra import InfrastructureAnalyzer
from .analyzers.links import analyze_links
from .analyzers.logo import LogoAnalyzer
from .scoring.risk import evaluate_hard_rules, score_result
from .scoring.evidence import evaluate_evidence, RULE_VERSION
from .analyzers.page import analyze_page
from .url_normalization import URLValidationError, normalize_url
from .utils.cache import TTLFileCache, null_cache


DEFAULT_WHITELIST_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'whitelist.txt'
)
DEFAULT_PROVIDERS_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'providers.py'
)
class PhishingDetector:
    def __init__(self, whitelist_path=DEFAULT_WHITELIST_PATH,
                 providers_path=DEFAULT_PROVIDERS_PATH, fetcher=None,
                 registration_lookup=None, whitelist_manager=None,
                 url_database=None, icp_services=None,
                 infra_analyzer=None, logo_analyzer=None):
        self.whitelist_manager = whitelist_manager or WhitelistManager(whitelist_path)
        self.fetcher = fetcher or HttpFetcher()
        self.providers_path = providers_path
        self.url_database = url_database or self._load_url_database(providers_path)
        self.icp_config = self._load_icp_config(providers_path)
        self.icp_record_store = self._load_icp_record_store(self.icp_config)
        self._icp_services = (
            self._build_icp_services() if icp_services is None else list(icp_services)
        )
        # Caches are shared across lookups so one scan warms the next.
        cache_config = self._load_cache_config(providers_path)
        self._cache = (
            TTLFileCache(cache_config['dir']) if cache_config['enabled'] else null_cache()
        )
        if registration_lookup is not None:
            self.registration_lookup = registration_lookup
        else:
            self.registration_lookup = RegistrationLookup(
                cache=self._cache,
                cache_ttl=cache_config['registration_ttl'],
            )
        self.infra_analyzer = (
            infra_analyzer if infra_analyzer is not None
            else self._build_infra_analyzer(providers_path)
        )
        self.logo_analyzer = (
            logo_analyzer if logo_analyzer is not None
            else self._build_logo_analyzer(providers_path)
        )

    def _build_infra_analyzer(self, providers_path):
        config = load_infrastructure_config(providers_path)
        if not config.get('enabled', True):
            return None
        cache = self._cache
        dns_lookup = (
            DNSRecordLookup(cache=cache, timeout=config['dns_timeout'])
            if config.get('dns', True) else None
        )
        asn_lookup = (
            ASNLookup(cache=cache, timeout=config['asn_timeout'])
            if config.get('asn', True) else None
        )
        ct_lookup = (
            CTLookup(cache=cache, timeout=config['ct_timeout'])
            if config.get('ct', False) else None
        )
        return InfrastructureAnalyzer(
            dns_lookup=dns_lookup,
            asn_lookup=asn_lookup,
            ct_lookup=ct_lookup,
            knowledge_base_path=config['knowledge_base_path'],
        )

    def _build_logo_analyzer(self, providers_path):
        config = load_logo_config(providers_path)
        if not config.get('enabled', True):
            return None
        return LogoAnalyzer(
            cache=self._cache, threshold=config['threshold'],
        )

    def _load_cache_config(self, providers_path):
        try:
            return load_cache_config(providers_path)
        except ValueError:
            return {'enabled': False, 'dir': '', 'registration_ttl': 604800}

    def _load_url_database(self, providers_path):
        try:
            config = load_url_database_config(providers_path)
        except ValueError:
            config = {'enabled': False, 'paths': []}
        return URLBlocklist(config.get('paths', []), enabled=config.get('enabled', True))

    def _load_icp_config(self, providers_path):
        try:
            return load_icp_service_config(providers_path)
        except ValueError:
            return {'enabled': False, 'cache': {'enabled': False}, 'fallback_api': {'enabled': False}}

    def _load_icp_record_store(self, icp_config):
        cache_config = icp_config.get('cache', {})
        if cache_config.get('enabled') and cache_config.get('path'):
            return ICPRecordStore(cache_config['path'])
        return None

    def analyze_url(self, url):
        original_input = str(url or '').strip()
        result = {
            'original_url': original_input,
            'url': original_input,
            'total_score': 0,
            'risk_level': '未知',
            'warnings': [],
            'suggestions': [],
            'evidence': [],
            'whois': {'available': False, 'registrant_emails': []},
            'http': {},
            'deformation_match': None,
            'dimension_scores': {},
            'hard_rules': [],
            'trust_signals': [],
            # V2 evidence-chain output; legacy score fields remain below for compatibility.
            'engine_version': RULE_VERSION,
            'verdict': 'UNKNOWN',
            'confidence': 0.0,
            'evidence_groups': {},
            'group_strength': {},
            'strong_groups': [],
            'evidence_summary': {'E0': 0, 'E1': 0, 'E2': 0, 'E3': 0, 'E4': 0},
            'v2_evidence': [],
        }

        try:
            target = normalize_url(original_input)
        except URLValidationError as exc:
            result['risk_level'] = '检测失败'
            result['error'] = str(exc)
            result['evidence'].append({
                'source': 'input_validation', 'result': '失败', 'detail': result['error']
            })
            return result
        url = target.url
        hostname_ascii = target.hostname_ascii
        hostname_unicode = target.hostname_unicode
        domain = target.registered_domain
        full_domain = target.full_domain
        result['original_url'] = target.original_url
        result['url'] = url
        result['requested_url'] = url
        result['url_signals'] = dict(target.signals)
        result['domain'] = domain
        result['full_domain'] = full_domain
        result['hostname_ascii'] = hostname_ascii
        result['hostname_unicode'] = hostname_unicode
        result['has_punycode'] = target.has_punycode
        result['is_ip'] = target.is_ip

        blocked_info = self.url_database.check(domain)
        if blocked_info:
            blocked_v2 = evaluate_evidence(blocked=True)
            result['engine_version'] = blocked_v2['engine_version']
            result['risk_level'] = blocked_v2['risk_level']
            result['verdict'] = blocked_v2['verdict']
            result['confidence'] = blocked_v2['confidence']
            result['evidence_groups'] = blocked_v2['evidence_groups']
            result['group_strength'] = blocked_v2['group_strength']
            result['strong_groups'] = blocked_v2['strong_groups']
            result['evidence_summary'] = blocked_v2['evidence_summary']
            result['v2_evidence'] = blocked_v2['evidence']
            result['total_score'] = 0
            result['blocked'] = True
            result['blocklist'] = blocked_info
            result['suggestions'].append("域名命中本地网址库，已拦截，不再进行钓鱼特征判定")
            result['evidence'].append({
                'source': 'local_url_database',
                'result': '已拦截',
                'detail': (
                    f"主域名 {domain} 命中本地库 {blocked_info.get('source', '')}: "
                    f"{blocked_info.get('matched', '')}"
                ),
            })
            return result

        is_wl, matched_rule = self.whitelist_manager.check(full_domain)
        if is_wl:
            result['whitelisted'] = True
            result['engine_version'] = RULE_VERSION
            result['risk_level'] = '安全'
            result['verdict'] = 'SAFE'
            result['confidence'] = 0.99
            result['evidence_groups'] = {}
            result['group_strength'] = {}
            result['strong_groups'] = []
            result['evidence_summary'] = {'E0': 0, 'E1': 0, 'E2': 0, 'E3': 0, 'E4': 0}
            result['v2_evidence'] = []
            result['total_score'] = 0
            result['suggestions'].append(f"域名在白名单中 (命中规则: {matched_rule})")
            result['evidence'].append({
                'source': 'whitelist', 'result': '白名单',
                'detail': f'命中白名单规则: {matched_rule}'
            })
            return result

        fetch_result = None
        soup = None

        try:
            fetch_result = self.fetcher.fetch(url)
            result['http'] = {
                'status_code': fetch_result.status_code,
                'final_url': fetch_result.final_url,
                'redirects': fetch_result.redirects,
                'redirect_chain': fetch_result.redirect_chain,
                'content_truncated': fetch_result.truncated,
                'redirect_userinfo': fetch_result.redirect_userinfo,
            }
            if fetch_result.redirect_userinfo:
                result['url_signals']['userinfo'] = True
            soup = BeautifulSoup(
                decode_content(fetch_result.content, fetch_result.headers),
                'html.parser',
            )
        except UnsafeTargetError as exc:
            result['risk_level'] = '检测失败'
            result['error'] = str(exc)
            result['evidence'].append({
                'source': 'network_safety', 'result': '拒绝', 'detail': str(exc)
            })
            return result
        except TLSVerificationError as exc:
            result['tls_mismatch'] = True
            result['warnings'].append(f"无法获取页面内容: {exc}")
        except Exception as exc:
            result['warnings'].append(f"无法获取页面内容: {exc}")

        analysis_url = fetch_result.final_url if fetch_result else url
        try:
            final_target = normalize_url(
                analysis_url, require_registered_domain=False
            )
        except URLValidationError as exc:
            result['warnings'].append(f'最终落地 URL 无法规范化: {exc}')
            final_target = target
        analysis_url = final_target.url
        result['final_url'] = analysis_url
        final_hostname_ascii = final_target.hostname_ascii
        final_hostname_unicode = final_target.hostname_unicode
        final_domain = final_target.registered_domain
        final_full_domain = final_target.full_domain

        result['requested_domain'] = domain
        result['requested_full_domain'] = full_domain
        result['final_domain'] = final_domain
        result['final_full_domain'] = final_full_domain
        if final_domain != domain:
            result['domain'] = final_domain
            result['full_domain'] = final_full_domain
            result['hostname_ascii'] = final_hostname_ascii
            result['hostname_unicode'] = final_hostname_unicode
            result['has_punycode'] = final_target.has_punycode
            result['is_ip'] = final_target.is_ip
            result['evidence'].append({
                'source': 'http:cross_domain_redirect',
                'result': '命中',
                'detail': f'请求域名 {domain} 重定向到 {final_domain}',
            })
            redirected_block = self.url_database.check(final_domain)
            if redirected_block:
                result['risk_level'] = '高置信钓鱼'
                result['verdict'] = 'PHISHING'
                result['confidence'] = 1.0
                result['blocked'] = True
                result['blocklist'] = redirected_block
                result['evidence'].append({
                    'source': 'local_url_database',
                    'result': '已拦截',
                    'detail': f'落地域名 {final_domain} 命中本地网址库',
                })
                return result
            redirected_whitelisted, matched_rule = self.whitelist_manager.check(
                final_full_domain
            )
            if redirected_whitelisted:
                result['whitelisted'] = True
                result['risk_level'] = '安全'
                result['verdict'] = 'SAFE'
                result['confidence'] = 0.99
                result['total_score'] = 0
                result['suggestions'].append(
                    f'最终落地域名在白名单中 (命中规则: {matched_rule})'
                )
                result['evidence'].append({
                    'source': 'whitelist',
                    'result': '白名单',
                    'detail': f'最终落地域名命中白名单规则: {matched_rule}',
                })
                return result

        domain = final_domain
        full_domain = final_full_domain
        hostname_ascii = final_hostname_ascii
        hostname_unicode = final_hostname_unicode

        if final_target.is_ip:
            result['whois'] = {
                'available': False, 'registrant_emails': [], 'sources': []
            }
        else:
            registration = self.registration_lookup.lookup(domain)
            result['whois'] = registration.data
            result['warnings'].extend(registration.warnings)
            if registration.rdap:
                result['rdap'] = registration.rdap

        # L2 infrastructure analysis (DNS/ASN/CT + local knowledge base).
        infra_analysis = None
        if self.infra_analyzer is not None and not final_target.is_ip:
            try:
                infra_analysis = self.infra_analyzer.analyze(
                    domain, registered_domain=domain,
                )
            except Exception as exc:
                result['warnings'].append(f'基础设施分析失败: {exc}')
            if infra_analysis:
                result['infrastructure_analysis'] = infra_analysis

        signals = {
            'batch_registration': 0,
            'unnecessary_hyphens': 0,
            'unreachable_domain': -1 if fetch_result is None else 0,
            'whois_unavailable': (
                -1 if not final_target.is_ip
                and not result['whois'].get('available') else 0
            ),
            'ip_host': -1 if final_target.is_ip else 0,
            'tls_mismatch': -1 if result.get('tls_mismatch') else 0,
            'redirect_count': (
                -1 if fetch_result is not None and fetch_result.redirects > 2 else 0
            ),
        }
        try:
            signals['batch_registration'] = features.batch_registration(
                result.get('whois', {})
            )
            signals['unnecessary_hyphens'] = features.unnecessary_hyphens(
                final_target.hostname_ascii
            )
        except Exception as exc:
            result['warnings'].append(f'域名弱信号分析失败: {exc}')
        age_days = _domain_age_days(result.get('whois', {}))
        signals['domain_age_days'] = age_days
        result['context'] = {
            'domain_age_days': age_days,
            'whois_available': bool(result.get('whois', {}).get('available')),
            'is_ip': bool(final_target.is_ip),
            'redirect_count': fetch_result.redirects if fetch_result else 0,
        }
        result['signal_summary'] = {
            name: score < 0 for name, score in signals.items()
            if isinstance(score, (int, float))
        }
        for name, score in signals.items():
            if isinstance(score, (int, float)):
                status = '命中' if score < 0 else ('未命中' if score > 0 else '未知')
                detail = features.describe_feature(name, score)
            else:
                status = '未知'
                detail = f'{name} 无可用数据，仅作为上下文记录'
            result['evidence'].append({
                'source': f'signal:{name}',
                'result': status,
                'detail': detail,
            })

        if not final_target.is_ip:
            self._apply_icp_detection_rule(url, domain, result)
        # Analyze links before scoring so behavior signals can be included.
        if soup:
            try:
                result['link_analysis'] = analyze_links(soup, full_domain)
            except Exception as e:
                result['warnings'].append(f"链接分析失败: {e}")

        # Consolidate brand and page signals before the final risk decision.
        try:
            brand_result = analyze_brand_domain(
                hostname_ascii,
                unicode_domain=hostname_unicode,
            )
        except Exception as e:
            brand_result = {}
            result['warnings'].append(f"品牌仿冒检测失败: {e}")
        result['brand_impersonation'] = brand_result or None
        if brand_result.get('deformation') and brand_result.get('official_domains'):
            result['deformation_match'] = brand_result['official_domains'][0]

        page_result = analyze_page(soup, analysis_url, full_domain)
        page_result['page_brands'] = find_page_brands(
            page_result.get('page_brand_text', [])
        )
        if not brand_result.get('brand_name') and page_result['page_brands']:
            brand_result = page_claim_brand_result(page_result['page_brands'][0])
            result['brand_impersonation'] = brand_result
        if len(page_result['page_brands']) > 1 and not brand_result.get('is_official'):
            brand_result['matched_brands'] = page_result['page_brands']
            brand_result['multiple_brands'] = True
        page_result['brand_text_match'] = _page_mentions_brand(
            page_result.get('page_brand_text', []), brand_result
        )
        page_result['content_mismatch'] = bool(
            page_result['page_brands']
            and not brand_result.get('is_official')
            and (
                brand_result.get('page_claim_only')
                or brand_result.get('brand_name') not in page_result['page_brands']
            )
        )
        sensitive_collection = any(
            page_result.get(key)
            for key in (
                'credential_collection',
                'otp_collection',
                'payment_collection',
                'wallet_seed',
                'personal_info_collection',
            )
        )
        # A page merely mentioning a brand (for example a software catalogue,
        # news article, or WHOIS lookup) is not an impersonation.  Require an
        # official-identity claim or an actual sensitive-data collection flow.
        page_result['page_impersonation'] = bool(
            brand_result.get('brand_name')
            and not brand_result.get('is_official')
            and page_result.get('brand_text_match')
            and (page_result.get('official_claim') or sensitive_collection)
        )
        # Visual brand check: compare the page favicon against the matched
        # brand's official favicon (pHash). Never blocks on its own; it is
        # G4 strong evidence that combines with the standard fusion rules.
        if self.logo_analyzer is not None and soup:
            try:
                logo_result = self.logo_analyzer.analyze(
                    soup, analysis_url, brand_result
                )
                if logo_result:
                    page_result['logo_impersonation'] = logo_result
            except Exception as exc:
                result['warnings'].append(f'Logo 视觉分析失败: {exc}')
        result['page_analysis'] = page_result

        hard_rules = evaluate_hard_rules(
            brand_result,
            page_result,
            has_punycode=result['has_punycode'],
            homograph=brand_result.get('homograph', False),
        )
        for rule in hard_rules:
            # Chinese hard-rule levels map to the V2 verdicts; explicit
            # verdicts from risk.py (MALWARE/SCAM) are preserved as-is.
            if not rule.get('verdict') and rule.get('level') in ('钓鱼', '高置信钓鱼'):
                rule['verdict'] = 'PHISHING'
        result['hard_rules'] = hard_rules
        risk = score_result(
            signals,
            brand=brand_result,
            page=page_result,
            link_analysis=result.get('link_analysis'),
            age_days=age_days,
            has_punycode=result['has_punycode'],
            icp_filing=result.get('icp_filing'),
            whois_data=result.get('whois', {}),
            url_signals=result.get('url_signals'),
        )
        result['total_score'] = risk['total_score']
        result['dimension_scores'] = risk['dimension_scores']
        result['risk_evidence'] = risk['evidence']
        result['max_score'] = risk['max_score']
        result['trust_signals'] = risk['trust_signals']
        v2 = evaluate_evidence(
            brand=brand_result,
            page=page_result,
            signals=signals,
            url_signals=result.get('url_signals'),
            link_analysis=result.get('link_analysis'),
            hard_rules=hard_rules,
            infrastructure={
                'icp_filing': result.get('icp_filing'),
                'signals': (result.get('infrastructure_analysis') or {}).get('signals'),
            },
        )
        result['engine_version'] = v2['engine_version']
        result['verdict'] = v2['verdict']
        result['confidence'] = v2['confidence']
        result['evidence_groups'] = v2['evidence_groups']
        result['group_strength'] = v2['group_strength']
        result['strong_groups'] = v2['strong_groups']
        result['evidence_summary'] = v2['evidence_summary']
        result['v2_evidence'] = v2['evidence']
        # V2 is the formal decision; risk_level is retained for existing consumers.
        result['risk_level'] = v2['risk_level']
        for item in v2['evidence']:
            result['evidence'].append({
                'source': f"v2:{item['rule_id']}",
                'result': item['level'],
                'detail': item['description'],
                'group': item['group'],
            })
        result['evidence'].append({
            'source': 'risk_scoring',
            'result': result['risk_level'],
            'score': result['total_score'],
            'detail': f"四维风险分 {result['total_score']}/{risk['max_score']}: {risk['dimension_scores']}",
        })
        for item in risk['evidence']:
            result['evidence'].append({
                'source': f"rule:{item['rule_id']}",
                'result': '风险',
                'score': item['score'],
                'detail': item['detail'],
            })
        for rule in hard_rules:
            result['evidence'].append({
                'source': f"hard_rule:{rule['id']}",
                'result': rule['level'],
                'detail': rule['detail'],
            })

        if hard_rules:
            result['suggestions'].append(
                f"命中硬规则 {', '.join(rule['id'] for rule in hard_rules)}，建议立即拦截或人工复核"
            )
        elif result['verdict'] in ('PHISHING', 'HIGH_RISK', 'MALWARE', 'SCAM'):
            result['suggestions'].append(f"风险分 {result['total_score']}/17，强烈建议勿访问")
        elif result['verdict'] == 'SUSPICIOUS':
            result['suggestions'].append(f"风险分 {result['total_score']}/17，建议进入二次检测")
        else:
            result['suggestions'].append("风险分较低，暂未发现足以判定为钓鱼的证据")

        return result

    def _apply_icp_detection_rule(self, url, domain, result):
        try:
            icp_results = query_icp_urls(
                domain,
                self._icp_services,
                record_store=self.icp_record_store,
            )
        except Exception as exc:
            result['warnings'].append(f"ICP备案规则执行失败: {exc}")
            self._record_icp_feature(result, 0, '未知', 'ICP备案无法判断或证据不足')
            return

        icp_result = icp_results[0] if icp_results else {}
        result['icp_filing'] = icp_result

        if icp_result.get('error'):
            result['warnings'].append(f"ICP备案查询失败: {icp_result['error']}")
            self._record_icp_feature(result, 0, '未知', 'ICP备案无法判断或证据不足')
            return

        if icp_result.get('has_filing'):
            self._record_icp_feature(
                result,
                0,
                '上下文',
                f'主域名 {domain} 存在官方备案，作为信任上下文记录，不进入风险分',
            )
            return

        self._record_icp_feature(
            result,
            0,
            '未知',
            f'主域名 {domain} 未查到官方备案',
        )

    def _record_icp_feature(self, result, score, status, detail):
        result['evidence'].append({
            'source': 'context:icp_filing',
            'result': status,
            'score': score,
            'detail': detail,
        })

    def _build_icp_services(self):
        services = []
        if self.icp_config.get('enabled', True):
            services.append(ICPService(
                base_url=self.icp_config.get('base_url', ''),
                exe_path=self.icp_config.get('exe_path', ''),
                auto_start=self.icp_config.get('auto_start', True),
                startup_timeout=self.icp_config.get('startup_timeout', 20),
                request_timeout=self.icp_config.get('request_timeout', 20),
            ))

        fallback_api = self.icp_config.get('fallback_api', {})
        if fallback_api.get('enabled') and fallback_api.get('url') and fallback_api.get('api_key'):
            services.append(ICP4759API(
                api_url=fallback_api['url'],
                api_key=fallback_api['api_key'],
                request_timeout=fallback_api.get('request_timeout', 20),
            ))
        return services

    def _stop_icp_services(self, services):
        for service in services:
            stop = getattr(service, 'stop', None)
            if callable(stop):
                stop()

    def close(self):
        """Release scanner-owned external service processes."""
        self._stop_icp_services(self._icp_services)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def batch_detect(self, urls, max_workers=2):
        from concurrent.futures import ThreadPoolExecutor, as_completed
        urls = list(urls)
        results = [None] * len(urls)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_item = {
                executor.submit(self.analyze_url, url): (index, url)
                for index, url in enumerate(urls)
            }
            for future in as_completed(future_to_item):
                index, url = future_to_item[future]
                try:
                    results[index] = future.result()
                except Exception as e:
                    results[index] = {
                        'url': url, 'error': str(e), 'risk_level': '检测失败'
                    }
        return results


def _domain_age_days(whois_data):
    from datetime import datetime, date
    value = (whois_data or {}).get('creation_date', '')
    if isinstance(value, list):
        value = value[0] if value else ''
    try:
        created = datetime.strptime(str(value)[:10], '%Y-%m-%d').date()
        return (date.today() - created).days
    except (TypeError, ValueError):
        return None


def _page_mentions_brand(page_brand_text, brand):
    if not brand or not brand.get('brand_name'):
        return False
    aliases = {
        str(brand.get('brand_name', '')).lower(),
        str(brand.get('matched_alias', '')).lower(),
        str(brand.get('matched_token', '')).lower(),
    }
    aliases = {value for value in aliases if len(value) >= 4}
    haystack = ' '.join(str(value).lower() for value in page_brand_text or [])
    return any(alias in haystack for alias in aliases)


def _highest_hard_level(rules):
    rank = {'高风险': 1, '钓鱼': 2, '高置信钓鱼': 3}
    return max((rule.get('level', '高风险') for rule in rules), key=lambda value: rank.get(value, 0))

