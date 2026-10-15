import json
from pathlib import Path
import re
from typing import Optional

from ..utils.tld import TLD_EXTRACTOR
from ..utils.domain import ascii_hostname, unicode_hostname
from ..utils.skeleton import skeleton, mixed_script

DEFAULT_BRAND_DATABASE_PATH = (
    Path(__file__).resolve().parents[2] / 'brands.json'
)


def load_brand_database(path=DEFAULT_BRAND_DATABASE_PATH):
    """Load and validate the configurable official brand asset database."""
    try:
        with Path(path).open('r', encoding='utf-8-sig') as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f'品牌库加载失败 {path}: {exc}') from exc
    entries = payload.get('brands') if isinstance(payload, dict) else payload
    if not isinstance(entries, list) or not entries:
        raise ValueError('品牌库 brands 必须是非空数组')
    result = []
    for index, entry in enumerate(entries, 1):
        if not isinstance(entry, dict):
            raise ValueError(f'品牌库第 {index} 项必须是对象')
        name = str(entry.get('name', '')).strip()
        domains = _string_list(entry.get('official_domains'))
        aliases = _string_list(entry.get('aliases') or entry.get('keywords'))
        if not name or not domains or not aliases:
            raise ValueError(f'品牌库第 {index} 项缺少 name、official_domains 或 aliases')
        result.append({
            'name': name,
            'official_domains': domains,
            'aliases': aliases,
        })
    return result


def _string_list(value):
    if not isinstance(value, list):
        return []
    return list(dict.fromkeys(
        str(item).strip().lower() for item in value if str(item).strip()
    ))


BRAND_DATABASE = load_brand_database()

_DOMAIN_TO_ENTRY = {}
for _entry in BRAND_DATABASE:
    for _domain in _entry['official_domains']:
        _DOMAIN_TO_ENTRY[_domain.lower()] = _entry

# The full UTS#39 confusables table lives in detector/utils/confusables.py
# and is applied via skeleton() from detector/utils/skeleton.py.

# Common dictionary tokens that must never similarity-match a brand alias
# through edit distance alone.  Exact/substring/homograph matching is not
# affected by this list.
GENERIC_TOKENS = frozenset({
    'china', 'soft', 'news', 'download', 'free', 'mail', 'web', 'net',
    'app', 'site', 'online', 'shop', 'live', 'game', 'video', 'music',
    'movie', 'bank', 'pay', 'card', 'money', 'safe', 'login', 'verify',
    'account', 'support', 'help', 'service', 'center', 'cloud', 'tool',
    'home', 'info', 'link', 'data', 'file', 'fast', 'best', 'top',
})

ASCII_SUBSTITUTION_MAP = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a',
    '5': 's', '6': 'g', '7': 't', '8': 'b',
    '@': 'a', '$': 's',
}

KEYBOARD_NEIGHBORS = {
    'q': 'wa', 'w': 'qesa', 'e': 'wrsd', 'r': 'etfd', 't': 'rygf',
    'y': 'tugh', 'u': 'yihj', 'i': 'uojk', 'o': 'ipkl', 'p': 'ol',
    'a': 'qwsz', 's': 'awedxz', 'd': 'serfcx', 'f': 'drtgvc',
    'g': 'ftyhbv', 'h': 'gyujnb', 'j': 'huikmn', 'k': 'jiolm',
    'l': 'kop', 'z': 'asx', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb',
    'b': 'vghn', 'n': 'bhjm', 'm': 'njk',
}


def _levenshtein(a: str, b: str) -> int:
    previous = list(range(len(b) + 1))
    for index_a, char_a in enumerate(a, 1):
        current = [index_a]
        for index_b, char_b in enumerate(b, 1):
            current.append(min(
                current[-1] + 1,
                previous[index_b] + 1,
                previous[index_b - 1] + (char_a != char_b),
            ))
        previous = current
    return previous[-1]


def _damerau_levenshtein(a: str, b: str) -> int:
    distances = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for index in range(len(a) + 1):
        distances[index][0] = index
    for index in range(len(b) + 1):
        distances[0][index] = index
    for index_a in range(1, len(a) + 1):
        for index_b in range(1, len(b) + 1):
            substitution = int(a[index_a - 1] != b[index_b - 1])
            distances[index_a][index_b] = min(
                distances[index_a - 1][index_b] + 1,
                distances[index_a][index_b - 1] + 1,
                distances[index_a - 1][index_b - 1] + substitution,
            )
            if (index_a > 1 and index_b > 1
                    and a[index_a - 1] == b[index_b - 2]
                    and a[index_a - 2] == b[index_b - 1]):
                distances[index_a][index_b] = min(
                    distances[index_a][index_b],
                    distances[index_a - 2][index_b - 2] + 1,
                )
    return distances[-1][-1]


def _is_keyboard_substitution(value: str, target: str) -> bool:
    if len(value) != len(target):
        return False
    differences = [
        (observed, expected)
        for observed, expected in zip(value, target)
        if observed != expected
    ]
    return bool(
        len(differences) == 1
        and differences[0][0] in KEYBOARD_NEIGHBORS.get(differences[0][1], '')
    )


def _normalize_confusable(value):
    """UTS#39 skeleton: confusables collapse to a canonical sequence."""
    return skeleton(value)


def _similarity_threshold(token: str, alias: str) -> int:
    """Dynamic edit-distance threshold per deep-research-report 6.2.

    Short names are fragile: an appended character usually produces a
    different entity (china vs chinaz), so length must match exactly.
    Longer names tolerate one insertion/deletion plus substitutions.
    """
    longest = max(len(token), len(alias))
    difference = abs(len(token) - len(alias))
    if longest <= 6:
        return 1 if difference == 0 else 0
    if longest <= 10:
        return 2 if difference <= 1 else 1
    if difference <= 1:
        return 3
    if difference <= 2:
        return 2
    return 1


def _normalize_substitution(value):
    return ''.join(
        ASCII_SUBSTITUTION_MAP.get(char, char)
        for char in str(value or '').lower()
    )


def _min_alias_length(alias):
    if alias.isdigit():
        return 2
    if alias.isascii():
        return 3
    return 2


def _brand_aliases(entry):
    aliases = set(entry['aliases'])
    for official_domain in entry['official_domains']:
        extracted = TLD_EXTRACTOR(official_domain.lower())
        if extracted.domain:
            aliases.add(extracted.domain.lower())
    return {alias for alias in aliases if len(alias) >= _min_alias_length(alias)}


def _canonical_brand_name(entry):
    return entry['name']


def find_official(domain: str) -> Optional[dict]:
    extracted = TLD_EXTRACTOR(str(domain or '').lower())
    if extracted.domain and extracted.suffix:
        registered_domain = f'{extracted.domain}.{extracted.suffix}'
    else:
        registered_domain = str(domain or '').lower().strip('.')
    return _DOMAIN_TO_ENTRY.get(registered_domain.replace('www.', '', 1))


def find_page_brands(values) -> list:
    """Return canonical brands explicitly mentioned in title/logo metadata."""
    text = ' '.join(str(value).lower() for value in values or [])
    matches = []
    for entry in BRAND_DATABASE:
        if any(re.search(
                rf'(?<![a-z0-9]){re.escape(alias)}(?![a-z0-9])', text)
                for alias in _brand_aliases(entry)):
            matches.append(entry['name'])
    return matches


def page_claim_brand_result(brand_name: str) -> dict:
    """Create a brand signal when the page, but not the domain, claims a brand."""
    entry = next(
        (item for item in BRAND_DATABASE if item['name'] == brand_name), None
    )
    if not entry:
        return {}
    return {
        'brand_name': entry['name'],
        'matched_brand': entry['name'],
        'official_domain': '',
        'official_domains': list(entry['official_domains']),
        'is_official': False,
        'matched_brands': [entry['name']],
        'multiple_brands': False,
        'high_similarity': False,
        'homograph': False,
        'character_substitution': False,
        'mixed_script': False,
        'fake_official_subdomain': False,
        'deformation': False,
        'deformation_score': 0.0,
        'page_claim_only': True,
    }


def analyze_domain(domain: str, unicode_domain: Optional[str] = None) -> dict:
    """Return brand, similarity, homograph, and official-domain signals."""
    ascii_host = ascii_hostname(domain)
    unicode_host = unicode_hostname(unicode_domain or ascii_host)
    extracted = TLD_EXTRACTOR(ascii_host)
    registered_domain = (
        f'{extracted.domain}.{extracted.suffix}'
        if extracted.domain and extracted.suffix else ascii_host
    )
    registered_label = extracted.domain.lower() if extracted.domain else ascii_host.split('.')[0]
    official_entry = find_official(registered_domain)
    ascii_labels = ascii_host.split('.')
    unicode_labels = unicode_host.split('.')
    matches = []

    for entry in BRAND_DATABASE:
        best = None
        for label_index, raw_label in enumerate(ascii_labels):
            unicode_label = (
                unicode_labels[label_index]
                if label_index < len(unicode_labels) else raw_label
            )
            ascii_tokens = [token for token in re.split(r'[-_]', raw_label) if token]
            unicode_tokens = [
                token for token in re.split(r'[-_]', unicode_label) if token
            ]
            for token_index, unicode_token in enumerate(unicode_tokens):
                token = (
                    ascii_tokens[token_index]
                    if token_index < len(ascii_tokens) else unicode_token
                )
                confusable_token = _normalize_confusable(unicode_token)
                substituted_token = _normalize_substitution(token)
                candidate = None
                method = ''
                high_similarity = False
                homograph = False
                character_substitution = False

                for alias in _brand_aliases(entry):
                    if token == alias or confusable_token == alias or substituted_token == alias:
                        if token == alias and unicode_token == alias:
                            method = 'exact'
                        elif confusable_token == alias and unicode_token != alias:
                            method = 'homograph'
                            homograph = True
                        else:
                            method = 'character_substitution'
                            character_substitution = True
                        candidate = alias
                        high_similarity = method != 'exact' or token == registered_label
                        break
                if candidate is None:
                    for alias in _brand_aliases(entry):
                        if len(token) >= len(alias) and alias in token:
                            candidate = alias
                            method = 'substring'
                            high_similarity = len(token) - len(alias) <= 3
                            break
                        if len(confusable_token) >= len(alias) and alias in confusable_token:
                            candidate = alias
                            method = 'homograph_substring'
                            high_similarity = len(confusable_token) - len(alias) <= 3
                            homograph = True
                            break
                if candidate is None and len(confusable_token) >= 4 and token not in GENERIC_TOKENS:
                    for alias in _brand_aliases(entry):
                        # Short aliases edit-distance match too many ordinary
                        # words; require a minimum length unless numeric.
                        if len(alias) < 5 and not alias.isdigit():
                            continue
                        if abs(len(confusable_token) - len(alias)) > 3:
                            continue
                        distance = min(
                            _levenshtein(confusable_token, alias),
                            _damerau_levenshtein(confusable_token, alias),
                        )
                        if distance <= _similarity_threshold(confusable_token, alias):
                            candidate = alias
                            if _is_keyboard_substitution(confusable_token, alias):
                                method = 'character_substitution'
                                character_substitution = True
                            else:
                                method = 'similarity'
                            high_similarity = True
                            break
                if candidate is None:
                    continue
                rank = {
                    'homograph': 5,
                    'homograph_substring': 5,
                    'character_substitution': 5,
                    'similarity': 4,
                    'substring': 3,
                    'exact': 2,
                }.get(method, 1)
                current = {
                    'entry': entry,
                    'method': method,
                    'rank': rank,
                    'high_similarity': high_similarity,
                    'homograph': homograph,
                    'character_substitution': character_substitution,
                    'mixed_script': (
                        method in ('homograph', 'homograph_substring')
                        and mixed_script(unicode_token)
                    ),
                    'in_subdomain': label_index < len(ascii_labels) - len(registered_domain.split('.')),
                    'matched_token': unicode_token,
                    'matched_alias': candidate,
                }
                if best is None or current['rank'] > best['rank']:
                    best = current
        if best:
            matches.append(best)

    matches.sort(key=lambda item: item['rank'], reverse=True)
    matched_brands = []
    for item in matches:
        name = _canonical_brand_name(item['entry'])
        if name not in matched_brands:
            matched_brands.append(name)

    primary = matches[0] if matches else None
    is_official = bool(official_entry)
    primary_name = _canonical_brand_name(primary['entry']) if primary else None
    result = {
        'brand_name': _canonical_brand_name(official_entry) if official_entry else primary_name,
        'matched_brand': _canonical_brand_name(official_entry) if official_entry else primary_name,
        'official_domain': registered_domain if official_entry else '',
        'official_domains': list(
            (official_entry or (primary and primary['entry']) or {}).get(
                'official_domains', []
            )
        ),
        'is_official': is_official,
        'matched_brands': matched_brands,
        'multiple_brands': len(matched_brands) >= 2 and not is_official,
        'high_similarity': bool(primary and primary['high_similarity'] and not is_official),
        'homograph': bool(primary and primary['homograph'] and not is_official),
        'mixed_script': bool(primary and primary['mixed_script'] and not is_official),
        'character_substitution': bool(
            primary and primary['character_substitution'] and not is_official
        ),
        'fake_official_subdomain': bool(primary and primary['in_subdomain'] and not is_official),
        'deformation': bool(
            primary and not is_official and registered_label != primary['matched_alias']
        ),
        'deformation_score': 0.0,
        'has_punycode': 'xn--' in ascii_host,
        'ascii_hostname': ascii_host,
        'unicode_hostname': unicode_host,
    }
    if primary and not is_official:
        if primary['homograph']:
            result['deformation_score'] = 3.0
        elif primary['character_substitution']:
            result['deformation_score'] = 1.5
        elif primary['method'] in ('similarity', 'homograph_substring'):
            result['deformation_score'] = 2.0
        else:
            result['deformation_score'] = 1.0
        result['matched_by'] = primary['method']
        result['matched_token'] = primary['matched_token']
        result['matched_alias'] = primary['matched_alias']
    return result
